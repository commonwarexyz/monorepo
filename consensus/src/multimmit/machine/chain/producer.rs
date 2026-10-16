//! The local producer: building, custody, and signing of this node's own blocks.
//!
//! The producer builds one block every `theta`, the configured production interval, whether or
//! not the block carries input: the application answers each build at once with whatever it has
//! to include, possibly nothing. It may build height `h` of its chain once
//! `h - max(h*, f) <= D`, the specification's flow bound, where `f` is the chain's greatest
//! height this node knows final. An empty body takes the next height like any other block, so an
//! idle chain fills its window at the same pace as a loaded one. The flow bound is a safety limit
//! rather than the pace: it holds a correct producer back only while its blocks' endorsements lag
//! production by `D` blocks.
//!
//! Each build is issued at its slot, `theta` after the previous one. A build issued within `theta`
//! of its slot keeps the slot, so late timers do not stretch the pace; one issued later, after the
//! flow bound held the producer, starts a new schedule at once, so a released producer resumes one
//! block per `theta` rather than in a burst.
//!
//! Blocks move through a pipeline that overlaps them: the next build starts at its slot once the
//! previous one returned its body, built bodies enter the application's durable custody
//! concurrently, and signatures are reserved in height order over the custodied prefix only, so no
//! header is ever signed before its body and every lower body are held. A reservation advances the
//! durable produced height in the same event, so no height is ever signed twice, and the header is
//! published only after its signed record is durable. Reservations staged together share one
//! journal barrier. Signatures may complete in any order; own headers are accepted in height order
//! as the signed prefix grows.
//!
//! After a restart the producer resumes from durable state: the reserved signatures are released
//! again under the new generation, signed headers above a missing signature wait for it, and
//! building resumes above the newest reserved header. Built blocks that were never reserved are
//! built again.

use super::is_capacity;
use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Role},
        machine::{
            capability::{AppJob, BuildId, BuildJob, Capabilities, Capability, CustodyJob},
            durability::{DurableEffect, SignRequest},
            input::{BuildCompletion, CustodyCompletion, Now, StepError, TimerFamily},
            job::{IdSequence, Issued},
            reducer::{
                components::{WorkResult, WorkStatus},
                machine::Machine,
            },
            scheduler::ProtocolComponent,
            view::timing::millis,
        },
        types::{Artifact, BlockRef, ChainId, SignedTransactionBlock, TransactionBlockHeader},
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// A built block whose header's signature is not yet reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Built<D: Digest> {
    /// The build that produced it, which its custody completion names.
    issued: Issued<BuildId>,
    header: TransactionBlockHeader<D>,
    /// Whether the application holds its body durably.
    custodied: bool,
}

/// Time the local producer spent held by the flow bound since the process started.
///
/// A hold counts from the later of the moment the bound refused the next height and that height's
/// slot, so only time the producer would otherwise have spent building is counted, and it is
/// recorded when the bound admits the next height.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProductionHolds {
    /// Milliseconds held.
    pub(crate) millis: u64,
    /// Holds that cost time.
    pub(crate) holds: u64,
}

impl ProductionHolds {
    /// Records a hold that lasted `millis`.
    const fn record(&mut self, millis: u64) {
        if millis == 0 {
            return;
        }
        self.millis = self.millis.saturating_add(millis);
        self.holds = self.holds.saturating_add(1);
    }
}

/// The local producer's volatile state.
pub(crate) struct Producer<V: Variant, D: Digest> {
    chain: ChainId,
    /// The newest header built, which the next build extends: the newest unreserved built header,
    /// else the newest header this node reserved a signature for, else the chain's origin.
    head: BlockRef<D>,
    /// The outstanding build.
    building: Option<Issued<BuildId>>,
    /// The slot of the newest build, from which the next one is paced; `None` until the first
    /// build after a start.
    slot: Option<Now>,
    /// Built headers above the newest reserved one, lowest first.
    unreserved: VecDeque<Built<D>>,
    /// Signed own headers above the accepted tip that wait for a lower header's signature.
    signed: BTreeMap<Height, Arc<SignedTransactionBlock<V, D>>>,
    /// Until when a build the application declined defers the next one.
    declined_until: Option<Now>,
    builds: IdSequence<BuildId>,
    /// When the flow bound's hold on the next build started to cost time.
    held: Option<Now>,
    /// Completed holds.
    holds: ProductionHolds,
}

impl<V: Variant, D: Digest> Producer<V, D> {
    /// Creates the producer of `profile`'s validator at `origin`, its chain's origin, or `None`
    /// when it produces no chain.
    pub(crate) fn new(profile: &Profile<D>, origin: &[BlockRef<D>]) -> Option<Self> {
        let Role::Validator(participant) = profile.role() else {
            return None;
        };
        let chain = profile.protocol().producer_chain(participant)?;
        Some(Self {
            chain,
            head: origin[chain.index()],
            building: None,
            slot: None,
            unreserved: VecDeque::new(),
            signed: BTreeMap::new(),
            declined_until: None,
            builds: IdSequence::new(),
            held: None,
            holds: ProductionHolds::default(),
        })
    }

    /// Returns the produced chain.
    pub(crate) const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Returns the outstanding build.
    pub(crate) const fn building(&self) -> Option<Issued<BuildId>> {
        self.building
    }

    /// Returns the job of the outstanding build.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn build_job(&self) -> Option<BuildJob<D>> {
        self.building.map(|issued| BuildJob::new(issued, self.head))
    }

    /// Returns whether the custody of the build `issued` is outstanding.
    pub(crate) fn awaits_custody(&self, issued: Issued<BuildId>) -> bool {
        self.unreserved
            .iter()
            .any(|built| built.issued == issued && !built.custodied)
    }

    /// Returns whether a built block waits for custody or for its signature reservation.
    pub(crate) fn custody_pending(&self) -> bool {
        !self.unreserved.is_empty()
    }

    /// Returns the completed holds.
    pub(crate) const fn holds(&self) -> ProductionHolds {
        self.holds
    }

    /// Notes at `now` whether the flow bound holds the next build, which was due at `due`,
    /// ending any hold it no longer applies.
    fn note_hold(&mut self, held: bool, due: Now, now: Now) {
        match (self.held, held) {
            (None, true) => self.held = Some(due.max(now)),
            (Some(since), false) => {
                self.holds.record(now.saturating_since(since));
                self.held = None;
            }
            _ => {}
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Advances the producer: reserves the signatures of the custodied prefix of built headers,
    /// then starts the next build once the producer's bounds admit it.
    pub(in crate::multimmit::machine) fn drive_producer(
        &mut self,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        if self.components.producer.is_none() {
            return Ok((WorkStatus::Complete, Capabilities::new()));
        }
        let (status, mut capabilities) = self.reserve_headers()?;
        capabilities.extend(self.start_build(now)?);
        Ok((status, capabilities))
    }

    /// Starts the next build when no build is outstanding, the next height lies within the flow
    /// bound, and its slot came: `theta` after the previous build's, and no sooner than a declined
    /// build defers it. Arms the production deadline when only the slot is missing.
    ///
    /// A rising `h*` or final height of the own chain wakes the producer again.
    fn start_build(&mut self, now: Now) -> Result<Capabilities<V, H::Digest>, StepError> {
        let pace = millis(self.profile.tuning().production_interval).max(1);
        let generation = self.generation();
        let layer = &self.components.chain;
        let Some(producer) = self.components.producer.as_mut() else {
            return Ok(Capabilities::new());
        };
        if producer.building.is_some() {
            return Ok(Capabilities::new());
        }
        let due = producer
            .slot
            .map_or(now, |slot| slot.saturating_add(pace))
            .max(producer.declined_until.unwrap_or_default());
        let held = !layer.admits_production(producer.chain, producer.head.height().next());
        producer.note_hold(held, due, now);
        if held {
            return Ok(Capabilities::new());
        }
        if now < due {
            return Ok(self
                .rearm(TimerFamily::Production, Some(due))
                .into_iter()
                .collect());
        }
        let id = producer
            .builds
            .issue()
            .ok_or(StepError::IdentifierExhausted)?;
        let issued = Issued::new(id, generation);
        producer.building = Some(issued);
        producer.declined_until = None;
        producer.slot = Some(if now < due.saturating_add(pace) {
            due
        } else {
            now
        });
        let job = BuildJob::new(issued, producer.head);
        Ok(vec![Capability::Application(AppJob::Build(job))])
    }

    /// Applies a reached production deadline: the next build's slot came, or the deferral of a
    /// declined build ended.
    pub(in crate::multimmit::machine) fn fire_production(
        &mut self,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        self.produce_or_block(now)
    }

    /// Drives the producer from a completion or deadline, parking it until an acknowledgement
    /// when it is blocked on capacity.
    fn produce_or_block(&mut self, now: Now) -> Result<Capabilities<V, H::Digest>, StepError> {
        let (status, capabilities) = self.drive_producer(now)?;
        if status == WorkStatus::Blocked {
            self.scheduler.block(ProtocolComponent::Producer);
        }
        Ok(capabilities)
    }

    /// Applies the completion of the outstanding build: a built body enters custody under its
    /// header and the next build is scheduled. A build the application declined takes no height
    /// and defers the next one by a vote interval.
    pub(in crate::multimmit::machine) fn producer_built(
        &mut self,
        completion: BuildCompletion<H::Digest>,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let epoch = self.profile.protocol().epoch();
        let retry = now.saturating_add(millis(self.profile.tuning().vote_interval));
        let producer = self
            .components
            .producer
            .as_mut()
            .ok_or(StepError::CompletionMismatch)?;
        if completion.parent() != producer.head {
            return Err(StepError::CompletionMismatch);
        }
        producer.building = None;
        let Some(body) = completion.body() else {
            producer.declined_until = Some(retry);
            return self.start_build(now);
        };
        let header = TransactionBlockHeader::new(
            epoch,
            producer.chain,
            producer.head.height().next(),
            producer.head.digest(),
            body,
        )
        .map_err(|_| StepError::ChainInvariant)?;
        let issued = completion.issued();
        producer.head = header.block_ref::<H>();
        producer.unreserved.push_back(Built {
            issued,
            header: header.clone(),
            custodied: false,
        });
        let mut capabilities = vec![Capability::Application(AppJob::Custody(CustodyJob::new(
            issued, header,
        )))];
        capabilities.extend(self.start_build(now)?);
        Ok(capabilities)
    }

    /// Applies the custody of a built block, which authorizes reserving its header's signature
    /// once every lower built header is reserved.
    pub(in crate::multimmit::machine) fn producer_custodied(
        &mut self,
        completion: CustodyCompletion<H::Digest>,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let producer = self
            .components
            .producer
            .as_mut()
            .ok_or(StepError::CompletionMismatch)?;
        let built = producer
            .unreserved
            .iter_mut()
            .find(|built| built.issued == completion.issued() && !built.custodied)
            .ok_or(StepError::CompletionMismatch)?;
        if built.header != *completion.header() {
            return Err(StepError::CompletionMismatch);
        }
        built.custodied = true;
        self.produce_or_block(now)
    }

    /// Reserves the signature of every custodied header at the front of the pipeline, advancing
    /// the durable produced height once per header. Reservations staged by one call share a
    /// journal barrier.
    fn reserve_headers(&mut self) -> WorkResult<V, H::Digest> {
        let mut capabilities = Capabilities::new();
        loop {
            let Some(header) = self
                .components
                .producer
                .as_ref()
                .and_then(|producer| producer.unreserved.front())
                .filter(|built| built.custodied)
                .map(|built| built.header.clone())
            else {
                return Ok((WorkStatus::Complete, capabilities));
            };
            let request = SignRequest::TransactionBlock(header);
            match self.reserve_effect(DurableEffect::sign(request)) {
                Ok(reserved) => capabilities.extend(reserved),
                Err(error) if is_capacity(&error) => {
                    return Ok((WorkStatus::Blocked, capabilities));
                }
                Err(error) => return Err(error),
            }
            self.components
                .producer
                .as_mut()
                .expect("the producer was checked above")
                .unreserved
                .pop_front();
        }
    }

    /// Accepts this node's freshly signed header, and with it every signed header above it that
    /// waited for its signature, and lets the producer build further.
    pub(in crate::multimmit::machine) fn own_header_signed(
        &mut self,
        block: Arc<SignedTransactionBlock<V, H::Digest>>,
        now: Now,
    ) -> Result<(), StepError> {
        let produced = self.durable.state.produced;
        let producer = self
            .components
            .producer
            .as_mut()
            .ok_or(StepError::ChainInvariant)?;
        let header = block.header();
        let accepted = self.components.chain.tip(producer.chain).height();
        if header.chain() != producer.chain
            || header.height() <= accepted
            || header.height() > produced
            || producer.signed.insert(header.height(), block).is_some()
        {
            return Err(StepError::ChainInvariant);
        }
        self.accept_signed_prefix(now)?;
        self.wake(ProtocolComponent::Producer);
        Ok(())
    }

    /// Accepts the signed own headers that extend the own chain's accepted tip, in height order.
    fn accept_signed_prefix(&mut self, now: Now) -> Result<(), StepError> {
        loop {
            let producer = self
                .components
                .producer
                .as_mut()
                .ok_or(StepError::ChainInvariant)?;
            let next = self.components.chain.tip(producer.chain).height().next();
            let Some(block) = producer.signed.remove(&next) else {
                return Ok(());
            };
            self.delay_estimator().produced(next, now);
            self.accept_own(block, now)?;
        }
    }

    /// Rebuilds the producer from durable state at `now` and returns the production timer that
    /// starts it, with a recall of every own header still reserved or published.
    ///
    /// The head is the header at the durable produced height: still reserved, signed and held
    /// locally, or accepted. Reserved headers wait for their signatures, which the new generation
    /// releases again, and signed headers above the accepted tip wait for the lower ones.
    ///
    /// The relay that disseminates own bodies learns them from staging, which a restart loses, or
    /// from custody checks. A header is published until `D` later heights are produced, and peers
    /// that have not accepted it need its body, so every own header above both `produced - D` and
    /// the chain's final height is recalled ([`AppJob::Recall`]). A final header was accepted by
    /// `n - f` validators, and the others fetch its body as adopters do.
    pub(in crate::multimmit::machine) fn restore_producer(
        &mut self,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let state = &self.durable.state;
        let Some(mut producer) = Producer::new(&self.profile, &state.origin) else {
            self.components.producer = None;
            return Ok(Capabilities::new());
        };
        let produced = state.produced;
        let accepted = self.components.chain.tip(producer.chain);
        let published = produced
            .get()
            .saturating_sub(u64::from(self.profile.codec().window().flow()))
            .max(self.components.chain.finalized(producer.chain).get());
        let mut republished = Vec::new();
        for artifact in state.local.values() {
            let Artifact::TransactionBlock(block) = artifact.as_ref() else {
                continue;
            };
            let header = block.header();
            if header.chain() != producer.chain {
                continue;
            }
            if header.height().get() > published {
                republished.push(header.clone());
            }
            if header.height() > accepted.height() {
                producer
                    .signed
                    .insert(header.height(), Arc::new(block.clone()));
            }
        }
        let mut reserved = None;
        for request in state.sign_requests() {
            if let SignRequest::TransactionBlock(header) = request {
                if header.height() == produced {
                    reserved = Some(header.block_ref::<H>());
                }
                republished.push(header.clone());
            }
        }
        let head = if produced == accepted.height() {
            Some(accepted)
        } else {
            reserved.or_else(|| {
                producer
                    .signed
                    .get(&produced)
                    .map(|block| block.header().block_ref::<H>())
            })
        };
        producer.head = head.ok_or(StepError::ChainInvariant)?;
        let mut capabilities = republished
            .into_iter()
            .map(|header| Capability::Application(AppJob::Recall(header)))
            .collect::<Capabilities<V, H::Digest>>();
        self.components.producer = Some(producer);
        capabilities.push(self.arm_timer(TimerFamily::Production, now));
        Ok(capabilities)
    }
}
