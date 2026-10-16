//! Protocol components and the hooks through which the reducer hands them work.
//!
//! The reducer owns everything protocol-agnostic: the generic admission bounds, verification
//! jobs, dependency waits, the persistence pipeline, completion correlation, and timer deadlines.
//! It never decides a protocol fact. Protocol behaviour belongs to the components
//! [`ProtocolComponent`] names, and reaches the reducer only through the hooks in this module:
//!
//! | hook | called | owner |
//! |---|---|---|
//! | [`Machine::precheck_protocol`] | before an observed artifact is verified, and when a parked one wakes | kind's component |
//! | [`Machine::dependency`] | after a valid verdict and whenever a provided key wakes it | kind's component |
//! | [`Machine::admit_ready`] | once an authenticated artifact holds every dependency | kind's component |
//! | [`Machine::fire_timer`] | when a [`TimerFamily`] deadline the machine holds is reached | family's component |
//! | producer and chain completions | after the reducer matched a completion to current work | chain layer, producer |
//! | [`Machine::signed`] | when a local signature is staged with its record | the signed artifact's component |
//! | [`Machine::start_components`] | when the machine starts or finishes recovery | every component |
//! | [`Machine::complete_crypto`] | when a parked aggregation reaches its staging turn | view, emission |
//! | [`Machine::drive_component`] | when the scheduler pops the component's wake key | the component |
//!
//! # Component contract
//!
//! - A component stages durable facts only through [`Machine::reserve_change`] and
//!   [`Machine::reserve_effect`]; both apply immediately, so later derivations see them. Staging
//!   fails with [`StepError::PersistenceCapacity`] when no batch is free; a drive returns
//!   [`WorkStatus::Blocked`] and is woken again by the acknowledgement that frees one.
//! - Every signature goes through a durable signing reservation in the outbox
//!   ([`DurableEffect::Sign`](crate::multimmit::machine::durability::DurableEffect::Sign)): the
//!   reservation advances its signing slot, and the signed artifact is published only after its
//!   own record is durable.
//! - Volatile work (builds, aggregations, retrievals, timers) is tagged with the current
//!   [`Generation`](crate::multimmit::machine::Generation); the reducer drops completions of
//!   earlier generations before any hook sees them.
//! - A component's volatile state is a function of durable state and the artifacts it was handed;
//!   it is rebuilt when the machine starts or finishes recovery ([`Machine::start_components`])
//!   and is never journaled.
//! - A component that needs servicing wakes itself with [`Machine::wake`]; a drive performs one
//!   bounded quantum and returns [`WorkStatus::Requeue`] while work remains.
//! - Hooks never block on I/O, read a clock other than the supplied [`Now`], or draw randomness.

use super::{machine::Machine, store::ArtifactEntry};
use crate::{
    Viewable as _,
    multimmit::{
        config::Profile,
        machine::{
            accountability::Accountability,
            capability::{Capabilities, Capability, TimerCommand},
            chain::{ChainLayer, producer::Producer},
            emit::Emitter,
            input::{
                CryptoCompletion, Now, Rejection, StepError, TimerFamily, ValidationCompletion,
            },
            pool::{Pool, lqc::LqcAssembly},
            resolution::RetrievalKey,
            scheduler::{Budget, ProtocolComponent, WorkKey},
            view::{
                ViewLayer, anchor::Anchor, assemble::Assembly, endorse::Sender, proposal::HeldVqc,
                vqc::VqcStore,
            },
        },
        types::{Artifact, ArtifactBatch, ArtifactId, VoteContent},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// Whether a work key needs another quantum.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum WorkStatus {
    /// The work is done until something wakes it again.
    Complete,
    /// More work is ready; the key is queued again behind other ready work.
    Requeue,
    /// The work waits for capacity an acknowledgement releases.
    Blocked,
}

/// The status and capabilities of one work quantum.
pub(crate) type WorkResult<V, D> = Result<(WorkStatus, Capabilities<V, D>), StepError>;

/// What admission does with an observed artifact that passed its protocol precheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Precheck<D: Digest> {
    /// Verify it now. A vote update carries the full content its signature covers.
    Verify(Option<Arc<VoteContent<D>>>),
    /// Hold it unverified until the artifact `key` names is read: a vote update whose content
    /// cannot be rebuilt yet. A parked artifact is checked again when it wakes.
    Park(RetrievalKey<D>),
}

/// The volatile state of every protocol component.
pub(crate) struct Components<V: Variant, D: Digest> {
    pub(crate) chain: ChainLayer<V, D>,
    /// The local producer, if this node produces a chain.
    pub(crate) producer: Option<Producer<V, D>>,
    /// The vote pool: every read vote and the reading state of every sender.
    pub(crate) pool: Pool<D>,
    /// The updates this node sent most recently, per view tag.
    pub(crate) sender: Sender<D>,
    /// The current view, the leader blocks received, declarations, and timing.
    pub(crate) view: ViewLayer<D>,
    /// The V-QCs held with their chain, and the L-QCs held.
    pub(crate) vqcs: VqcStore<V, D>,
    /// This node's V-QC assembly for the current view.
    pub(crate) assembly: Assembly<V, D>,
    /// The emission state reported and the progress of the open view.
    pub(crate) emitter: Emitter<D>,
    /// This node's L-QC assembly.
    pub(crate) lqc_assembly: LqcAssembly<V, D>,
    /// The equivocation evidence held and the validators it proved faulty.
    pub(crate) accountability: Accountability<D>,
    /// The floor this node may anchor on and the validators seen far ahead.
    pub(crate) anchor: Anchor<V, D>,
}

impl<V: Variant, D: Digest> Components<V, D> {
    pub(super) fn new(profile: &Profile<D>) -> Self {
        Self {
            chain: ChainLayer::new(profile, profile.protocol().genesis().tips(), Now::default()),
            producer: Producer::new(profile, profile.protocol().genesis().tips()),
            pool: Pool::new(profile.codec().participants()),
            sender: Sender::new(),
            view: ViewLayer::new(
                profile,
                View::new(1),
                Some(HeldVqc::genesis(profile.protocol().genesis())),
                Now::default(),
            ),
            vqcs: VqcStore::new(),
            assembly: Assembly::new(),
            emitter: Emitter::new(),
            lqc_assembly: LqcAssembly::new(),
            accountability: Accountability::new(),
            anchor: Anchor::new(),
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Checks the protocol bounds of an observed artifact beyond the generic ones, and returns the
    /// full signed content of a vote update, which its verification covers, or the artifact a
    /// vote update must wait for before its content can be rebuilt.
    pub(super) fn precheck_protocol(
        &self,
        artifact: &Artifact<V, H::Digest>,
        parked: bool,
    ) -> Result<Precheck<H::Digest>, Rejection> {
        match artifact {
            Artifact::TransactionBlock(block) => {
                self.precheck_header(block).map(|()| Precheck::Verify(None))
            }
            Artifact::Update(update) => self.precheck_update(update, parked),
            Artifact::LeaderBlock(block) => self.precheck_leader_block(block),
            Artifact::Vqc(vqc) => self.precheck_vqc(vqc),
            Artifact::Lqc(lqc) => self.precheck_lqc(lqc),
            Artifact::Floor(floor) => self.precheck_floor(floor),
        }
    }

    /// Returns the first artifact an authenticated artifact still needs, or `None` once it can
    /// be handed to its component.
    ///
    /// A header's missing parent buffers it in the chain layer rather than here, and an L-QC is
    /// checked against the committee alone. A vote update holds the headers its payload hashes
    /// rebuild before it names a missing one. A V-QC carries its own resolution paths and waits
    /// only for its parent chain. A floor is self-contained.
    pub(super) fn dependency(
        &mut self,
        entry: &ArtifactEntry<V, H::Digest>,
    ) -> Option<RetrievalKey<H::Digest>> {
        match entry.artifact.as_ref() {
            Artifact::TransactionBlock(_) | Artifact::Lqc(_) | Artifact::Floor(_) => None,
            Artifact::Update(update) => self.update_dependency(update),
            Artifact::LeaderBlock(block) => self.leader_block_dependency(block),
            Artifact::Vqc(vqc) => self.vqc_dependency(vqc),
        }
    }

    /// Hands one authenticated artifact with every dependency held to its component.
    pub(super) fn admit_ready(
        &mut self,
        id: ArtifactId<H::Digest>,
        entry: &ArtifactEntry<V, H::Digest>,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        if let Some(signer) = entry.artifact.signer() {
            self.note_heard(signer, now);
        }
        match entry.artifact.as_ref() {
            Artifact::TransactionBlock(_) => Ok(self.receive_header(id, &entry.artifact)),
            Artifact::Update(update) => {
                if self.read_update(id, update, entry.content.as_ref(), now, entry.received) {
                    if update.is_final() {
                        self.note_final(update.view(), update.attestation());
                    }
                    if let Some(content) = &entry.content {
                        self.note_leader_vote(content, update.attestation());
                    }
                }
                Ok(Capabilities::new())
            }
            Artifact::LeaderBlock(block) => {
                self.admit_leader_block(block);
                Ok(Capabilities::new())
            }
            Artifact::Vqc(_) => {
                self.admit_vqc(id, &entry.artifact, now, entry.received);
                Ok(Capabilities::new())
            }
            Artifact::Lqc(_) => {
                self.admit_lqc(id, &entry.artifact);
                Ok(Capabilities::new())
            }
            Artifact::Floor(_) => {
                self.admit_floor(id, &entry.artifact);
                Ok(Capabilities::new())
            }
        }
    }

    /// Runs the protocol action of a reached deadline.
    pub(super) fn fire_timer(
        &mut self,
        family: TimerFamily,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        match family {
            TimerFamily::Production => self.fire_production(now),
            TimerFamily::View | TimerFamily::Update | TimerFamily::Liveness => {
                self.wake(ProtocolComponent::View);
                Ok(Capabilities::new())
            }
        }
    }

    /// Applies a chain plane's verdict on one block, the fence for its full acceptance.
    pub(super) fn chain_validated(
        &mut self,
        completion: ValidationCompletion<H::Digest>,
        _now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        self.record_validation(completion);
        Ok(Capabilities::new())
    }

    /// Rebuilds the components' volatile state from durable state when the machine starts or
    /// finishes recovery at `now`, and returns the deadlines they arm.
    pub(in crate::multimmit::machine) fn start_components(
        &mut self,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        self.restore_chain(now)?;
        self.restore_votes(now)?;
        let mut capabilities = self.restore_vqcs(now)?;
        self.restore_emission();
        self.restore_view(now);
        capabilities.extend(self.restore_anchor()?);
        capabilities.extend(self.request_notarised_proposal()?);
        capabilities.extend(self.restore_producer(now)?);
        self.wake(ProtocolComponent::Retention);
        Ok(capabilities)
    }

    /// Hands artifacts this node just signed, staged with their record, to their components.
    pub(super) fn signed(
        &mut self,
        artifacts: &ArtifactBatch<V, H::Digest>,
        now: Now,
    ) -> Result<(), StepError> {
        for artifact in artifacts.iter() {
            match artifact.as_ref() {
                Artifact::TransactionBlock(block) => {
                    self.own_header_signed(Arc::new(block.clone()), now)?;
                }
                Artifact::LeaderBlock(block) => self.record_proposal(block.block()),
                Artifact::Update(update) => {
                    if update.is_final() {
                        self.note_final(update.view(), update.attestation());
                    }
                    self.note_own_vote(update);
                }
                Artifact::Vqc(_) | Artifact::Lqc(_) | Artifact::Floor(_) => {}
            }
        }
        Ok(())
    }

    /// Stages one aggregated certificate.
    pub(super) fn complete_crypto(
        &mut self,
        completion: CryptoCompletion<V, H::Digest>,
        _now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        match completion {
            CryptoCompletion::Vqc(completion) => self.complete_vqc(*completion),
            CryptoCompletion::Lqc(completion) => self.complete_lqc(*completion),
        }
        Ok(Capabilities::new())
    }

    /// Runs one bounded quantum of `component`'s work.
    pub(super) fn drive_component(
        &mut self,
        component: ProtocolComponent,
        budget: &mut Budget,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        match component {
            ProtocolComponent::Chain => self.drive_chain(budget, now),
            ProtocolComponent::Producer => self.drive_producer(now),
            ProtocolComponent::View => self.drive_view(now),
            ProtocolComponent::Pool => self.drive_pool(now),
            ProtocolComponent::Emission => self.drive_emission(),
            ProtocolComponent::Forwarding => self.drive_forwarding(now),
            ProtocolComponent::Retention => self.drive_retention(),
        }
    }

    /// Queues `component` for a work quantum.
    pub(in crate::multimmit::machine) fn wake(&mut self, component: ProtocolComponent) {
        self.scheduler.enqueue(WorkKey::Drive(component));
    }

    /// Holds the deadline `at` for `family`, replacing an earlier one, and returns the command
    /// that arms it.
    pub(in crate::multimmit::machine) const fn arm_timer(
        &mut self,
        family: TimerFamily,
        at: Now,
    ) -> Capability<V, H::Digest> {
        self.timers[family as usize] = Some(at);
        Capability::Timer(TimerCommand::Arm { family, at })
    }

    /// Holds the deadline `at` for `family`, or none, and returns the command that arms or
    /// cancels it unless the machine already holds exactly that.
    pub(in crate::multimmit::machine) fn rearm(
        &mut self,
        family: TimerFamily,
        at: Option<Now>,
    ) -> Option<Capability<V, H::Digest>> {
        if self.timers[family as usize] == at {
            return None;
        }
        Some(match at {
            Some(at) => self.arm_timer(family, at),
            None => self.cancel_timer(family),
        })
    }

    /// Holds the deadline `at` for `family` unless the machine holds one no later, and returns
    /// the command that arms it.
    ///
    /// For deadlines that only wake a component to re-evaluate: a stale earlier deadline costs one
    /// spurious wake, which re-arms the next one.
    pub(in crate::multimmit::machine) fn arm_before(
        &mut self,
        family: TimerFamily,
        at: Option<Now>,
    ) -> Option<Capability<V, H::Digest>> {
        let at = at?;
        if self.timers[family as usize].is_some_and(|held| held <= at) {
            return None;
        }
        Some(self.arm_timer(family, at))
    }

    /// Drops the deadline of `family` and returns the command that cancels it.
    pub(in crate::multimmit::machine) const fn cancel_timer(
        &mut self,
        family: TimerFamily,
    ) -> Capability<V, H::Digest> {
        self.timers[family as usize] = None;
        Capability::Timer(TimerCommand::Cancel(family))
    }
}
