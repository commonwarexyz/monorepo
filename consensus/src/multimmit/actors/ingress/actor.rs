//! The ingress task: receive and decode plane traffic, buffer it in fair lanes, and forward it.
//!
//! One task serves the three network planes, the voter's returned observation credits, and the
//! verifier it hosts. Each wake handles one verifier event, credit return, or decoded arrival, and
//! then forwards buffered cohorts while the voter holds observation credit.

use super::{
    Config, IngressLimits, Mailbox,
    lanes::{Cohort, DropReason, Group, LaneId, Lanes},
    mailbox::Message,
    metrics::Metrics as ActorMetrics,
    receiver::{IngressOutcome, IngressReceiver, InvalidIngress},
};
use crate::{
    multimmit::{
        actors::{
            metrics::Traffic,
            verifier::{self, Verifier},
            voter::{Completions, Observations, Observed},
        },
        types::{CodecConfig, EncodedBounds},
        wire::{EnvelopeConfig, Plane},
    },
    types::Epoch,
};
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::{select, select_loop};
use commonware_p2p::Receiver;
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell, telemetry::metrics::HistogramExt as _,
};
use commonware_utils::ordered::Set;
use rand_core::CryptoRng;
use std::{marker::PhantomData, sync::Arc};
use tracing::{debug, debug_span, error};

/// Why the ingress actor stopped before shutdown.
#[derive(Debug, thiserror::Error)]
pub(super) enum Fatal {
    #[error("ingress worker panicked")]
    WorkerPanicked,
    #[error("received more observation credits than cohorts in flight")]
    ExcessCredits,
    #[error("voter observation path failed")]
    ObservationPath,
    #[error(transparent)]
    Verifier(#[from] verifier::Fatal),
}

/// One completed decode and the plane whose frame produced it.
pub(super) struct Arrival<P, V: Variant, D: Digest> {
    pub(super) plane: Plane,
    pub(super) outcome: IngressOutcome<P, V, D>,
}

/// Decodes peer traffic on three planes and forwards fair bounded cohorts to the voter.
pub(crate) struct Actor<E, H, P, V, T, C>
where
    E: Clock + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
    C: Strategy,
{
    context: ContextCell<E>,
    epoch: Epoch,
    participants: Arc<Set<P>>,
    pub(super) strategy: T,
    pub(super) critical_strategy: C,
    codec: CodecConfig,
    bounds: EncodedBounds,
    limits: IngressLimits,
    observation_capacity: usize,
    mailbox: mailbox::Receiver<Message>,
    pub(super) metrics: ActorMetrics,
    _types: PhantomData<(H, P, V)>,
}

impl<E, H, P, V, T, C> Actor<E, H, P, V, T, C>
where
    E: Clock + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
    C: Strategy,
{
    /// Creates the ingress actor and its control mailbox.
    pub(crate) fn new(context: E, config: Config<P, T, C>) -> (Self, Mailbox) {
        let metrics = ActorMetrics::new(&context);
        let (sender, receiver) = mailbox::new(context.child("credits"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                epoch: config.epoch,
                participants: config.participants,
                strategy: config.strategy,
                critical_strategy: config.critical_strategy,
                codec: config.codec,
                bounds: config.bounds,
                limits: config.limits,
                observation_capacity: config.observation_capacity.get(),
                mailbox: receiver,
                metrics,
                _types: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Starts the actor over already-registered fixed-epoch plane receivers, serving `verifier`
    /// on the same task.
    ///
    /// The loop serves the verifier's job messages and finished jobs before credits and network
    /// traffic, so a verification job the voter issues runs in the same scheduler turn, and between
    /// any two ingress turns. The task stops when either side stops.
    pub(crate) fn start(
        mut self,
        verifier: Verifier<E, H, P, V, T, C>,
        completions: Completions<V, H::Digest>,
        observations: Observations<P, V, H::Digest>,
        data: impl Receiver<PublicKey = P>,
        consensus: impl Receiver<PublicKey = P>,
        certificates: impl Receiver<PublicKey = P>,
    ) -> Handle<()>
    where
        E: CryptoRng,
    {
        spawn_cell!(
            self.context,
            self.run(
                verifier,
                completions,
                observations,
                data,
                consensus,
                certificates
            )
        )
    }

    async fn run(
        mut self,
        mut verifier: Verifier<E, H, P, V, T, C>,
        completions: Completions<V, H::Digest>,
        observations: Observations<P, V, H::Digest>,
        data: impl Receiver<PublicKey = P>,
        consensus: impl Receiver<PublicKey = P>,
        certificates: impl Receiver<PublicKey = P>,
    ) where
        E: CryptoRng,
    {
        let mut ingress = self.ingress(data, consensus, certificates);
        match self
            .serve(&mut ingress, &mut verifier, &completions, &observations)
            .await
        {
            Ok(()) => {}
            Err(Fatal::Verifier(verifier::Fatal::VoterClosed)) => {
                debug!("voter stopped, stopping ingress and verifier");
            }
            Err(Fatal::Verifier(verifier::Fatal::WorkerPanicked(span))) => {
                span.in_scope(|| error!("verification worker panicked"));
            }
            Err(fatal) => error!(%fatal, "ingress stopped"),
        }
    }

    async fn serve<DR, CR, RR>(
        &mut self,
        ingress: &mut Ingress<E, H, P, V, T, C, DR, CR, RR>,
        verifier: &mut Verifier<E, H, P, V, T, C>,
        completions: &Completions<V, H::Digest>,
        observations: &Observations<P, V, H::Digest>,
    ) -> Result<(), Fatal>
    where
        E: CryptoRng,
        DR: Receiver<PublicKey = P>,
        CR: Receiver<PublicKey = P>,
        RR: Receiver<PublicKey = P>,
    {
        let budget = self.strategy.manual().parallelism();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping ingress");
            },
            Some(event) = verifier.next() else break => verifier.handle(event, completions)?,
            Some(message) = self.mailbox.recv() else break => {
                match message {
                    Message::Consumed(cohorts) => ingress.consume(cohorts)?,
                }
            },
            Some(first) = ingress.recv() else break => {
                ingress.drain_ready(first, budget, &self.metrics)?;
            },
            on_end => {
                // Forward buffered artifacts while the voter has observation credit. Cohorts
                // collect ready ingress and any backlog retained while credits were in flight.
                ingress.flush(self.context.as_ref(), observations, &self.metrics)?;
            },
        }
        Ok(())
    }

    /// Builds the running state over the three plane receivers.
    pub(super) fn ingress<DR, CR, RR>(
        &self,
        data: DR,
        consensus: CR,
        certificates: RR,
    ) -> Ingress<E, H, P, V, T, C, DR, CR, RR>
    where
        DR: Receiver<PublicKey = P>,
        CR: Receiver<PublicKey = P>,
        RR: Receiver<PublicKey = P>,
    {
        Ingress {
            data: self.receiver(data, Plane::Data, self.strategy.clone()),
            consensus: self.receiver(consensus, Plane::Consensus, self.critical_strategy.clone()),
            certificates: self.receiver(
                certificates,
                Plane::Certificate,
                self.critical_strategy.clone(),
            ),
            lanes: Lanes::new(self.codec.chains(), self.codec.participants(), self.limits),
            participants: Arc::clone(&self.participants),
            next: Plane::Consensus,
            inflight: 0,
            capacity: self.observation_capacity,
            cohort_items: self.limits.cohort_items.get(),
        }
    }

    /// Builds the bounded receiver of one plane.
    pub(super) fn receiver<R: Receiver<PublicKey = P>, S: Strategy>(
        &self,
        receiver: R,
        plane: Plane,
        strategy: S,
    ) -> IngressReceiver<E, R, H, V, S> {
        let context = self
            .context
            .child("ingress")
            .with_attribute("plane", plane.as_str());
        // A receiver stops reading its channel once `capacity` decodes are in flight, leaving later
        // frames in the bounded network backlog. More jobs than the plane's pool has workers would
        // only queue inside the pool, and capping at the bulk parallelism (the per-turn ingress
        // budget in `serve`) lets one actor turn buffer every completion one plane has ready.
        let capacity = self
            .strategy
            .manual()
            .parallelism()
            .min(strategy.manual().parallelism());
        let max_frame_bytes = match plane {
            Plane::Data => self.bounds.max_data_frame_bytes(),
            Plane::Consensus => self.bounds.max_consensus_frame_bytes(),
            Plane::Certificate => self.bounds.max_certificate_frame_bytes(),
        };
        IngressReceiver::new(
            context,
            receiver,
            plane,
            EnvelopeConfig {
                max_frame_bytes,
                epoch: self.epoch,
                payload: self.codec,
            },
            strategy,
            capacity,
        )
    }
}

/// The running ingress state: plane receivers, fair lanes, and observation credits.
pub(super) struct Ingress<E, H, P, V, T, C, DR, CR, RR>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    DR: Receiver<PublicKey = P>,
    CR: Receiver<PublicKey = P>,
    RR: Receiver<PublicKey = P>,
{
    pub(super) data: IngressReceiver<E, DR, H, V, T>,
    pub(super) consensus: IngressReceiver<E, CR, H, V, C>,
    pub(super) certificates: IngressReceiver<E, RR, H, V, C>,
    pub(super) lanes: Lanes<P, V, H::Digest>,
    /// The identity-key committee, for the data-availability-vote sender check.
    pub(super) participants: Arc<Set<P>>,
    /// The plane scanned first for the next ready completion.
    pub(super) next: Plane,
    /// Cohorts forwarded to the voter and not yet consumed.
    pub(super) inflight: usize,
    /// Maximum cohorts awaiting voter consumption.
    pub(super) capacity: usize,
    /// Target artifacts in one data-plane cohort.
    pub(super) cohort_items: usize,
}

impl<E, H, P, V, T, C, DR, CR, RR> Ingress<E, H, P, V, T, C, DR, CR, RR>
where
    E: Clock,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
    C: Strategy,
    DR: Receiver<PublicKey = P>,
    CR: Receiver<PublicKey = P>,
    RR: Receiver<PublicKey = P>,
{
    /// Receives one completed decode, scanning planes in rotation order from `next`.
    ///
    /// `select!` is biased toward earlier arms, so each block lists the planes in
    /// [`Plane::rotation`] order from its starting plane. The receivers have different types, so
    /// the three orders are written out instead of looped.
    pub(super) async fn recv(&mut self) -> Option<Arrival<P, V, H::Digest>> {
        let arrival = |plane| move |outcome| Arrival { plane, outcome };
        match self.next {
            Plane::Consensus => {
                select! {
                    outcome = self.consensus.recv() => outcome.map(arrival(Plane::Consensus)),
                    outcome = self.certificates.recv() => outcome.map(arrival(Plane::Certificate)),
                    outcome = self.data.recv() => outcome.map(arrival(Plane::Data)),
                }
            }
            Plane::Certificate => {
                select! {
                    outcome = self.certificates.recv() => outcome.map(arrival(Plane::Certificate)),
                    outcome = self.data.recv() => outcome.map(arrival(Plane::Data)),
                    outcome = self.consensus.recv() => outcome.map(arrival(Plane::Consensus)),
                }
            }
            Plane::Data => {
                select! {
                    outcome = self.data.recv() => outcome.map(arrival(Plane::Data)),
                    outcome = self.consensus.recv() => outcome.map(arrival(Plane::Consensus)),
                    outcome = self.certificates.recv() => outcome.map(arrival(Plane::Certificate)),
                }
            }
        }
    }

    /// Returns a completion that is already ready, scanning planes in rotation order from `next`.
    fn try_ready(&mut self) -> Option<Arrival<P, V, H::Digest>> {
        self.next.rotation().into_iter().find_map(|plane| {
            let outcome = match plane {
                Plane::Data => self.data.try_completed(),
                Plane::Consensus => self.consensus.try_completed(),
                Plane::Certificate => self.certificates.try_completed(),
            }?;
            Some(Arrival { plane, outcome })
        })
    }

    /// Buffers `first` and up to `budget - 1` further completions that are already ready,
    /// rotating planes after each.
    pub(super) fn drain_ready(
        &mut self,
        first: Arrival<P, V, H::Digest>,
        budget: usize,
        metrics: &ActorMetrics,
    ) -> Result<(), Fatal> {
        let mut ready = Some(first);
        for _ in 0..budget {
            let Some(Arrival { plane, outcome }) = ready.take().or_else(|| self.try_ready()) else {
                break;
            };
            self.next = plane.next();
            match outcome {
                IngressOutcome::Panicked => return Err(Fatal::WorkerPanicked),
                IngressOutcome::Invalid {
                    reason: InvalidIngress::Decode,
                } => {}
                IngressOutcome::Invalid {
                    reason: InvalidIngress::ProposalParent,
                } => {
                    metrics.decoded.get_or_create(&Traffic::from(plane)).inc();
                }
                IngressOutcome::Ready { peer, lane, group } => {
                    metrics.decoded.get_or_create(&Traffic::from(plane)).inc();
                    debug_assert_eq!(lane.plane(), plane, "a plane fills only its own lanes");
                    if group
                        .da_vote_signers()
                        .any(|signer| self.participants.get(usize::from(signer)) != Some(&peer))
                    {
                        // Honest data-availability votes are sent only by their own signer, so a
                        // vote whose claimed signer is not the sender is not honest traffic.
                        // Dropping it keeps a misattributed share out of the producer's recovery
                        // pool and out of the machine's per-signer vote slot.
                        debug!(
                            ?lane,
                            "dropped a data-availability vote not sent by its signer"
                        );
                        metrics.dropped_misattributed.inc();
                        continue;
                    }
                    self.buffer(lane, peer, group, metrics);
                }
            }
        }
        Ok(())
    }

    /// Atomically buffers one identified ingress group with bounded fairness accounting.
    fn buffer(
        &mut self,
        lane: LaneId,
        peer: P,
        group: Group<V, H::Digest>,
        metrics: &ActorMetrics,
    ) {
        let items = group.len() as u64;
        match self.lanes.push_group(lane, peer, group) {
            Ok(()) => {}
            Err(DropReason::Lane) => {
                debug!(items, ?lane, "artifact group dropped by a full lane");
                metrics.dropped_lane.inc_by(items);
            }
            Err(DropReason::Peer) => {
                debug!(
                    items,
                    ?lane,
                    "artifact group dropped by a peer item or byte budget"
                );
                metrics.dropped_peer.inc_by(items);
            }
        }
    }

    /// Returns observation credits after the voter consumes `cohorts` cohorts.
    pub(super) fn consume(&mut self, cohorts: usize) -> Result<(), Fatal> {
        self.inflight = self
            .inflight
            .checked_sub(cohorts)
            .ok_or(Fatal::ExcessCredits)?;
        Ok(())
    }

    /// Forwards buffered cohorts while the voter has observation credit.
    ///
    /// Cohorts are plane-pure, so one flush emits one cohort per buffered plane while credit
    /// remains.
    pub(super) fn flush(
        &mut self,
        clock: &impl Clock,
        voter: &Observations<P, V, H::Digest>,
        metrics: &ActorMetrics,
    ) -> Result<(), Fatal> {
        while self.inflight < self.capacity && self.lanes.items() > 0 {
            let Some(Cohort { plane, selected }) = self.lanes.flush(self.cohort_items) else {
                break;
            };
            let items = selected.len() as u64;
            let span = debug_span!("multimmit.batcher.observe", items);
            let now = clock.current();
            // Admission already measured every artifact, so the cohort carries its encoded weight
            // and the voter never re-walks a decoded certificate to account for it.
            let mut bytes = 0usize;
            let artifacts = selected
                .into_iter()
                .map(|selected| {
                    bytes = bytes.saturating_add(selected.bytes);
                    metrics
                        .ingress_dwell
                        .observe_between(selected.received_at, now);
                    (selected.peer, selected.artifact)
                })
                .collect();
            match voter.observed(Observed {
                artifacts,
                bytes,
                plane,
                span,
                forwarded_at: now,
            }) {
                Unreliable::Rejected => {
                    metrics.dropped_voter_cohorts.inc();
                    return Err(Fatal::ObservationPath);
                }
                Unreliable::Outcome(Feedback::Closed | Feedback::Backoff) => {
                    return Err(Fatal::ObservationPath);
                }
                Unreliable::Outcome(Feedback::Ok) => {
                    self.inflight += 1;
                    metrics.forwarded.inc_by(items);
                }
            }
        }
        Ok(())
    }
}
