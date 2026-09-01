//! The voter's side of its persistence actor: appends, results, and the checkpoint cadence.

use super::{
    AtRoot as _, DigestOf, Failure, Fatal, Hooks as _, RetentionBoundary, VoterTypes, live::Live,
};
use crate::multimmit::{
    actors::voter::persistence::{
        self, CheckpointOrigin, Durable, Mailbox, Output, checkpoint_span,
    },
    machine::{BarrierAck, CoreError, Input, Lane, PersistDirective, PersistJob, Snapshot},
};
use commonware_actor::mailbox;
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_p2p::Sender;
use commonware_runtime::telemetry::traces::TracedExt as _;
use std::num::NonZeroU64;
use tracing::{Span, info_span};

/// Where the voter's current checkpoint stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointPhase {
    /// No checkpoint is in progress.
    Idle,
    /// The journal rolled and the snapshot is being written.
    Writing,
    /// The snapshot is durable; authority-producing input waits until no append is outstanding.
    Stored,
    /// The journal prunes behind the snapshot.
    Pruning,
}

/// The voter's count of outstanding appends and acknowledged events, and its checkpoint phase.
#[derive(Debug)]
pub(crate) struct Ledger {
    /// Admitted appends whose durability has not been received.
    outstanding: usize,
    checkpoint: CheckpointPhase,
    /// Acknowledged journal events since the last checkpoint cut.
    events: u64,
    interval: NonZeroU64,
}

impl Ledger {
    /// Starts with `events` acknowledged since the newest checkpoint and a checkpoint every
    /// `interval` events.
    pub(crate) const fn new(events: u64, interval: NonZeroU64) -> Self {
        Self {
            outstanding: 0,
            checkpoint: CheckpointPhase::Idle,
            events,
            interval,
        }
    }

    /// Returns the admitted appends whose durability has not been received.
    pub(crate) const fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// Returns the acknowledged journal events since the last checkpoint cut.
    pub(crate) const fn events(&self) -> u64 {
        self.events
    }

    /// Returns whether the persistence actor owes the voter a result.
    pub(crate) fn expects_output(&self) -> bool {
        self.outstanding > 0 || self.checkpoint != CheckpointPhase::Idle
    }

    /// Returns whether authority-producing input waits for the checkpoint.
    pub(crate) const fn fenced(&self) -> bool {
        self.events >= self.interval.get() || matches!(self.checkpoint, CheckpointPhase::Stored)
    }

    /// Returns whether a checkpoint is due and the pipeline is quiescent enough to cut it.
    pub(crate) fn due(&self) -> bool {
        self.events >= self.interval.get()
            && self.outstanding == 0
            && self.checkpoint == CheckpointPhase::Idle
    }

    /// Records one admitted append.
    const fn admitted(&mut self) {
        self.outstanding += 1;
    }

    /// Records one admitted checkpoint and restarts the event count.
    const fn cut(&mut self) {
        self.events = 0;
        self.checkpoint = CheckpointPhase::Writing;
    }

    /// Records one durable append of `events` journal events.
    fn acknowledged(&mut self, events: usize) -> Result<(), CoreError> {
        self.outstanding = self
            .outstanding
            .checked_sub(1)
            .ok_or(CoreError::SchedulerInvariant)?;
        self.events += events as u64;
        self.settle();
        Ok(())
    }

    /// Records a durable snapshot.
    fn stored(&mut self) -> Result<(), CoreError> {
        if self.checkpoint != CheckpointPhase::Writing {
            return Err(CoreError::SchedulerInvariant);
        }
        self.checkpoint = CheckpointPhase::Stored;
        self.settle();
        Ok(())
    }

    /// Records the prune behind a stored snapshot.
    const fn pruned(&mut self) -> Result<(), CoreError> {
        if !matches!(
            self.checkpoint,
            CheckpointPhase::Stored | CheckpointPhase::Pruning
        ) {
            return Err(CoreError::SchedulerInvariant);
        }
        self.checkpoint = CheckpointPhase::Idle;
        Ok(())
    }

    /// Lifts the checkpoint fence once no append is outstanding, which lets the actor prune.
    fn settle(&mut self) {
        if self.checkpoint == CheckpointPhase::Stored && self.outstanding == 0 {
            self.checkpoint = CheckpointPhase::Pruning;
        }
    }
}

/// The persistence actor as the voter tracks it.
pub(crate) struct Persistence<H: Hasher, V: Variant> {
    mailbox: Mailbox<H, V>,
    output: mailbox::Receiver<Output<V, H::Digest>>,
    ledger: Ledger,
}

impl<H: Hasher, V: Variant> Persistence<H, V> {
    /// Tracks the actor behind `mailbox`, whose results arrive on `output`.
    pub(crate) const fn new(
        mailbox: Mailbox<H, V>,
        output: mailbox::Receiver<Output<V, H::Digest>>,
        ledger: Ledger,
    ) -> Self {
        Self {
            mailbox,
            output,
            ledger,
        }
    }

    /// Returns the actor's command mailbox.
    pub(crate) const fn mailbox(&self) -> &Mailbox<H, V> {
        &self.mailbox
    }

    /// Returns the receiver of the actor's results.
    pub(crate) const fn output(&mut self) -> &mut mailbox::Receiver<Output<V, H::Digest>> {
        &mut self.output
    }

    /// Returns the voter's accounting of appends and checkpoint progress.
    pub(crate) const fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Returns whether a command can be admitted without waiting.
    pub(crate) fn has_capacity(&self) -> bool {
        self.mailbox.has_capacity()
    }

    /// Admits one append.
    pub(crate) fn append(
        &mut self,
        root: Span,
        span: Span,
        job: PersistJob<V, H::Digest>,
    ) -> Result<(), Fatal> {
        self.mailbox.append(root, span, job)?;
        self.ledger.admitted();
        Ok(())
    }

    /// Requests durability for every admitted append.
    pub(crate) fn flush(&self) -> Result<(), persistence::Error> {
        self.mailbox.flush()
    }

    /// Admits one checkpoint of `cut`.
    fn checkpoint(
        &mut self,
        cut: Snapshot<V, H::Digest>,
        origin: CheckpointOrigin,
        span: Span,
    ) -> Result<(), Fatal> {
        self.mailbox.checkpoint(cut, origin, span)?;
        self.ledger.cut();
        Ok(())
    }
}

impl<T, S> Live<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Appends one barrier and releases the work it authorizes on admission.
    ///
    /// Barriers pipeline: the journal appends behind in-flight syncs, and their acknowledgements
    /// arrive strictly in cursor order.
    pub(crate) fn persist(
        &mut self,
        directive: PersistDirective<T::Variant, DigestOf<T>>,
        root: &Span,
    ) -> Result<(), Fatal> {
        let PersistDirective {
            job,
            staged_retention,
            release_after_enqueue,
            ..
        } = directive;

        // A dedicated span makes each barrier's wall time (append, fsync, acknowledgement)
        // visible per round; staging stalls behind exactly this interval.
        let span = info_span!(
            "multimmit.voter.persist",
            epoch = self.epoch.get().traced(),
            view = self.telemetry.round_view().get().traced(),
            barrier = job.id().get().traced(),
            events = job.events().len().traced()
        );
        let barrier = job.id();
        self.persistence.append(root.clone(), span, job)?;
        for artifact in staged_retention {
            self.retain_served(&artifact, RetentionBoundary::Staged(barrier))?;
        }
        for job in release_after_enqueue {
            self.execute_released(job, root)?;
        }
        Ok(())
    }

    /// Admits one result of the persistence actor.
    pub(crate) fn persisted(
        &mut self,
        output: Output<T::Variant, DigestOf<T>>,
    ) -> Result<(), Failure> {
        match output {
            Output::Durable(Durable {
                root,
                span,
                job,
                ack,
            }) => self
                .admit_durable(span, job.events().len(), ack, &root)
                .at(&root),
            Output::Stored => self
                .persistence
                .ledger
                .stored()
                .at(self.telemetry.round_span()),
            Output::Pruned => self
                .persistence
                .ledger
                .pruned()
                .at(self.telemetry.round_span()),
            Output::Failed { root, error } => Err((root, error.into())),
        }
    }

    /// Returns the failure a closed output stands for: the actor stopped without reporting why.
    pub(crate) fn persistence_closed(&self) -> Output<T::Variant, DigestOf<T>> {
        Output::Failed {
            root: self.round_span(),
            error: persistence::Error::Closed,
        }
    }

    /// Returns whether the persistence output can be received now.
    ///
    /// A durability takes a persistence-completion slot in the core; checkpoint progress and
    /// failures take none, so they are received even while that lane is full.
    pub(crate) fn persistence_receivable(&self) -> bool {
        let ledger = self.persistence.ledger();
        ledger.expects_output()
            && (ledger.outstanding() == 0 || self.machine.can_admit(Lane::PersistenceCompletion))
    }

    /// Admits the acknowledgement of one durable barrier of `events` journal events.
    fn admit_durable(
        &mut self,
        span: Span,
        events: usize,
        ack: BarrierAck,
        root: &Span,
    ) -> Result<(), Fatal> {
        self.persistence.ledger.acknowledged(events)?;
        let ticket = self.track_transition(|core| core.enqueue(Input::Persisted(ack)), root)?;
        self.hooks.acknowledged(ticket, ack);
        self.correlation.respan(ticket, span)?;
        Ok(())
    }

    /// Cuts a checkpoint once it is due and every staged barrier is acknowledged.
    pub(crate) fn maybe_checkpoint(&mut self) -> Result<(), Fatal> {
        // A snapshot is only valid at a quiescent staging pipeline: every staged batch is
        // acknowledged and nothing is emitted-but-unappended. Reaching the checkpoint cadence
        // closes authority-producing ingress until that finite prefix drains and the cut is made.
        if !self.persistence.ledger.due() {
            return Ok(());
        }
        let Some(cut) = self.machine.machine().checkpoint_cut() else {
            return Ok(());
        };
        let origin = CheckpointOrigin {
            epoch: self.epoch,
            view: self.telemetry.round_view(),
            cursor: cut.cursor(),
            retired_views: cut.retired_view(),
        };
        let checkpoint = checkpoint_span!(
            self.telemetry.round_span(),
            "multimmit.voter.checkpoint",
            origin
        );
        // Roll the journal to a fresh section: once the snapshot is durable, every prior
        // section is covered and prunable as a whole.
        let roll = checkpoint_span!(None, "multimmit.voter.checkpoint.roll", origin);
        roll.follows_from(checkpoint.id());
        self.persistence.checkpoint(cut, origin, roll)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU64;

    const INTERVAL: NonZeroU64 = NZU64!(4);

    #[test]
    fn checkpoint_fence_holds_until_outstanding_appends_drain() {
        let mut ledger = Ledger::new(INTERVAL.get(), INTERVAL);
        assert!(ledger.fenced(), "reaching the cadence fences authority");
        assert!(ledger.due());
        ledger.cut();
        assert_eq!(ledger.checkpoint, CheckpointPhase::Writing);
        assert!(
            !ledger.fenced(),
            "the cut reopens authority while the snapshot is written"
        );
        assert!(ledger.expects_output());

        ledger.admitted();
        ledger.admitted();
        ledger.stored().unwrap();
        assert_eq!(ledger.checkpoint, CheckpointPhase::Stored);
        assert!(
            ledger.fenced(),
            "a stored snapshot fences authority while appends are outstanding"
        );
        assert!(!ledger.due());

        ledger.acknowledged(1).unwrap();
        assert!(ledger.fenced());
        ledger.acknowledged(1).unwrap();
        assert_eq!(ledger.checkpoint, CheckpointPhase::Pruning);
        assert!(!ledger.fenced(), "the drained journal lets the actor prune");

        // Appends admitted while the prune runs do not re-arm the fence.
        ledger.admitted();
        assert!(!ledger.fenced());
        assert!(!ledger.due(), "one checkpoint runs at a time");
        ledger.pruned().unwrap();
        assert_eq!(ledger.checkpoint, CheckpointPhase::Idle);
        assert!(ledger.expects_output());
        ledger.acknowledged(1).unwrap();
        assert!(!ledger.expects_output());
        assert_eq!(ledger.events, 3);
    }

    #[test]
    fn snapshot_stored_without_outstanding_appends_goes_straight_to_pruning() {
        let mut ledger = Ledger::new(INTERVAL.get(), INTERVAL);
        ledger.cut();
        ledger.stored().unwrap();
        assert_eq!(ledger.checkpoint, CheckpointPhase::Pruning);
        assert!(!ledger.fenced());
        ledger.pruned().unwrap();
        assert!(!ledger.expects_output());
    }

    #[test]
    fn unexpected_results_are_scheduler_invariants() {
        let mut ledger = Ledger::new(0, INTERVAL);
        assert!(matches!(
            ledger.acknowledged(1),
            Err(CoreError::SchedulerInvariant)
        ));
        assert!(matches!(
            ledger.stored(),
            Err(CoreError::SchedulerInvariant)
        ));
        assert!(matches!(
            ledger.pruned(),
            Err(CoreError::SchedulerInvariant)
        ));
        ledger.cut();
        assert!(matches!(
            ledger.pruned(),
            Err(CoreError::SchedulerInvariant)
        ));
    }
}
