//! Durable journal events, persistence barriers, and replay errors.

use super::{BatchId, Cursor, DurableEffect, DurableJob, EffectId, SnapshotReason};
use crate::{
    multimmit::{
        machine::job::Generation,
        types::{Artifact, ArtifactBatch, ArtifactId},
    },
    types::{Epoch, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use core::fmt;
use std::sync::Arc;

/// One versioned state transition written to the safety journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DomainEvent<V: Variant, D: Digest> {
    pub(super) epoch: Epoch,
    pub(super) cursor: Cursor,
    pub(super) change: Change<V, D>,
}

impl<V: Variant, D: Digest> DomainEvent<V, D> {
    pub(crate) const fn new(epoch: Epoch, cursor: Cursor, change: Change<V, D>) -> Self {
        Self {
            epoch,
            cursor,
            change,
        }
    }

    /// Returns the bound epoch.
    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the journal position.
    pub(crate) const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Returns the typed durable state change.
    pub(crate) const fn change(&self) -> &Change<V, D> {
        &self.change
    }
}

/// A durable machine state change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Change<V: Variant, D: Digest> {
    /// Starts a new process generation after startup or recovery.
    GenerationAdvanced(Generation),
    /// Adds one stable external action to the durable outbox.
    OutboxQueued {
        /// Stable action identifier.
        id: EffectId,
        /// Immutable action.
        effect: Box<DurableEffect<V, D>>,
    },
    /// Atomically retains locally signed artifacts and replaces their signing job with
    /// publication.
    SignedArtifacts {
        /// Completed signing action.
        sign: EffectId,
        /// Stable atomic publication created by this transition.
        publication: EffectId,
        /// Locally signed artifacts, in request order, retained across publication
        /// attempts.
        artifacts: ArtifactBatch<V, D>,
    },
    /// Advances one chain's durable DA floor and atomically retires its obsolete live work.
    DaCertificateAdvanced {
        /// Publication installed for a locally assembled certificate.
        publication: Option<EffectId>,
        /// Publications made obsolete by this certificate.
        retired_publications: Vec<EffectId>,
        /// Highest accepted certificate for the chain.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Retains one locally assembled view certificate without queuing a publication.
    ///
    /// V-QCs and nullifications reach peers later through representative selection. An L-QC is
    /// local finality evidence that lagging peers fetch through resolution.
    ViewCertificateCreated {
        /// Locally assembled V-QC, nullification, or L-QC.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Durably marks and broadcasts the selected first certificate for one view.
    ArtifactForwarded {
        /// Stable publication action created by this transition.
        publication: EffectId,
        /// Older exit push obligations discharged by this durable successor.
        retired_publications: Vec<EffectId>,
        /// Authenticated certificate selected by observation order.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Advances exactly one view using an authenticated current-view exit proof.
    ViewAdvanced {
        /// Identifier of the retained V-QC or nullification authorizing the transition.
        proof: ArtifactId<D>,
        /// The retention floor the transition applied.
        ///
        /// Staging derives it from the profile; replay applies the journaled value, so a journal
        /// written under a larger view retention replays exactly after the retention is lowered.
        floor: View,
        /// Own-message obligations ended by the new retention floor.
        retired_publications: Vec<EffectId>,
    },
    /// Raises the signing view through an independently authenticated finalization.
    FinalityFloorAdvanced {
        /// L-QC proving finality at the skipped-through view.
        proof: Arc<Artifact<V, D>>,
        /// Obsolete consensus signing requests retired by the floor.
        retired_signing: Vec<EffectId>,
        /// Own-message obligations ended by the new retention floor.
        retired_publications: Vec<EffectId>,
    },
}

impl<V: Variant, D: Digest> Change<V, D> {
    /// Returns the outbox effect this change queues, if any.
    pub(crate) const fn queued_effect(&self) -> Option<EffectId> {
        match self {
            Self::OutboxQueued { id, .. } => Some(*id),
            Self::SignedArtifacts { publication, .. }
            | Self::ArtifactForwarded { publication, .. } => Some(*publication),
            Self::DaCertificateAdvanced { publication, .. } => *publication,
            Self::GenerationAdvanced(_)
            | Self::ViewAdvanced { .. }
            | Self::FinalityFloorAdvanced { .. }
            | Self::ViewCertificateCreated { .. } => None,
        }
    }

    /// Returns whether this change records a fresh local signature.
    ///
    /// The publication such a change queues must not leave the process before the record is
    /// durable: a crash that forgets a released signature could re-sign a conflicting subject
    /// for the same slot, and that equivocation is exactly what the journal exists to prevent.
    pub(crate) const fn records_local_signature(&self) -> bool {
        matches!(self, Self::SignedArtifacts { .. })
    }

    pub(crate) const fn kind(&self) -> ChangeKind {
        match self {
            Self::GenerationAdvanced(_) => ChangeKind::GenerationAdvanced,
            Self::OutboxQueued { .. } => ChangeKind::OutboxQueued,
            Self::SignedArtifacts { .. } => ChangeKind::SignedArtifacts,
            Self::ViewCertificateCreated { .. } => ChangeKind::ViewCertificateCreated,
            Self::DaCertificateAdvanced { .. } => ChangeKind::DaCertificateAdvanced,
            Self::ArtifactForwarded { .. } => ChangeKind::ArtifactForwarded,
            Self::ViewAdvanced { .. } => ChangeKind::ViewAdvanced,
            Self::FinalityFloorAdvanced { .. } => ChangeKind::FinalityFloorAdvanced,
        }
    }
}

/// The kind of one durable [`Change`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChangeKind {
    /// [`Change::GenerationAdvanced`].
    GenerationAdvanced,
    /// [`Change::OutboxQueued`].
    OutboxQueued,
    /// [`Change::SignedArtifacts`].
    SignedArtifacts,
    /// [`Change::ViewCertificateCreated`].
    ViewCertificateCreated,
    /// [`Change::DaCertificateAdvanced`].
    DaCertificateAdvanced,
    /// [`Change::ArtifactForwarded`].
    ArtifactForwarded,
    /// [`Change::ViewAdvanced`].
    ViewAdvanced,
    /// [`Change::FinalityFloorAdvanced`].
    FinalityFloorAdvanced,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GenerationAdvanced => "generation advance",
            Self::OutboxQueued => "outbox queue",
            Self::SignedArtifacts => "signed artifacts",
            Self::ViewCertificateCreated => "view certificate creation",
            Self::DaCertificateAdvanced => "DA certificate advance",
            Self::ArtifactForwarded => "artifact forward",
            Self::ViewAdvanced => "view advance",
            Self::FinalityFloorAdvanced => "finality floor advance",
        })
    }
}

/// Append-and-sync work for one safety-journal barrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PersistJob<V: Variant, D: Digest> {
    id: BatchId,
    generation: Generation,
    previous: Cursor,
    events: Arc<Vec<DomainEvent<V, D>>>,
    urgent: bool,
}

impl<V: Variant, D: Digest> PersistJob<V, D> {
    /// Returns whether an external release is gated on this barrier's durability.
    ///
    /// The machine marks a barrier urgent when one of its events records a fresh local
    /// signature (its publication must not leave before the record is durable) or starts a
    /// generation (the recovered outbox re-releases at its acknowledgement). Non-urgent
    /// barriers may defer their sync to a later covering barrier.
    pub(crate) const fn urgent(&self) -> bool {
        self.urgent
    }

    pub(crate) fn new(
        id: BatchId,
        generation: Generation,
        previous: Cursor,
        events: Vec<DomainEvent<V, D>>,
        urgent: bool,
    ) -> Self {
        Self {
            id,
            generation,
            previous,
            events: Arc::new(events),
            urgent,
        }
    }

    /// Returns the barrier identifier.
    pub(crate) const fn id(&self) -> BatchId {
        self.id
    }

    /// Returns the process generation that issued the write.
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the cursor that must precede this batch.
    pub(crate) const fn previous(&self) -> Cursor {
        self.previous
    }

    /// Extends this batch by one contiguous event.
    pub(crate) fn push_event(&mut self, event: DomainEvent<V, D>, urgent: bool) {
        Arc::make_mut(&mut self.events).push(event);
        self.urgent |= urgent;
    }

    pub(crate) fn shared_events(&self) -> Arc<Vec<DomainEvent<V, D>>> {
        Arc::clone(&self.events)
    }

    /// Returns the ordered journal entries.
    pub(crate) fn events(&self) -> &[DomainEvent<V, D>] {
        self.events.as_slice()
    }

    /// Returns the final cursor established by this barrier.
    pub(crate) fn last_cursor(&self) -> Cursor {
        self.events
            .last()
            .map_or(self.previous, DomainEvent::cursor)
    }

    /// Returns the acknowledgement that this barrier and its journal prefix are durable.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn ack(&self) -> BarrierAck {
        BarrierAck::new(self.id, self.generation, self.last_cursor())
    }
}

/// One machine-issued journal barrier and the work fenced by its admission.
///
/// Once the journal accepts the barrier, the voter:
/// 1. installs `staged_retention` in resolver custody, then
/// 2. releases `release_after_enqueue`, publications that peers can verify on their own.
#[derive(Clone, Debug)]
pub(crate) struct PersistDirective<V: Variant, D: Digest> {
    /// The events to append and sync.
    pub(crate) job: PersistJob<V, D>,
    /// Artifacts to install in resolver custody once the journal accepts the barrier.
    pub(crate) staged_retention: Vec<Arc<Artifact<V, D>>>,
    /// Publications released once the journal accepts the barrier.
    pub(crate) release_after_enqueue: Vec<DurableJob<V, D>>,
}

/// Acknowledgement of one persistence barrier and covered journal prefix.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct BarrierAck {
    barrier: BatchId,
    generation: Generation,
    cursor: Cursor,
}

impl BarrierAck {
    /// Creates an acknowledgement for a machine-issued persistence job.
    pub(crate) const fn new(barrier: BatchId, generation: Generation, cursor: Cursor) -> Self {
        Self {
            barrier,
            generation,
            cursor,
        }
    }

    /// Returns the completed barrier.
    pub(crate) const fn barrier(self) -> BatchId {
        self.barrier
    }

    /// Returns the issuing process generation.
    pub(crate) const fn generation(self) -> Generation {
        self.generation
    }

    /// Returns the cursor made durable by the barrier.
    pub(crate) const fn cursor(self) -> Cursor {
        self.cursor
    }
}

/// The durable transition check an event or restored state failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransitionReason {
    /// The generation does not advance by exactly one.
    #[error("generation does not advance by one")]
    Generation,
    /// A new effect's identifier is not the cursor of the event that queues it.
    #[error("effect identifier is not the event cursor")]
    EffectCursor,
    /// A new effect's identifier is already held.
    #[error("effect identifier is already held")]
    DuplicateEffect,
    /// The durable outbox would exceed its ceiling.
    #[error("durable outbox is full")]
    OutboxFull,
    /// Durably retained artifacts would exceed the artifact cache.
    #[error("durable artifacts exceed the artifact cache")]
    ArtifactCapacity,
    /// The forwarding history would exceed its ceiling.
    #[error("forwarding history is full")]
    ForwardingFull,
    /// The local profile cannot authorize the effect.
    #[error("profile cannot authorize the effect")]
    Unauthorized,
    /// An artifact belongs to another epoch.
    #[error("artifact belongs to another epoch")]
    Epoch,
    /// An artifact exceeds the configured byte ceiling.
    #[error("artifact exceeds the byte ceiling")]
    ArtifactSize,
    /// An artifact the change creates is already durably held.
    #[error("artifact is already durably held")]
    DuplicateArtifact,
    /// An artifact has the wrong kind for the change.
    #[error("artifact kind does not match the change")]
    ArtifactKind,
    /// A proposal's parent V-QC is missing, attached at genesis, or conflicts with a held copy.
    #[error("proposal parent is invalid")]
    ProposalParent,
    /// A produced header does not extend this producer's chain by one.
    #[error("produced header does not extend the producer chain")]
    ProducerHeight,
    /// A DA vote does not extend its chain's durable safety height by one.
    #[error("DA vote does not extend the safe height")]
    DaHeight,
    /// Chain state rejects the change.
    #[error("chain state rejects the change")]
    ChainState,
    /// View state rejects the change.
    #[error("view state rejects the change")]
    ViewState,
    /// Finality state rejects the change.
    #[error("finality state rejects the change")]
    FinalityState,
    /// A signing reservation is missing, duplicated, or held by an observer.
    #[error("signing reservation is invalid")]
    Signing,
    /// A signed artifact does not match the request that authorized it.
    #[error("signed artifact does not match its request")]
    RequestMismatch,
    /// A publication obligation cannot be installed or retired.
    #[error("publication obligation is invalid")]
    Obligation,
    /// Retired effects differ from the set the transition retires.
    #[error("retired effects differ from the expected set")]
    Retirement,
    /// A DA certificate does not advance its chain's certified tip.
    #[error("certificate does not advance the certified tip")]
    StaleCertificate,
    /// A view exit proof is missing, already recorded, or out of order.
    #[error("view exit is invalid")]
    Exit,
    /// A finality floor is stale or its view's V-QC was not forwarded.
    #[error("finality floor is invalid")]
    FinalityFloor,
    /// A durable reference or reservation count overflowed or underflowed.
    #[error("durable reference count is invalid")]
    References,
    /// A durable counter or view overflowed.
    #[error("durable counter overflowed")]
    Overflow,
}

/// An invalid snapshot, journal event, or replay lifecycle operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// Snapshot or event belongs to another epoch or role.
    #[error("recovery context does not match the machine profile")]
    Context,
    /// A journal entry is not at the next cursor.
    #[error("journal cursor is not contiguous")]
    Cursor,
    /// A durable state change violates its transition invariant.
    #[error("invalid durable state transition: {0}")]
    Transition(TransitionReason),
    /// A restored snapshot violates a durable invariant.
    #[error("invalid snapshot: {0}")]
    Snapshot(SnapshotReason),
    /// Replay was attempted after live processing began.
    #[error("journal replay is only allowed during recovery")]
    Lifecycle,
}
