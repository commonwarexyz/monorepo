//! Durable journal events, persistence barriers, and replay errors.

use super::{
    Acceptance, BatchId, Cursor, DurableEffect, DurableJob, EffectId, RetentionRoot, SnapshotReason,
};
use crate::{
    multimmit::{
        machine::job::Generation,
        types::{Artifact, ArtifactBatch, ArtifactId, HistoryRecord, Resolution},
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

    /// Returns the journal cursor.
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
    ///
    /// A signing reservation also advances the signing slot it occupies and retires the
    /// publications and reservations of older own messages that the advance ends.
    OutboxQueued {
        /// Stable action identifier.
        id: EffectId,
        /// Immutable action.
        effect: Box<DurableEffect<V, D>>,
    },
    /// Atomically retains locally signed artifacts and replaces their signing job, whose
    /// reservation already advanced the slots they occupy, with their publication.
    ///
    /// The artifacts are a header, a leader block, or a vote update.
    SignedArtifacts {
        /// Completed signing action.
        sign: EffectId,
        /// Stable atomic publication created by this transition.
        publication: EffectId,
        /// Locally signed artifacts, in request order, retained across publication attempts.
        artifacts: ArtifactBatch<V, D>,
    },
    /// Records accepted headers, lowest height first per chain.
    ///
    /// Acceptances are staged at an earlier cursor than the next vote update that endorses them,
    /// so no update endorses a header whose acceptance a crash could forget.
    Accepted {
        /// The accepted headers.
        blocks: Vec<Acceptance<V, D>>,
    },
    /// Records the emission state of one view, its base and the history record of the view before,
    /// before the resolution it fixes is reported. Written once per view, in view order without
    /// gaps.
    EmissionResolved {
        /// The view whose base is fixed.
        view: View,
        /// The history record of the view before, whose tips are the base.
        record: HistoryRecord<D>,
        /// How consensus fixed the base.
        by: Resolution<D>,
    },
    /// Durably marks and broadcasts one certificate for its view.
    ArtifactForwarded {
        /// Stable publication action created by this transition.
        publication: EffectId,
        /// The authenticated certificate.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Enters the next view using a retained, authenticated exit proof for the current view, and
    /// retains the proof's parent chain down to a V-QC a retention holder already keeps.
    ViewEntered {
        /// Identifier of the retained V-QC or L-QC authorizing the transition.
        proof: ArtifactId<D>,
        /// The V-QCs on the proof's parent chain above the retired view that no retention holder
        /// keeps, newest first: the first is the proof's parent, each one's parent is the next,
        /// and the last one's parent is kept.
        ancestors: Vec<Arc<Artifact<V, D>>>,
        /// Own-message publications ended by the transition.
        retired_publications: Vec<EffectId>,
    },
    /// Retains one locally assembled V-QC or L-QC without queuing a publication.
    CertificateCreated {
        /// The assembled certificate.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Raises the retention floor, retiring every view at or below it.
    ///
    /// Replay applies the journaled floor, so a journal written under a larger retention replays
    /// exactly after the retention is lowered.
    RetentionAdvanced {
        /// The new retired view.
        floor: View,
        /// The V-QC of the new retired view on the chain this node entered later views on.
        root: RetentionRoot<D>,
        /// Obsolete signing requests retired by the floor.
        retired_signing: Vec<EffectId>,
        /// Own-message publications ended by the floor.
        retired_publications: Vec<EffectId>,
    },
    /// Re-roots consensus at a verified finalization certificate of a view more than the anchor
    /// lag above the current one: enters its view on the parent its leader block names, retires
    /// every earlier view, and starts every chain's accepted path at or above the finalized base.
    Anchored {
        /// The [`Artifact::Floor`] anchored on.
        floor: Arc<Artifact<V, D>>,
        /// Signing requests of the views the anchor retires.
        retired_signing: Vec<EffectId>,
        /// Own-message publications ended by the anchor.
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
            Self::GenerationAdvanced(_)
            | Self::Accepted { .. }
            | Self::EmissionResolved { .. }
            | Self::ViewEntered { .. }
            | Self::CertificateCreated { .. }
            | Self::RetentionAdvanced { .. }
            | Self::Anchored { .. } => None,
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
            Self::Accepted { .. } => ChangeKind::Accepted,
            Self::EmissionResolved { .. } => ChangeKind::EmissionResolved,
            Self::ArtifactForwarded { .. } => ChangeKind::ArtifactForwarded,
            Self::ViewEntered { .. } => ChangeKind::ViewEntered,
            Self::CertificateCreated { .. } => ChangeKind::CertificateCreated,
            Self::RetentionAdvanced { .. } => ChangeKind::RetentionAdvanced,
            Self::Anchored { .. } => ChangeKind::Anchored,
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
    /// [`Change::Accepted`].
    Accepted,
    /// [`Change::EmissionResolved`].
    EmissionResolved,
    /// [`Change::ArtifactForwarded`].
    ArtifactForwarded,
    /// [`Change::ViewEntered`].
    ViewEntered,
    /// [`Change::CertificateCreated`].
    CertificateCreated,
    /// [`Change::RetentionAdvanced`].
    RetentionAdvanced,
    /// [`Change::Anchored`].
    Anchored,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GenerationAdvanced => "generation advance",
            Self::OutboxQueued => "outbox queue",
            Self::SignedArtifacts => "signed artifacts",
            Self::Accepted => "header acceptance",
            Self::EmissionResolved => "emission resolution",
            Self::ArtifactForwarded => "artifact forward",
            Self::ViewEntered => "view entry",
            Self::CertificateCreated => "certificate creation",
            Self::RetentionAdvanced => "retention advance",
            Self::Anchored => "anchor",
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
    /// A signature would conflict with or regress a durable signing slot.
    #[error("signing slot conflict")]
    SigningSlot,
    /// An accepted header does not extend its chain's accepted path or exceeds its bounds.
    #[error("accepted header is invalid")]
    Acceptance,
    /// An emission is out of order, malformed, or rewrites an earlier one.
    #[error("emission is invalid")]
    Emission,
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
    /// A view exit proof is missing, already recorded, or out of order.
    #[error("view exit is invalid")]
    Exit,
    /// The ancestors a view entry retains are not the exit proof's parent chain down to a V-QC
    /// a retention holder keeps, or one of them is already kept.
    #[error("entry chain ancestors are invalid")]
    Ancestors,
    /// A retention floor does not advance or passes the current view.
    #[error("retention floor is invalid")]
    RetentionFloor,
    /// An anchor is not a well-formed finalization certificate of this epoch, lies at or below a
    /// view or vote tag this node may have signed in, or contradicts the own chain.
    #[error("anchor is invalid")]
    Anchor,
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
