//! Durable events, the outbox, snapshots, and replay validation.
//!
//! ```text
//! change -> DomainEvent (cursor n) -> apply to DurableState -> journal batch -> ack (cursor n)
//!                                                                                 |
//!                  outbox releases for events <= n  <-----------------------------+
//!                  snapshot at an acknowledged cursor with nothing staged  <-------+
//! ```
//!
//! # Events
//!
//! Every durable change is a [`DomainEvent`] with the epoch and the next contiguous [`Cursor`].
//! The machine applies an event to [`DurableState`] when it stages it, through the same function
//! replay uses, so live staging and recovery cannot diverge. Each process lifetime starts with a
//! [`Change::GenerationAdvanced`] event; completions issued under an older generation are stale.
//! The clock never enters an event, so replay needs none.
//!
//! # Signing slots
//!
//! A signing reservation advances the durable slot its signature will occupy in the event that
//! queues it ([`Change::OutboxQueued`]): the own chain's produced height, the leader block of a
//! view, the notarised leader of a view, and the vote watermark of a view tag. The signature is
//! recorded later ([`Change::SignedArtifacts`]), and its publication waits until that record is
//! durable, so a slot is always durable before any signature occupying it can leave the process.
//! Accepted headers are staged at an earlier cursor than the next update that endorses them, so
//! after a crash this node never endorses less than it already signed.
//!
//! # Outbox and obligations
//!
//! External actions that must survive a crash, signing requests and publications, wait in the
//! durable outbox under a stable [`EffectId`]. A signing action is released only once its event is
//! acknowledged, and its completion atomically replaces it with the publication of the signed
//! artifacts. A publication stays queued, and is sent again after recovery, until a later durable
//! fact discharges it (see [`DischargeKind`]).
//!
//! # Snapshots
//!
//! A [`Snapshot`] projects [`DurableState`] at an acknowledged cursor with nothing staged. Restore
//! validates it against the profile, and replay applies the journal suffix after its cursor.
//!
//! # Replay
//!
//! Replay checks each event against the restored state before applying it, and any mismatch is a
//! [`ReplayError`] rather than a repair. A [`Change::RetentionAdvanced`] carries the floor it
//! applied, so replay reproduces the writer's retirements even when the restoring profile retains
//! fewer views.

mod apply;
mod codec;
mod effect;
mod event;
mod ids;
mod outbox;
mod snapshot;
mod state;

pub(crate) use codec::{DomainEventCodecConfig, SnapshotCodecConfig};
pub(crate) use effect::{
    DurableEffect, DurableJob, EffectCompletion, EffectResult, Proposal, ProposalParent,
    ProposalPublication, ProposalRequest, Publication, Retained, SignEffect, SignRequest,
    UpdateRequest,
};
pub(crate) use event::{BarrierAck, Change, ChangeKind, DomainEvent, PersistDirective, PersistJob};
pub use event::{ReplayError, TransitionReason};
pub use ids::{BatchId, Cursor, EffectId};
pub(crate) use outbox::{Discharge, DischargeKind, OutboxEntry};
pub(crate) use snapshot::Snapshot;
pub use snapshot::SnapshotReason;
pub(crate) use state::{
    Acceptance, DischargeFacts, DurableState, Emission, RetentionRoot, VoteWatermark,
};

/// Durable event and snapshot schema version.
///
/// This version is independent of the network wire version.
pub(crate) const DURABILITY_SCHEMA_VERSION: u8 = 0;
