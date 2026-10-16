//! Synchronous protocol core for one Multimmit committee.
//!
//! [`CoreState`] queues typed [`Input`]s in bounded lanes and feeds them to the reducer's
//! [machine](reducer::machine::Machine), which owns all protocol state. Each turn returns
//! [`Capability`] values that the voter executes. The core performs no I/O and reads no clock or
//! randomness: the voter supplies a volatile [`Now`] reading with every admission and every turn,
//! and durable state never records it, so replaying the journal reproduces the same state.
//!
//! ```text
//! +-------+   Input, Now   +-----------+   InputPass, Now   +---------+
//! | voter | -------------> | CoreState | -----------------> | Machine |
//! +-------+                +-----------+                    +---------+
//!     ^                                                          |
//!     |                        capabilities                      |
//!     +----------------------------------------------------------+
//! ```
//!
//! # Capability families
//!
//! [`Capability`] is grouped by the runtime piece that executes it:
//!
//! - verification: [`Capability::Verify`] batches of decoded peer artifacts (vote updates carry
//!   the content the machine rebuilt for them) and [`Capability::Quarantine`] participants proven
//!   to equivocate.
//! - journal: [`Capability::Journal`] event batches, then [`Capability::Acknowledged`],
//!   [`Capability::Released`], [`Capability::Retain`], and [`Capability::Retire`] for the
//!   signatures, publications, and resolver custody each acknowledgement covers.
//! - application: [`Capability::Application`] builds and custody for the local producer.
//! - crypto: [`Capability::Crypto`] V-QC and L-QC aggregation from votes the machine selected.
//! - timers: [`Capability::Timer`] arms or cancels the deadline of one [`TimerFamily`]; the
//!   deadline fires as [`Input::Tick`].
//! - chain planes: [`Capability::Chain`] asks one producer chain's plane to run the application's
//!   verification of a block, the fence for its full acceptance, and reports accepted tip heights.
//! - resolver: [`Capability::Resolver`] fetches, cancellations, rejections, and prunes of the
//!   artifacts a [`RetrievalKey`] names.
//!
//! Workers may run capabilities concurrently, but only the machine decides protocol facts.
//! Completions return as inputs tagged with the [`Generation`] that issued them, and the machine
//! ignores completions from an earlier generation.
//!
//! # Durability
//!
//! A change applies to machine state when it is staged, through the same function replay uses.
//! A signing reservation advances its durable signing slot in the event that queues it, and a
//! signature's publication waits for the acknowledgement that covers the event recording the
//! signature. A checkpoint is cut only at an acknowledged cursor with no staged batch
//! outstanding, and recovery restores it and replays the journal suffix.
//!
//! # Lifecycle
//!
//! 1. Open: [`CoreState::fresh`] starts from an empty store, or [`CoreState::restore`] loads a
//!    [`Snapshot`] and [`CoreState::replay`] applies each journaled [`DomainEvent`] after it.
//! 2. Enter a generation: [`Input::Start`] or [`Input::RecoveryComplete`] stages the next
//!    [`Generation`]. Nothing is released until that event is acknowledged.
//! 3. Serve: the voter admits inputs with [`CoreState::enqueue`] and [`CoreState::observe`], then
//!    calls [`CoreState::next_action`] and executes the capabilities each turn returns, until the
//!    turn reports [`CoreTurn::Idle`] or [`CoreTurn::YieldRequired`].
//! 4. Checkpoint: at an acknowledged cursor with nothing staged, the machine cuts a [`Snapshot`].
//!    Once stored, it replaces the journal prefix it covers.

mod accountability;
mod artifact;
mod capability;
mod chain;
mod core_state;
mod durability;
mod emit;
mod input;
mod job;
mod pool;
mod reducer;
mod resolution;
mod retention;
mod scheduler;
#[cfg(any(test, feature = "mocks"))]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "benchmark drivers use a subset of the test support"
    )
)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
mod util;
mod verification;
mod view;

pub(crate) use artifact::IdentifiedArtifact;
pub(crate) use capability::{
    AppJob, BuildId, BuildJob, Capabilities, Capability, ChainCommand, CryptoJob, CustodyJob,
    ResolverCommand, TimerCommand,
};
pub(crate) use chain::{accept::Refusals, producer::ProductionHolds};
pub(crate) use core_state::{
    CoreBootstrapError, CoreError, CoreState, CoreTurn, InputTicket, max_lane_artifacts,
};
#[cfg(any(test, feature = "mocks"))]
pub(crate) use durability::Change;
pub(crate) use durability::{
    BarrierAck, DomainEvent, DomainEventCodecConfig, DurableEffect, DurableJob, EffectCompletion,
    PersistDirective, PersistJob, ProposalParent, ProposalPublication, Publication, SignRequest,
    Snapshot, SnapshotCodecConfig,
};
pub use durability::{BatchId, Cursor, EffectId, ReplayError, SnapshotReason, TransitionReason};
pub(crate) use emit::PinnedUndetermined;
#[cfg(test)]
pub(crate) use emit::UndeterminedChains;
pub(crate) use input::{
    Aggregated, BlockValidity, BuildCompletion, CryptoCompletion, CustodyCompletion, Input,
    InputKind, Now, ObservationStatus, PollResult, Rejection, StepError, StepStatus, TimerFamily,
    ValidationCompletion,
};
pub use job::Generation;
pub(crate) use job::Issued;
pub use reducer::machine::{ChainProgress, Inspection, ProducerProgress};
pub(crate) use reducer::{
    MAX_BATCH_BYTES, MAX_BATCH_EVENTS, MAX_INFLIGHT_BARRIERS, machine::CoreProgress,
};
pub(crate) use resolution::{ResolutionCompletion, ResolutionJob, RetrievalKey};
pub(crate) use scheduler::{Lane, ProtocolComponent};
#[cfg(any(test, feature = "mocks"))]
pub(crate) use testing::world;
pub use verification::JobId;
#[cfg(test)]
pub(crate) use verification::{Observation, VerificationTicket};
pub(crate) use verification::{Verdict, VerificationCompletion, VerificationItem, VerifyJob};
pub(crate) use view::declare::{DeclarationContext, DeclarationContexts};
pub use view::declare::{DeclarationCounts, DeclarationRule, ViewEnd, ViewEnds};
