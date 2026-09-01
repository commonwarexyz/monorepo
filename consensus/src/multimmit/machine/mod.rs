//! Synchronous protocol core for one Multimmit committee.
//!
//! [`CoreState`] queues typed [`Input`]s in bounded lanes and feeds them to the reducer's
//! [machine](reducer::machine::Machine), which owns all protocol state. Each turn returns
//! [`Capability`] values that the voter executes. The core performs no I/O and reads no clock or
//! randomness, so replaying the same inputs reproduces the same state and capabilities.
//!
//! ```text
//! +-------+   Input    +-----------+   InputPass   +---------+
//! | voter | ---------> | CoreState | ------------> | Machine |
//! +-------+            +-----------+               +---------+
//!     ^                                                 |
//!     |                    capabilities                 |
//!     +-------------------------------------------------+
//! ```
//!
//! # Capability families
//!
//! [`Capability`] is grouped by the runtime piece that executes it:
//!
//! - verification: [`Capability::Verify`] batches of decoded peer artifacts and
//!   [`Capability::Quarantine`] participants proven to equivocate.
//! - journal: [`Capability::Journal`] event batches, then [`Capability::Acknowledged`],
//!   [`Capability::Released`], [`Capability::Retain`], and [`Capability::Retire`] for the
//!   signatures, publications, and resolver custody each acknowledgement covers.
//! - application: [`Capability::Application`] builds, custody, and custody cancellations for the
//!   local producer.
//! - crypto: [`Capability::Crypto`] nullification recovery and V-QC and L-QC aggregation.
//! - timers: [`Capability::Timer`] view timeouts and production deadlines.
//! - chain planes: [`Capability::Validator`] commands for one producer chain's plane and
//!   [`Capability::OwnChainDa`] commands for the producer's own-chain DA recovery task.
//! - resolver: [`Capability::Resolver`] fetches, cancellations, rejections, and prunes of view
//!   proofs the machine is missing.
//!
//! Workers may run capabilities concurrently, but only the machine decides protocol facts.
//! Completions return as inputs tagged with the [`Generation`] that issued them, and the machine
//! ignores completions from an earlier generation. A chain plane's eligible DA-vote run arrives
//! as a [`DaVotesOffer`] with the same generation check. The core applies it at once instead of
//! queueing it, so offers keep the scheduling of the work around them.
//!
//! # Durability
//!
//! A change applies to machine state when it is staged, through the same function replay uses.
//! Fresh signatures and publication retirements wait for the acknowledgement that covers their
//! event. A checkpoint is cut only at an acknowledged cursor with no staged batch outstanding, and
//! recovery restores it and replays the journal suffix.
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
//!
//! Production users start [`crate::multimmit::Engine`] and never drive the machine directly. The
//! [state-machine guide](crate::multimmit::docs::state_machine) specifies the transitions and
//! invariants and defines the [terminology](crate::multimmit::docs::state_machine#terminology)
//! these docs use, and the [property ledger](crate::multimmit::docs::properties) indexes its proof
//! obligations.

mod accountability;
mod artifact;
mod capability;
mod chain;
mod core_state;
mod da;
mod durability;
mod eligibility;
mod finality;
mod input;
mod job;
mod producer;
mod publication;
mod reducer;
mod resolution;
mod scheduler;
mod signing;
mod util;
mod verification;
mod view;
mod vote_body;

pub(crate) use artifact::{Held, IdentifiedArtifact, VqcKind};
pub(crate) use capability::{
    AppJob, Capabilities, Capability, ChainCommand, CryptoJob, ObservedBlock, ResolverCommand,
    TimerCommand, ValidatorCommand,
};
pub(crate) use core_state::{
    CoreBootstrapError, CoreError, CoreState, CoreTurn, InputTicket, ServicedInput,
    max_lane_artifacts,
};
pub(crate) use da::DaChoice;
#[cfg(test)]
pub(crate) use durability::Change;
#[cfg(any(test, feature = "mocks"))]
pub(crate) use durability::DischargeKind;
pub(crate) use durability::{
    BarrierAck, DomainEvent, DomainEventCodecConfig, DurableEffect, DurableJob, EffectCompletion,
    PersistDirective, PersistJob, ProposalParent, ProposalPublication, Publication, SendRequest,
    SignRequest, Snapshot, SnapshotCodecConfig,
};
pub use durability::{BatchId, Cursor, EffectId, ReplayError, SnapshotReason, TransitionReason};
pub(crate) use eligibility::{
    BlockValidity, ChainEligibility, EligibleRun, ValidationCompletion, ValidationId,
    ValidationOutcome,
};
pub(crate) use finality::{LqcAggregateCompletion, LqcAggregateJob};
pub(crate) use input::{
    CryptoCompletion, DaVotesOffer, Input, ObservationStatus, PollResult, Rejection, StepError,
    StepStatus,
};
pub use job::Generation;
pub(crate) use job::Issued;
pub use producer::ProducerProgress;
pub(crate) use producer::{
    BuildCompletion, BuildId, BuildJob, CustodyCancellation, CustodyCompletion, CustodyJob,
    ProductionTimer,
};
#[cfg(test)]
pub(crate) use reducer::MAX_STAGED_BARRIERS;
#[cfg(any(test, feature = "mocks"))]
pub(crate) use reducer::machine::Machine;
pub use reducer::machine::{ChainProgress, Inspection};
pub(crate) use reducer::{MAX_BATCH_BYTES, MAX_BATCH_EVENTS, MAX_INFLIGHT_BARRIERS};
pub(crate) use resolution::{ResolutionCompletion, ResolutionJob};
pub(crate) use scheduler::Lane;
pub use verification::JobId;
#[cfg(test)]
pub(crate) use verification::{Observation, VerificationTicket};
pub(crate) use verification::{Verdict, VerificationCompletion, VerificationItem, VerifyJob};
pub(crate) use view::{
    NullificationRecoveryCompletion, NullificationRecoveryJob, ViewTimer, VqcAggregateCompletion,
    VqcAggregateJob,
};
pub(crate) use vote_body::VoteBuild;
#[cfg(test)]
pub(crate) use vote_body::VoteBuildStats;

#[cfg(any(test, feature = "mocks"))]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
