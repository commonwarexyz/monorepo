//! Private synchronous protocol state for one Multimmit committee.
//!
//! The voter owns one [`CoreState`] on one dedicated runtime task. `CoreState` serializes bounded
//! persistence, completion, timer, resolver, and observation lanes before calling the private
//! [`Machine`] reducer. The reducer is the only production authority for observation order,
//! producer-header facts, DA choices, views, finality, signing reservations, durable events,
//! publication obligations, retention, and snapshots. DA, View, and Finality are semantic
//! partitions inside that one atomic owner, not independently coordinated components.
//!
//! ```text
//!                         one dedicated voter task
//! +-------------------------------------------------------------------+
//! | bounded lanes -> CoreState -> private Machine reducer             |
//! |                      ^                    |                        |
//! |                      |                    v                        |
//! |                  completions      five typed capability ports     |
//! +----------------------+--------------------+------------------------+
//!                        |                    |
//!        +---------------+-----+--------------+---------------+
//!        |                     |                              |
//!   batch verification   journal + checkpoint        app + crypto + timer
//!                                                resolver + publication
//! ```
//!
//! A core turn applies one named transition or bounded reducer work pass and returns immutable
//! capabilities in deterministic issuance order. Actors and workers may execute them concurrently,
//! but they never choose a protocol fact, replace a subject, infer a publication retirement, or
//! mutate reducer state. Every completion carries the issuing generation and exact job, subject, or
//! transcript identity back through a reserved core lane.
//!
//! # Capability ports
//!
//! The private [`Capability`] enum has five ownership-shaped ports:
//!
//! - [`VerificationCapability`] authenticates bounded cohorts of hostile decoded artifacts.
//! - [`DurabilityCapability`] appends exact cursor-contiguous event ranges and returns ordered
//!   acknowledgements from the journal owner, then releases durable signing and publication work.
//! - [`ProducerCapability`] schedules producer pacing, builds and validates opaque application
//!   payload digests, cancels obsolete validation, and recovers DA certificates.
//! - [`LeaderCapability`] schedules view timers, recovers nullifications, and aggregates V-QCs and
//!   L-QCs.
//! - [`ResolverCapability`] fetches authenticated V-QCs, nullifications, or covering L-QCs for one
//!   level-triggered view-proof want.
//!
//! `Automaton::propose` selects opaque application payloads so producer preparation can pipeline.
//! Before reserving each transaction-header signature, the producer issues `Automaton::verify` for
//! that exact context and digest; `true` is the validity and crash-recoverable custody fence. Remote
//! payloads cross the same fence before DA authority is reserved. `Automaton` is not a fetch
//! interface and never receives a V-QC, nullification, L-QC, leader block, or other consensus proof.
//! Missing view proofs use the resolver port; producer-body retrieval remains application-owned.
//!
//! # Producer and leader boundaries
//!
//! ```text
//! application-owned                         consensus-owned
//! -----------------                         -----------------
//! producer body --opaque digest--> signed producer header -> DA evidence
//!                                                        \
//!                                                         +-> leader block
//!                                                             + votes/V-QC/L-QC
//!                                                             + sparse finality facts
//!
//! marshal: proofs + producer history -> dense application order
//! ```
//!
//! Consensus owns the signed producer metadata, DA evidence, protocol-constant leader blocks,
//! votes, certificates, tip commitments, and sparse finalized-leader facts. It does not own
//! application bodies, body codecs, producer-history retrieval, dense total-order extraction,
//! delivery cursors, or application acknowledgements. A reporter notification is a lossy hint, not
//! an acknowledged delivery handoff.
//!
//! # Durability and recovery
//!
//! A semantic transition applies ordered domain events through the same reducer used by replay and
//! stages at most one cursor-contiguous persistence range per poll. The journal owner may append
//! newer ranges behind one covering sync, but Core accepts acknowledgements only in exact prefix
//! order. Fresh signatures and publication retirements remain private until the covering durable
//! acknowledgement releases them. Publication retries keep one stable effect identity until a
//! distinct durable semantic successor discharges the obligation.
//!
//! Only Core mints a checkpoint cut, at an acknowledged cursor after its bounded staged prefix has
//! drained. The journal coordinator treats the snapshot bytes opaquely while it rolls, stores,
//! syncs, and prunes. Replay restores that normalized semantic cut and applies the contiguous journal
//! suffix; there is no second actor-side projection or cross-component handoff transcript.
//!
//! Engine recovery derives the retained `(Context, payload_digest)` requirements whose application
//! custody still supports live producer-dependent authority. It completes ordinary payload-only
//! `Automaton::verify` calls before actors, ingress, timers, producer work, resolver requests, or
//! publication reissue can start. After every result is `true`, Core reserves a new process
//! generation, rebuilds discardable service metadata, and reissues still-live durable obligations.
//!
//! # Service and resource bounds
//!
//! Core services persistence completions, local completions, timers, resolver results, and peer
//! observations with positive lane weights and a bounded work budget. Input admission charges item
//! and byte capacity before retention. Application and cryptographic work reserves both execution
//! and completion capacity before becoming mandatory. Local construction and authority-critical
//! cryptography retain capacity that remote validation and bulk work cannot consume, and remote
//! validation rotates across producer chains.
//!
//! Retention is reachability-based within the configured view and producer windows. Every retained
//! artifact, dependency, job, signing reservation, publication obligation, and finality pool has a
//! profile-derived ceiling. Exhausting a core budget explicitly reschedules the voter; exhausting an
//! ingress lane backpressures that source without blocking the completion path that relieves it.
//!
//! # Supported boundary
//!
//! The reducer lifecycle is implementation-private even though selected protocol/configuration and
//! diagnostic types are re-exported from [`crate::multimmit`]. Production users construct and start
//! [`crate::multimmit::Engine`]; they do not drive `Machine`, reducer inputs, or capabilities.
//! Fuzzing and benchmarks reach the same production mechanisms only through byte-oriented or fixed
//! scenario facades under the `test-utils` feature.
//!
//! The enduring implementation contract is the
//! [architecture guide](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/STATE_MACHINE.md),
//! and its
//! [property ledger](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md)
//! indexes the in-scope proof obligations.

mod admission;
pub(crate) mod algebra;
mod chain;
mod config;
pub(crate) mod contracts;
mod controller;
mod da;
mod durability;
mod emission;
mod finality;
mod publication;
mod reducer;
mod scheduler;
mod state;
mod view;

#[cfg(all(feature = "test-utils", feature = "mocks", not(target_arch = "wasm32")))]
#[path = "../test_utils/benchmarks/mod.rs"]
pub(crate) mod benchmarks;

pub use admission::*;
pub(crate) use chain::*;
pub use config::*;
pub(crate) use controller::*;
pub(crate) use da::*;
pub use durability::*;
pub use emission::ViewProof;
pub(crate) use emission::{ResolutionCompletion, ResolutionJob};
pub use finality::{FinalityFact, FinalityId, PoolSummary};
pub(crate) use finality::{LqcAggregateCompletion, LqcAggregateJob};
pub(crate) use reducer::*;
pub(crate) use scheduler::*;
use state::Machine;
pub(crate) use state::{
    ArtifactEntry, ArtifactState, CheckpointCut, FrozenAcknowledgement, Lifecycle,
    PendingPersistence, PendingSigningCompletion, Progress,
};
pub use state::{ChainProgress, Inspection, ProducerProgress};
pub(crate) use view::{
    NullificationRecoveryCompletion, NullificationRecoveryJob, VqcAggregateCompletion,
    VqcAggregateJob,
};

#[cfg(any(test, feature = "test-utils"))]
pub(crate) mod tests;

#[cfg(test)]
#[path = "tests/crypto.rs"]
mod crypto_tests;
