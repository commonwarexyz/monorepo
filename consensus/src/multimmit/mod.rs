//! Multimmit consensus for independently produced application-block chains.
//!
//! Multimmit separates dissemination from ordering. An ordered subset of committee members owns
//! producer chains and can disseminate new application blocks without waiting for a consensus
//! leader. Leaders and voters exchange only signed headers, commitments, per-chain positions, and
//! certificates; the resulting leader chain authenticates the sparse facts from which an external
//! consumer can derive one deterministic order across all producer chains.
//!
//! # Protocol Shape
//!
//! A producer chain carries one participant's application commitments. The leader chain is a
//! separate consensus construction: one scheduled leader per view summarizes all producer chains,
//! and the certified summaries determine their common order. There are therefore many producer
//! chains but only one leader chain.
//!
//! ```text
//! participant 0:  genesis -> tx 1 -> tx 2 -> ... --+
//! participant 1:  genesis -> tx 1 -> tx 2 -> ... --+-- signed headers and DA facts
//! participant 2:  genesis -> tx 1 -> tx 2 -> ... --+              |
//!                                                               v
//! view 1 leader -> view 2 leader -> view 3 leader -> ... -> one global order
//!       |                 |                 |
//!       +-- votes/V-QC ---+-- votes/L-QC ---+
//! ```
//!
//! Transaction bodies stay with the attached application. Multimmit orders authenticated header
//! identities, so consensus traffic does not grow with payload size. A slow or unavailable body
//! affects only its producer chain's reported position; it does not prevent the other chains or the
//! leader chain from advancing.
//!
//! The enduring implementation contract is documented in
//! [the architecture and state-machine guide](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/STATE_MACHINE.md).
//! Its [property ledger](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md)
//! maps the safety, liveness, and resource invariants to focused and deterministic proofs.
//!
//! # Supported Engine Lifecycle
//!
//! Production users drive [`Engine`], not the private reducer lifecycle:
//!
//! ```text
//! EngineConfig -> Engine::new -> start(data, consensus, certificates, resolver)
//!                                      |
//!                                      v
//!                               Running::ready
//!                                      |
//!                           inspect / serve / protocol work
//!                                      |
//!                                      v
//!                              abort -> Running::join
//! ```
//!
//! The
//! [log-multimmit example](https://github.com/commonwarexyz/monorepo/blob/main/examples/log-multimmit/src/main.rs)
//! shows the supported end-to-end construction: it builds the profile and application attachment,
//! registers the four network planes, starts `Engine`, waits for readiness, inspects progress, and
//! joins the engine during shutdown.
//!
//! # Security and Recovery Model
//!
//! For a committee of `n` validators, Multimmit derives `f = floor((n - 1) / 5)` and assumes at
//! most `f` Byzantine validators, hence `n >= 5f + 1`. Its safety, liveness, and availability
//! claims are conditional on that bound. The implementation provides no safety or recovery
//! backstop when more than `f` validators are Byzantine. Resource limits defend the protocol
//! within this model; observing more than `f` authenticated equivocators is a fault-bound-breach
//! diagnostic, not permission to retain unbounded evidence.
//!
//! Durable signing history is part of a validator's identity. A validator must never restart with
//! empty storage under the same active-epoch key: doing so could authorize a conflicting subject.
//! Recovery under that key requires the machine's acknowledged checkpoint and journal suffix,
//! together with the attached application's matching durable state. A node that cannot recover
//! those facts must import a trusted checkpoint containing both safety and application state, or
//! join a new epoch under a new key.
//!
//! # Committee and Memory
//!
//! One epoch-local synchronous core serves one fixed committee and runs indefinitely. Its ordered
//! committee, ordered producer ownership map, cryptographic material, protocol parameters, genesis
//! facts, and resource limits are fixed by [`config::Config`] and [`Profile`]. Live views
//! start at one; view zero contains only the synthetic genesis leader and the height-zero genesis
//! commitment for each producer chain.
//!
//! Memory is bounded by a retention window below the current view rather than by any end state. A
//! machine that has advanced past a view can never act in that view again, so it retires the view's
//! transitions, artifacts, and pools even while finality is stalled.
//! [`Tuning::view_retention`] sets the window, and every internal bound is derived from it
//! and the committee size.
//!
//! Write `W = Tuning::view_retention`. Consensus recovery is keyed directly by view. A
//! response provides authenticated evidence that crosses the requested view: its exact V-QC or
//! nullification, or a covering L-QC. Requests remain
//! level-triggered across temporary unavailability and end when the machine owner retracts them or
//! a covering finality floor is admitted. Producer-chain history is not resolver material.
//!
//! # Deployment Liveness Bounds
//!
//! As in [`crate::simplex`], network channel quotas and backlogs are part of the deployment's
//! synchrony model. Each plane's per-peer quota must bound aggregate Byzantine ingress below the
//! node's sustained decode and verification capacity, and the channel backlog must absorb the
//! permitted burst. Channels deliberately drop under backpressure, so correct senders must retry
//! protocol messages until the receiver has admitted them.
//!
//! [`Tuning::view_timeout`] must cover the paper's `2 * delta` deadline after including
//! those admission bounds, the batcher's coalescing window, runtime scheduling, and cryptographic
//! verification. Increasing only the timeout cannot compensate for an ingress configuration whose
//! sustained admitted rate exceeds local service capacity.
//!
//! Changing the committee is a deployment concern, as it is for [`crate::simplex`]. The epoch in
//! [`config::Config`] is an immutable label bound into every signed subject; a deployment stops one
//! machine and constructs the next from new immutable genesis facts under a new label. Application
//! blocks remain generic, so Multimmit defines neither an in-band reconfiguration block nor a
//! boundary-proof format. No unfinalized votes, certificates, producer blocks, or signing choices
//! carry across.
//!
//! # Producer Chains and Availability
//!
//! A transaction block is a signed protocol header containing a chain, height, parent, and
//! application block digest. Its application body and the transactions or state transitions within
//! it are not Multimmit types and never enter the consensus engine. The opaque application digest is
//! distinct from the block's protocol identity: the latter hashes the complete canonical header and
//! is used by parent links, certificates, tips, and tip commitments. Producers may pipeline up to the
//! configured depth beyond their latest DA-certified block. The shared [`crate::Automaton`] returns
//! block commitments and validates them in application context. A successful verification is the
//! attached application's assertion of both a stable validity verdict and local payload
//! availability; while the payload is missing, the verification remains pending. Only a successful
//! verification makes a header eligible for a local DA share. [`crate::Relay`] notifies the attached
//! application when a commitment should be disseminated outside the protocol wire.
//!
//! For this engine, [`crate::Automaton::propose`] returning a commitment and
//! [`crate::Automaton::verify`] returning `true` are custody fences: the attached system promises
//! that the exact payload is locally available and reconstructible after a crash. A temporary lack
//! of bytes or durable custody keeps the operation pending; `false` means permanently invalid.
//! Multimmit reserves no payload-dependent header or DA-vote signing subject before that fence.
//! `Automaton` handles only application payloads. Consensus certificates and leader blocks never
//! enter this interface; missing view proofs are handled by the resolver.
//! The attached payload service, not `Automaton` or `Relay`, fetches and retains bodies by
//! commitment for the same reference and view horizon as their headers. Losing this attached state
//! is validator-state loss, not a condition that permits the machine to replace an already reserved
//! signing subject.
//!
//! ## Paper departure: validity-gated DA votes
//!
//! The paper requires a DA vote for every eligible block without an application-validity condition.
//! This implementation deliberately withholds the vote until [`crate::Automaton::verify`] succeeds.
//! The paper's liveness proof assumes its original rule, so this practical validity gate is an
//! explicit protocol departure rather than an implementation detail.
//!
//! Exactly `n - 2f` valid DA shares recover a constant-size threshold certificate. This proves both
//! availability and uniqueness for the certified chain position, but certification does not gate the
//! fast path: a leader may propose uncertified descendants and voters report only the prefixes they
//! actually hold. Votes may also carry bounded extensions beyond the proposal, allowing fresh blocks
//! to reach voters directly rather than first passing through a leader.
//!
//! # Views and Certificates
//!
//! Each view has a scheduled leader. Its leader block names an earlier V-QC and proposes one anchored
//! path per producer chain. A vote signs the complete proposal-relative position and extension vector,
//! so missing data lowers only the affected chain's contribution.
//!
//! - A V-QC accounts for `n - f..=n` attributed votes or novotes, including at least `2f + 1` votes for
//!   its designated leader. It selects tips that are safe for every later leader to extend and
//!   authorizes leaving the view.
//! - An L-QC contains `n - f` complete votes for one leader. Those votes finalize the leader and a
//!   tip on every producer chain. A local sticky pool reaches the same finality immediately at
//!   `n - f`; constructing an L-QC is portable evidence and is not a local-finality prerequisite.
//! - A timeout contributes an attributed novote when the validator has not voted and an independent
//!   nullify share. Exactly `2f + 1` nullify shares recover a threshold nullification, which proves
//!   the view can be skipped. A validator that already voted may later nullify only under the
//!   protocol's post-vote non-support rule, and never emits a novote for that view.
//!
//! V-QCs and L-QCs are aggregates of ordinary signatures over the exact attributed transcript; they
//! are not threshold certificates. DA certificates use the independent `n - 2f` threshold sharing,
//! while nullifications use the independent `2f + 1` sharing. [`scheme`] implements this split for
//! both BLS12-381 MinPk and MinSig.
//!
//! # Runtime Topology and Backpressure
//!
//! One dedicated voter task owns the serial core. DA, View, and Finality are synchronous semantic
//! partitions inside that one authority; they are not actors, and producer chains do not receive
//! one actor each. Runtime-owned work surrounds this serial core:
//!
//! ```text
//! data / consensus / certificate planes
//!                 |
//!                 v
//!       bounded batcher + verification workers
//!                 |
//!                 v
//! +------------------------------------------------------------+
//! | dedicated voter task                                      |
//! | bounded input lanes -> CoreState -> private reducer         |
//! |                              |            |                 |
//! |                    typed capabilities   reporter            |
//! +------------------------------+-----------------------------+
//!            ^                   ^                    ^
//!            |                   |                    |
//!    journal owner task   resolver/serving actor   shared tasks
//!    append + one sync    view-proof fetches       app + crypto
//! ```
//!
//! The batcher, core lanes, worker permits, journal owner, resolver control paths, and egress
//! obligations have configuration-derived item and byte bounds. Work reserves its destination and
//! completion capacity before the machine makes that work mandatory. A full observation lane
//! pauses that ingress plane while persistence acknowledgements, local completions, resolver
//! results, and timers keep their reserved paths. Local block construction has a slot remote
//! validation cannot consume; signing and critical aggregation retain capacity that bulk
//! verification cannot consume. Remote validations queue per producer chain and use a rotating
//! cursor. Once the core's deterministic credit budget is exhausted, the voter explicitly
//! yields through the Commonware runtime before continuing.
//!
//! # Finality and delivery
//!
//! Finality is first chain-local: once a leader reaches `n - f` votes, the chosen prefix of each
//! producer chain cannot later change. Exact cross-chain placement may be shorter until a V-QC fixes
//! how far a lagging chain extended. The consensus machine does not maintain a durable global
//! delivery cursor or expose an ordered-finalized application stream; bounded
//! [`Inspection`] data exists only for diagnostics.
//!
//! This division keeps consensus traffic independent of application payload volume. The private
//! synchronous core owns bounded deterministic protocol work, while attached actors own runtime
//! scheduling, networking, persistence, cryptographic execution, and the shared application
//! attachments.

#[cfg(not(target_arch = "wasm32"))]
mod actors;
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
mod engine;
pub(crate) mod machine;
#[cfg(any(test, feature = "mocks"))]
pub mod mocks;
pub mod scheme;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod storage;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod twins;
pub mod types;

#[cfg(not(target_arch = "wasm32"))]
pub use engine::{Config as EngineConfig, Engine, Inspector, OpenError, Running};
pub use machine::{
    Artifact, ArtifactId, BarrierId, ChainProgress, Cursor, EffectId, FinalityFact, FinalityId,
    Inspection, JobId, PoolSummary, ProducerProgress, Profile, ProfileError, ReplayError,
    ResourceLimits, Role, Timers, Tuning, ViewProof,
};
#[cfg(not(target_arch = "wasm32"))]
pub use storage::{CheckpointError, JournalError};

/// Opaque test entry points that exercise production Multimmit mechanisms without exposing the
/// private core lifecycle.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod test_utils;
