//! Simple and fast BFT agreement inspired by Simplex Consensus.
//!
//! Inspired by [Simplex Consensus](https://eprint.iacr.org/2023/463), `threshold-simplex` provides
//! simple and fast BFT agreement that seeks to minimize view latency (i.e. block time)
//! and to provide optimal finalization latency in a partially synchronous setting.
//!
//! _For a non-threshold version of this, checkout `simplex`._
//!
//! # Features
//!
//! * Wicked Fast Block Times (2 Network Hops)
//! * Optimal Finalization Latency (3 Network Hops)
//! * Externalized Uptime and Fault Proofs
//! * Decoupled Block Broadcast and Sync
//! * Flexible Block Format
//! * VRF for Block-Ahead Leader Election
//! * Threshold Certificates for Notarization and Finality
//!
//! # Design
//!
//! ## Architecture
//!
//! All logic is split into two components: the `Voter` and the `Resolver` (and the user of `simplex`
//! provides `Application`). The `Voter` is responsible for participating in the latest view and the
//! `Resolver` is responsible for fetching artifacts from previous views required to verify proposed
//! blocks in the latest view.
//!
//! To provide great performance, all interactions between `Voter`, `Resolver`, and `Application` are
//! non-blocking. This means that, for example, the `Voter` can continue processing messages while the
//! `Application` verifies a proposed block or the `Resolver` verifies a notarization.
//!
//! ```txt
//! +---------------+           +---------+            +++++++++++++++
//! |               |<----------+         +----------->+             +
//! |  Application  |           |  Voter  |            +    Peers    +
//! |               +---------->|         |<-----------+             +
//! +---------------+           +--+------+            +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                |   |
//!                                |   |
//!                                v   |
//!                            +-------+----+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |  Resolver  |          +    Peers    +
//!                            |            |<---------+             +
//!                            +------------+          +++++++++++++++
//! ```
//!
//! _Application is usually a single object that implements the `Automaton`, `Relay`, `Committer`,
//! and `Supervisor` traits._
//!
//! ## Joining Consensus
//!
//! As soon as `2f+1` votes or finalizes are observed for some view `v`, the `Voter` will enter `v+1`.
//! This means that a new participant joining consensus will immediately jump ahead to the latest view
//! and begin participating in consensus (assuming it can verify blocks).
//!
//! ## Persistence
//!
//! The `Voter` caches all data required to participate in consensus to avoid any disk reads on
//! on the critical path. To enable recovery, the `Voter` writes valid messages it receives from
//! consensus and messages it generates to a write-ahead log (WAL) implemented by [`Journal`](https://docs.rs/commonware-storage/latest/commonware_storage/journal/index.html).
//! Before sending a message, the `Journal` sync is invoked to prevent inadvertent Byzantine behavior
//! on restart (especially in the case of unclean shutdown).
//!
//! ## Protocol Description
//!
//! ### Specification for View `v`
//!
//! Upon entering view `v`:
//! * Determine leader `l` for view `v`
//! * Set timer for leader proposal `t_l = 2Δ` and advance `t_a = 3Δ`
//!     * If leader `l` has not been active (no votes) in last `r` views, set `t_l` to 0.
//! * If leader `l`, broadcast `(part(v), notarize(c,v))`
//!   * If can't propose container in view `v` because missing notarization/nullification for a
//!     previous view `v_m`, request `v_m`
//!
//! Upon receiving first `(part(v), notarize(c,v))` from `l`:
//! * Cancel `t_l`
//! * If the container's parent `c_parent` is notarized at `v_parent` and we have null notarizations for all views
//!   between `v` and `v_parent`, verify `c` and broadcast `(part(v), notarize(c,v))`
//!
//! Upon receiving `2f+1` `(part(v), notarize(c,v))`:
//! * Cancel `t_a`
//! * Mark `c` as notarized
//! * Broadcast `(seed(v), notarization(c,v))` (even if we have not verified `c`)
//! * If have not broadcast `(part(v), nullify(v))`, broadcast `finalize(c,v)`
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `(part(v), nullify(v))`:
//! * Broadcast `(seed(v), nullification(v))`
//!     * If observe `>= f+1` `notarize(c,v)` for some `c`, request `notarization(c_parent, v_parent)` and any missing
//!       `nullification(*)` between `v_parent` and `v`. If `c_parent` is than last finalized, broadcast last finalization
//!       instead.
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `finalize(c,v)`:
//! * Mark `c` as finalized (and recursively finalize its parents)
//! * Broadcast `(seed(v), finalization(c,v))` (even if we have not verified `c`)
//!
//! Upon `t_l` or `t_a` firing:
//! * Broadcast `(part(v), nullify(v))`
//! * Every `t_r` after `(part(v), nullify(v))` broadcast that we are still in view `v`:
//!    * Rebroadcast `(part(v), nullify(v))` and either `(seed(v-1), notarization(v-1))` or `(seed(v-1), nullification(v-1))`
//!
//! ### VRF
//!
//! When broadcasting a `notarize(c,v)` or `nullify(v)` message, a validator must also include a `part(v)` message (a partial
//! signature over the view `v` index). When `2f+1` `notarize(c,v)` or `nullify(v)` messages are received, a validator can
//! derive `seed(v)`. Because `part(v)` is only over the view `v`, the seed is the same for a given view `v` regardless of
//! whether or not a block was notarized in said view `v`.
//!
//! `seed(v)` can be used as bias-resistant randomness to select the leader for `v+1` and in the execution of `c` (at view `v`).
//! TODO: more elaboration on why this is safe.
//!
//! ### Threshold Certificates
//!
//! Because all messages are partial signatures (`notarize(c,v)`, `nullify(v)`, `finalize(c,v)`), `notarization(c,v)`, `nullification(v)`,
//! and `finalization(c,v)` are all recovered threshold signatures (of a static public key). This makes it possible for an external
//! process to verify that a block is canonical in a given consensus instance without actually following that consensus instance.
//!
//! This can be used both to secure interopability between different consensus instances and to secure user interactions with an RPC provider.
//!
//! ### Deviations from Simplex Consensus
//!
//! * Fetch missing notarizations/nullifications as needed rather than assuming each proposal contains
//!   a set of all notarizations/nullifications for all historical blocks.
//! * Introduce distinct messages for `notarize` and `nullify` rather than referring to both as a `vote` for
//!   either a "block" or a "dummy block", respectively.
//! * Introduce a "leader timeout" to trigger early view transitions for unresponsive leaders.
//! * Skip "leader timeout" and "notarization timeout" if a designated leader hasn't participated in
//!   some number of views (again to trigger early view transition for an unresponsive leader).
//! * Introduce message rebroadcast to continue making progress if messages from a given view are dropped (only way
//!   to ensure messages are reliably delivered is with a heavyweight reliable broadcast protocol).

use commonware_cryptography::Digest;

mod actors;
mod config;
pub use config::Config;
mod encoder;
mod engine;
pub use engine::Engine;
mod metrics;
mod prover;
pub use prover::Prover;
#[cfg(test)]
pub mod mocks;
mod verifier;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/threshold_simplex.wire.rs"));
}

/// View is a monotonically increasing counter that represents the current focus of consensus.
pub type View = u64;

/// Context is a collection of metadata from consensus about a given payload.
#[derive(Clone)]
pub struct Context {
    /// Current view of consensus.
    pub view: View,

    /// Parent the payload is built on.
    ///
    /// Payloads from views between the current view and the parent view can never be
    /// directly finalized (must exist some nullification).
    pub parent: (View, Digest),
}

use crate::Activity;
use thiserror::Error;

/// Errors that can occur during consensus.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Network closed")]
    NetworkClosed,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid container")]
    InvalidContainer,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Notarize a payload at a given view.
///
/// ## Clarifications
/// * Vote for leader is considered a proposal and a vote.
/// * It is ok to have both a vote for a proposal and the null
///   container in the same view.
/// * It is ok to notarize/finalize different proposals in the same view.
pub const NOTARIZE: Activity = 0;
/// Finalize a payload at a given view.
pub const FINALIZE: Activity = 1;
/// Notarize a payload that conflicts with a previous notarize.
pub const CONFLICTING_NOTARIZE: Activity = 2;
/// Finalize a payload that conflicts with a previous finalize.
pub const CONFLICTING_FINALIZE: Activity = 3;
/// Nullify and finalize in the same view.
pub const NULLIFY_AND_FINALIZE: Activity = 4;
