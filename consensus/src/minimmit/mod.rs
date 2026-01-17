//! Minimmit consensus protocol.
//!
//! Minimmit is a Byzantine Fault Tolerant (BFT) State Machine Replication protocol
//! that achieves **2-round finality** (one round for proposals, one for voting) under
//! the assumption that `n >= 5f + 1`.
//!
//! # Key Innovation
//!
//! Unlike traditional 2-round finality protocols, Minimmit allows view progression
//! on a smaller M-quorum (`2f + 1`) while requiring the larger L-quorum (`n - f`)
//! only for finalization. This decoupling reduces view latency without sacrificing
//! safety, because in realistic networks receiving `2f + 1` votes is significantly
//! faster than waiting for `n - f` votes.
//!
//! # Comparison with Simplex
//!
//! | Property            | Simplex (3f+1)         | Minimmit (5f+1)              |
//! |---------------------|------------------------|------------------------------|
//! | Rounds to finality  | 3 (propose + 2 votes)  | 2 (propose + 1 vote)         |
//! | View progression    | 2f+1 notarize votes    | 2f+1 notarize OR nullify     |
//! | Finalization        | 2f+1 finalize votes    | n-f notarize votes (same!)   |
//! | Vote types          | Notarize, Nullify, **Finalize** | Notarize, Nullify    |
//!
//! # Parameters
//!
//! - **Byzantine tolerance**: At most `f` processors may exhibit Byzantine faults
//! - **Total processors**: `n >= 5f + 1`
//! - **Network model**: Partial synchrony with unknown GST; messages arrive within
//!   `delta` time after GST
//!
//! # Quorums
//!
//! - **M-quorum** (mini): `2f + 1` votes - sufficient for view progression
//! - **L-quorum** (large): `n - f` votes - required for finalization
//!
//! The key insight is that any M-quorum and L-quorum intersect in at least `f + 1`
//! processors, guaranteeing at least one honest processor in the intersection.
//!
//! # Message Types
//!
//! | Message               | Description                                                   |
//! |-----------------------|---------------------------------------------------------------|
//! | `propose(v, b, v', b')` | Block `b` for view `v`, extending block `b'` from view `v'` |
//! | `notarize(v, b)`      | Vote endorsing block `b` for view `v`                         |
//! | `nullify(v)`          | Vote to skip view `v` (no progress)                           |
//! | `M-notarization(v, b)`| Certificate: `2f+1` notarize votes for `b` in view `v`        |
//! | `nullification(v)`    | Certificate: `2f+1` nullify votes for view `v`                |
//! | `finalization(v, b)`  | Certificate: `n-f` notarize votes for `b` in view `v`         |
//!
//! Note: Finalization uses the **same notarize votes** as M-notarization, just more
//! of them. There is no separate finalize vote type.
//!
//! # Protocol Specification
//!
//! ## Entering a View
//!
//! Upon entering view `v`:
//! 1. Determine leader `l` for view `v`
//! 2. If self is leader: broadcast `propose(v, b, v', b')` where `b'` is the highest
//!    M-notarized block and nullifications exist for all views in `(v', v)`
//! 3. Otherwise: start timer `t = 2*delta`
//!    - If leader was inactive recently, set `t = 0` (immediate timeout)
//!
//! ## Voting
//!
//! Upon receiving a valid proposal `b` for view `v`:
//! - If not yet voted and not nullified: broadcast `notarize(v, b)`
//! - Cancel the leader timer
//!
//! Upon timer expiry (before voting): broadcast `nullify(v)`
//!
//! ## View Progression
//!
//! Advance to view `v + 1` upon receiving either:
//! - An M-notarization for any block in view `v`, OR
//! - A nullification for view `v`
//!
//! Before advancing, if an M-notarization is received and we haven't voted or
//! nullified, vote for that block (ensures L-quorum can form for correct leaders).
//!
//! ## Finalization
//!
//! Upon receiving `n - f` notarize votes for block `b` in view `v`:
//! - Finalize `b` and all its ancestors
//! - This may occur before or after advancing past view `v`
//!
//! ## Condition (b): Handling Leader Equivocation
//!
//! If, after broadcasting `notarize(v, b)`, we receive `2f + 1` messages that are
//! either `nullify(v)` or `notarize(v, b')` where `b' != b`:
//! - Broadcast `nullify(v)`
//!
//! This ensures view progression even when a Byzantine leader equivocates.
//!
//! # Safety Invariants
//!
//! - **X1**: If block `b` receives an L-notarization (finalization) for view `v`,
//!   no other block `b' != b` can receive an M-notarization for view `v`
//! - **X2**: If block `b` receives an L-notarization for view `v`, view `v` cannot
//!   receive a nullification
//!
//! # References
//!
//! - Paper: [arXiv:2508.10862](https://arxiv.org/abs/2508.10862) "Minimmit"
//! - Quint specification: `pipeline/minimmit/quint/`

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        use crate::types::{View, ViewDelta};

        pub mod ancestry;
        mod actors;
        pub mod config;
        pub use config::{Config, ConfigError};
        mod engine;
        pub use engine::Engine;
        mod metrics;
        pub mod state;
        pub mod view;

        /// The minimum view we are tracking both in-memory and on-disk.
        pub(crate) const fn min_active(activity_timeout: ViewDelta, last_finalized: View) -> View {
            last_finalized.saturating_sub(activity_timeout)
        }

        /// Whether or not a view is interesting to us. This is a function
        /// of both `min_active` and whether or not the view is too far
        /// in the future (based on the view we are currently in).
        pub(crate) fn interesting(
            activity_timeout: ViewDelta,
            last_finalized: View,
            current: View,
            pending: View,
            allow_future: bool,
        ) -> bool {
            // If the view is genesis, skip it, genesis doesn't have votes
            if pending.is_zero() {
                return false;
            }
            if pending < min_active(activity_timeout, last_finalized) {
                return false;
            }
            if !allow_future && pending > current.next() {
                return false;
            }
            true
        }
    }
}

#[cfg(any(test, feature = "mocks"))]
pub mod mocks;

#[cfg(test)]
mod tests;
