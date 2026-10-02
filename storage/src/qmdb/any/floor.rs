//! Policies that advance a batch's inactivity floor.
//!
//! [`merkleize_with`](super::batch::UnmerkleizedBatch::merkleize_with) replaces the automatic
//! floor raise with a [`Policy`]. It reads `(entries, skips)` from [`Policy::limits`] once, then
//! starts at the batch's inherited inactivity floor. While updates remain to decide, it moves the
//! floor to the next active update, spending a skip on each inactive location it passes, and
//! applies the [`Decision`] the policy returns for that update. Keeping, evicting, or replacing
//! an update moves the floor one past it. The pass ends when `entries` updates are decided, when
//! the policy returns [`Decision::Stop`], when the floor reaches the batch's original tip, or when
//! the next active update, or the original tip if none remains, lies beyond the remaining skips,
//! in which case the floor advances by the remaining skips. The batch commits that floor, or the
//! new commit location if its final state is empty.
//!
//! Updates to keys the batch writes are inactive. Kept updates move to the tip as the automatic
//! floor raise moves them. Evictions and replacements resolve as writes to their keys.
//!
//! Reads stay below the batch's original tip and below `entries + skips` locations past the
//! inherited floor. Each read round decodes up to `entries` candidate locations plus those
//! sharing a translated-key bucket with keys the batch writes, so `entries = usize::MAX` reads
//! every reachable candidate in one round.

use crate::merkle::{Family, Location};

/// What a policy does with the active update at the floor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision<V> {
    /// Move the update to the tip.
    Keep,
    /// Delete the key.
    Evict,
    /// Write the value for the key at the tip.
    Replace(V),
    /// Leave the update in place. The floor stays at its location and no further update is
    /// decided.
    Stop,
}

/// Chooses how a batch advances its inactivity floor.
pub trait Policy<F: Family, K, V> {
    /// The most active updates to decide and the most inactive locations to pass.
    fn limits(&self) -> (usize, u64);

    /// Decide the active update at `location`.
    ///
    /// The decision must depend only on the arguments and the policy's own state.
    fn decide(&mut self, location: Location<F>, key: &K, value: &V) -> Decision<V>;
}

/// Holds the floor at its inherited location.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hold;

impl<F: Family, K, V> Policy<F, K, V> for Hold {
    fn limits(&self) -> (usize, u64) {
        (0, 0)
    }

    fn decide(&mut self, _: Location<F>, _: &K, _: &V) -> Decision<V> {
        Decision::Stop
    }
}

/// Keeps every active update it reaches, within its limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compact {
    /// The most active updates to keep.
    pub entries: usize,
    /// The most inactive locations to pass.
    pub skips: u64,
}

impl<F: Family, K, V> Policy<F, K, V> for Compact {
    fn limits(&self) -> (usize, u64) {
        (self.entries, self.skips)
    }

    fn decide(&mut self, _: Location<F>, _: &K, _: &V) -> Decision<V> {
        Decision::Keep
    }
}
