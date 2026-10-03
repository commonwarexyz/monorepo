//! Policies that advance a batch's inactivity floor.
//!
//! [`merkleize`](super::any::batch::UnmerkleizedBatch::merkleize) and the store's
//! [`apply_batch`](super::store::db::Db::apply_batch) read [`Policy::limits`] once. With
//! [`Limits::Fixed`], the pass starts at the batch's inherited inactivity floor. While updates
//! remain to decide, it moves the floor to the next active update and hands that update to
//! [`Policy::decide`] as an [`Entry`]. Each inactive location the floor passes spends a skip.
//! Keeping, evicting, or replacing the entry moves the floor one past it. The pass ends when
//! `entries` updates are decided, when the policy stops at an entry, or when the floor reaches
//! the batch's original tip. If neither an active update nor the original tip lies within the
//! remaining skips, the floor advances by the remaining skips and the pass ends. The batch
//! commits that floor, or the new commit location if its final state is empty.
//!
//! Updates to keys the batch writes are inactive. Kept updates move to the tip as
//! [`Limits::Proportional`] moves them. Evictions and replacements resolve as writes to their
//! keys.
//!
//! The pass reads only below the batch's original tip and below `entries + skips` locations past
//! the inherited floor.

use crate::merkle::{Family, Location};
use std::marker::PhantomData;

/// An invariant lifetime that ties a [`Decision`] to the call of [`Policy::decide`] that made it.
type Brand<'a> = PhantomData<fn(&'a ()) -> &'a ()>;

/// How far a policy advances the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limits {
    /// Move up to one active update to the tip for each operation the batch makes inactive: each
    /// update it supersedes, each delete it appends, and its previous commit. Moved updates lie
    /// below the tip as it stood before the moves. [`Policy::decide`] is not called.
    Proportional,
    /// Decide at most `entries` active updates and pass at most `skips` inactive locations.
    Fixed {
        /// The most active updates to decide.
        entries: usize,
        /// The most inactive locations to pass.
        skips: u64,
    },
}

/// Chooses how a batch advances its inactivity floor.
///
/// [`Proportional`] is the default compaction.
pub trait Policy<F: Family, K, V> {
    /// How far the floor advances.
    fn limits(&self) -> Limits;

    /// Decide `entry`, the active update at the floor.
    ///
    /// The decision must depend only on the entry and the policy's own state.
    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, V>;
}

/// An active update at the floor that [`Policy::decide`] receives.
///
/// The entry borrows the update's key for `'a` and owns its value. `'a` is unique to one call of
/// [`Policy::decide`], so the [`Decision`] an entry makes can only be returned from that call.
///
/// # Examples
///
/// ```
/// use commonware_storage::{
///     merkle::Family,
///     qmdb::floor::{Decision, Entry, Limits, Policy},
/// };
///
/// struct Evict;
///
/// impl<F: Family> Policy<F, u64, u64> for Evict {
///     fn limits(&self) -> Limits {
///         Limits::Fixed { entries: 1, skips: 0 }
///     }
///
///     fn decide<'a>(&mut self, entry: Entry<'a, F, u64, u64>) -> Decision<'a, u64> {
///         entry.evict().0
///     }
/// }
/// ```
///
/// ```compile_fail
/// use commonware_storage::{
///     merkle::Family,
///     qmdb::floor::{Decision, Entry, Limits, Policy},
/// };
///
/// struct Stash(Option<Decision<'static, u64>>);
///
/// impl<F: Family> Policy<F, u64, u64> for Stash {
///     fn limits(&self) -> Limits {
///         Limits::Fixed { entries: 2, skips: 0 }
///     }
///
///     fn decide<'a>(&mut self, entry: Entry<'a, F, u64, u64>) -> Decision<'a, u64> {
///         match self.0.replace(entry.keep()) {
///             Some(stashed) => stashed,
///             None => unreachable!(),
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Entry<'a, F: Family, K, V> {
    location: Location<F>,
    key: &'a K,
    value: V,
}

impl<'a, F: Family, K, V> Entry<'a, F, K, V> {
    /// Return an entry for the update of `key` to `value` at `location`.
    pub(crate) const fn new(location: Location<F>, key: &'a K, value: V) -> Self {
        Self {
            location,
            key,
            value,
        }
    }

    /// The update's location.
    pub const fn location(&self) -> Location<F> {
        self.location
    }

    /// The updated key.
    pub const fn key(&self) -> &K {
        self.key
    }

    /// The updated value.
    pub const fn value(&self) -> &V {
        &self.value
    }

    /// Move the update to the tip.
    pub fn keep(self) -> Decision<'a, V> {
        Decision::new(Action::Keep(self.value))
    }

    /// Leave the update in place. The floor stays at its location and no further update is
    /// decided.
    pub fn stop(self) -> Decision<'a, V> {
        Decision::new(Action::Stop)
    }

    /// Write `value` for the key at the tip.
    pub fn replace(self, value: V) -> Decision<'a, V> {
        Decision::new(Action::Replace(value))
    }

    /// Delete the key and return the decision with the owned value. A policy that needs the key
    /// clones [`key`](Self::key) first.
    pub fn evict(self) -> (Decision<'a, V>, V) {
        (Decision::new(Action::Evict), self.value)
    }
}

/// What a policy does with an [`Entry`]. Only the entry's methods construct it.
#[derive(Debug)]
pub struct Decision<'a, V> {
    action: Action<V>,
    brand: Brand<'a>,
}

impl<V> Decision<'_, V> {
    const fn new(action: Action<V>) -> Self {
        Self {
            action,
            brand: PhantomData,
        }
    }

    /// Return the action the decided update resolves to.
    pub(crate) fn into_action(self) -> Action<V> {
        self.action
    }
}

/// What the policy pass does with a decided update.
#[derive(Debug)]
pub(crate) enum Action<V> {
    /// Rebuild the update from its key and the value and move it to the tip.
    Keep(V),
    /// Leave the update in place and end the pass.
    Stop,
    /// Write the value for the update's key at the tip.
    Replace(V),
    /// Delete the update's key.
    Evict,
}

/// Advances the floor in proportion to the operations a batch makes inactive.
///
/// Each update a batch supersedes, each delete it appends, and its previous commit become
/// inactive and cannot be pruned until the floor passes them. When every batch moves one active
/// update to the tip for each of them, the floor stays at most `3 * (n + 1)` operations behind
/// the tip for `n` active keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Proportional;

impl<F: Family, K, V> Policy<F, K, V> for Proportional {
    fn limits(&self) -> Limits {
        Limits::Proportional
    }

    /// Not called under [`Limits::Proportional`].
    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, V> {
        entry.keep()
    }
}

/// Holds the floor at its inherited location, or moves it to the new commit location if the
/// batch's final state is empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hold;

impl<F: Family, K, V> Policy<F, K, V> for Hold {
    fn limits(&self) -> Limits {
        Limits::Fixed {
            entries: 0,
            skips: 0,
        }
    }

    /// Not called with zero `entries`.
    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, V> {
        entry.stop()
    }
}

/// Keeps every active update it reaches within its limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compact {
    /// The most active updates to keep.
    pub entries: usize,
    /// The most inactive locations to pass.
    pub skips: u64,
}

impl<F: Family, K, V> Policy<F, K, V> for Compact {
    fn limits(&self) -> Limits {
        Limits::Fixed {
            entries: self.entries,
            skips: self.skips,
        }
    }

    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, V> {
        entry.keep()
    }
}
