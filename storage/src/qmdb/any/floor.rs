//! Policies that advance a batch's inactivity floor.
//!
//! [`Proportional`] is the default compaction.
//!
//! [`merkleize`](super::batch::UnmerkleizedBatch::merkleize) reads [`Policy::limits`] once. With
//! [`Limits::Fixed`], it starts at the batch's inherited inactivity floor. While updates remain
//! to decide, it moves the floor to the next active update, spending a skip on each inactive
//! location it passes, and hands that update to [`Policy::decide`] as an [`Entry`]. Keeping,
//! evicting, or replacing the entry moves the floor one past it. The pass ends when `entries`
//! updates are decided, when the policy stops at an entry, when the floor reaches the batch's
//! original tip, or when the next active update, or the original tip if none remains, lies
//! beyond the remaining skips, in which case the floor advances by the remaining skips. The
//! batch commits that floor, or the new commit location if its final state is empty.
//!
//! Updates to keys the batch writes are inactive. Kept updates move to the tip as
//! [`Limits::Proportional`] moves them. Evictions and replacements resolve as writes to their
//! keys.
//!
//! Reads stay below the batch's original tip and below `entries + skips` locations past the
//! inherited floor.

use crate::merkle::{Family, Location};
use std::marker::PhantomData;

/// An invariant lifetime that ties a [`Decision`] to the [`Entry`] it decides.
type Brand<'a> = PhantomData<fn(&'a ()) -> &'a ()>;

/// How far a policy advances the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limits {
    /// Move up to one active update to the tip for each operation the batch supersedes, plus one
    /// for its previous commit. [`Policy::decide`] is not called.
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
pub trait Policy<F: Family, K, V> {
    /// How far the floor advances.
    fn limits(&self) -> Limits;

    /// Decide `entry`, the active update at the floor.
    ///
    /// The decision must depend only on the entry and the policy's own state.
    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, K, V>;
}

/// An active update at the floor, handed to [`Policy::decide`].
///
/// `'a` is unique to one call of [`Policy::decide`], so the [`Decision`] an entry makes can only
/// be returned from that call.
///
/// # Examples
///
/// ```
/// use commonware_storage::{
///     merkle::Family,
///     qmdb::any::floor::{Decision, Entry, Limits, Policy},
/// };
///
/// struct Evict;
///
/// impl<F: Family> Policy<F, u64, u64> for Evict {
///     fn limits(&self) -> Limits {
///         Limits::Fixed { entries: 1, skips: 0 }
///     }
///
///     fn decide<'a>(&mut self, entry: Entry<'a, F, u64, u64>) -> Decision<'a, u64, u64> {
///         entry.evict().0
///     }
/// }
/// ```
///
/// ```compile_fail
/// use commonware_storage::{
///     merkle::Family,
///     qmdb::any::floor::{Decision, Entry, Limits, Policy},
/// };
///
/// struct Stash<F: Family>(Option<Entry<'static, F, u64, u64>>);
///
/// impl<F: Family> Policy<F, u64, u64> for Stash<F> {
///     fn limits(&self) -> Limits {
///         Limits::Fixed { entries: 1, skips: 0 }
///     }
///
///     fn decide<'a>(&mut self, entry: Entry<'a, F, u64, u64>) -> Decision<'a, u64, u64> {
///         match self.0.replace(entry) {
///             Some(stashed) => stashed.keep(),
///             None => unreachable!(),
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Entry<'a, F: Family, K, V> {
    location: Location<F>,
    key: K,
    value: V,
    brand: Brand<'a>,
}

impl<'a, F: Family, K, V> Entry<'a, F, K, V> {
    /// Return an entry for the update of `key` to `value` at `location`.
    pub(crate) const fn new(location: Location<F>, key: K, value: V) -> Self {
        Self {
            location,
            key,
            value,
            brand: PhantomData,
        }
    }

    /// The update's location.
    pub const fn location(&self) -> Location<F> {
        self.location
    }

    /// The updated key.
    pub const fn key(&self) -> &K {
        &self.key
    }

    /// The updated value.
    pub const fn value(&self) -> &V {
        &self.value
    }

    /// Move the update to the tip.
    pub fn keep(self) -> Decision<'a, K, V> {
        Decision::new(Action::Keep(self.key, self.value))
    }

    /// Leave the update in place. The floor stays at its location and no further update is
    /// decided.
    pub fn stop(self) -> Decision<'a, K, V> {
        Decision::new(Action::Stop)
    }

    /// Write `value` for the key at the tip.
    pub fn replace(self, value: V) -> Decision<'a, K, V> {
        Decision::new(Action::Replace(self.key, value))
    }

    /// Delete the key, returning the decision with the owned key and value.
    pub fn evict(self) -> (Decision<'a, K, V>, K, V)
    where
        K: Clone,
    {
        let decision = Decision::new(Action::Evict(self.key.clone()));
        (decision, self.key, self.value)
    }
}

/// What a policy does with an [`Entry`]. Only the entry's methods construct it.
#[derive(Debug)]
pub struct Decision<'a, K, V> {
    action: Action<K, V>,
    brand: Brand<'a>,
}

impl<K, V> Decision<'_, K, V> {
    const fn new(action: Action<K, V>) -> Self {
        Self {
            action,
            brand: PhantomData,
        }
    }

    /// Return the action the decided update resolves to.
    pub(crate) fn into_action(self) -> Action<K, V> {
        self.action
    }
}

/// What the policy pass does with a decided update.
#[derive(Debug)]
pub(crate) enum Action<K, V> {
    /// Move the update, rebuilt from the key and value, to the tip.
    Keep(K, V),
    /// Leave the update in place and end the pass.
    Stop,
    /// Write the value for the key at the tip.
    Replace(K, V),
    /// Delete the key.
    Evict(K),
}

/// Advances the floor in proportion to the operations a batch supersedes.
///
/// Every operation a batch supersedes, and its previous commit, becomes inactive and cannot be
/// pruned until the floor passes it. Moving one active update to the tip for each of them keeps
/// the inactive operations retained ahead of the floor within a constant multiple of the active
/// operations in expectation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Proportional;

impl<F: Family, K, V> Policy<F, K, V> for Proportional {
    fn limits(&self) -> Limits {
        Limits::Proportional
    }

    /// Not called under [`Limits::Proportional`].
    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, K, V> {
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
    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, K, V> {
        entry.stop()
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
    fn limits(&self) -> Limits {
        Limits::Fixed {
            entries: self.entries,
            skips: self.skips,
        }
    }

    fn decide<'a>(&mut self, entry: Entry<'a, F, K, V>) -> Decision<'a, K, V> {
        entry.keep()
    }
}
