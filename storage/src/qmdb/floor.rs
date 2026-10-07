//! Policies that advance a batch's inactivity floor.
//!
//! After a batch's writes resolve, it asks [`Policy::limits`] for its budget and walks the
//! operations in location order from the floor it inherits toward the tip its writes reached.
//! Every operation below that tip is eligible, including the batch's own writes. The walk's own
//! effects land at or past that tip, so what it sees below the tip is the state the writes left.
//!
//! Each inactive location the walk passes spends a skip, whether it holds a superseded update, a
//! delete, or a commit. Each active update it reaches goes to [`Policy::decide`] as an
//! [`Entry`]: keeping, replacing, or evicting it spends an entry and moves the floor one past it,
//! while stopping spends nothing and ends the walk with the floor at the update. The walk applies
//! the decisions of a policy that [never evicts](Policy::evicts) as it makes them, and the
//! decisions of one that may once it ends.
//!
//! Unless the policy stops it, the walk ends in one of three ways. When its entries run out, the
//! floor stays where the last decision left it, or where it was inherited if there were none.
//! When the next active update lies beyond the remaining skips, the floor advances by them. When
//! no active update remains below the tip, the floor moves to the tip if the remaining skips
//! reach it, and by them otherwise.
//!
//! The walk appends its effects after the batch's writes and before its commit operation: kept
//! and replaced updates are rewritten at the tip, and evicted keys are deleted. Evicting a key
//! from an ordered database also rewrites the link of the key that precedes it, even one the walk
//! stopped at or never reached. The commit operation records the floor the walk reached, or its
//! own location if the batch's final state is empty.
//!
//! The limits bound what the walk decides and passes, not what it reads: it may read candidates
//! it then passes or never reaches, but only below both the tip and the inherited floor plus
//! `skips` plus `entries` of the limits that sized the read, which for a staged batch's first
//! round are the limits of an estimated count. Relinking an ordered database past evicted keys
//! also reads the applied updates in their translated-key buckets and the buckets before them,
//! wherever those lie.
//!
//! A walk reads candidates in rounds and may hold the operations of up to `entries` reached
//! candidates in memory at once.

use crate::merkle::{Family, Location};
use commonware_utils::Widen;

/// How far a walk advances the floor: it decides at most `entries` active updates and passes at
/// most `skips` inactive locations. Skips left once `entries` updates are decided go unspent, and
/// zero `entries` passes no location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most active updates to decide.
    pub entries: usize,
    /// The most inactive locations to pass.
    pub skips: u64,
}

/// Chooses how a batch advances its inactivity floor.
///
/// [`Proportional`] is the policy for batches that need no custom rule.
pub trait Policy<F: Family, K, V> {
    /// Whether [`decide`](Self::decide) may evict an entry.
    ///
    /// The walk applies the decisions of a policy that never evicts as it makes them. It collects
    /// the decisions of one that may, so an ordered batch can repair the links its evictions
    /// break once the walk ends.
    fn evicts(&self) -> bool;

    /// How far the floor advances when the batch's writes made `made_inactive` operations
    /// inactive: one for each update they supersede and two for each delete.
    ///
    /// The limits must depend only on `made_inactive` and the policy's own state. A batch asks
    /// with the exact count before its walk, and only that answer bounds the walk. A staged batch
    /// also asks earlier with an estimate, which can fall on either side of the exact count, to
    /// size the candidates it reads while its writes resolve.
    fn limits(&self, made_inactive: usize) -> Limits;

    /// Decide `entry`, the active update at the floor.
    ///
    /// The decision must depend only on the entry and the policy's own state, so the same batch
    /// and policy state always produce the same operations and root. A decision takes effect only
    /// if its batch is applied, so state the policy records in `decide` is provisional until then.
    fn decide(&mut self, entry: Entry<'_, F, K, V>) -> Decision<V>;
}

/// An active update at the floor that [`Policy::decide`] receives.
///
/// The entry borrows the update's key and owns its value. Only its methods construct a
/// [`Decision`].
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
///     fn evicts(&self) -> bool {
///         true
///     }
///
///     fn limits(&self, _inactive: usize) -> Limits {
///         Limits { entries: 1, skips: 0 }
///     }
///
///     fn decide(&mut self, entry: Entry<'_, F, u64, u64>) -> Decision<u64> {
///         entry.evict().0
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
    pub fn keep(self) -> Decision<V> {
        Decision::new(Action::Write(self.value))
    }

    /// Decide nothing for the update and end the walk with the floor at its location. On an
    /// ordered database, evicting the key that follows it still rewrites its link.
    pub fn stop(self) -> Decision<V> {
        Decision::new(Action::Stop)
    }

    /// Write `value` for the key at the tip.
    pub fn replace(self, value: V) -> Decision<V> {
        Decision::new(Action::Write(value))
    }

    /// Delete the key and return the decision with the owned value. A policy that needs the key
    /// clones [`key`](Self::key) first.
    pub fn evict(self) -> (Decision<V>, V) {
        (Decision::new(Action::Evict), self.value)
    }
}

/// What a policy does with an [`Entry`]. Only the entry's methods construct it.
#[derive(Debug)]
pub struct Decision<V> {
    action: Action<V>,
}

impl<V> Decision<V> {
    const fn new(action: Action<V>) -> Self {
        Self { action }
    }

    pub(crate) fn into_action(self) -> Action<V> {
        self.action
    }
}

/// What the walk does with a decided update.
#[derive(Debug)]
pub(crate) enum Action<V> {
    /// Write the value for the update's key at the tip.
    Write(V),
    /// Leave the update in place and end the walk.
    Stop,
    /// Delete the update's key.
    Evict,
}

/// A floor walk's position and remaining limits. The floor it reaches depends only on which
/// locations hold active updates, not on how they were read.
pub(crate) struct Walk<F: Family> {
    /// Every location below it is inactive or decided.
    pub(crate) floor: Location<F>,
    /// The walk reads and decides nothing at or past it.
    pub(crate) end: Location<F>,
    /// Active updates left to decide.
    pub(crate) entries: usize,
    /// Inactive locations left to pass.
    skips: u64,
}

impl<F: Family> Walk<F> {
    /// Start a walk at `floor` that ends at `tip` or where `skips` and `entries` run out,
    /// whichever comes first.
    pub(crate) fn new(floor: Location<F>, tip: Location<F>, entries: usize, skips: u64) -> Self {
        let reach = (*floor)
            .saturating_add(skips)
            .saturating_add(Widen::widen(entries));
        Self {
            floor,
            end: Location::new(reach).min(tip),
            entries,
            skips,
        }
    }

    /// Move the floor to the active update at `loc`, spending the inactive gap in skips. When the
    /// gap exceeds the remaining skips, the floor advances by them instead and the walk ends.
    pub(crate) fn reach(&mut self, loc: Location<F>) -> bool {
        let gap = *loc - *self.floor;
        if gap > self.skips {
            self.floor += self.skips;
            self.skips = 0;
            return false;
        }
        self.skips -= gap;
        self.floor = loc;
        true
    }

    /// Spend an entry on the update at the floor and move the floor past it.
    pub(crate) fn decide(&mut self) {
        self.entries -= 1;
        self.floor += 1;
    }

    /// The number of leading `candidates`, the ascending locations of active updates, that the
    /// walk's remaining entries and skips let it reach. A policy may stop the walk before it
    /// decides them all.
    pub(crate) fn reachable(&self, candidates: &[u64]) -> usize {
        let (mut floor, mut skips) = (*self.floor, self.skips);
        candidates
            .iter()
            .take(self.entries)
            .take_while(|&&loc| {
                let gap = loc - floor;
                if gap > skips {
                    return false;
                }
                skips -= gap;
                floor = loc + 1;
                true
            })
            .count()
    }

    /// No active update remains below `end`: the floor moves there if the remaining skips reach
    /// it, and by them otherwise.
    pub(crate) fn exhaust(&mut self) {
        let gap = (*self.end - *self.floor).min(self.skips);
        self.floor += gap;
        self.skips -= gap;
    }
}

/// Advances the floor in proportion to the operations a batch makes inactive.
///
/// Each update a batch supersedes, each delete it appends, and its previous commit become
/// inactive and cannot be pruned until the floor passes them. The walk moves up to one active
/// update to the tip for each of them.
///
/// When every batch since the initial commit uses this policy, each batch leaves the database's
/// size at most `3 * n + 1` operations past its floor, for `n` active keys.
///
/// The argument counts each key's current update and the latest commit as active. It maintains
/// that every nonempty suffix of the log starting at or above the floor holds at most `3 * a - 2`
/// operations when `a` of them are active. At the floor, `a` is `n + 1`.
///
/// Take a batch with `r` updates of existing keys, ordered link rewrites included, and `d`
/// deletes. Its updates, deletes, and commit raise a surviving old suffix's length minus three
/// times its active count by at most `r + 4 * d + 1`, and its creates only lower it. When the
/// walk makes all `r + 2 * d + 1` of its moves, each lowers that quantity by two, because every
/// moved update's old location lies below the new floor. A suffix starting in the batch's writes
/// holds at most `d` inactive operations, which the moved updates and the new commit outweigh.
///
/// When candidates run out first, the floor reaches the tip the writes left, so only moved
/// updates and the new commit lie above it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Proportional;

impl<F: Family, K, V> Policy<F, K, V> for Proportional {
    fn evicts(&self) -> bool {
        false
    }

    /// One entry per operation the batch made inactive and one for its previous commit, with
    /// unlimited skips, so the walk ends at the tip of the batch's writes unless the entries run
    /// out first.
    fn limits(&self, made_inactive: usize) -> Limits {
        Limits {
            entries: made_inactive + 1,
            skips: u64::MAX,
        }
    }

    /// Keeps the entry.
    fn decide(&mut self, entry: Entry<'_, F, K, V>) -> Decision<V> {
        entry.keep()
    }
}

/// Holds the floor at its inherited location, or moves it to the new commit location if the
/// batch's final state is empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hold;

impl<F: Family, K, V> Policy<F, K, V> for Hold {
    fn evicts(&self) -> bool {
        false
    }

    fn limits(&self, _: usize) -> Limits {
        Limits {
            entries: 0,
            skips: 0,
        }
    }

    /// Not called with zero `entries`.
    fn decide(&mut self, entry: Entry<'_, F, K, V>) -> Decision<V> {
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
    fn evicts(&self) -> bool {
        false
    }

    fn limits(&self, _: usize) -> Limits {
        Limits {
            entries: self.entries,
            skips: self.skips,
        }
    }

    /// Keeps the entry.
    fn decide(&mut self, entry: Entry<'_, F, K, V>) -> Decision<V> {
        entry.keep()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr;

    fn at(n: u64) -> Location<mmr::Family> {
        Location::new(n)
    }

    /// The window ends at the tip or where the limits run out, whichever comes first, and
    /// unbounded limits saturate at the tip.
    #[test]
    fn walk_window_ends_at_tip_or_limits() {
        assert_eq!(Walk::new(at(3), at(100), 2, 4).end, at(9));
        assert_eq!(Walk::new(at(3), at(5), 2, 4).end, at(5));
        assert_eq!(Walk::new(at(3), at(100), usize::MAX, u64::MAX).end, at(100));
        assert_eq!(Walk::new(at(3), at(100), 0, 0).end, at(3));
    }

    /// Reaching an update spends its gap in skips and deciding it moves the floor past it, while a
    /// gap beyond the remaining skips advances the floor by them and ends the walk.
    #[test]
    fn walk_reaches_and_decides() {
        let mut walk = Walk::new(at(0), at(100), 2, 3);
        assert!(walk.reach(at(2)));
        assert_eq!(walk.floor, at(2));
        walk.decide();
        assert_eq!((walk.floor, walk.entries), (at(3), 1));
        assert!(walk.reach(at(3)));
        walk.decide();
        assert_eq!((walk.floor, walk.entries), (at(4), 0));

        let mut walk = Walk::new(at(0), at(100), 2, 3);
        assert!(walk.reach(at(1)));
        walk.decide();
        assert!(!walk.reach(at(5)));
        assert_eq!(walk.floor, at(4));
    }

    /// Exhausting the window moves the floor to its end if the remaining skips reach it, and by
    /// them otherwise.
    #[test]
    fn walk_exhausts_to_window_end() {
        let mut walk = Walk::new(at(0), at(10), 5, 2);
        walk.exhaust();
        assert_eq!(walk.floor, at(2));

        let mut walk = Walk::new(at(0), at(3), 5, 10);
        walk.exhaust();
        assert_eq!(walk.floor, at(3));

        let mut walk = Walk::new(at(4), at(10), 1, u64::MAX);
        assert!(walk.reach(at(6)));
        walk.exhaust();
        assert_eq!(walk.floor, at(10));
    }

    /// The reachable prefix of ascending active locations ends where the entries or the skips
    /// run out. An update at the floor needs no skip, and an inactive location at the floor
    /// blocks every candidate when no skip is left.
    #[test]
    fn walk_reaches_leading_candidates_within_limits() {
        assert_eq!(Walk::new(at(0), at(100), 3, 2).reachable(&[1, 2, 5, 6]), 2);
        assert_eq!(Walk::new(at(0), at(100), 1, 10).reachable(&[3, 4]), 1);
        assert_eq!(Walk::new(at(0), at(100), 2, 0).reachable(&[0, 2]), 1);
        assert_eq!(Walk::new(at(0), at(100), 2, 0).reachable(&[1]), 0);
        assert_eq!(Walk::new(at(0), at(100), 0, 10).reachable(&[0]), 0);
        assert_eq!(Walk::new(at(0), at(100), 2, 0).reachable(&[]), 0);
    }
}
