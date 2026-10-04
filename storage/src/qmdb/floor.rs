//! Policies that advance a batch's inactivity floor.

use crate::merkle::Family;

/// How far a policy advances the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limits {
    /// Move up to one active update for each operation the batch makes inactive.
    Proportional,
}

/// Chooses how a batch advances its inactivity floor.
///
/// [`Proportional`] is the policy for batches that need no custom rule.
pub trait Policy<F: Family, K, V> {
    /// How far the floor advances.
    fn limits(&self) -> Limits;
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
}
