//! Policies that advance a batch's inactivity floor.

use crate::merkle::Family;

/// How far a policy advances the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limits {
    /// Move up to one active update for each superseded update and the previous commit.
    Proportional,
}

/// Chooses how a batch advances its inactivity floor.
///
/// [`Proportional`] is the policy for batches that need no custom rule.
pub trait Policy<F: Family, K, V> {
    /// How far the floor advances.
    fn limits(&self) -> Limits;
}

/// Advances the floor in proportion to the operations a batch supersedes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Proportional;

impl<F: Family, K, V> Policy<F, K, V> for Proportional {
    fn limits(&self) -> Limits {
        Limits::Proportional
    }
}
