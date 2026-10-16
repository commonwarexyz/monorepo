//! Points at the voter's typed boundaries where a test can observe what it executed.

use crate::multimmit::{
    actors::voter::persistence,
    machine::{DurableEffect, EffectId, Generation},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};

/// Points at the voter's typed boundaries where a test can observe what it executed.
///
/// The persistence actor's points come with it through [`persistence::Hooks`].
pub(crate) trait Hooks<V: Variant, D: Digest>: persistence::Hooks {
    /// Runs when durable effect `id` is issued for execution in `generation`.
    fn issued(&self, _id: EffectId, _generation: Generation, _effect: &DurableEffect<V, D>) {}

    /// Runs when publication `id` of `generation` is installed.
    fn installed(&self, _id: EffectId, _generation: Generation) {}

    /// Runs when publications `ids` are retired.
    fn retired(&self, _ids: &[EffectId]) {}
}

impl<V: Variant, D: Digest> Hooks<V, D> for persistence::NoHooks {}
