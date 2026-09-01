//! Points at the voter's typed boundaries where a test can observe what it executed.

use crate::{
    multimmit::{
        actors::voter::persistence,
        machine::{
            BarrierAck, BatchId, DurableEffect, EffectId, Generation, InputTicket, ServicedInput,
        },
        types::ViewProof,
    },
    types::View,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use tracing::Span;

/// Causal boundary at which a resolver proof entered process-local serving custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionBoundary {
    /// Staged with the barrier that persists it.
    Staged(BatchId),
    /// Released by a durable acknowledgement.
    Acknowledged,
    /// Seeded from recovered durable state.
    Recovered,
    /// Released at its local signature exposure floor.
    Exposure,
}

/// Points at the voter's typed boundaries where a test can observe what it executed.
///
/// The persistence actor's points come with it through [`persistence::Hooks`].
pub(crate) trait Hooks<V: Variant, D: Digest>: persistence::Hooks {
    /// Runs when one core cycle starts.
    fn cycle_started(&self) {}

    /// Runs when the core resumes with a fresh service cycle after yielding to the runtime.
    fn resumed(&self) {}

    /// Runs when the core services `input`, before its step is applied.
    fn serviced(&self, _input: &ServicedInput<V, D>) {}

    /// Runs inside an input's span before its step is applied, with the root that owns its
    /// terminal errors and the current round's view.
    fn dispatching(&self, _root: &Span, _view: View) {}

    /// Runs before one unit of machine-owned work under `root` in round `view`.
    fn working(&self, _root: &Span, _view: View) {}

    /// Runs when a production timer is armed for work owned by `root`.
    fn production_timer_armed(&self, _root: &Span) {}

    /// Runs when the acknowledgement `ack` is admitted as `ticket`.
    fn acknowledged(&self, _ticket: InputTicket, _ack: BarrierAck) {}

    /// Runs when durable effect `id` is issued for execution in `generation`.
    fn issued(&self, _id: EffectId, _generation: Generation, _effect: &DurableEffect<V, D>) {}

    /// Runs when `proof` enters serving custody at `boundary`.
    fn retained(&self, _proof: &ViewProof<V, D>, _boundary: RetentionBoundary) {}

    /// Runs when publication `id` of `generation` is installed.
    fn installed(&self, _id: EffectId, _generation: Generation) {}

    /// Runs when publications `ids` are retired.
    fn retired(&self, _ids: &[EffectId]) {}
}

impl<V: Variant, D: Digest> Hooks<V, D> for persistence::NoHooks {}
