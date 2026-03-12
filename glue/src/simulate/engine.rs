//! Engine definition trait and supporting types.

use super::tracker::FinalizationUpdate;
use commonware_cryptography::PublicKey;
use commonware_p2p::simulated::{self, Oracle};
use commonware_runtime::{deterministic, Handle, Quota};
use commonware_utils::channel::mpsc;
use std::future::Future;

/// A registered p2p channel pair (sender, receiver).
pub type ChannelPair<P> = (
    simulated::Sender<P, deterministic::Context>,
    simulated::Receiver<P>,
);

/// Arguments passed to [`EngineDefinition::init`].
pub struct InitContext<'a, P: PublicKey> {
    /// Labeled runtime context for this validator.
    pub context: deterministic::Context,
    /// Index of this validator in the participant list.
    pub index: usize,
    /// This validator's public key.
    pub public_key: &'a P,
    /// Network oracle for peer management.
    pub oracle: &'a Oracle<P, deterministic::Context>,
    /// Registered p2p channel pairs (same order as `channels()`).
    pub channels: Vec<ChannelPair<P>>,
    /// All participants in the simulation.
    pub participants: &'a [P],
    /// Channel for reporting finalization events to the harness.
    pub monitor: mpsc::Sender<FinalizationUpdate<P>>,
}

/// Defines how to construct and start one validator's service stack.
///
/// The harness calls these methods for each validator in the simulation.
/// The lifecycle is:
/// 1. `channels()` -- declare which p2p channels are needed.
/// 2. `init()` -- construct the engine (actors, archives, mailboxes).
/// 3. `start()` -- start all actors, return a joinable handle.
///
/// On restart after a crash, `init()` and `start()` are called again
/// with the same validator identity but a fresh runtime context (storage
/// state is preserved by the deterministic runtime).
pub trait EngineDefinition: Clone + Send + 'static {
    /// The public key type used by this engine.
    type PublicKey: PublicKey;

    /// The constructed engine, passed from `init` to `start`.
    type Engine: Send + 'static;

    /// Per-validator state inspectable by property checkers.
    type State: Send + Sync + 'static;

    /// The participants for this simulation.
    ///
    /// Called once by the harness to determine the validator set. The engine
    /// is responsible for generating keys and any associated state (signing
    /// schemes, databases, etc.) during construction.
    fn participants(&self) -> Vec<Self::PublicKey>;

    /// Which p2p channels to register for each validator.
    ///
    /// Returns `(channel_id, quota)` pairs. The harness registers each
    /// on the simulated oracle and passes sender/receiver pairs to
    /// `init` in the same order.
    fn channels(&self) -> Vec<(u64, Quota)>;

    /// Construct the engine for a single validator.
    fn init(
        &self,
        ctx: InitContext<'_, Self::PublicKey>,
    ) -> impl Future<Output = (Self::Engine, Self::State)> + Send;

    /// Start all actors in the engine. Returns a handle the harness
    /// can join on (or abort on crash).
    fn start(engine: Self::Engine) -> Handle<()>;
}
