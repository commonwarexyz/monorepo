//! Engine definition trait and supporting types.

use super::{processed::ProcessedHeight, tracker::FinalizationUpdate};
use commonware_actor::Feedback;
use commonware_cryptography::{PublicKey, Signer};
use commonware_p2p::{
    Advertisement, Blocker, Manager, PeerSetSubscription, Provider, Reachability,
    ReachabilityManager, ReachableTrackedPeers, TrackedPeers,
    authenticated::lookup::{ReachabilityOracle, Receiver, Sender},
};
use commonware_runtime::{Handle, Quota, deterministic, deterministic::network::Endpoint};
use commonware_utils::{PlatformSend, TryCollect, channel::mpsc, ordered::Map};
use std::{collections::BTreeMap, fmt, future::Future};

/// A registered p2p channel pair (sender, receiver).
pub type ChannelPair<P> = (Sender<P, deterministic::Context>, Receiver<P>);

/// Membership manager for endpoint-addressed authenticated lookup networks.
#[derive(Clone)]
pub struct LookupManager<P: PublicKey> {
    oracle: ReachabilityOracle<P, Endpoint>,
    endpoints: BTreeMap<P, Endpoint>,
}

impl<P: PublicKey> fmt::Debug for LookupManager<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LookupManager").finish_non_exhaustive()
    }
}

impl<P: PublicKey> LookupManager<P> {
    pub(crate) fn new(oracle: ReachabilityOracle<P, Endpoint>, participants: &[P]) -> Self {
        let endpoints = participants
            .iter()
            .enumerate()
            .map(|(index, public_key)| (public_key.clone(), Endpoint::new(index as u64 + 1)))
            .collect();
        Self { oracle, endpoints }
    }

    fn reachable(
        &self,
        peers: commonware_utils::ordered::Set<P>,
    ) -> Map<P, Reachability<Endpoint>> {
        peers
            .into_iter()
            .map(|public_key| {
                let endpoint = *self
                    .endpoints
                    .get(&public_key)
                    .expect("tracked peer has a deterministic endpoint");
                let advertisement = Advertisement::new(vec![endpoint])
                    .expect("one endpoint is a valid advertisement");
                (public_key, Reachability::Dialable(advertisement))
            })
            .try_collect()
            .expect("tracked peers must be unique")
    }
}

impl<P: PublicKey> Provider for LookupManager<P> {
    type PublicKey = P;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<P>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<P> {
        self.oracle.subscribe().await
    }
}

impl<P: PublicKey> Manager for LookupManager<P> {
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<P>> + PlatformSend,
    {
        let peers = peers.into();
        let reachable = ReachableTrackedPeers::new(
            self.reachable(peers.primary),
            self.reachable(peers.secondary),
        );
        self.oracle.track(id, reachable)
    }
}

impl<P: PublicKey> Blocker for LookupManager<P> {
    type PublicKey = P;

    #[allow(
        clippy::disallowed_methods,
        reason = "membership adapter forwards the real lookup Blocker implementation"
    )]
    fn block(&mut self, public_key: P) -> Feedback {
        self.oracle.block(public_key)
    }
}

/// Arguments passed to [`EngineDefinition::init`].
pub struct InitContext<'a, P: PublicKey> {
    /// Labeled runtime context for this validator.
    pub context: deterministic::Context,
    /// Index of this validator in the participant list.
    pub index: usize,
    /// Whether this validator was configured as a delayed participant.
    pub delayed: bool,
    /// This validator's public key.
    pub public_key: &'a P,
    /// Authenticated lookup membership and blocking handle.
    pub oracle: &'a LookupManager<P>,
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

    /// Signer used to authenticate this validator's network connections.
    type Signer: Signer<PublicKey = Self::PublicKey>;

    /// The constructed engine, passed from `init` to `start`.
    type Engine: Send + 'static;

    /// Per-validator state inspectable by property checkers.
    type State: ProcessedHeight + Send + Sync + 'static;

    /// The participants for this simulation.
    ///
    /// Called once by the harness to determine the validator set. The engine
    /// is responsible for generating keys and any associated state (signing
    /// schemes, databases, etc.) during construction.
    fn participants(&self) -> Vec<Self::PublicKey>;

    /// Return the network signer for the participant at `index`.
    fn signer(&self, index: usize) -> Self::Signer;

    /// Which p2p channels to register for each validator.
    ///
    /// Returns `(channel_id, quota)` pairs. The harness registers each
    /// on the validator's lookup network and passes sender/receiver pairs to
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
