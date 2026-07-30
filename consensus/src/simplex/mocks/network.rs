//! Authenticated lookup network support for consensus tests.

use commonware_actor::Feedback;
use commonware_cryptography::{Signer, ed25519};
use commonware_p2p::{
    Advertisement, Blocker, CheckedSender as _, LimitedSender as _, Manager, Provider,
    Message, Reachability, ReachabilityManager, ReachableTrackedPeers, Receiver as _, Recipients,
    TrackedPeers,
    authenticated::lookup::{ReachabilityOracle, Receiver, Sender},
};
use commonware_runtime::{
    Clock as _, Quota, Scheduler as _, Supervisor as _, deterministic,
    deterministic::network::{self as transport, Endpoint},
};
use commonware_utils::{
    channel::{
        fallible::FallibleExt as _,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    ordered::Map,
    sync::Mutex,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

pub type PublicKey = ed25519::PublicKey;
pub type PrivateKey = ed25519::PrivateKey;
pub type Channel = (
    Sender<PublicKey, deterministic::Context>,
    RestartableReceiver,
);

struct ChannelSlot {
    sender: Sender<PublicKey, deterministic::Context>,
    route: Arc<Mutex<Option<UnboundedSender<Message<PublicKey>>>>>,
}

/// Receiver that can be replaced when a validator restarts.
pub struct RestartableReceiver {
    receiver: UnboundedReceiver<Message<PublicKey>>,
}

impl std::fmt::Debug for RestartableReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestartableReceiver").finish_non_exhaustive()
    }
}

impl commonware_p2p::Receiver for RestartableReceiver {
    type Error = io::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_TEST_LOOKUP";
const PROBE_CHANNEL: u64 = u64::MAX;

/// A directional, reliable link used by consensus tests.
#[derive(Clone, Debug)]
pub struct Link {
    pub latency: Duration,
    pub jitter: Duration,
    /// Retained while migrating old test inputs. Reliable streams never drop accepted bytes.
    pub success_rate: f64,
}

impl Link {
    fn transport(self) -> transport::Link {
        assert!((0.0..=1.0).contains(&self.success_rate));
        if self.success_rate == 0.0 {
            return transport::Link::new(self.latency)
                .with_jitter(self.jitter)
                .with_behavior(transport::Behavior::Fail);
        }

        // A reliable stream cannot lose accepted bytes. Represent partial delivery rates as
        // proportionally slower links while retaining deterministic ordering and delivery.
        let slowdown = self.success_rate.recip();
        transport::Link::new(self.latency.mul_f64(slowdown))
            .with_jitter(self.jitter.mul_f64(slowdown))
    }
}

struct State {
    endpoints: HashMap<PublicKey, Endpoint>,
    channels: HashMap<(PublicKey, u64), ChannelSlot>,
    links: HashSet<(PublicKey, PublicKey)>,
    blocked: Vec<(PublicKey, PublicKey)>,
}

/// Node-local lookup access used by consensus actors and tests.
pub struct Control {
    local: PublicKey,
    oracle: ReachabilityOracle<PublicKey, Endpoint>,
    probe: Sender<PublicKey, deterministic::Context>,
    state: Arc<Mutex<State>>,
}

/// Membership control shared by every lookup node in a test cluster.
#[derive(Clone)]
pub struct ManagerControl {
    oracles: Vec<ReachabilityOracle<PublicKey, Endpoint>>,
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for ManagerControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerControl").finish_non_exhaustive()
    }
}

impl Control {
    #[allow(clippy::unused_async, reason = "matches network registration setup")]
    pub async fn register(&self, channel: u64, _quota: Quota) -> Result<Channel, ()> {
        let state = self.state.lock();
        let slot = state
            .channels
            .get(&(self.local.clone(), channel))
            .ok_or(())?;
        let (sender, receiver) = mpsc::unbounded_channel();
        *slot.route.lock() = Some(sender);
        Ok((
            slot.sender.clone(),
            RestartableReceiver { receiver },
        ))
    }

    fn connected_to(&self, peers: &[PublicKey]) -> bool {
        let mut probe = self.probe.clone();
        let Ok(connected) = probe.check(Recipients::All) else {
            return false;
        };
        let connected = connected.recipients();

        peers
            .iter()
            .all(|peer| peer == &self.local || connected.contains(peer))
    }
}

impl Clone for Control {
    fn clone(&self) -> Self {
        Self {
            local: self.local.clone(),
            oracle: self.oracle.clone(),
            probe: self.probe.clone(),
            state: self.state.clone(),
        }
    }
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl Provider for Control {
    type PublicKey = PublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<PublicKey> {
        self.oracle.subscribe().await
    }
}

impl Manager for Control {
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<PublicKey>> + commonware_utils::PlatformSend,
    {
        let peers = peers.into();
        let state = self.state.lock();
        let reachable = |peers: commonware_utils::ordered::Set<PublicKey>| {
            Map::from_iter_dedup(peers.into_iter().map(|peer| {
                let endpoint = state.endpoints[&peer];
                let advertisement = Advertisement::new(vec![endpoint]).unwrap();
                (peer, Reachability::Dialable(advertisement))
            }))
        };
        let tracked =
            ReachableTrackedPeers::new(reachable(peers.primary), reachable(peers.secondary));
        drop(state);
        self.oracle.track(id, tracked)
    }
}

impl Blocker for Control {
    type PublicKey = PublicKey;

    #[allow(
        clippy::disallowed_methods,
        reason = "test harness records the directed block before delegating"
    )]
    fn block(&mut self, peer: PublicKey) -> Feedback {
        self.state
            .lock()
            .blocked
            .push((self.local.clone(), peer.clone()));
        self.oracle.block(peer)
    }
}

impl Provider for ManagerControl {
    type PublicKey = PublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<PublicKey>> {
        self.oracles.first_mut()?.peer_set(id).await
    }

    async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<PublicKey> {
        self.oracles.first_mut().unwrap().subscribe().await
    }
}

impl Manager for ManagerControl {
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<PublicKey>> + commonware_utils::PlatformSend,
    {
        let peers = peers.into();
        let state = self.state.lock();
        let reachable = |peers: commonware_utils::ordered::Set<PublicKey>| {
            Map::from_iter_dedup(peers.into_iter().map(|peer| {
                let endpoint = state.endpoints[&peer];
                let advertisement = Advertisement::new(vec![endpoint]).unwrap();
                (peer, Reachability::Dialable(advertisement))
            }))
        };
        let tracked =
            ReachableTrackedPeers::new(reachable(peers.primary), reachable(peers.secondary));
        drop(state);

        let mut feedback = Feedback::Ok;
        for oracle in &mut self.oracles {
            let current = oracle.track(id, tracked.clone());
            if current == Feedback::Closed {
                feedback = Feedback::Closed;
            } else if current == Feedback::Backoff && feedback == Feedback::Ok {
                feedback = Feedback::Backoff;
            }
        }
        feedback
    }
}

/// A set of real authenticated lookup nodes over the deterministic runtime transport.
pub struct Network {
    transport: transport::Oracle<deterministic::Context>,
    controls: HashMap<PublicKey, Control>,
    _probe_receivers: Vec<Receiver<PublicKey>>,
    state: Arc<Mutex<State>>,
}

impl Network {
    pub fn new(
        context: deterministic::Context,
        private_keys: impl IntoIterator<Item = PrivateKey>,
        primary: impl IntoIterator<Item = PublicKey>,
        secondary: impl IntoIterator<Item = PublicKey>,
        channels: &[u64],
    ) -> Self {
        let private_keys: Vec<_> = private_keys.into_iter().collect();
        let primary: Vec<_> = primary.into_iter().collect();
        let secondary: Vec<_> = secondary.into_iter().collect();
        let transport = transport::Oracle::new(transport::Config::default());
        let endpoints = private_keys
            .iter()
            .enumerate()
            .map(|(index, key)| (key.public_key(), Endpoint::new(index as u64 + 1)))
            .collect::<HashMap<_, _>>();
        let links = endpoints
            .keys()
            .flat_map(|from| {
                endpoints
                    .keys()
                    .filter(move |to| *to != from)
                    .map(move |to| (from.clone(), to.clone()))
            })
            .collect();
        let state = Arc::new(Mutex::new(State {
            endpoints,
            channels: HashMap::new(),
            links,
            blocked: Vec::new(),
        }));
        let reachable = |peers: &[PublicKey]| {
            let state = state.lock();
            Map::from_iter_dedup(peers.iter().cloned().map(|peer| {
                let endpoint = state.endpoints[&peer];
                let advertisement = Advertisement::new(vec![endpoint]).unwrap();
                (peer, Reachability::Dialable(advertisement))
            }))
        };
        let tracked = ReachableTrackedPeers::new(reachable(&primary), reachable(&secondary));
        let mut nodes = Vec::new();
        let mut controls = HashMap::new();
        let mut probe_receivers = Vec::new();

        for private_key in private_keys {
            let public_key = private_key.public_key();
            let endpoint = state.lock().endpoints[&public_key];
            let (mut network, mut oracle) = commonware_p2p::utils::mocks::lookup(
                context
                    .child("lookup_node")
                    .with_attribute("public_key", &public_key),
                &transport,
                private_key,
                endpoint,
                NAMESPACE,
                MAX_MESSAGE_SIZE,
            );
            oracle.track(0, tracked.clone());
            let (probe, probe_receiver) =
                network.register(PROBE_CHANNEL, Quota::per_second(NonZeroU32::MAX), 1);
            probe_receivers.push(probe_receiver);
            for &channel in channels {
                assert_ne!(channel, PROBE_CHANNEL, "probe channel is reserved");
                let (sender, mut receiver) =
                    network.register(channel, Quota::per_second(NonZeroU32::MAX), 1024);
                let route = Arc::new(Mutex::new(None::<
                    UnboundedSender<Message<PublicKey>>,
                >));
                let router = route.clone();
                context
                    .child("channel_router")
                    .spawn(move |_| async move {
                        while let Ok(message) = receiver.recv().await {
                            if let Some(sender) = router.lock().as_ref() {
                                sender.send_lossy(message);
                            }
                        }
                        router.lock().take();
                    });
                state.lock().channels.insert(
                    (public_key.clone(), channel),
                    ChannelSlot { sender, route },
                );
            }
            nodes.push((public_key, network, oracle, probe));
        }

        let endpoints = state.lock().endpoints.values().copied().collect::<Vec<_>>();
        for &from in &endpoints {
            for &to in &endpoints {
                if from == to {
                    continue;
                }
                transport
                    .set_link(from, to, transport::Link::new(Duration::ZERO))
                    .expect("test nodes are registered");
            }
        }

        for (public_key, network, oracle, probe) in nodes {
            network.start();
            controls.insert(
                public_key.clone(),
                Control {
                    local: public_key,
                    oracle,
                    probe,
                    state: state.clone(),
                },
            );
        }

        Self {
            transport,
            controls,
            _probe_receivers: probe_receivers,
            state,
        }
    }

    /// Waits until every listed peer has an authenticated connection to every other peer.
    pub async fn wait_for_peers(&self, context: &deterministic::Context, peers: &[PublicKey]) {
        let deadline = context.current() + Duration::from_secs(10);
        loop {
            let connected = peers.iter().all(|peer| {
                self.controls
                    .get(peer)
                    .is_some_and(|control| control.connected_to(peers))
            });
            if connected {
                return;
            }

            assert!(context.current() < deadline, "lookup connection timed out");
            context.sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits until `from` has an authenticated connection to `to`.
    pub async fn wait_for_connection(
        &self,
        context: &deterministic::Context,
        from: &PublicKey,
        to: &PublicKey,
    ) {
        let deadline = context.current() + Duration::from_secs(10);
        loop {
            let connected = self
                .controls
                .get(from)
                .is_some_and(|control| control.connected_to(std::slice::from_ref(to)));
            if connected {
                return;
            }

            assert!(
                context.current() < deadline,
                "lookup connection from {from} to {to} timed out"
            );
            context.sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn control(&self, peer: PublicKey) -> Control {
        self.controls[&peer].clone()
    }

    pub fn manager(&self) -> ManagerControl {
        ManagerControl {
            oracles: self
                .controls
                .values()
                .map(|control| control.oracle.clone())
                .collect(),
            state: self.state.clone(),
        }
    }

    #[allow(clippy::unused_async, reason = "keeps topology setup uniform")]
    pub async fn add_link(&self, from: PublicKey, to: PublicKey, link: Link) -> Result<(), ()> {
        let mut state = self.state.lock();
        let from_endpoint = state.endpoints[&from];
        let to_endpoint = state.endpoints[&to];
        let link = link.transport();
        self.transport
            .set_link(from_endpoint, to_endpoint, link)
            .map_err(|_| ())?;
        self.transport
            .set_link(to_endpoint, from_endpoint, link)
            .map_err(|_| ())?;
        state.links.insert((from.clone(), to.clone()));
        state.links.insert((to, from));
        drop(state);

        Ok(())
    }

    #[allow(clippy::unused_async, reason = "keeps topology setup uniform")]
    pub async fn remove_link(&self, from: PublicKey, to: PublicKey) -> Result<(), ()> {
        let mut state = self.state.lock();
        let from_endpoint = state.endpoints[&from];
        let to_endpoint = state.endpoints[&to];
        self.transport.remove_link(from_endpoint, to_endpoint);
        self.transport.remove_link(to_endpoint, from_endpoint);
        state.links.remove(&(from.clone(), to.clone()));
        state.links.remove(&(to, from));
        Ok(())
    }

    pub fn linked(&self, from: &PublicKey, to: &PublicKey) -> bool {
        self.state
            .lock()
            .links
            .contains(&(from.clone(), to.clone()))
    }

    #[allow(clippy::unused_async, reason = "keeps network inspection uniform")]
    pub async fn blocked(&self) -> Result<Vec<(PublicKey, PublicKey)>, ()> {
        Ok(self.state.lock().blocked.clone())
    }
}
