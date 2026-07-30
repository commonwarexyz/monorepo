//! Validator set management for simulation testing.
//!
//! Manages starting, crashing, and restarting validators.

use super::{
    engine::{ChannelPair, EngineDefinition, InitContext, LookupManager},
    tracker::FinalizationUpdate,
};
use commonware_p2p::{
    Advertisement, Reachability, ReachabilityManager as _, ReachableTrackedPeers,
    authenticated::lookup::{
        Config as LookupConfig, DialOnlyNetwork, GenericConfig, UnrestrictedAdmission,
    },
};
use commonware_runtime::{
    Handle, Supervisor as _, deterministic,
    deterministic::network::{Endpoint, Link, Oracle as NetworkOracle},
};
use commonware_utils::{NZU32, TryCollect, channel::mpsc, ordered::Map};
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};
use tracing::info;

/// Manages running validators and their engines.
///
/// Handles starting, crashing, and restarting individual nodes.
pub struct Team<D: EngineDefinition> {
    /// Engine definition (cloned per validator init).
    definition: D,

    /// All participant public keys in order.
    participants: Vec<D::PublicKey>,

    /// Running task handles, keyed by public key.
    handles: BTreeMap<D::PublicKey, NodeHandles>,

    /// Inspectable state per validator.
    states: BTreeMap<D::PublicKey, D::State>,

    /// Restart count per validator (monotonically increasing).
    restart_counts: BTreeMap<D::PublicKey, u32>,

    transport: NetworkOracle<deterministic::Context>,

    max_message_size: u32,
}

struct NodeHandles {
    engine: Handle<()>,
    network: Handle<()>,
}

impl NodeHandles {
    async fn abort(mut self) {
        self.engine.abort();
        self.network.abort();
        let _ = futures::join!(&mut self.engine, &mut self.network);
    }
}

impl<D: EngineDefinition> Team<D> {
    /// Create a new team with the given participants.
    pub const fn new(
        definition: D,
        participants: Vec<D::PublicKey>,
        transport: NetworkOracle<deterministic::Context>,
        max_message_size: u32,
    ) -> Self {
        Self {
            definition,
            participants,
            handles: BTreeMap::new(),
            states: BTreeMap::new(),
            restart_counts: BTreeMap::new(),
            transport,
            max_message_size,
        }
    }

    fn endpoint(&self, public_key: &D::PublicKey) -> Endpoint {
        let index = self
            .participants
            .iter()
            .position(|candidate| candidate == public_key)
            .expect("participant not found");
        Endpoint::new(index as u64 + 1)
    }

    fn tracked_peers(&self) -> ReachableTrackedPeers<D::PublicKey, Endpoint> {
        let primary = self
            .participants
            .iter()
            .enumerate()
            .map(|(index, public_key)| {
                let advertisement = Advertisement::new(vec![Endpoint::new(index as u64 + 1)])
                    .expect("one endpoint is a valid advertisement");
                (public_key.clone(), Reachability::Dialable(advertisement))
            })
            .try_collect::<Map<_, _>>()
            .expect("participants must be unique");
        ReachableTrackedPeers::primary(primary)
    }

    /// Start a single validator. Registers channels, calls init, start.
    ///
    /// If the validator is already running, aborts its existing handle first.
    pub async fn start_one(
        &mut self,
        ctx: &deterministic::Context,
        pk: D::PublicKey,
        monitor: mpsc::Sender<FinalizationUpdate<D::PublicKey>>,
        delayed: bool,
    ) {
        // Abort existing handle if present
        if let Some(handle) = self.handles.remove(&pk) {
            handle.abort().await;
        }

        let restart_count = self.restart_counts.entry(pk.clone()).or_insert(0);
        let index = self
            .participants
            .iter()
            .position(|p| p == &pk)
            .expect("participant not found");
        let validator_ctx = ctx
            .child("validator")
            .with_attribute("index", index)
            .with_attribute("restart", *restart_count);
        *restart_count += 1;

        let endpoint = self.endpoint(&pk);
        self.transport
            .set_online(endpoint, true)
            .expect("participant is registered");
        let mut config = GenericConfig::from(LookupConfig::local(
            self.definition.signer(index),
            b"_COMMONWARE_GLUE_SIMULATE_LOOKUP",
            SocketAddr::from(([0, 0, 0, 0], 0)),
            self.max_message_size,
        ));
        config.tracked_peer_sets = commonware_utils::NZUsize!(1);
        let node = self
            .transport
            .register(validator_ctx.child("transport"), endpoint, None);
        let (dialer, acceptor) = node.split();
        let (network, mut oracle) =
            DialOnlyNetwork::new(validator_ctx.child("lookup"), dialer, config);
        let mut network =
            network.accepting(acceptor, endpoint, UnrestrictedAdmission, NZU32!(1_024));
        oracle.track(0, self.tracked_peers());
        let oracle = LookupManager::new(oracle, &self.participants);

        // Register channels
        let channel_specs = self.definition.channels();
        let mut channels: Vec<ChannelPair<D::PublicKey>> = Vec::with_capacity(channel_specs.len());
        for (channel_id, quota) in &channel_specs {
            let pair = network.register(*channel_id, *quota, 1024);
            channels.push(pair);
        }
        let network = network.start();

        // Init engine
        let (engine, state) = self
            .definition
            .init(InitContext {
                context: validator_ctx,
                index,
                delayed,
                public_key: &pk,
                oracle: &oracle,
                channels,
                participants: &self.participants,
                monitor,
            })
            .await;

        // Start engine
        let handle = D::start(engine);
        self.handles.insert(
            pk.clone(),
            NodeHandles {
                engine: handle,
                network,
            },
        );
        self.states.insert(pk, state);
    }

    /// Start all non-delayed validators and link all peers.
    pub async fn start(
        &mut self,
        ctx: &deterministic::Context,
        link: Link,
        monitor: mpsc::Sender<FinalizationUpdate<D::PublicKey>>,
        delayed: &HashSet<D::PublicKey>,
    ) {
        // Link all participants
        let participants = self.participants.clone();
        for v1 in &participants {
            for v2 in &participants {
                if v1 == v2 {
                    continue;
                }
                self.transport
                    .set_link(self.endpoint(v1), self.endpoint(v2), link)
                    .unwrap();
            }
        }

        // Start non-delayed participants
        for pk in participants {
            if delayed.contains(&pk) {
                info!(target: "simulator", ?pk, "delayed participant");
                continue;
            }
            self.start_one(ctx, pk, monitor.clone(), false).await;
        }
    }

    /// Crash a validator by aborting its task handle.
    ///
    /// Returns `true` if the validator was running and is now crashed.
    pub async fn crash(&mut self, pk: &D::PublicKey) -> bool {
        let Some(handle) = self.handles.remove(pk) else {
            return false;
        };
        handle.abort().await;
        self.transport
            .set_online(self.endpoint(pk), false)
            .expect("participant is registered");
        info!(target: "simulator", ?pk, "crashed validator");
        true
    }

    /// Restart a previously crashed validator.
    pub async fn restart(
        &mut self,
        ctx: &deterministic::Context,
        pk: D::PublicKey,
        monitor: mpsc::Sender<FinalizationUpdate<D::PublicKey>>,
        delayed: bool,
    ) {
        info!(target: "simulator", ?pk, "restarting validator");
        self.start_one(ctx, pk, monitor, delayed).await;
    }

    /// Collect references to all active (non-crashed) validator states.
    pub fn active_states(&self) -> Vec<&D::State> {
        self.handles
            .keys()
            .filter_map(|pk| self.states.get(pk))
            .collect()
    }

    /// Get the public keys of all currently active validators.
    pub fn active_keys(&self) -> Vec<D::PublicKey> {
        self.handles.keys().cloned().collect()
    }

    /// Get a validator's inspectable state if it is currently active.
    pub fn active_state(&self, pk: &D::PublicKey) -> Option<&D::State> {
        if !self.handles.contains_key(pk) {
            return None;
        }
        self.states.get(pk)
    }

    /// All participants (including crashed ones).
    pub fn participants(&self) -> &[D::PublicKey] {
        &self.participants
    }
}
