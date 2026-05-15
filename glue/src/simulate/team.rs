//! Validator set management for simulation testing.
//!
//! Manages starting, crashing, and restarting validators.

use super::{
    engine::{ChannelPair, EngineDefinition, InitContext},
    tracker::FinalizationUpdate,
};
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{deterministic, Handle, Supervisor as _};
use commonware_utils::channel::mpsc;
use std::collections::{BTreeMap, HashSet};
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
    handles: BTreeMap<D::PublicKey, Handle<()>>,

    /// Inspectable state per validator.
    states: BTreeMap<D::PublicKey, D::State>,

    /// Restart count per validator (monotonically increasing).
    restart_counts: BTreeMap<D::PublicKey, u32>,
}

impl<D: EngineDefinition> Team<D> {
    /// Create a new team with the given participants.
    pub const fn new(definition: D, participants: Vec<D::PublicKey>) -> Self {
        Self {
            definition,
            participants,
            handles: BTreeMap::new(),
            states: BTreeMap::new(),
            restart_counts: BTreeMap::new(),
        }
    }

    /// Start a single validator. Registers channels, calls init, start.
    ///
    /// If the validator is already running, aborts its existing handle first.
    pub async fn start_one(
        &mut self,
        ctx: &deterministic::Context,
        oracle: &Oracle<D::PublicKey, deterministic::Context>,
        pk: D::PublicKey,
        monitor: mpsc::Sender<FinalizationUpdate<D::PublicKey>>,
    ) {
        // Abort existing handle if present
        if let Some(handle) = self.handles.remove(&pk) {
            handle.abort();
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

        // Register channels
        let control = oracle.control(pk.clone());
        let channel_specs = self.definition.channels();
        let mut channels: Vec<ChannelPair<D::PublicKey>> = Vec::with_capacity(channel_specs.len());
        for (channel_id, quota) in &channel_specs {
            let pair = control
                .register(*channel_id, *quota)
                .await
                .expect("channel registration failed");
            channels.push(pair);
        }

        // Init engine
        let (engine, state) = self
            .definition
            .init(InitContext {
                context: validator_ctx,
                index,
                public_key: &pk,
                oracle,
                channels,
                participants: &self.participants,
                monitor,
            })
            .await;

        // Start engine
        let handle = D::start(engine);
        self.handles.insert(pk.clone(), handle);
        self.states.insert(pk, state);
    }

    /// Start all non-delayed validators and link all peers.
    pub async fn start(
        &mut self,
        ctx: &deterministic::Context,
        oracle: &Oracle<D::PublicKey, deterministic::Context>,
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
                oracle
                    .add_link(v1.clone(), v2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }

        // Start non-delayed participants
        for pk in participants {
            if delayed.contains(&pk) {
                info!(target: "simulator", ?pk, "delayed participant");
                continue;
            }
            self.start_one(ctx, oracle, pk, monitor.clone()).await;
        }
    }

    /// Crash a validator by aborting its task handle.
    ///
    /// Returns `true` if the validator was running and is now crashed.
    pub fn crash(&mut self, pk: &D::PublicKey) -> bool {
        self.handles.remove(pk).is_some_and(|handle| {
            handle.abort();
            info!(target: "simulator", ?pk, "crashed validator");
            true
        })
    }

    /// Restart a previously crashed validator.
    pub async fn restart(
        &mut self,
        ctx: &deterministic::Context,
        oracle: &Oracle<D::PublicKey, deterministic::Context>,
        pk: D::PublicKey,
        monitor: mpsc::Sender<FinalizationUpdate<D::PublicKey>>,
    ) {
        info!(target: "simulator", ?pk, "restarting validator");
        self.start_one(ctx, oracle, pk, monitor).await;
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

    /// All participants (including crashed ones).
    pub fn participants(&self) -> &[D::PublicKey] {
        &self.participants
    }
}
