//! Simulation harness for the example chain.
//!
//! Spawns N nodes in a single process using the tokio runtime and the simulated P2P transport.
//! The harness waits for a fixed number of finalized blocks and asserts all nodes converge on the
//! same head, state commitment, and balances.

use crate::{
    application::{
        start_node, threshold_schemes, NodeEnvironment, ThresholdScheme, TransportControl,
    },
    BootstrapConfig, ConsensusDigest, FinalizationEvent,
};
use alloy_evm::revm::primitives::{B256, U256};
use anyhow::Context as _;
use commonware_cryptography::ed25519;
use commonware_p2p::{simulated, Manager as _};
use commonware_runtime::{tokio, Metrics as _, Runner as _};
use commonware_utils::{channel::mpsc, ordered::Set, TryCollect as _};
use std::time::Duration;

mod demo;

/// Maximum size (bytes) of a single simulated network message.
pub(super) const MAX_MSG_SIZE: usize = 1024 * 1024;
/// Fixed latency (milliseconds) for simulated P2P links.
pub(super) const P2P_LINK_LATENCY_MS: u64 = 5;

#[derive(Clone, Copy, Debug)]
/// Configuration for a simulation run.
pub struct SimConfig {
    /// Number of nodes participating in the simulation.
    pub nodes: usize,
    /// Number of blocks to finalize before stopping.
    pub blocks: u64,
    /// Seed used for deterministic randomness.
    pub seed: u64,
}

#[derive(Clone, Copy, Debug)]
/// Summary of a completed simulation run.
pub struct SimOutcome {
    /// Finalized head digest (the value ordered by threshold-simplex).
    pub head: ConsensusDigest,
    /// State commitment at the head digest.
    pub state_root: crate::StateRoot,
    /// Latest tracked threshold-simplex seed hash (used as `prevrandao`).
    pub seed: B256,
    /// Final balance of the sender account after the demo transfer.
    pub from_balance: U256,
    /// Final balance of the receiver account after the demo transfer.
    pub to_balance: U256,
}

type NodeHandle = crate::application::NodeHandle;
type SimTransport = simulated::Oracle<ed25519::PublicKey, tokio::Context>;

fn transport_control(
    transport: &SimTransport,
    me: ed25519::PublicKey,
) -> simulated::Control<ed25519::PublicKey, tokio::Context> {
    simulated::Oracle::control(transport, me)
}

fn transport_manager(
    transport: &SimTransport,
) -> simulated::Manager<ed25519::PublicKey, tokio::Context> {
    simulated::Oracle::manager(transport)
}

struct SimEnvironment<'a> {
    context: tokio::Context,
    transport: &'a mut SimTransport,
}

impl<'a> SimEnvironment<'a> {
    const fn new(context: tokio::Context, transport: &'a mut SimTransport) -> Self {
        Self { context, transport }
    }
}

impl TransportControl for SimTransport {
    type Control = simulated::Control<ed25519::PublicKey, tokio::Context>;
    type Manager = simulated::Manager<ed25519::PublicKey, tokio::Context>;

    fn control(&self, me: ed25519::PublicKey) -> Self::Control {
        transport_control(self, me)
    }

    fn manager(&self) -> Self::Manager {
        transport_manager(self)
    }
}

impl NodeEnvironment for SimEnvironment<'_> {
    type Transport = SimTransport;

    fn context(&self) -> tokio::Context {
        self.context.clone()
    }

    fn transport(&mut self) -> &mut SimTransport {
        self.transport
    }
}

#[cfg(unix)]
fn raise_open_file_limit() {
    use libc::{getrlimit, rlimit, setrlimit, RLIMIT_NOFILE};

    // Best effort: avoid hitting low per-process fd limits during simulations.
    // SAFETY: best-effort process limit adjustment with well-defined libc calls.
    unsafe {
        let mut limits = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if getrlimit(RLIMIT_NOFILE, &mut limits) != 0 {
            return;
        }
        if limits.rlim_cur < limits.rlim_max {
            let updated = rlimit {
                rlim_cur: limits.rlim_max,
                rlim_max: limits.rlim_max,
            };
            let _ = setrlimit(RLIMIT_NOFILE, &updated);
        }
    }
}

#[cfg(not(unix))]
fn raise_open_file_limit() {}

/// Run the multi-node simulation and return the final outcome.
pub fn simulate(cfg: SimConfig) -> anyhow::Result<SimOutcome> {
    raise_open_file_limit();
    // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
    let executor = tokio::Runner::default();
    executor.start(|context| async move { run_sim(context, cfg).await })
}

async fn run_sim(context: tokio::Context, cfg: SimConfig) -> anyhow::Result<SimOutcome> {
    let (participants_vec, schemes) = threshold_schemes(cfg.seed, cfg.nodes)?;
    let participants_set = participants_set(&participants_vec)?;

    let mut transport = start_network(&context, participants_set).await;
    connect_all_peers(&mut transport, &participants_vec).await?;

    let demo = demo::DemoTransfer::new();
    let bootstrap = BootstrapConfig::new(demo.alloc.clone(), vec![demo.tx.clone()]);

    let (nodes, mut finalized_rx) = start_all_nodes(
        &context,
        &mut transport,
        &participants_vec,
        &schemes,
        &bootstrap,
    )
    .await?;

    let head = wait_for_finalized_head(&mut finalized_rx, cfg.nodes, cfg.blocks).await?;
    let (state_root, seed) = assert_all_nodes_converged(&nodes, head, &demo).await?;

    Ok(SimOutcome {
        head,
        state_root,
        seed,
        from_balance: demo.expected_from,
        to_balance: demo.expected_to,
    })
}

/// Spawn all nodes (application + consensus) for a simulation run.
async fn start_all_nodes(
    context: &tokio::Context,
    transport: &mut SimTransport,
    participants: &[ed25519::PublicKey],
    schemes: &[ThresholdScheme],
    bootstrap: &BootstrapConfig,
) -> anyhow::Result<(Vec<NodeHandle>, mpsc::UnboundedReceiver<FinalizationEvent>)> {
    let (finalized_tx, finalized_rx) = mpsc::unbounded_channel();
    let mut nodes = Vec::with_capacity(participants.len());
    let mut env = SimEnvironment::new(context.clone(), transport);

    for (i, pk) in participants.iter().cloned().enumerate() {
        let handle = start_node(
            &mut env,
            i,
            pk,
            schemes[i].clone(),
            finalized_tx.clone(),
            bootstrap,
        )
        .await?;
        nodes.push(handle);
    }

    Ok((nodes, finalized_rx))
}

/// Ensure the provided round-robin identity list is unique for the simulation.
fn participants_set(
    participants: &[ed25519::PublicKey],
) -> anyhow::Result<Set<ed25519::PublicKey>> {
    participants
        .iter()
        .cloned()
        .try_collect()
        .map_err(|_| anyhow::anyhow!("participant public keys are not unique"))
}

/// Boot the simulated p2p network and register the participant set.
async fn start_network(
    context: &tokio::Context,
    participants: Set<ed25519::PublicKey>,
) -> SimTransport {
    let (network, transport) = simulated::Network::new(
        context.with_label("network"),
        simulated::Config {
            max_size: MAX_MSG_SIZE as u32,
            disconnect_on_block: true,
            tracked_peer_sets: None,
        },
    );
    network.start();

    transport.manager().track(0, participants).await;
    transport
}

/// Connect all peers in a full mesh with fixed links.
async fn connect_all_peers(
    transport: &mut SimTransport,
    peers: &[ed25519::PublicKey],
) -> anyhow::Result<()> {
    for a in peers.iter() {
        for b in peers.iter() {
            if a == b {
                continue;
            }
            transport
                .add_link(
                    a.clone(),
                    b.clone(),
                    simulated::Link {
                        latency: Duration::from_millis(P2P_LINK_LATENCY_MS),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .context("add_link")?;
        }
    }
    Ok(())
}

/// Wait until each node has observed `blocks` finalizations and return the common head digest.
async fn wait_for_finalized_head(
    finalized_rx: &mut mpsc::UnboundedReceiver<FinalizationEvent>,
    nodes: usize,
    blocks: u64,
) -> anyhow::Result<ConsensusDigest> {
    if blocks == 0 {
        return Err(anyhow::anyhow!("blocks must be greater than zero"));
    }

    let mut counts = vec![0u64; nodes];
    let mut nth = vec![None; nodes];
    while nth.iter().any(Option::is_none) {
        let Some((node, digest)) = finalized_rx.recv().await else {
            break;
        };
        let idx = node as usize;
        if nth[idx].is_some() {
            continue;
        }
        counts[idx] += 1;
        if counts[idx] == blocks {
            nth[idx] = Some(digest);
        }
    }

    let head = nth
        .first()
        .and_then(|d| *d)
        .ok_or_else(|| anyhow::anyhow!("missing finalization"))?;
    for (i, d) in nth.iter().enumerate() {
        let Some(d) = d else {
            return Err(anyhow::anyhow!("node {i} missing finalization"));
        };
        if *d != head {
            return Err(anyhow::anyhow!("divergent finalized heads"));
        }
    }
    Ok(head)
}

/// Query each node's application store at `head` and assert they all agree on the outcome.
async fn assert_all_nodes_converged(
    nodes: &[NodeHandle],
    head: ConsensusDigest,
    demo: &demo::DemoTransfer,
) -> anyhow::Result<(crate::StateRoot, B256)> {
    let mut state_root = None;
    let mut seed = None;
    for node in nodes.iter() {
        let from_balance = node
            .query_balance(head, demo.from)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing from balance"))?;
        let to_balance = node
            .query_balance(head, demo.to)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing to balance"))?;
        if from_balance != demo.expected_from || to_balance != demo.expected_to {
            return Err(anyhow::anyhow!("unexpected balances"));
        }

        let root = node
            .query_state_root(head)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing state root"))?;
        state_root = match state_root {
            None => Some(root),
            Some(prev) if prev == root => Some(prev),
            Some(_) => return Err(anyhow::anyhow!("divergent state roots")),
        };

        let node_seed = node
            .query_seed(head)
            .await
            .ok_or_else(|| anyhow::anyhow!("missing seed"))?;
        seed = match seed {
            None => Some(node_seed),
            Some(prev) if prev == node_seed => Some(prev),
            Some(_) => return Err(anyhow::anyhow!("divergent seeds")),
        };
    }

    let state_root = state_root.ok_or_else(|| anyhow::anyhow!("missing state root"))?;
    let seed = seed.ok_or_else(|| anyhow::anyhow!("missing seed"))?;
    Ok((state_root, seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sim_smoke() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        let outcome = simulate(SimConfig {
            nodes: 4,
            blocks: 3,
            seed: 42,
        })
        .unwrap();
        assert_eq!(outcome.from_balance, U256::from(1_000_000u64 - 100));
        assert_eq!(outcome.to_balance, U256::from(100u64));
    }
}
