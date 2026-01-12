//! Simulation harness for the example chain.
//!
//! Spawns N nodes in a single process using the tokio runtime and the simulated P2P transport.
//! The harness waits for a fixed number of finalized blocks and asserts all nodes converge on the
//! same head, state commitment, and balances.

use crate::ConsensusDigest;
use alloy_evm::revm::primitives::{B256, U256};
use commonware_consensus::simplex;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};
use commonware_runtime::{tokio, Runner as _};

type ThresholdScheme = simplex::scheme::bls12381_threshold::Scheme<ed25519::PublicKey, MinSig>;

mod checks;
mod demo;
mod dkg;
mod network;
mod node;

pub(super) const MAX_MSG_SIZE: usize = 1024 * 1024;
pub(super) const MAILBOX_SIZE: usize = 1024;
pub(super) const CHANNEL_VOTES: u64 = 0;
pub(super) const CHANNEL_CERTS: u64 = 1;
pub(super) const CHANNEL_RESOLVER: u64 = 2;
pub(super) const CHANNEL_BLOCKS: u64 = 3;
// Marshal backfill requests/responses use a resolver protocol and are kept separate from the
// best-effort broadcast channel used for full blocks.
pub(super) const CHANNEL_BACKFILL: u64 = 4;
pub(super) const BLOCK_CODEC_MAX_TXS: usize = 64;
pub(super) const BLOCK_CODEC_MAX_CALLDATA: usize = 1024;
pub(super) const P2P_LINK_LATENCY_MS: u64 = 5;
pub(super) const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_REVM_SIMPLEX";

#[derive(Clone, Copy, Debug)]
/// Configuration for a simulation run.
pub struct SimConfig {
    pub nodes: usize,
    pub blocks: u64,
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
    pub from_balance: U256,
    pub to_balance: U256,
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
    let executor = tokio::Runner::default();
    executor.start(|context| async move { run_sim(context, cfg).await })
}

async fn run_sim(context: tokio::Context, cfg: SimConfig) -> anyhow::Result<SimOutcome> {
    let (participants_vec, schemes) = dkg::threshold_schemes(cfg.seed, cfg.nodes)?;
    let participants_set = dkg::participants_set(&participants_vec)?;

    let mut oracle = network::start_network(&context, participants_set).await;
    network::connect_all_peers(&mut oracle, &participants_vec).await?;

    let demo = demo::DemoTransfer::new();

    let (nodes, mut finalized_rx) =
        node::start_all_nodes(&context, &mut oracle, &participants_vec, &schemes, &demo).await?;

    let head = checks::wait_for_finalized_head(&mut finalized_rx, cfg.nodes, cfg.blocks).await?;
    let (state_root, seed) = checks::assert_all_nodes_converged(&nodes, head, &demo).await?;

    Ok(SimOutcome {
        head,
        state_root,
        seed,
        from_balance: demo.expected_from,
        to_balance: demo.expected_to,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sim_smoke() {
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
