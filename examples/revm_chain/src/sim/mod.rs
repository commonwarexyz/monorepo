use crate::ConsensusDigest;
use alloy_evm::revm::primitives::{B256, U256};
use commonware_consensus::simplex;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};
use commonware_runtime::{deterministic, Runner as _};

type ThresholdScheme =
    simplex::signing_scheme::bls12381_threshold::Scheme<ed25519::PublicKey, MinSig>;

mod checks;
mod dkg;
mod genesis;
mod network;
mod node;

pub(super) const MAX_MSG_SIZE: usize = 1024 * 1024;
pub(super) const MAILBOX_SIZE: usize = 1024;
pub(super) const CHANNEL_VOTES: u64 = 0;
pub(super) const CHANNEL_CERTS: u64 = 1;
pub(super) const CHANNEL_RESOLVER: u64 = 2;
pub(super) const CHANNEL_BLOCKS: u64 = 3;
pub(super) const BLOCK_CODEC_MAX_TXS: usize = 64;
pub(super) const BLOCK_CODEC_MAX_CALLDATA: usize = 1024;
pub(super) const P2P_LINK_LATENCY_MS: u64 = 5;

#[derive(Clone, Copy, Debug)]
pub struct SimConfig {
    pub nodes: usize,
    pub blocks: u64,
    pub seed: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SimOutcome {
    pub head: ConsensusDigest,
    pub state_root: crate::StateRoot,
    pub seed: B256,
    pub from_balance: U256,
    pub to_balance: U256,
}

pub fn simulate(cfg: SimConfig) -> anyhow::Result<SimOutcome> {
    let executor = deterministic::Runner::seeded(cfg.seed);
    executor.start(|context| async move { run_sim(context, cfg).await })
}

async fn run_sim(context: deterministic::Context, cfg: SimConfig) -> anyhow::Result<SimOutcome> {
    let (participants_vec, schemes) = dkg::threshold_schemes(cfg.seed, cfg.nodes)?;
    let participants_set = dkg::participants_set(&participants_vec)?;

    let mut oracle = network::start_network(&context, participants_set).await;
    network::connect_all_peers(&mut oracle, &participants_vec).await?;

    let genesis = genesis::GenesisTransfer::new();

    let (nodes, mut finalized_rx) =
        node::start_all_nodes(&context, &mut oracle, &participants_vec, &schemes, &genesis).await?;

    let head = checks::wait_for_finalized_head(&mut finalized_rx, cfg.nodes, cfg.blocks).await?;
    let (state_root, seed) = checks::assert_all_nodes_converged(&nodes, head, &genesis).await?;

    Ok(SimOutcome {
        head,
        state_root,
        seed,
        from_balance: genesis.expected_from,
        to_balance: genesis.expected_to,
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
