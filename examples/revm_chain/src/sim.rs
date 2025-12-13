use alloy_evm::revm::primitives::B256;
use commonware_cryptography::ed25519;
use commonware_cryptography::PrivateKeyExt as _;
use commonware_cryptography::Signer as _;
use commonware_p2p::Manager as _;
use commonware_p2p::simulated;
use commonware_runtime::{deterministic, Metrics as _, Runner as _};
use commonware_utils::{ordered::Set, TryCollect as _};

#[derive(Clone, Copy, Debug)]
pub struct SimConfig {
    pub nodes: usize,
    pub blocks: u64,
    pub seed: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SimOutcome {
    pub head: B256,
}

pub fn simulate(cfg: SimConfig) -> anyhow::Result<SimOutcome> {
    let executor = deterministic::Runner::seeded(cfg.seed);
    executor.start(|context| async move {
        let _ = cfg.blocks;
        let participants: Set<_> = (0..cfg.nodes)
            .map(|i| ed25519::PrivateKey::from_seed(i as u64).public_key())
            .try_collect()
            .expect("participant public keys are unique");

        let (network, oracle) = simulated::Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
            },
        );
        network.start();

        let mut manager = oracle.manager();
        manager.update(0, participants).await;

        Ok(SimOutcome { head: B256::ZERO })
    })
}
