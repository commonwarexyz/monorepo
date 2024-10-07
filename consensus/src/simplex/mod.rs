//! Simplex
//!
//! PoA Consensus useful for running a DKG (no reconfiguration support, round-robin
//! leader selection).
//!
//! # Sync
//!
//! Wait for block finalization at tip (2f+1), fetch heights backwards (don't
//! need to backfill views).
//!
//! # Differences from Simplex Paper
//!
//! * Block timeout in addition to notarization timeout
//! * Backfill blocks from notarizing peers rather than passing along with notarization

mod config;
mod engine;
mod orchestrator;
mod runner;
mod voter;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Network closed")]
    NetworkClosed,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid block")]
    InvalidBlock,
    #[error("Invalid signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_p2p::simulated::network::{self, Network};
    use commonware_runtime::{deterministic::Executor, Runner};

    #[test]
    fn test_simple() {
        // Create runtime
        let n = 5;
        let (executor, runtime, _) = Executor::seeded(0);
        executor.start(async move {
            // Create simulated network
            let mut network = Network::new(
                runtime.clone(),
                network::Config {
                    max_message_size: 1024 * 1024,
                },
            );

            // Register participants
            let mut validators = Vec::new();
            for i in 0..n {
                let pk = Ed25519::from_seed(i as u64).public_key();
            }
        });
    }
}
