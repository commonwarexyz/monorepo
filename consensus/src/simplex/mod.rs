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
    use std::time::Duration;

    use super::*;
    use crate::{Application, Hash, Payload};
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_p2p::simulated::network::{self, Network};
    use commonware_runtime::{deterministic::Executor, Clock, Runner, Spawner};

    struct MockApplication {}

    impl Application for MockApplication {
        fn propose(&mut self, _parent: Hash) -> Option<Payload> {
            None
        }

        fn parse(&self, _payload: Payload) -> Option<Hash> {
            None
        }

        fn verify(&self, _payload: Payload) -> bool {
            true
        }

        fn notarized(&mut self, _payload: Payload) {}

        fn finalized(&mut self, _payload: Payload) {}
    }

    #[test]
    fn test_simple() {
        // Configure logging
        tracing_subscriber::fmt().with_test_writer().init();

        // Create runtime
        let n = 5;
        let (executor, runtime, _) = Executor::seeded(0);
        executor.start(async move {
            // Create simulated network
            let mut network = Network::new(runtime.clone(), network::Config {});

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();

            // Create runners
            for scheme in schemes.into_iter() {
                let validator = scheme.public_key();
                let (block_sender, block_receiver) =
                    network.register(validator.clone(), 0, 1024 * 1024).unwrap();
                let (vote_sender, vote_receiver) =
                    network.register(validator.clone(), 1, 1024 * 1024).unwrap();
                let mut runner = runner::Runner::new(runtime.clone(), validators.clone());
                runtime.spawn("runner", async move {
                    runner
                        .run(
                            scheme,
                            MockApplication {},
                            (block_sender, block_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                });
            }

            // Loop forever
            //
            // TODO: replace with conditions based on application
            loop {
                runtime.sleep(Duration::from_secs(1)).await;
            }
        });
    }
}
