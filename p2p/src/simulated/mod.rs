//! Send messages between arbitrary peers with configurable performance (drops, latency, corruption, etc.)
//!
//! TODO: move to a separate crate because it requires registering instances to handle messages (far outside of
//! the scope of p2p...this is probably ok if it is just a trait).

pub mod network;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("message too large: {0}")]
    MessageTooLarge(usize),
    #[error("network closed")]
    NetworkClosed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use bytes::Bytes;
    use commonware_cryptography::{ed25519::insecure_signer, utils::hex, Scheme};
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use tracing::debug;

    async fn simulate_messages(size: usize) {
        // Create simulated network
        let mut network = network::Network::new(network::Config {
            max_message_len: 1024 * 1024,
            mailbox_size: 1024,
        });

        // Register agents
        let mut agents = HashMap::new();
        let (seen_sender, mut seen_receiver) = tokio::sync::mpsc::channel(1024);
        for i in 0..size {
            let pk = insecure_signer(i as u64).me();
            let (sender, mut receiver) = network.register(pk.clone());
            agents.insert(pk, sender);
            let seen_sender = seen_sender.clone();
            tokio::spawn(async move {
                let mut seen = 0;
                while let Ok(msg) = receiver.recv().await {
                    debug!("{}: {:?}", i, msg);
                    seen += 1;
                    if seen == size {
                        seen_sender.send(()).await.unwrap();
                    }
                }
            });
        }

        // Link agents
        for agent in agents.keys() {
            for other in agents.keys() {
                if agent != other {
                    network.link(
                        agent.clone(),
                        other.clone(),
                        network::Link {
                            latency_mean: 5.0,
                            latency_stddev: 5.0,
                            success_rate: 0.5,
                            outstanding: 32,
                        },
                    );
                }
            }
        }

        // Send messages
        tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0);
            let keys = agents.keys().collect::<Vec<_>>();
            loop {
                let sender = keys[rng.gen_range(0..keys.len())];
                let msg = format!("hello from {}", hex(sender));
                let msg = Bytes::from(msg);
                let message_sender = agents.get(sender).unwrap().clone();
                let sent = message_sender
                    .send(Recipients::All, msg.clone(), false)
                    .await
                    .unwrap();
                assert_eq!(sent.len(), keys.len() - 1);
            }
        });

        // Start network
        tokio::spawn(network.run());

        // Wait for all recipients
        for _ in 0..size {
            seen_receiver.recv().await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_small() {
        simulate_messages(10).await;
    }

    #[tokio::test]
    async fn test_medium() {
        simulate_messages(100).await;
    }

    #[tokio::test]
    async fn test_large() {
        simulate_messages(500).await;
    }
}
