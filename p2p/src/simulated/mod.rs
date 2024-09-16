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
    #[error("not valid to link self")]
    LinkingSelf,
    #[error("invalid success rate (must be in [0, 1]): {0}")]
    InvalidSuccessRate(f64),
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

    async fn simulate_messages(size: usize) {
        // Create simulated network
        let mut network = network::Network::new(network::Config {
            max_message_size: 1024 * 1024,
        });

        // Register agents
        let mut agents = HashMap::new();
        let (seen_sender, mut seen_receiver) = tokio::sync::mpsc::channel(1024);
        for i in 0..size {
            let pk = insecure_signer(i as u64).me();
            let (sender, mut receiver) = network.register(pk.clone());
            agents.insert(pk, sender);
            let agent_sender = seen_sender.clone();
            tokio::spawn(async move {
                for _ in 0..size {
                    receiver.recv().await.unwrap();
                }
                agent_sender.send(()).await.unwrap();

                // Exiting early here tests the case where the recipient end of an agent is dropped
            });
        }

        // Randomly link agents
        let only_inbound = insecure_signer(0).me();
        for agent in agents.keys() {
            if agent == &only_inbound {
                // Test that we can gracefully handle missing links
                continue;
            }
            for other in agents.keys() {
                let result = network.link(
                    agent.clone(),
                    other.clone(),
                    network::Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 0.75,
                        capacity: 1,
                    },
                );
                if agent == other {
                    assert!(matches!(result, Err(Error::LinkingSelf)));
                } else {
                    assert!(result.is_ok());
                }
            }
        }

        // Send messages
        tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
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
                if sender == &only_inbound {
                    assert_eq!(sent.len(), 0);
                } else {
                    assert_eq!(sent.len(), keys.len() - 1);
                }
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

    #[tokio::test]
    async fn test_invalid_message() {
        // Create simulated network
        let mut network = network::Network::new(network::Config {
            max_message_size: 1024 * 1024,
        });

        // Register agents
        let mut agents = HashMap::new();
        for i in 0..10 {
            let pk = insecure_signer(i as u64).me();
            let (sender, _) = network.register(pk.clone());
            agents.insert(pk, sender);
        }

        // Start network
        tokio::spawn(network.run());

        // Send invalid message
        let mut rng = StdRng::from_entropy();
        let keys = agents.keys().collect::<Vec<_>>();
        let sender = keys[rng.gen_range(0..keys.len())];
        let message_sender = agents.get(sender).unwrap().clone();
        let mut msg = vec![0u8; 1024 * 1024 + 1];
        rng.fill(&mut msg[..]);
        let result = message_sender
            .send(Recipients::All, msg.into(), false)
            .await
            .unwrap_err();

        // Confirm error is correct
        assert!(matches!(result, Error::MessageTooLarge(_)));
    }
}
