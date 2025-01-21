use crate::bn254::Bn254;
use commonware_cryptography::{Hasher, PublicKey, Scheme, Sha256};
use commonware_p2p::{Receiver, Sender};
use prost::Message;
use std::collections::HashSet;
use tracing::info;

use super::wire;

pub struct Contributor {
    orchestrator: PublicKey,
    signer: Bn254,
}

impl Contributor {
    pub fn new(orchestrator: PublicKey, signer: Bn254) -> Self {
        Self {
            orchestrator,
            signer,
        }
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        let mut hasher = Sha256::new();
        let mut signed = HashSet::new();
        while let Ok((s, message)) = receiver.recv().await {
            // Check if from orchestrator
            if s != self.orchestrator {
                continue;
            }

            // Parse message
            let Ok(message) = wire::Aggregation::decode(message) else {
                continue;
            };
            match message.payload {
                Some(wire::aggregation::Payload::Start(start)) => start,
                _ => continue,
            };

            // Check if already signed at round
            let round = message.round;
            if !signed.insert(round) {
                continue;
            }

            // Generate signature
            let payload = message.round.to_be_bytes();
            hasher.update(&payload);
            let payload = hasher.finalize();
            let signature = self.signer.sign(None, &payload);

            // Return signature to orchestrator
            let message = wire::Aggregation {
                round,
                payload: Some(wire::aggregation::Payload::Signature(wire::Signature {
                    signature,
                })),
            }
            .encode_to_vec()
            .into();
            sender
                .send(
                    commonware_p2p::Recipients::One(self.orchestrator.clone()),
                    message,
                    true,
                )
                .await
                .expect("failed to broadcast signature");
            info!(round, "broadcast signature");
        }
    }
}
