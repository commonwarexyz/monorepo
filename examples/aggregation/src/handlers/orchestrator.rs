use commonware_cryptography::{Hasher, PublicKey, Scheme, Sha256};
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Clock;
use commonware_utils::hex;
use prost::Message;
use std::{
    collections::HashMap,
    time::{Duration, UNIX_EPOCH},
};
use tracing::info;

use crate::{
    bn254::{self, Bn254},
    handlers::wire,
};

pub struct Orchestrator<E: Clock> {
    runtime: E,

    aggregation_frequency: Duration,

    contributors: Vec<PublicKey>,
    ordered_contributors: HashMap<PublicKey, usize>,
    t: usize,
}

impl<E: Clock> Orchestrator<E> {
    pub fn new(
        runtime: E,
        aggregation_frequency: Duration,
        mut contributors: Vec<PublicKey>,
        t: usize,
    ) -> Self {
        contributors.sort();
        let mut ordered_contributors = HashMap::new();
        for (idx, contributor) in contributors.iter().enumerate() {
            ordered_contributors.insert(contributor.clone(), idx);
        }
        Self {
            runtime,
            aggregation_frequency,
            contributors,
            ordered_contributors,
            t,
        }
    }

    pub async fn run(self, mut sender: impl Sender, mut receiver: impl Receiver) {
        let mut hasher = Sha256::new();
        let mut signatures = HashMap::new();
        loop {
            // Generate payload
            let current = self.runtime.current();
            let current = current.duration_since(UNIX_EPOCH).unwrap().as_secs();
            info!("generated message: {}", current);

            // Broadcast payload
            let message = wire::Aggregation {
                round: current,
                payload: Some(wire::aggregation::Payload::Start(wire::Start {})),
            }
            .encode_to_vec()
            .into();
            sender
                .send(commonware_p2p::Recipients::All, message, true)
                .await
                .expect("failed to broadcast message");
            signatures.insert(current, HashMap::new());

            // Listen for messages until the next broadcast
            let continue_time = self.runtime.current() + self.aggregation_frequency;
            loop {
                select! {
                    _ = self.runtime.sleep_until(continue_time) => {break;},
                    msg = receiver.recv() => {
                        // Parse message
                        let (sender, msg) = match msg {
                            Ok(msg) => msg,
                            Err(_) => continue,
                        };

                        // Get contributor
                        let Some(contributor) = self.ordered_contributors.get(&sender) else {
                            continue;
                        };

                        // Check if round exists
                        let Ok(msg) = wire::Aggregation::decode(msg) else {
                            continue;
                        };
                        let Some(round) = signatures.get_mut(&msg.round) else {
                            continue;
                        };

                        // Check if contributor has already signed
                        if round.contains_key(contributor) {
                            continue;
                        }

                        // Verify signature
                        let signature = match msg.payload {
                            Some(wire::aggregation::Payload::Signature(signature)) => signature.signature,
                            _ => continue,
                        };
                        let payload = msg.round.to_be_bytes();
                        hasher.update(&payload);
                        let payload = hasher.finalize();
                        if !Bn254::verify(None, &payload, &sender, &signature) {
                            continue;
                        }

                        // Insert signature
                        round.insert(contributor, signature);

                        // Check if should aggregate
                        if round.len() < self.t {
                            continue;
                        }

                        // Aggregate signatures
                        let mut participating = Vec::new();
                        let mut pretty_participating = Vec::new();
                        let mut signatures = Vec::new();
                        for i in 0..self.contributors.len() {
                            let Some(signature) = round.get(&i) else {
                                continue;
                            };
                            let contributor = &self.contributors[i];
                            participating.push(contributor.clone());
                            pretty_participating.push(hex(contributor));
                            signatures.push(signature.clone());
                        }
                        let agg_signature = bn254::aggregate_signatures(&signatures).unwrap();

                        // Verify aggregated signature (already verified individual signatures so should never fail)
                        if !bn254::aggregate_verify(&participating, None, &payload, &agg_signature) {
                            panic!("failed to verify aggregated signature");
                        }
                        info!(
                            round = msg.round,
                            participants = ?pretty_participating,
                            signature = hex(&agg_signature),
                            "aggregated signatures",
                        );
                    },
                }
            }
        }
    }
}
