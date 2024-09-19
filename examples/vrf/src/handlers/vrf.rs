use crate::handlers::wire;
use commonware_cryptography::{
    bls12381::{
        dkg::contributor::Output,
        primitives::{
            group::{self, Element},
            ops,
            poly::Eval,
        },
    },
    utils::hex,
    PublicKey,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::{select, sync::mpsc};
use tracing::{debug, info, warn};

/// Generate bias-resistant, verifiable randomness using BLS12-381
/// Threshold Signatures.
pub struct Vrf {
    timeout: Duration,
    threshold: u32,
    contributors: Vec<PublicKey>,
    ordered_contributors: HashMap<PublicKey, u32>,
    requests: mpsc::Receiver<(u64, Output)>,
}

impl Vrf {
    pub fn new(
        timeout: Duration,
        threshold: u32,
        mut contributors: Vec<PublicKey>,
        requests: mpsc::Receiver<(u64, Output)>,
    ) -> Self {
        contributors.sort();
        let ordered_contributors = contributors
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();
        Self {
            timeout,
            threshold,
            contributors,
            ordered_contributors,
            requests,
        }
    }

    async fn run_round(
        &self,
        output: &Output,
        round: u64,
        sender: &impl Sender,
        receiver: &mut impl Receiver,
    ) -> Option<group::Signature> {
        // Construct payload
        let payload = round.to_be_bytes();
        let signature = ops::partial_sign(&output.share, &payload);

        // Construct partial signature
        let mut partials = vec![signature.clone()];

        // Send partial signature to peers
        sender
            .send(
                Recipients::Some(self.contributors.clone()),
                wire::Vrf {
                    round,
                    signature: signature.serialize(),
                }
                .encode_to_vec()
                .into(),
                true,
            )
            .await
            .expect("failed to send signature");

        // Wait for partial signatures from peers or timeout
        let start = tokio::time::Instant::now();
        let t_signature = start + self.timeout;
        let mut received = HashSet::new();
        loop {
            select! {
                biased;

                _ = tokio::time::sleep_until(t_signature) => {
                    debug!(round, "signature timeout");
                    break;
                }
                result = receiver.recv() => match result{
                    Ok((sender, msg)) => {
                        let dealer = match self.ordered_contributors.get(&sender) {
                            Some(sender) => sender,
                            None => {
                                warn!(round, "received signature from invalid player");
                                continue;
                            }
                        };
                        if !received.insert(*dealer) {
                            warn!(round, dealer, "received duplicate signature");
                            continue;
                        }
                        let msg = match wire::Vrf::decode(msg) {
                            Ok(msg) => msg,
                            Err(_) => {
                                warn!(round, "received invalid message from player");
                                continue;
                            }
                        };
                        if msg.round != round {
                            warn!(
                                round,
                                msg.round, "received signature message with wrong round"
                            );
                            continue;
                        }
                        let signature: Eval<group::Signature> = match Eval::deserialize(&msg.signature) {
                            Some(signature) => signature,
                            None => {
                                warn!(round, dealer, "received invalid signature");
                                continue;
                            }
                        };
                        match ops::partial_verify(&output.public, &payload, &signature) {
                            Ok(_) => {
                                partials.push(signature);
                                debug!(round, dealer, "received partial signature");
                            }
                            Err(_) => {
                                warn!(round, dealer, "received invalid partial signature");
                            }
                        }
                    },
                    Err(err) => {
                        warn!(round, ?err, "failed to receive signature");
                        break;
                    }
                }
            }
        }

        // Aggregate partial signatures
        match ops::aggregate(self.threshold, partials) {
            Ok(signature) => Some(signature),
            Err(_) => {
                warn!(round, "failed to aggregate partial signatures");
                None
            }
        }
    }

    pub async fn run(mut self, sender: impl Sender, mut receiver: impl Receiver) {
        loop {
            let (round, output) = match self.requests.recv().await {
                Some(request) => request,
                None => {
                    return;
                }
            };

            match self.run_round(&output, round, &sender, &mut receiver).await {
                Some(signature) => {
                    let signature = signature.serialize();
                    info!(
                        round,
                        siganture = hex(&signature.into()),
                        "generated signature"
                    );
                }
                None => {
                    warn!(round, "failed to generate signature");
                }
            }
        }
    }
}
