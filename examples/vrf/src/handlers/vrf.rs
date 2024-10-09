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
    PublicKey,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use commonware_utils::hex;
use futures::{channel::mpsc, StreamExt};
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, info, warn};

const VRF_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_VRF_";

/// Generate bias-resistant, verifiable randomness using BLS12-381
/// Threshold Signatures.
pub struct Vrf<E: Clock> {
    runtime: E,
    timeout: Duration,
    threshold: u32,
    contributors: Vec<PublicKey>,
    ordered_contributors: HashMap<PublicKey, u32>,
    requests: mpsc::Receiver<(u64, Output)>,
}

impl<E: Clock> Vrf<E> {
    pub fn new(
        runtime: E,
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
            runtime,
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
        sender: &mut impl Sender,
        receiver: &mut impl Receiver,
    ) -> Option<group::Signature> {
        // Construct payload
        let payload = round.to_be_bytes();
        let signature = ops::partial_sign(&output.share, VRF_NAMESPACE, &payload);

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
        let start = self.runtime.current();
        let t_signature = start + self.timeout;
        let mut received = HashSet::new();
        loop {
            select! {
                _timeout = self.runtime.sleep_until(t_signature) => {
                    debug!(round, "signature timeout");
                    break;
                },
                result = receiver.recv() => {
                    match result {
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
                            match ops::partial_verify(&output.public, VRF_NAMESPACE, &payload, &signature) {
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
                    };
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

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        loop {
            let (round, output) = match self.requests.next().await {
                Some(request) => request,
                None => {
                    return;
                }
            };

            match self
                .run_round(&output, round, &mut sender, &mut receiver)
                .await
            {
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
