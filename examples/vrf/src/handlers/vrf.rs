use crate::handlers::wire;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::{
        dkg::player::Output,
        primitives::{
            ops,
            variant::{MinSig, Variant},
        },
    },
    PublicKey,
};
use commonware_macros::select_loop;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use futures::{channel::mpsc, StreamExt};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tracing::{debug, info, warn};

const VRF_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_VRF_";

/// Generate bias-resistant, verifiable randomness using BLS12-381
/// Threshold Signatures.
pub struct Vrf<E: Clock + Spawner, P: PublicKey> {
    context: ContextCell<E>,
    timeout: Duration,
    threshold: u32,
    contributors: Vec<P>,
    ordered_contributors: HashMap<P, u32>,
    requests: mpsc::Receiver<(u64, Output<MinSig>)>,
}

impl<E: Clock + Spawner, P: PublicKey> Vrf<E, P> {
    pub fn new(
        context: E,
        timeout: Duration,
        threshold: u32,
        mut contributors: Vec<P>,
        requests: mpsc::Receiver<(u64, Output<MinSig>)>,
    ) -> Self {
        contributors.sort();
        let ordered_contributors = contributors
            .iter()
            .enumerate()
            .map(|(i, pk)| (pk.clone(), i as u32))
            .collect();
        Self {
            context: ContextCell::new(context),
            timeout,
            threshold,
            contributors,
            ordered_contributors,
            requests,
        }
    }

    async fn run_round(
        &self,
        output: &Output<MinSig>,
        round: u64,
        sender: &mut impl Sender<PublicKey = P>,
        receiver: &mut impl Receiver<PublicKey = P>,
    ) -> Option<<MinSig as Variant>::Signature> {
        // Construct payload
        let payload = round.to_be_bytes();
        let signature =
            ops::partial_sign_message::<MinSig>(&output.share, Some(VRF_NAMESPACE), &payload);

        // Construct partial signature
        let mut partials = vec![signature.clone()];

        // Send partial signature to peers
        sender
            .send(
                Recipients::Some(self.contributors.clone()),
                wire::Vrf { round, signature }.encode().into(),
                true,
            )
            .await
            .expect("failed to send signature");

        // Wait for partial signatures from peers or timeout
        let start = self.context.current();
        let t_signature = start + self.timeout;
        let mut received = HashSet::new();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping round");
                return None;
            },
            _ = self.context.sleep_until(t_signature) => {
                debug!(round, "signature timeout");
                break;
            },
            result = receiver.recv() => {
                match result {
                    Ok((peer, msg)) => {
                        let dealer = match self.ordered_contributors.get(&peer) {
                            Some(dealer) => dealer,
                            None => {
                                warn!(round, "received signature from invalid player");
                                continue;
                            }
                        };
                        // We mark we received a message from a dealer during this round before checking if its valid to
                        // avoid doing useless work (where the dealer can keep sending us outdated/invalid messages).
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
                        // We must check that the signature is from the correct dealer to ensure malicious dealers don't provide
                        // us with multiple instances of the same partial signature.
                        if msg.signature.index != *dealer {
                            warn!(round, dealer, "received signature from wrong player");
                            continue;
                        }
                        match ops::partial_verify_message::<MinSig>(&output.public, Some(VRF_NAMESPACE), &payload, &msg.signature) {
                            Ok(_) => {
                                partials.push(msg.signature);
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

        // Aggregate partial signatures
        ops::threshold_signature_recover::<MinSig, _>(self.threshold, &partials).map_or_else(
            |_| {
                warn!(round, "failed to aggregate partial signatures");
                None
            },
            Some,
        )
    }

    pub fn start(
        mut self,
        sender: impl Sender<PublicKey = P>,
        receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(sender, receiver).await)
    }

    async fn run(
        mut self,
        mut sender: impl Sender<PublicKey = P>,
        mut receiver: impl Receiver<PublicKey = P>,
    ) {
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
                    info!(round, ?signature, "generated signature");
                }
                None => {
                    warn!(round, "failed to generate signature");
                }
            }
        }
    }
}
