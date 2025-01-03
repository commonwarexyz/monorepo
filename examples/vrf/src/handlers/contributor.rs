use crate::handlers::{
    utils::{payload, public_hex, SHARE_NAMESPACE},
    wire,
};
use commonware_cryptography::{
    bls12381::{
        dkg::{
            self,
            dealer::{Output, P0, P1},
            utils::threshold,
        },
        primitives::{
            group::{self, Private},
            poly,
        },
    },
    PublicKey, Scheme,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_utils::hex;
use futures::{channel::mpsc, SinkExt};
use prost::Message;
use rand::rngs::OsRng;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// A DKG/Resharing contributor that can be configured to behave honestly
/// or deviate as a rogue, lazy, or defiant participant.
pub struct Contributor<C: Scheme> {
    crypto: C,
    arbiter: PublicKey,
    t: u32,
    contributors: Vec<PublicKey>,
    contributors_ordered: HashMap<PublicKey, u32>,
    rogue: bool,
    lazy: bool,

    signatures: mpsc::Sender<(u64, Output)>,
}

impl<C: Scheme> Contributor<C> {
    pub fn new(
        crypto: C,
        arbiter: PublicKey,
        mut contributors: Vec<PublicKey>,
        rogue: bool,
        lazy: bool,
    ) -> (Self, mpsc::Receiver<(u64, Output)>) {
        contributors.sort();
        let contributors_ordered: HashMap<PublicKey, u32> = contributors
            .iter()
            .enumerate()
            .map(|(idx, pk)| (pk.clone(), idx as u32))
            .collect();
        let (sender, receiver) = mpsc::channel(32);
        (
            Self {
                crypto,
                arbiter,
                t: threshold(contributors.len() as u32).unwrap(),
                contributors,
                contributors_ordered,
                rogue,
                lazy,
                signatures: sender,
            },
            receiver,
        )
    }

    async fn run_round(
        &mut self,
        previous: Option<&Output>,
        sender: &mut impl Sender,
        receiver: &mut impl Receiver,
    ) -> (u64, Option<Output>) {
        // Configure me
        let me = self.crypto.public_key();
        let me_idx = *self.contributors_ordered.get(&me).unwrap();

        // Wait for start message from arbiter
        let (public, round) = loop {
            match receiver.recv().await {
                Ok((sender, msg)) => {
                    if sender != self.arbiter {
                        debug!("dropping messages until receive start message from arbiter");
                        continue;
                    }
                    let msg = match wire::Dkg::decode(msg) {
                        Ok(msg) => msg,
                        Err(_) => {
                            warn!("received invalid message from arbiter");
                            continue;
                        }
                    };
                    let round = msg.round;
                    let msg = match msg.payload {
                        Some(wire::dkg::Payload::Start(msg)) => msg,
                        _ => {
                            // This could happen if out-of-sync on phase.
                            return (round, None);
                        }
                    };
                    if let Some(group) = msg.group {
                        let result = poly::Public::deserialize(&group, self.t);
                        if result.is_none() {
                            warn!("received invalid group polynomial");
                            continue;
                        }
                        break (Some(result.unwrap()), round);
                    }
                    break (None, round);
                }
                Err(err) => {
                    debug!(?err, "did not receive start message");
                    continue;
                }
            }
        };

        // If don't have polynomial or there is a round mismatch, attempt to
        // recover using round but don't deal.
        let mut should_deal = true;
        match (&previous, &public) {
            (Some(previous), None) => {
                warn!(
                    expected = public_hex(&previous.public),
                    "previous group polynomial but found none"
                );
                should_deal = false;
            }
            (Some(previous), Some(public)) => {
                if previous.public != *public {
                    warn!(
                        expected = public_hex(&previous.public),
                        found = public_hex(public),
                        "group polynomial does not match expected"
                    );
                    should_deal = false;
                }
            }
            (None, Some(public)) => {
                warn!(
                    found = public_hex(public),
                    "found group polynomial but expected none"
                );
                should_deal = false;
            }
            _ => {}
        }
        info!(
            round,
            should_deal,
            reshare = public.is_some(),
            "starting round"
        );

        // Send commitment to arbiter
        let (mut p1, shares) = if should_deal {
            let previous = public
                .as_ref()
                .map(|public| (public.clone(), previous.unwrap().share));
            let p0 = P0::new(
                me.clone(),
                previous,
                self.contributors.clone(),
                self.contributors.clone(),
                1,
            );
            let (p1, commitment, shares) = p0.finalize();
            let mut p1 = p1.unwrap();
            if let Err(e) = p1.commitment(me.clone(), commitment.clone()) {
                warn!(round, error = ?e, "failed to add our commitment");
                return (round, None);
            }
            sender
                .send(
                    Recipients::One(self.arbiter.clone()),
                    wire::Dkg {
                        round,
                        payload: Some(wire::dkg::Payload::Commitment(wire::Commitment {
                            commitment: commitment.serialize(),
                        })),
                    }
                    .encode_to_vec()
                    .into(),
                    true,
                )
                .await
                .expect("could not send commitment");
            debug!(round, "sent commitment");

            (p1, Some(shares))
        } else {
            (
                P1::new(
                    me.clone(),
                    public,
                    self.contributors.clone(),
                    self.contributors.clone(),
                    1,
                ),
                None,
            )
        };

        // Wait for other commitments
        loop {
            match receiver.recv().await {
                Ok((sender, msg)) => {
                    if sender != self.arbiter {
                        debug!("dropping messages until receive commitments from arbiter");
                        continue;
                    }
                    let msg = match wire::Dkg::decode(msg) {
                        Ok(msg) => msg,
                        Err(_) => {
                            warn!("received invalid message from arbiter");
                            return (round, None);
                        }
                    };
                    if msg.round != round {
                        warn!(
                            round,
                            msg_round = msg.round,
                            "received commitments round does not match expected"
                        );
                        return (round, None);
                    }
                    let msg = match msg.payload {
                        Some(wire::dkg::Payload::Commitments(msg)) => msg,
                        _ => {
                            return (round, None);
                        }
                    };

                    // Compile commitments
                    for commitment in msg.dealers {
                        let dealer = commitment.dealer;
                        let dealer = match self.contributors.get(dealer as usize) {
                            Some(dealer) => dealer,
                            None => {
                                warn!(
                                    round,
                                    dealer,
                                    "received commitment of invalid contributor from arbiter"
                                );
                                return (round, None);
                            }
                        };
                        let commitment =
                            match poly::Public::deserialize(&commitment.commitment, self.t) {
                                Some(commitment) => commitment,
                                None => {
                                    warn!("received invalid commitment from player");
                                    return (round, None);
                                }
                            };

                        // Verify commitment is on public
                        if let Err(e) = p1.commitment(dealer.clone(), commitment) {
                            warn!(round, dealer = hex(dealer), error = ?e, "received invalid commitment");
                            return (round, None);
                        }
                    }
                    break;
                }
                Err(err) => {
                    debug!(?err, "did not receive commitments");
                    return (round, None);
                }
            }
        }
        if !p1.has(me.clone()) && should_deal {
            warn!(round, "commitment is missing from arbiter");
            should_deal = false;
        }

        // Exit if not enough commitments
        let commitments = p1.count();
        let mut p2 = match p1.finalize() {
            Some(p2) => {
                info!(
                    round,
                    commitments, "received sufficient commitments from arbiter"
                );
                p2
            }
            None => {
                warn!(round, commitments, "insufficient commitments");
                return (round, None);
            }
        };

        // Send shares to other contributors
        let mut shares_sent = 0;
        if should_deal {
            let shares = shares.clone().unwrap();
            for (idx, player) in self.contributors.iter().enumerate() {
                let share = shares[idx];
                if idx == me_idx as usize {
                    if let Err(e) = p2.share(me.clone(), share) {
                        warn!(round, error = ?e, "failed to add our share");
                        return (round, None);
                    }
                    continue;
                }
                let mut share_bytes = share.serialize();

                // Tweak behavior depending on role
                if self.rogue {
                    // If we are rogue, randomly modify the share.
                    share_bytes = group::Share {
                        index: share.index,
                        private: Private::rand(&mut OsRng),
                    }
                    .serialize();
                    warn!(round, player = idx, "modified share");
                }
                if self.lazy && shares_sent == self.t - 1 {
                    warn!(round, recipient = idx, "not sending share beause lazy");
                    continue;
                }

                let payload = payload(round, me_idx, &share_bytes);
                let signature = self.crypto.sign(Some(SHARE_NAMESPACE), &payload);
                sender
                    .send(
                        Recipients::One(player.clone()),
                        wire::Dkg {
                            round,
                            payload: Some(wire::dkg::Payload::Share(wire::Share {
                                share: share_bytes,
                                signature,
                            })),
                        }
                        .encode_to_vec()
                        .into(),
                        true,
                    )
                    .await
                    .expect("could not send share");
                debug!(round, player = idx, "sent share");
                shares_sent += 1;
            }
        }

        // Send acks to arbiter when receive shares from other contributors
        let dealers = loop {
            match receiver.recv().await {
                Ok((s, msg)) => {
                    let msg = match wire::Dkg::decode(msg) {
                        Ok(msg) => msg,
                        Err(_) => {
                            warn!("received invalid message from arbiter");
                            return (round, None);
                        }
                    };
                    if round != msg.round {
                        warn!(
                            round,
                            msg.round, "received success message with wrong round"
                        );
                        return (round, None);
                    }
                    if s == self.arbiter {
                        match msg.payload {
                            Some(wire::dkg::Payload::Success(msg)) => {
                                break msg.dealers;
                            }
                            _ => {
                                return (round, None);
                            }
                        }
                    }
                    let dealer = match self.contributors_ordered.get(&s) {
                        Some(dealer) => dealer,
                        None => {
                            warn!(round, "received share from invalid player");
                            continue;
                        }
                    };
                    let msg = match msg.payload {
                        Some(wire::dkg::Payload::Share(msg)) => msg,
                        _ => {
                            warn!(round, "received unexpected message from player");
                            continue;
                        }
                    };
                    let share = match group::Share::deserialize(&msg.share) {
                        Some(share) => share,
                        None => {
                            warn!(round, dealer, "received invalid share");
                            continue;
                        }
                    };

                    // Verify signature on incoming share
                    let payload = payload(round, *dealer as u32, &msg.share);
                    if !C::verify(Some(SHARE_NAMESPACE), &payload, &s, &msg.signature) {
                        warn!(round, dealer, "received invalid share signature");
                        continue;
                    }

                    // Store share
                    match p2.share(s, share) {
                        Ok(_) => {
                            // Send share ack
                            sender
                                .send(
                                    Recipients::One(self.arbiter.clone()),
                                    wire::Dkg {
                                        round,
                                        payload: Some(wire::dkg::Payload::Ack(wire::Ack {
                                            dealer: *dealer as u32,
                                        })),
                                    }
                                    .encode_to_vec()
                                    .into(),
                                    true,
                                )
                                .await
                                .expect("could not send ack");
                            debug!(round, dealer, "sent ack");
                        }
                        Err(dkg::Error::ShareWrongCommitment)
                        | Err(dkg::Error::CommitmentWrongDegree) => {
                            warn!(round, dealer, "received invalid share");

                            // Send complaint
                            sender
                                .send(
                                    Recipients::One(self.arbiter.clone()),
                                    wire::Dkg {
                                        round,
                                        payload: Some(wire::dkg::Payload::Complaint(
                                            wire::Complaint {
                                                dealer: *dealer as u32,
                                                share: msg.share,
                                                signature: msg.signature,
                                            },
                                        )),
                                    }
                                    .encode_to_vec()
                                    .into(),
                                    true,
                                )
                                .await
                                .expect("could not send complaint");
                            warn!(round, dealer, "sent complaint");
                        }
                        Err(e) => {
                            // Some errors may occur if the share is sent to the wrong participant (but it may still
                            // be correct).
                            warn!(round, dealer, error=?e, "received invalid share");
                        }
                    }
                }
                Err(err) => {
                    debug!(?err, "did not receive shares");
                    return (round, None);
                }
            };
        };

        // Construct new public + share
        let output = match p2.finalize(dealers) {
            Ok(output) => Some(output),
            Err(e) => {
                warn!(round, error = ?e, "failed to finalize round");
                None
            }
        };
        (round, output)
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        if self.rogue {
            warn!("running as rogue player");
        }
        if self.lazy {
            warn!("running as lazy player");
        }
        let mut previous = None;
        loop {
            let (round, output) = self
                .run_round(previous.as_ref(), &mut sender, &mut receiver)
                .await;
            match output {
                None => {
                    warn!(round, "round failed");
                    continue;
                }
                Some(output) => {
                    info!(
                        round,
                        participants = output.commitments.len(),
                        public = public_hex(&output.public),
                        "round complete"
                    );

                    // Generate signature over round
                    self.signatures.send((round, output.clone())).await.unwrap();

                    // Update state
                    previous = Some(output);
                }
            }
        }
    }
}
