use crate::handlers::{
    utils::{payload, public_hex, ACK_NAMESPACE},
    wire,
};
use commonware_cryptography::{
    bls12381::{
        dkg::{self, dealer, player},
        primitives::{
            group::{self, Private},
            poly,
        },
    },
    PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::{hex, quorum};
use futures::{channel::mpsc, SinkExt};
use prost::Message;
use rand::rngs::OsRng;
use std::{collections::HashMap, time::Duration};
use tracing::{debug, info, warn};

/// A DKG/Resharing contributor that can be configured to behave honestly
/// or deviate as a rogue, lazy, or defiant participant.
pub struct Contributor<E: Clock, C: Scheme> {
    runtime: E,
    crypto: C,
    dkg_phase_timeout: Duration,
    arbiter: PublicKey,
    t: u32,
    contributors: Vec<PublicKey>,
    contributors_ordered: HashMap<PublicKey, u32>,
    rogue: bool,
    lazy: bool,

    signatures: mpsc::Sender<(u64, player::Output)>,
}

impl<E: Clock, C: Scheme> Contributor<E, C> {
    pub fn new(
        runtime: E,
        crypto: C,
        dkg_phase_timeout: Duration,
        arbiter: PublicKey,
        mut contributors: Vec<PublicKey>,
        rogue: bool,
        lazy: bool,
    ) -> (Self, mpsc::Receiver<(u64, player::Output)>) {
        contributors.sort();
        let contributors_ordered: HashMap<PublicKey, u32> = contributors
            .iter()
            .enumerate()
            .map(|(idx, pk)| (pk.clone(), idx as u32))
            .collect();
        let (sender, receiver) = mpsc::channel(32);
        (
            Self {
                runtime,
                crypto,
                dkg_phase_timeout,
                arbiter,
                t: quorum(contributors.len() as u32).unwrap(),
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
        previous: Option<&player::Output>,
        sender: &mut impl Sender,
        receiver: &mut impl Receiver,
    ) -> (u64, Option<player::Output>) {
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

        // Create dealer
        let mut dealer_obj = if should_deal {
            let previous = previous.map(|previous| previous.share);
            let (p0, commitment, shares) = dealer::P0::new(previous, self.contributors.clone());
            Some((
                p0,
                commitment,
                commitment.serialize(),
                shares,
                HashMap::new(),
            ))
        } else {
            None
        };

        // Create player
        let mut player_obj = player::P0::new(
            me.clone(),
            public.clone(),
            self.contributors.clone(),
            self.contributors.clone(),
            1,
        );

        // Distribute shares
        if let Some((p0, commitment, serialized_commitment, shares, acks)) = &mut dealer_obj {
            // Send to self
            player_obj
                .share(
                    me.clone(),
                    commitment.clone(),
                    shares[me_idx as usize].clone(),
                )
                .unwrap();
            p0.ack(me.clone()).unwrap();
            let payload = payload(round, &me, &serialized_commitment);
            let signature = self.crypto.sign(Some(ACK_NAMESPACE), &payload);
            acks.insert(me_idx, signature);

            // Send to others
            for (idx, player) in self.contributors.iter().enumerate() {
                if idx == me_idx as usize {
                    continue;
                }
                sender
                    .send(
                        Recipients::One(player.clone()),
                        wire::Dkg {
                            round,
                            payload: Some(wire::dkg::Payload::Share(wire::Share {
                                commitment: serialized_commitment.clone(),
                                share: shares[idx].serialize(),
                            })),
                        }
                        .encode_to_vec()
                        .into(),
                        true,
                    )
                    .await
                    .expect("could not send share");
            }
        }

        // Respond to commitments and wait for acks
        let t = self.runtime.current() + 2 * self.dkg_phase_timeout;
        loop {
            select! {
                    _ = self.runtime.sleep_until(t) => {
                        debug!(round, "ack timeout");
                        break;
                    },
                    result = receiver.recv() => {
                        match result {
                            Ok((s, msg)) => {
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
                                    Some(wire::dkg::Payload::Ack(msg)) => {
                                        // Skip if not dealing
                                        let Some((p0, _, commitment, _, acks)) = &mut dealer_obj else {
                                            continue;
                                        };

                                        // Verify index matches
                                        let Some(player) = self.contributors.get(msg.public_key as usize) else {
                                            continue;
                                        };
                                        if player != &s {
                                            warn!(round, "received ack with wrong index");
                                            continue;
                                        }

                                        // Verify signature on incoming ack
                                        let payload = payload(round, &me, &commitment);
                                        if !C::verify(Some(ACK_NAMESPACE), &payload, &s, &msg.signature) {
                                            warn!(round, sender = hex(&s), "received invalid ack signature");
                                            continue;
                                        }

                                        // Store ack
                                        p0.ack(s);

                                    },
                                    Some(wire::dkg::Payload::Share(msg)) => {
                                        // Deserialize commitment
                                        let commitment = match poly::Public::deserialize(&msg.commitment, self.t) {
                                            Some(commitment) => commitment,
                                            None => {
                                                warn!(round, "received invalid commitment");
                                                continue;
                                            }
                                        };

                                        // Deserialize share
                                        let share = match group::Share::deserialize(&msg.share) {
                                            Some(share) => share,
                                            None => {
                                                warn!(round, "received invalid share");
                                                continue;
                                            }
                                        };

                                        // Store share
                                        if let Err(e) = player_obj.share(sender, commitment, share){
                                            warn!(round, error = ?e, "failed to add share");
                                            continue;
                                        }

                                        // Send ack
                                        let payload = payload(round, &s, &msg.commitment);
                                        let signature = self.crypto.sign(Some(ACK_NAMESPACE), &payload);
                                        sender
                                            .send(
                                                Recipients::One(s),
                                                wire::Dkg {
                                                    round,
                                                    payload: Some(wire::dkg::Payload::Ack(wire::Ack {
                                                        public_key: me_idx,
                                                        signature,
                                                    })),
                                                }
                                                .encode_to_vec()
                                                .into(),
                                                true,
                                            )
                                            .await
                                            .expect("could not send ack");
                                    },
                                    _ => {
                                        // Useless message
                                        continue;
                                    }
                                };
                            }
                            Err(err) => {
                                debug!(?err, "did not receive ack");
                                return (round, None);
                            }
                        }
                    }
            }
        }

        // Send commitment to arbiter
        if let Some((p0, commitment, serialized_commitment, shares, acks)) = dealer_obj {
            let mut ack_vec = Vec::with_capacity(acks.len());
            let mut reveals = Vec::new();
            for idx in 0..self.contributors.len() as u32 {
                match acks.get(&idx) {
                    Some(signature) => {
                        ack_vec.push(wire::Ack {
                            public_key: idx,
                            signature: signature.clone(),
                        });
                    }
                    None => {
                        reveals.push(shares[idx as usize].serialize());
                    }
                }
            }
            sender
                .send(
                    Recipients::One(self.arbiter.clone()),
                    wire::Dkg {
                        round,
                        payload: Some(wire::dkg::Payload::Commitment(wire::Commitment {
                            commitment: serialized_commitment,
                            acks: ack_vec,
                            reveals,
                        })),
                    }
                    .encode_to_vec()
                    .into(),
                    true,
                )
                .await
                .expect("could not send commitment");
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
