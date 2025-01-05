use crate::handlers::{
    utils::{payload, public_hex, ACK_NAMESPACE},
    wire,
};
use commonware_cryptography::{
    bls12381::{
        dkg::{dealer, player},
        primitives::{group, poly},
    },
    PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::{hex, quorum};
use futures::{channel::mpsc, SinkExt};
use prost::Message;
use rand::Rng;
use std::{collections::HashMap, time::Duration};
use tracing::{debug, info, warn};

/// A DKG/Resharing contributor that can be configured to behave honestly
/// or deviate as a rogue, lazy, or defiant participant.
pub struct Contributor<E: Clock + Rng, C: Scheme> {
    runtime: E,
    crypto: C,
    dkg_phase_timeout: Duration,
    arbiter: PublicKey,
    t: u32,
    contributors: Vec<PublicKey>,
    contributors_ordered: HashMap<PublicKey, u32>,
    corrupt: bool,
    lazy: bool,
    forger: bool,

    signatures: mpsc::Sender<(u64, player::Output)>,
}

impl<E: Clock + Rng, C: Scheme> Contributor<E, C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: E,
        crypto: C,
        dkg_phase_timeout: Duration,
        arbiter: PublicKey,
        mut contributors: Vec<PublicKey>,
        corrupt: bool,
        lazy: bool,
        forger: bool,
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
                corrupt,
                lazy,
                forger,

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
            let serialized_commitment = commitment.serialize();
            Some((
                p0,
                commitment,
                serialized_commitment,
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
            let mut sent = 0;
            for (idx, player) in self.contributors.iter().enumerate() {
                // Send to self
                let share = shares[idx];
                if idx == me_idx as usize {
                    player_obj
                        .share(me.clone(), commitment.clone(), share)
                        .unwrap();
                    p0.ack(me.clone()).unwrap();
                    let payload = payload(round, &me, serialized_commitment);
                    let signature = self.crypto.sign(Some(ACK_NAMESPACE), &payload);
                    acks.insert(me_idx, signature);
                    continue;
                }

                // Send to others
                let mut serialized_share = shares[idx].serialize();
                if self.forger {
                    // If we are a forger, don't send any shares and instead create fake signatures.
                    let _ = p0.ack(player.clone());
                    let mut signature = vec![0u8; C::len().1];
                    self.runtime.fill_bytes(&mut signature);
                    acks.insert(idx as u32, signature.into());
                    warn!(
                        round,
                        player = hex(player),
                        "not sending share because forger"
                    );
                    continue;
                }
                if self.corrupt {
                    // If we are corrupt, randomly modify the share.
                    serialized_share = group::Share {
                        index: share.index,
                        private: group::Scalar::rand(&mut self.runtime),
                    }
                    .serialize();
                    warn!(round, player = hex(player), "modified share");
                }
                if self.lazy && sent == self.t - 1 {
                    // This will still lead to the commitment being used (>= t acks) because
                    // the dealer has already acked.
                    warn!(
                        round,
                        player = hex(player),
                        "not sending share because lazy"
                    );
                    continue;
                }
                let success = sender
                    .send(
                        Recipients::One(player.clone()),
                        wire::Dkg {
                            round,
                            payload: Some(wire::dkg::Payload::Share(wire::Share {
                                commitment: serialized_commitment.clone(),
                                share: serialized_share,
                            })),
                        }
                        .encode_to_vec()
                        .into(),
                        true,
                    )
                    .await
                    .expect("could not send share");
                if success.is_empty() {
                    warn!(round, player = hex(player), "failed to send share");
                } else {
                    debug!(round, player = hex(player), "sent share");
                    sent += 1;
                }
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
                                match msg.payload {
                                    Some(wire::dkg::Payload::Ack(msg)) => {
                                        // Skip if not dealing
                                        let Some((p0, _, commitment, _, acks)) = &mut dealer_obj else {
                                            continue;
                                        };

                                        // Skip if forger
                                        if self.forger {
                                            continue;
                                        }

                                        // Verify index matches
                                        let Some(player) = self.contributors.get(msg.public_key as usize) else {
                                            continue;
                                        };
                                        if player != &s {
                                            warn!(round, "received ack with wrong index");
                                            continue;
                                        }

                                        // Verify signature on incoming ack
                                        let payload = payload(round, &me, commitment);
                                        if !C::verify(Some(ACK_NAMESPACE), &payload, &s, &msg.signature) {
                                            warn!(round, sender = hex(&s), "received invalid ack signature");
                                            continue;
                                        }

                                        // Store ack
                                        let _ = p0.ack(s);
                                        acks.insert(msg.public_key, msg.signature);

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
                                        if let Err(e) = player_obj.share(s.clone(), commitment, share){
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
        if let Some((_, _, serialized_commitment, shares, acks)) = dealer_obj {
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
            debug!(
                round,
                acks = ack_vec.len(),
                reveals = reveals.len(),
                "sending commitment to arbiter"
            );
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

        // Wait for message from arbiter
        loop {
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
                    if s != self.arbiter {
                        continue;
                    }
                    let msg = match msg.payload {
                        Some(wire::dkg::Payload::Success(msg)) => msg,
                        _ => {
                            warn!(round, "didn't receive success message");
                            return (round, None);
                        }
                    };

                    // Handle success
                    debug!(
                        round,
                        commitments = msg.commitments.len(),
                        reveals = msg.reveals.len(),
                        "finalizing round"
                    );
                    let mut commitments = HashMap::new();
                    for (idx, commitment) in msg.commitments {
                        let commitment = match poly::Public::deserialize(&commitment, self.t) {
                            Some(commitment) => commitment,
                            None => {
                                warn!(round, "received invalid commitment");
                                continue;
                            }
                        };
                        commitments.insert(idx, commitment);
                    }
                    if should_deal && !commitments.contains_key(&me_idx) {
                        warn!(round, "commitment not included");
                    }
                    let mut reveals = HashMap::new();
                    for (idx, share) in msg.reveals {
                        let share = match group::Share::deserialize(&share) {
                            Some(share) => share,
                            None => {
                                warn!(round, "received invalid share");
                                continue;
                            }
                        };
                        reveals.insert(idx, share);
                    }
                    let Ok(output) = player_obj.finalize(commitments, reveals) else {
                        warn!(round, "failed to finalize round");
                        return (round, None);
                    };
                    return (round, Some(output));
                }
                Err(err) => {
                    debug!(?err, "did not receive success message");
                    return (round, None);
                }
            }
        }
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        if self.corrupt {
            warn!("running as corrupt player");
        }
        if self.lazy {
            warn!("running as lazy player");
        }
        if self.forger {
            warn!("running as forger player");
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
                    info!(round, public = public_hex(&output.public), "round complete");

                    // Generate signature over round
                    self.signatures.send((round, output.clone())).await.unwrap();

                    // Update state
                    previous = Some(output);
                }
            }
        }
    }
}
