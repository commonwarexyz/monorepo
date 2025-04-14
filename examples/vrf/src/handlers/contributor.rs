use crate::handlers::{
    utils::{payload, public_hex, ACK_NAMESPACE},
    wire,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    bls12381::{
        dkg::{player::Output, Dealer, Player},
        primitives::group,
    },
    Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::quorum;
use futures::{channel::mpsc, SinkExt};
use rand::Rng;
use std::{collections::HashMap, time::Duration};
use tracing::{debug, info, warn};

/// A DKG/Resharing contributor that can be configured to behave honestly
/// or deviate as a rogue, lazy, or forger.
pub struct Contributor<E: Clock + Rng + Spawner, C: Scheme> {
    context: E,
    crypto: C,
    dkg_phase_timeout: Duration,
    arbiter: C::PublicKey,
    t: u32,
    contributors: Vec<C::PublicKey>,
    contributors_ordered: HashMap<C::PublicKey, u32>,

    corrupt: bool,
    lazy: bool,
    forger: bool,

    signatures: mpsc::Sender<(u64, Output)>,
}

impl<E: Clock + Rng + Spawner, C: Scheme> Contributor<E, C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: E,
        crypto: C,
        dkg_phase_timeout: Duration,
        arbiter: C::PublicKey,
        mut contributors: Vec<C::PublicKey>,
        corrupt: bool,
        lazy: bool,
        forger: bool,
    ) -> (Self, mpsc::Receiver<(u64, Output)>) {
        contributors.sort();
        let contributors_ordered: HashMap<C::PublicKey, u32> = contributors
            .iter()
            .enumerate()
            .map(|(idx, pk)| (pk.clone(), idx as u32))
            .collect();
        let (sender, receiver) = mpsc::channel(32);
        (
            Self {
                context,
                crypto,
                dkg_phase_timeout,
                arbiter,
                t: quorum(contributors.len() as u32),
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
        previous: Option<&Output>,
        sender: &mut impl Sender<PublicKey = C::PublicKey>,
        receiver: &mut impl Receiver<PublicKey = C::PublicKey>,
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
                    let msg = match wire::DKG::decode_cfg(msg, &(self.t as usize)) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, "received invalid message from arbiter");
                            continue;
                        }
                    };
                    let round = msg.round;
                    let wire::Payload::Start { group } = msg.payload else {
                        // This could happen if out-of-sync on phase.
                        return (round, None);
                    };
                    break (group, round);
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
            let (dealer, commitment, shares) =
                Dealer::new(&mut self.context, previous, self.contributors.clone());
            Some((dealer, commitment, shares, HashMap::new()))
        } else {
            None
        };

        // Create player
        let mut player_obj = Player::new(
            me.clone(),
            public.clone(),
            self.contributors.clone(),
            self.contributors.clone(),
            1,
        );

        // Distribute shares
        if let Some((dealer, commitment, shares, acks)) = &mut dealer_obj {
            let mut sent = 0;
            for (idx, player) in self.contributors.iter().enumerate() {
                // Send to self
                let share = shares[idx];
                if idx == me_idx as usize {
                    player_obj
                        .share(me.clone(), commitment.clone(), share)
                        .unwrap();
                    dealer.ack(me.clone()).unwrap();
                    let payload = payload(round, &me, commitment);
                    let signature = self.crypto.sign(Some(ACK_NAMESPACE), &payload);
                    acks.insert(me_idx, signature);
                    continue;
                }

                // Send to others
                if self.forger {
                    // If we are a forger, don't send any shares and instead create fake signatures.
                    let _ = dealer.ack(player.clone());
                    let signature = self.crypto.sign(None, b"fake");
                    acks.insert(idx as u32, signature);
                    warn!(round, ?player, "not sending share because forger");
                    continue;
                }
                if self.corrupt {
                    // If we are corrupt, randomly modify the share.
                    share = group::Share {
                        index: share.index,
                        private: group::Scalar::rand(&mut self.context),
                    };
                    warn!(round, ?player, "modified share");
                }
                if self.lazy && sent == self.t - 1 {
                    // This will still lead to the commitment being used (>= t acks) because
                    // the dealer has already acked.
                    warn!(round, ?player, "not sending share because lazy");
                    continue;
                }
                let success = sender
                    .send(
                        Recipients::One(player.clone()),
                        wire::DKG {
                            round,
                            payload: wire::Payload::Share {
                                commitment: commitment.clone(),
                                share,
                            },
                        }
                        .encode()
                        .into(),
                        true,
                    )
                    .await
                    .expect("could not send share");
                if success.is_empty() {
                    warn!(round, ?player, "failed to send share");
                } else {
                    debug!(round, ?player, "sent share");
                    sent += 1;
                }
            }
        }

        // Respond to commitments and wait for acks
        let t = self.context.current() + 2 * self.dkg_phase_timeout;
        loop {
            select! {
                    _ = self.context.sleep_until(t) => {
                        debug!(round, "ack timeout");
                        break;
                    },
                    result = receiver.recv() => {
                        match result {
                            Ok((s, msg)) => {
                                let msg = match wire::DKG::decode_cfg(msg, &(self.t as usize)) {
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
                                    wire::Payload::Ack(msg) => {
                                        // Skip if not dealing
                                        let Some((dealer, _, commitment, acks)) = &mut dealer_obj else {
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
                                        let Ok(signature) = C::Signature::try_from(&msg.signature) else {
                                            warn!(round, sender = ?s, "received invalid ack signature");
                                            continue;
                                        };
                                        if !C::verify(Some(ACK_NAMESPACE), &payload, &s, &signature) {
                                            warn!(round, sender = ?s, "received invalid ack signature");
                                            continue;
                                        }

                                        // Store ack
                                        if let Err(e) = dealer.ack(s.clone()) {
                                            warn!(round, error = ?e, sender = ?s, "failed to record ack");
                                            continue;
                                        }
                                        acks.insert(msg.public_key, signature);

                                    },
                                    wire::Payload::Share{ commitment, share } => {
                                        // Store share
                                        if let Err(e) = player_obj.share(s.clone(), commitment, share){
                                            warn!(round, error = ?e, "failed to store share");
                                            continue;
                                        }

                                        // Send ack
                                        let payload = payload(round, &s, &commitment);
                                        let signature = self.crypto.sign(Some(ACK_NAMESPACE), &payload);
                                        sender
                                            .send(
                                                Recipients::One(s),
                                                wire::DKG {
                                                    round,
                                                    payload: wire::Payload::Ack(wire::Ack {
                                                        public_key: me_idx,
                                                        signature,
                                                    }),
                                                }
                                                .encode()
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
                            Err(e) => {
                                debug!(round, error = ?e, "unable to read message");
                                return (round, None);
                            }
                        }
                    }
            }
        }

        // Send commitment to arbiter
        if let Some((_, commitment, shares, acks)) = dealer_obj {
            let mut ack_vec: Vec<wire::Ack<C::Signature>> = Vec::with_capacity(acks.len());
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
                        reveals.push(shares[idx as usize]);
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
                    wire::DKG {
                        round,
                        payload: wire::Payload::Commitment {
                            commitment,
                            acks: ack_vec,
                            reveals,
                        },
                    }
                    .encode()
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
                    let msg = match wire::DKG::decode_cfg(msg, &(self.t as usize)) {
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
                    let (commitments, reveals) = match msg.payload {
                        wire::Payload::Success {
                            commitments,
                            reveals,
                        } => (commitments, reveals),
                        wire::Payload::Abort => {
                            warn!(round, "received abort message");
                            return (round, None);
                        }
                        _ => {
                            warn!(round, "received unexpected message");
                            return (round, None);
                        }
                    };

                    // Handle success
                    debug!(
                        round,
                        commitments = commitments.len(),
                        reveals = reveals.len(),
                        "finalizing round"
                    );
                    if should_deal && !commitments.contains_key(&me_idx) {
                        warn!(round, "commitment not included");
                    }
                    let Ok(output) = player_obj.finalize(commitments, reveals) else {
                        warn!(round, "failed to finalize round");
                        return (round, None);
                    };
                    return (round, Some(output));
                }
                Err(e) => {
                    debug!(error = ?e, "unable to read message");
                    return (round, None);
                }
            }
        }
    }

    pub fn start(
        mut self,
        sender: impl Sender<PublicKey = C::PublicKey>,
        receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) {
        self.context.spawn_ref()(self.run(sender, receiver));
    }

    async fn run(
        mut self,
        mut sender: impl Sender<PublicKey = C::PublicKey>,
        mut receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) {
        if self.corrupt {
            warn!("running as corrupt");
        }
        if self.lazy {
            warn!("running as lazy");
        }
        if self.forger {
            warn!("running as forger");
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
                    info!(round, public = public_hex(&output.public), "round success");

                    // Generate signature over round
                    self.signatures.send((round, output.clone())).await.unwrap();

                    // Update state
                    previous = Some(output);
                }
            }
        }
    }
}
