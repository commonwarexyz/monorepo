use crate::handlers::{wire, ACK_NAMESPACE};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    bls12381::{
        dkg::{
            player::Output,
            types::{Ack, Share},
            Dealer, Player,
        },
        primitives::{group, variant::MinSig},
    },
    Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Spawner};
use commonware_utils::{ordered::Set, quorum};
use futures::{channel::mpsc, SinkExt};
use rand_core::CryptoRngCore;
use std::time::Duration;
use tracing::{debug, info, warn};

/// A DKG/Resharing contributor that can be configured to behave honestly
/// or deviate as a rogue, lazy, or forger.
pub struct Contributor<E: Clock + CryptoRngCore + Spawner, C: Signer> {
    context: ContextCell<E>,
    crypto: C,
    dkg_phase_timeout: Duration,
    arbiter: C::PublicKey,
    t: u32,
    contributors: Set<C::PublicKey>,

    corrupt: bool,
    lazy: bool,
    forger: bool,

    signatures: mpsc::Sender<(u64, Output<MinSig>)>,
}

impl<E: Clock + CryptoRngCore + Spawner, C: Signer> Contributor<E, C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: E,
        crypto: C,
        dkg_phase_timeout: Duration,
        arbiter: C::PublicKey,
        contributors: Set<C::PublicKey>,
        corrupt: bool,
        lazy: bool,
        forger: bool,
    ) -> (Self, mpsc::Receiver<(u64, Output<MinSig>)>) {
        let (sender, receiver) = mpsc::channel(32);
        (
            Self {
                context: ContextCell::new(context),
                crypto,
                dkg_phase_timeout,
                arbiter,
                t: quorum(contributors.len() as u32),
                contributors,

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
        previous: Option<&Output<MinSig>>,
        sender: &mut impl Sender<PublicKey = C::PublicKey>,
        receiver: &mut impl Receiver<PublicKey = C::PublicKey>,
    ) -> (u64, Option<Output<MinSig>>) {
        // Configure me
        let me = self.crypto.public_key();
        let me_idx = self.contributors.position(&me).unwrap() as u32;

        // Wait for start message from arbiter
        let (public, round) = loop {
            match receiver.recv().await {
                Ok((sender, msg)) => {
                    if sender != self.arbiter {
                        debug!("dropping messages until receive start message from arbiter");
                        continue;
                    }
                    let msg = match wire::Dkg::<C::Signature>::decode_cfg(
                        msg,
                        &self.contributors.len(),
                    ) {
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
                    expected = ?previous.public,
                    "previous group polynomial but found none"
                );
                should_deal = false;
            }
            (Some(previous), Some(public)) => {
                if previous.public != *public {
                    warn!(
                        expected = ?previous.public,
                        found = ?public,
                        "group polynomial does not match expected"
                    );
                    should_deal = false;
                }
            }
            (None, Some(public)) => {
                warn!(
                    found = ?public,
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
            let previous = previous.map(|previous| previous.share.clone());
            let (dealer, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut self.context, previous, self.contributors.clone());
            Some((dealer, commitment, shares, Vec::new()))
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
                let mut share = shares[idx].clone();
                if idx == me_idx as usize {
                    player_obj
                        .share(me.clone(), commitment.clone(), share)
                        .unwrap();
                    dealer.ack(me.clone()).unwrap();
                    acks.push(Ack::new::<_, MinSig>(
                        ACK_NAMESPACE,
                        &self.crypto,
                        me_idx,
                        round,
                        &me,
                        commitment,
                    ));
                    continue;
                }

                // Send to others
                if self.forger {
                    // If we are a forger, don't send any shares and instead create fake signatures.
                    let _ = dealer.ack(player.clone());
                    let signature = self.crypto.sign(b"fake", b"fake");
                    acks.push(Ack {
                        player: idx as u32,
                        signature,
                    });
                    warn!(round, ?player, "not sending share because forger");
                    continue;
                }
                if self.corrupt {
                    // If we are corrupt, randomly modify the share.
                    share = group::Share {
                        index: share.index,
                        private: group::Scalar::from_rand(&mut self.context),
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
                        wire::Dkg::<C::Signature> {
                            round,
                            payload: wire::Payload::Share(Share::new(commitment.clone(), share)),
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
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping round");
                return (round, None);
            },
            _ = self.context.sleep_until(t) => {
                debug!(round, "ack timeout");
                break;
            },
            result = receiver.recv() => {
                match result {
                    Ok((peer, msg)) => {
                        let msg = match wire::Dkg::<C::Signature>::decode_cfg(msg, &self.contributors.len()) {
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
                            wire::Payload::Ack(ack) => {
                                // Skip if not dealing
                                let Some((dealer, commitment, _, acks)) = &mut dealer_obj else {
                                    continue;
                                };

                                // Skip if forger
                                if self.forger {
                                    continue;
                                }

                                // Verify index matches
                                let Some(player) = self.contributors.get(ack.player as usize) else {
                                    continue;
                                };
                                if player != &peer {
                                    warn!(round, ?peer, "received ack with wrong index");
                                    continue;
                                }

                                // Verify signature on incoming ack
                                if !ack.verify::<MinSig, _>(ACK_NAMESPACE, &peer, round, &me, commitment) {
                                    warn!(round, ?peer, "received invalid ack signature");
                                    continue;
                                }

                                // Store ack
                                if let Err(e) = dealer.ack(peer) {
                                    warn!(round, error = ?e, "failed to record ack");
                                    continue;
                                }
                                acks.push(ack);
                            },
                            wire::Payload::Share(Share {  commitment, share }) => {
                                // Store share
                                if let Err(e) = player_obj.share(peer.clone(), commitment.clone(), share){
                                    warn!(round, error = ?e, "failed to store share");
                                    continue;
                                }

                                // Send ack
                                let ack = Ack::new::<C, MinSig>(
                                    ACK_NAMESPACE,
                                    &self.crypto,
                                    me_idx,
                                    round,
                                    &peer,
                                    &commitment
                                );
                                sender
                                    .send(
                                        Recipients::One(peer),
                                        wire::Dkg {
                                            round,
                                            payload: wire::Payload::Ack(ack),
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

        // Send commitment to arbiter
        if let Some((_, commitment, shares, acks)) = dealer_obj {
            let mut reveals = Vec::new();
            for idx in 0..self.contributors.len() as u32 {
                if !acks.iter().any(|a| a.player == idx) {
                    reveals.push(shares[idx as usize].clone());
                }
            }
            debug!(
                round,
                acks = acks.len(),
                reveals = reveals.len(),
                "sending commitment to arbiter"
            );
            sender
                .send(
                    Recipients::One(self.arbiter.clone()),
                    wire::Dkg {
                        round,
                        payload: wire::Payload::Commitment {
                            commitment,
                            acks,
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
                Ok((peer, msg)) => {
                    let msg = match wire::Dkg::<C::Signature>::decode_cfg(
                        msg,
                        &self.contributors.len(),
                    ) {
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
                    if peer != self.arbiter {
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
        spawn_cell!(self.context, self.run(sender, receiver).await);
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
                    info!(round, public = ?output.public, "round success");

                    // Generate signature over round
                    self.signatures.send((round, output.clone())).await.unwrap();

                    // Update state
                    previous = Some(output);
                }
            }
        }
    }
}
