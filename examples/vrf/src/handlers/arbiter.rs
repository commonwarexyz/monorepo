use crate::handlers::{
    utils::{payload, public_hex, ACK_NAMESPACE},
    wire,
};
use commonware_cryptography::{
    bls12381::{
        dkg::arbiter::P0,
        primitives::{
            group::{self, Element},
            poly,
        },
    },
    PublicKey, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::hex;
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tracing::{debug, info, warn};

pub struct Arbiter<E: Clock> {
    runtime: E,

    dkg_frequency: Duration,
    dkg_phase_timeout: Duration,

    players: Vec<PublicKey>,
    t: u32,
}

/// Implementation of a "trusted arbiter" that tracks commitments,
/// acknowledgements, and complaints during a DKG round.
impl<E: Clock> Arbiter<E> {
    pub fn new(
        runtime: E,
        dkg_frequency: Duration,
        dkg_phase_timeout: Duration,
        mut players: Vec<PublicKey>,
        t: u32,
    ) -> Self {
        players.sort();
        Self {
            runtime,

            dkg_frequency,
            dkg_phase_timeout,

            players,
            t,
        }
    }

    async fn run_round<C: Scheme>(
        &self,
        round: u64,
        previous: Option<poly::Public>,
        sender: &mut impl Sender,
        receiver: &mut impl Receiver,
    ) -> (Option<poly::Public>, HashSet<PublicKey>) {
        // Create a new round
        let start = self.runtime.current();
        let t = start + 3 * self.dkg_phase_timeout;

        // Send round start message to players
        let mut group = None;
        if let Some(previous) = &previous {
            group = Some(previous.serialize());
            let public = poly::public(previous).serialize();
            info!(round, public = hex(&public), "starting reshare");
        } else {
            info!(round, "starting key generation");
        }
        sender
            .send(
                Recipients::All,
                wire::Dkg {
                    round,
                    payload: Some(wire::dkg::Payload::Start(wire::Start { group })),
                }
                .encode_to_vec()
                .into(),
                true,
            )
            .await
            .expect("failed to send start message");

        // Collect commitments
        let mut p0 = P0::new(previous, self.players.clone(), self.players.clone(), 1);
        loop {
            select! {
                _ = self.runtime.sleep_until(t) => {
                    debug!("commitment phase timed out");
                    break
                },
                result = receiver.recv() => {
                    match result {
                        Ok((sender, msg)) =>{
                            // Parse msg
                            let msg = match wire::Dkg::decode(msg) {
                                Ok(msg) => msg,
                                Err(_) => {
                                    p0.disqualify(sender);
                                    continue;
                                }
                            };
                            if msg.round != round {
                                continue;
                            }
                            let msg = match msg.payload {
                                Some(wire::dkg::Payload::Commitment(msg)) => msg,
                                _ => {
                                    // Useless message from previous step
                                    continue;
                                }
                            };

                            // Parse commitment
                            let commitment = match poly::Public::deserialize(&msg.commitment, self.t) {
                                Some(commitment) => commitment,
                                None => {
                                    p0.disqualify(sender);
                                    continue;
                                }
                            };

                            // Parse acks
                            let mut disqualify = false;
                            let mut acks = Vec::new();
                            for ack in &msg.acks {
                                let Some(public_key) = self.players.get(ack.public_key as usize) else {
                                    disqualify = true;
                                    break;
                                };
                                let payload = payload(round, &sender, &msg.commitment);
                                if !C::verify(Some(ACK_NAMESPACE), &payload, &public_key, &ack.signature) {
                                    disqualify= true;
                                    break;
                                }
                                acks.push(ack.public_key);
                            }
                            if disqualify {
                                p0.disqualify(sender);
                                continue;
                            }

                            // Parse reveals
                            let mut reveals = Vec::new();
                            for reveal in &msg.reveals {
                                let share = match group::Share::deserialize(reveal) {
                                    Some(share) => share,
                                    None => {
                                        disqualify = true;
                                        break;
                                    }
                                };
                                reveals.push(share);
                            }
                            if disqualify {
                                p0.disqualify(sender);
                                continue;
                            }

                            // Check dealer commitment
                            //
                            // Any faults here will be considered as a disqualification.
                            let _ = p0.commitment(sender, commitment, acks, reveals);
                        },
                        Err(err) => {
                            warn!(round, ?err, "failed to receive commitment");
                            break;
                        }
                    };
                }
            }
        }

        // Finalize P0
        let (result, disqualified) = p0.finalize();
        let output = match result {
            Ok(output) => output,
            Err(e) => {
                warn!(round, error=?e, "unable to complete");
                sender
                    .send(
                        Recipients::All,
                        wire::Dkg {
                            round,
                            payload: Some(wire::dkg::Payload::Abort(wire::Abort {})),
                        }
                        .encode_to_vec()
                        .into(),
                        true,
                    )
                    .await
                    .expect("failed to send abort message");
                return (None, disqualified);
            }
        };

        // Send commitments and reveals to all players
        info!(
            round,
            // commitments = ?commitments.iter().map(|(_, pk, _)| hex(pk)).collect::<Vec<_>>(),
            disqualified = ?disqualified
                .iter()
                .map(|pk| hex(pk))
                .collect::<Vec<_>>(),
            "ack phase complete"
        );

        // Broadcast commitments
        let mut commitments = HashMap::new();
        for (dealer_idx, commitment) in output.commitments {
            commitments.insert(dealer_idx, commitment.serialize());
        }
        let mut reveals = HashMap::new();
        for (dealer_idx, shares) in output.reveals {
            for share in shares {
                reveals
                    .entry(share.index)
                    .or_insert_with(HashMap::new)
                    .insert(dealer_idx, share.serialize());
            }
        }
        for (player_idx, player) in self.players.iter().enumerate() {
            let reveals = reveals.remove(&(player_idx as u32)).unwrap_or_default();
            sender
                .send(
                    Recipients::One(player.clone()),
                    wire::Dkg {
                        round,
                        payload: Some(wire::dkg::Payload::Success(wire::Success {
                            commitments: commitments.clone(),
                            reveals: reveals.clone(),
                        })),
                    }
                    .encode_to_vec()
                    .into(),
                    true,
                )
                .await
                .expect("failed to send success message");
        }
        (Some(output.public), disqualified)
    }

    pub async fn run<C: Scheme>(self, mut sender: impl Sender, mut receiver: impl Receiver) {
        let mut round = 0;
        let mut previous = None;
        loop {
            let (public, disqualified) = self
                .run_round::<C>(round, previous.clone(), &mut sender, &mut receiver)
                .await;

            // Log round results
            match public {
                Some(public) => {
                    info!(
                        round,
                        public = public_hex(&public),
                        disqualified = ?disqualified.into_iter().map(|pk| hex(&pk)).collect::<Vec<_>>(),
                        "round complete"
                    );

                    // Only update previous if the round was successful
                    previous = Some(public);
                }
                None => {
                    info!(round, disqualified = ?disqualified.into_iter().map(|pk| hex(&pk)).collect::<Vec<_>>(), "round aborted");
                }
            }

            // Update state
            round += 1;

            // Wait for next round
            self.runtime.sleep(self.dkg_frequency).await;
        }
    }
}
