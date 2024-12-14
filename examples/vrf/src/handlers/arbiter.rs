use crate::handlers::{
    utils::{payload, public_hex, SHARE_NAMESPACE},
    wire,
};
use commonware_cryptography::{
    bls12381::{
        idkg::arbiter::P0,
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
use std::{collections::HashSet, time::Duration};
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
        let t_commitment = start + self.dkg_phase_timeout;
        let t_ack = start + self.dkg_phase_timeout * 2;

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
                _ = self.runtime.sleep_until(t_commitment) => {
                    debug!("commitment phase timed out");
                    break
                },
                result = receiver.recv() => {
                    match result {
                        Ok((sender, msg)) =>{
                            let msg = match wire::Dkg::decode(msg) {
                                Ok(msg) => msg,
                                Err(_) => {
                                    p0.disqualify(sender);
                                    continue;
                                }
                            };
                            if msg.round != round {
                                p0.disqualify(sender);
                                continue;
                            }
                            let msg = match msg.payload {
                                Some(wire::dkg::Payload::Commitment(msg)) => msg,
                                _ => {
                                    p0.disqualify(sender);
                                    continue;
                                }
                            };
                            let commitment = match poly::Public::deserialize(&msg.commitment, self.t) {
                                Some(commitment) => commitment,
                                None => {
                                    p0.disqualify(sender);
                                    continue;
                                }
                            };
                            let _ = p0.commitment(sender, commitment);

                            // Check if we are ready to move to next phase
                            if p0.ready() {
                                debug!(round, "commitment phase ready");
                                break;
                            }
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
        let (p1, disqualified) = p0.finalize();
        let mut p1 = match p1 {
            Some(p1) => p1,
            None => {
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

        let commitments = p1.commitments();
        info!(
            round,
            commitments = ?commitments.iter().map(|(_, pk, _)| hex(pk)).collect::<Vec<_>>(),
            disqualified = ?disqualified
                .into_iter()
                .map(|pk| hex(&pk))
                .collect::<Vec<_>>(),
            "commitment phase complete"
        );

        // Send all commitments on preferred group
        let mut dealers = Vec::with_capacity(commitments.len());
        for (dealer, _, commitment) in &commitments {
            dealers.push(wire::Dealer {
                dealer: *dealer,
                commitment: commitment.serialize(),
            });
        }
        sender
            .send(
                Recipients::All,
                wire::Dkg {
                    round,
                    payload: Some(wire::dkg::Payload::Commitments(wire::Commitments {
                        dealers,
                    })),
                }
                .encode_to_vec()
                .into(),
                false,
            )
            .await
            .expect("failed to send commitments");

        // Collect acks and complaints
        loop {
            select! {
                _ = self.runtime.sleep_until(t_ack) => {
                    debug!("ack phase timed out");
                    break
                },
                result = receiver.recv() => {
                    match result {
                        Ok((sender, msg)) =>{
                            // Parse message as Ack or Complaint
                            let msg = match wire::Dkg::decode(msg) {
                                Ok(msg) => msg,
                                Err(_) => {
                                    p1.disqualify(sender);
                                    continue;
                                }
                            };

                            // Verify the message
                            if msg.round != round {
                                p1.disqualify(sender);
                                continue;
                            }

                            match msg.payload{
                                Some(wire::dkg::Payload::Ack(ack)) => {
                                    let _ = p1.ack(sender, ack.dealer);
                                }
                                Some(wire::dkg::Payload::Complaint(complaint)) => {
                                    let share = match group::Share::deserialize(&complaint.share) {
                                        Some(share) => share,
                                        None => {
                                            p1.disqualify(sender);
                                            continue;
                                        }
                                    };
                                    let bad_dealer = match p1.dealer(complaint.dealer) {
                                        Some(bad_dealer) => bad_dealer,
                                        None => {
                                            p1.disqualify(sender);
                                            continue;
                                        }
                                    };
                                    let payload = payload(round, complaint.dealer, &complaint.share);
                                    if !C::verify(SHARE_NAMESPACE, &payload, &bad_dealer, &complaint.signature) {
                                        p1.disqualify(sender);
                                        continue;
                                    }
                                    let _ = p1.complaint(sender, complaint.dealer, &share);
                                }
                                _ => {
                                    p1.disqualify(sender);
                                    continue
                                }
                            }

                            // Check if we are ready to move to next phase
                            if p1.ready() {
                                debug!(round, "ack phase ready");
                                break;
                            }
                        }
                        Err(err) => {
                            warn!(round, ?err, "failed to receive ack or complaint");
                            break;
                        }
                    };
                }
            }
        }

        // Finalize P1
        let (result, disqualified) = p1.finalize();
        let result = match result {
            Ok(result) => result,
            Err(e) => {
                warn!(round, error=?e,  "unable to recover public key");
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
        info!(
            round,
            commitments = ?commitments.iter().map(|(_, pk, _)| hex(pk)).collect::<Vec<_>>(),
            disqualified = ?disqualified
                .iter()
                .map(|pk| hex(pk))
                .collect::<Vec<_>>(),
            "ack phase complete"
        );

        // Broadcast commitments
        sender
            .send(
                Recipients::All,
                wire::Dkg {
                    round,
                    payload: Some(wire::dkg::Payload::Success(wire::Success {
                        dealers: result.commitments,
                    })),
                }
                .encode_to_vec()
                .into(),
                true,
            )
            .await
            .expect("failed to send success message");
        (Some(result.public), disqualified)
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
