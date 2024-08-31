use crate::handlers::{
    utils::{payload, public_hex, SHARE_NAMESPACE},
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
    utils::hex,
    PublicKey, Scheme,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tokio::{select, time};
use tracing::{debug, info, warn};

pub struct Arbiter {
    dkg_frequency: Duration,
    dkg_phase_timeout: Duration,

    players: Vec<PublicKey>,
    t: u32,
}

/// Implementation of a "trusted arbiter" that tracks commitments,
/// acknoledgements, complaints, and reveals during a DKG round.
///
/// Following the release of `commonware-consensus`, this will be
/// updated to use the "replicated arbiter" pattern.
impl Arbiter {
    pub fn new(
        dkg_frequency: Duration,
        dkg_phase_timeout: Duration,
        mut players: Vec<PublicKey>,
        t: u32,
    ) -> Self {
        players.sort();
        Self {
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
        sender: &Sender,
        receiver: &mut Receiver,
    ) -> (Option<poly::Public>, HashSet<PublicKey>) {
        // Create a new round
        let start = tokio::time::Instant::now();
        let t_commitment = start + self.dkg_phase_timeout;
        let t_ack = start + self.dkg_phase_timeout * 2;
        let t_repair = start + self.dkg_phase_timeout * 3;

        // Send round start message to players
        let mut group = None;
        if let Some(previous) = &previous {
            group = Some(previous.serialize());
            let public = poly::public(previous).serialize();
            info!(round, public = hex(&public.into()), "starting reshare");
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
        let mut p0 = P0::new(
            self.t,
            previous,
            self.players.clone(),
            self.players.clone(),
            1,
        );
        loop {
            select! {
                biased;

                _ = tokio::time::sleep_until(t_commitment) => {
                    debug!("commitment phase timed out");
                    break
                }
                result = receiver.recv() => match result {
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
                    },
                    Err(err) => {
                        warn!(round, ?err, "failed to receive commitment");
                        break;
                    }
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
                biased;

                _ = tokio::time::sleep_until(t_ack) => {
                    debug!("ack phase timed out");
                    break
                }
                result = receiver.recv() => match result {
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
                    }
                    Err(err) => {
                        warn!(round, ?err, "failed to receive ack or complaint");
                        break;
                    }
                }
            }
        }

        // Finalize P1
        let (p2, disqualified) = p1.finalize();

        // Abort if not `t` dealings each with at least `t` acks
        let (mut p2, requests) = match p2 {
            Some(p2) => p2,
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
        let commitments = p2.commitments();
        info!(
            round,
            commitments = ?commitments.iter().map(|(_, pk, _)| hex(pk)).collect::<Vec<_>>(),
            disqualified = ?disqualified.into_iter().map(|pk| hex(&pk)).collect::<Vec<_>>(),
            "ack phase complete"
        );

        // If no shares to reveal, broadcast success
        if requests.is_empty() {
            debug!(round, "no shares to reveal, recovering public key");

            let (result, disqualified) = p2.finalize();
            if let Err(e) = result {
                warn!(round, error=?e, "unable to recover public key");
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

            let result = result.unwrap();
            sender
                .send(
                    Recipients::All,
                    wire::Dkg {
                        round,
                        payload: Some(wire::dkg::Payload::Success(wire::Success {
                            dealers: result.commitments,
                            resolutions: Vec::new(),
                        })),
                    }
                    .encode_to_vec()
                    .into(),
                    true,
                )
                .await
                .expect("failed to send success message");
            return (Some(result.public), disqualified);
        }

        // Broadcast missing shares
        let mut missing = Vec::new();
        for (dealer, recipient) in &requests {
            missing.push(wire::Request {
                dealer: *dealer,
                share: *recipient,
            });
        }
        debug!(round, missing = missing.len(), "requesting missing shares");
        sender
            .send(
                Recipients::All,
                wire::Dkg {
                    round,
                    payload: Some(wire::dkg::Payload::Missing(wire::Missing {
                        shares: missing,
                    })),
                }
                .encode_to_vec()
                .into(),
                false,
            )
            .await
            .expect("failed to send missing shares");

        // Collect missing shares
        let mut signatures = HashMap::new();
        loop {
            select! {
                biased;

                _ = tokio::time::sleep_until(t_repair) => {
                    break
                }
                result = receiver.recv() => match result {
                    Ok((sender, msg)) => {
                        let msg = match wire::Dkg::decode(msg) {
                            Ok(msg) => msg,
                            Err(_) => {
                                p2.disqualify(sender);
                                continue;
                            }
                        };
                        if msg.round != round {
                            p2.disqualify(sender);
                            continue;
                        }
                        let msg = match msg.payload {
                            Some(wire::dkg::Payload::Reveal(msg)) => msg,
                            _ => {
                                p2.disqualify(sender);
                                continue;
                            }
                        };
                        let share = match group::Share::deserialize(&msg.share) {
                            Some(share) => share,
                            None => {
                                p2.disqualify(sender);
                                continue;
                            }
                        };
                        let dealer = match p2.dealer(&sender) {
                            Some(dealer) => dealer,
                            None => {
                                p2.disqualify(sender);
                                continue;
                            }
                        };
                        let payload = payload(round, dealer, &msg.share);
                        if !C::verify(SHARE_NAMESPACE, &payload, &sender, &msg.signature) {
                            p2.disqualify(sender);
                            continue;
                        }
                        match p2.reveal(sender.clone(), share) {
                            Ok(()) => {
                                signatures.insert((dealer, share.index), msg.signature);
                            }
                            Err(_) => {
                                p2.disqualify(sender);
                                continue;
                            }
                        }
                    }
                    Err(err) => {
                        warn!(round, ?err, "failed to receive missing share");
                        break;
                    }
                }
            };
        }

        // Finalize P2
        let (result, disqualified) = p2.finalize();
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
                .map(hex)
                .collect::<Vec<_>>(),
            "repair phase complete"
        );

        // Broadcast resolutions
        let mut resolutions = Vec::new();
        for ((dealer, recipient), share) in result.resolutions {
            let signature = signatures
                .remove(&(dealer, recipient))
                .expect("missing signature");
            resolutions.push(wire::Resolution {
                dealer,
                share: share.serialize(),
                signature,
            });
        }
        sender
            .send(
                Recipients::All,
                wire::Dkg {
                    round,
                    payload: Some(wire::dkg::Payload::Success(wire::Success {
                        dealers: result.commitments,
                        resolutions,
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

    pub async fn run<C: Scheme>(self, sender: Sender, mut receiver: Receiver) {
        let mut round = 0;
        let mut previous = None;
        loop {
            let (public, disqualified) = self
                .run_round::<C>(round, previous.clone(), &sender, &mut receiver)
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
            time::sleep(self.dkg_frequency).await;
        }
    }
}
