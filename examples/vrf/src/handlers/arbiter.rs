use crate::handlers::{
    utils::{payload, public_hex, ACK_NAMESPACE},
    wire,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    bls12381::{dkg, primitives::poly},
    Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use commonware_utils::hex;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tracing::{debug, info, warn};

pub struct Arbiter<E: Clock + Spawner, C: Scheme> {
    context: E,

    dkg_frequency: Duration,
    dkg_phase_timeout: Duration,

    contributors: Vec<C::PublicKey>,
    t: u32,
}

/// Implementation of a "trusted arbiter" that tracks commitments,
/// acknowledgements, and complaints during a DKG round.
impl<E: Clock + Spawner, C: Scheme> Arbiter<E, C> {
    pub fn new(
        context: E,
        dkg_frequency: Duration,
        dkg_phase_timeout: Duration,
        mut contributors: Vec<C::PublicKey>,
        t: u32,
    ) -> Self {
        contributors.sort();
        Self {
            context,

            dkg_frequency,
            dkg_phase_timeout,

            contributors,
            t,
        }
    }

    async fn run_round(
        &self,
        round: u64,
        previous: Option<poly::Public>,
        sender: &mut impl Sender<PublicKey = C::PublicKey>,
        receiver: &mut impl Receiver<PublicKey = C::PublicKey>,
    ) -> (Option<poly::Public>, HashSet<C::PublicKey>) {
        // Create a new round
        let start = self.context.current();
        let timeout = start + 4 * self.dkg_phase_timeout; // start -> commitment/share -> ack -> arbiter

        // Send round start message to contributors
        if let Some(previous) = &previous {
            info!(round, public = hex(&previous.encode()), "starting reshare");
        } else {
            info!(round, "starting key generation");
        }
        sender
            .send(
                Recipients::All,
                wire::Dkg::<C::Signature> {
                    round,
                    payload: wire::Payload::Start {
                        group: previous.clone(),
                    },
                }
                .encode()
                .into(),
                true,
            )
            .await
            .expect("failed to send start message");

        // Collect commitments
        let mut arbiter = dkg::Arbiter::new(
            previous,
            self.contributors.clone(),
            self.contributors.clone(),
            1,
        );
        loop {
            select! {
                _ = self.context.sleep_until(timeout) => {
                    warn!(round, "timed out waiting for commitments");
                    break
                },
                result = receiver.recv() => {
                    match result {
                        Ok((sender, msg)) =>{
                            // Parse msg
                            let msg = match wire::Dkg::decode_cfg(msg, &(self.t as usize)) {
                                Ok(msg) => msg,
                                Err(_) => {
                                    arbiter.disqualify(sender);
                                    continue;
                                }
                            };
                            if msg.round != round {
                                continue;
                            }
                            let wire::Payload::Commitment{commitment, acks, reveals} = msg.payload else {
                                // Useless message from previous step
                                continue;
                            };

                            // Validate the signature of each ack
                            let payload = payload(round, &sender, &commitment);
                            if !acks.iter().all(|(i, sig)| {
                                self.contributors.get(*i as usize).map(|signer| {
                                    C::verify(Some(ACK_NAMESPACE), &payload, signer, sig)
                                }).unwrap_or(false)
                            }) {
                                arbiter.disqualify(sender);
                                continue;
                            }

                            // Check dealer commitment
                            //
                            // Any faults here will be considered as a disqualification.
                            let ack_indices: Vec<u32> = acks.keys().copied().collect();
                            if let Err(e) = arbiter.commitment(sender.clone(), commitment, ack_indices, reveals) {
                                warn!(round, error = ?e, ?sender, "failed to process commitment");
                                break;
                            }

                            // If we are ready, break
                            if arbiter.ready() {
                                debug!("collected sufficient commitments");
                                break;
                            }
                        },
                        Err(e) => {
                            warn!(round, error = ?e, "unable to read message");
                            break;
                        }
                    };
                }
            }
        }

        // Finalize
        let (result, disqualified) = arbiter.finalize();
        let output = match result {
            Ok(output) => output,
            Err(e) => {
                warn!(round, error=?e, "unable to complete");
                sender
                    .send(
                        Recipients::All,
                        wire::Dkg {
                            round,
                            payload: wire::Payload::<C::Signature>::Abort,
                        }
                        .encode()
                        .into(),
                        true,
                    )
                    .await
                    .expect("failed to send abort message");
                return (None, disqualified);
            }
        };

        // Send commitments and reveals to all contributors
        info!(
            round,
            commitments = ?output.commitments.keys().map(|idx| self.contributors[*idx as usize].to_string()).collect::<Vec<_>>(),
            disqualified = ?disqualified
                .iter()
                .map(|pk| pk.to_string())
                .collect::<Vec<_>>(),
            "selected commitments"
        );

        // Broadcast commitments
        let mut commitments = HashMap::new();
        for (dealer_idx, commitment) in output.commitments {
            commitments.insert(dealer_idx, commitment);
        }
        let mut reveals = HashMap::new();
        for (dealer_idx, shares) in output.reveals {
            for share in shares {
                reveals
                    .entry(share.index)
                    .or_insert_with(HashMap::new)
                    .insert(dealer_idx, share);
            }
        }
        for (player_idx, player) in self.contributors.iter().enumerate() {
            let reveals = reveals.remove(&(player_idx as u32)).unwrap_or_default();
            sender
                .send(
                    Recipients::One(player.clone()),
                    wire::Dkg {
                        round,
                        payload: wire::Payload::<C::Signature>::Success {
                            commitments: commitments.clone(),
                            reveals,
                        },
                    }
                    .encode()
                    .into(),
                    true,
                )
                .await
                .expect("failed to send success message");
        }
        (Some(output.public), disqualified)
    }

    pub fn start(
        mut self,
        sender: impl Sender<PublicKey = C::PublicKey>,
        receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(sender, receiver))
    }

    async fn run(
        self,
        mut sender: impl Sender<PublicKey = C::PublicKey>,
        mut receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) {
        let mut round = 0;
        let mut previous = None;
        loop {
            let (public, disqualified) = self
                .run_round(round, previous.clone(), &mut sender, &mut receiver)
                .await;

            // Log round results
            match public {
                Some(public) => {
                    info!(
                        round,
                        public = public_hex(&public),
                        disqualified = ?disqualified.into_iter().map(|pk| pk.to_string()).collect::<Vec<_>>(),
                        "round complete"
                    );

                    // Only update previous if the round was successful
                    previous = Some(public);
                }
                None => {
                    info!(round, disqualified = ?disqualified.into_iter().map(|pk| pk.to_string()).collect::<Vec<_>>(), "round aborted");
                }
            }

            // Update state
            round += 1;

            // Wait for next round
            self.context.sleep(self.dkg_frequency).await;
        }
    }
}
