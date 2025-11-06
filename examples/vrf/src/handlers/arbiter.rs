use crate::handlers::{wire, ACK_NAMESPACE};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    bls12381::{
        dkg::{self},
        primitives::{poly, variant::MinSig},
    },
    PublicKey,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use commonware_utils::set::Ordered;
use std::{
    collections::{BTreeMap, HashSet},
    time::Duration,
};
use tracing::{debug, info, warn};

pub struct Arbiter<E: Clock + Spawner, C: PublicKey> {
    context: ContextCell<E>,
    dkg_frequency: Duration,
    dkg_phase_timeout: Duration,
    contributors: Ordered<C>,
}

/// Implementation of a "trusted arbiter" that tracks commitments,
/// acknowledgements, and complaints during a DKG round.
impl<E: Clock + Spawner, C: PublicKey> Arbiter<E, C> {
    pub fn new(
        context: E,
        dkg_frequency: Duration,
        dkg_phase_timeout: Duration,
        contributors: Ordered<C>,
    ) -> Self {
        Self {
            context: ContextCell::new(context),
            dkg_frequency,
            dkg_phase_timeout,
            contributors,
        }
    }

    async fn run_round<S, R>(
        &self,
        round: u64,
        previous: Option<poly::Public<MinSig>>,
        sender: &mut S,
        receiver: &mut R,
    ) -> (Option<poly::Public<MinSig>>, HashSet<C>)
    where
        S: Sender<Codec = Bytes, PublicKey = C>,
        R: Receiver<Codec = Bytes, PublicKey = C>,
    {
        // Create a new round
        let start = self.context.current();
        let timeout = start + 4 * self.dkg_phase_timeout; // start -> commitment/share -> ack -> arbiter

        // Send round start message to contributors
        if let Some(previous) = &previous {
            info!(round, public=?previous, "starting reshare");
        } else {
            info!(round, "starting key generation");
        }
        sender
            .send(
                Recipients::All,
                Bytes::from(
                    wire::Dkg::<C::Signature> {
                        round,
                        payload: wire::Payload::Start {
                            group: previous.clone(),
                        },
                    }
                    .encode(),
                ),
                true,
            )
            .await
            .expect("failed to send start message");

        // Collect commitments
        let mut arbiter = dkg::Arbiter::<_, MinSig>::new(
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
                        Ok((peer, msg)) =>{
                            let msg = match msg {
                                Ok(bytes) => bytes,
                                Err(err) => {
                                    warn!(round, ?peer, ?err, "failed to decode inbound payload");
                                    arbiter.disqualify(peer);
                                    continue;
                                }
                            };
                            // Parse msg
                            let msg = match wire::Dkg::decode_cfg(msg.clone(), &self.contributors.len()) {
                                Ok(msg) => msg,
                                Err(_) => {
                                    arbiter.disqualify(peer);
                                    continue;
                                }
                            };
                            if msg.round != round {
                                continue;
                            }
                            let wire::Payload::Commitment { commitment, acks, reveals } = msg.payload else {
                                // Useless message from previous step
                                continue;
                            };

                            // Validate the signature of each ack
                            if !acks.iter().all(|ack| {
                                self.contributors.get(ack.player as usize).map(|signer| {
                                    ack.verify::<MinSig, _>(ACK_NAMESPACE, signer, round, &peer, &commitment)
                                }).unwrap_or(false)
                            }) {
                                arbiter.disqualify(peer);
                                continue;
                            }

                            // Check dealer commitment
                            //
                            // Any faults here will be considered as a disqualification.
                            let ack_indices: Vec<u32> = acks.iter().map(|a| a.player).collect();
                            if let Err(e) = arbiter.commitment(peer.clone(), commitment, ack_indices, reveals) {
                                warn!(round, error = ?e, ?peer, "failed to process commitment");
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
        let mut commitments = BTreeMap::new();
        for (dealer_idx, commitment) in output.commitments {
            commitments.insert(dealer_idx, commitment);
        }
        let mut reveals = BTreeMap::new();
        for (dealer_idx, shares) in output.reveals {
            for share in shares {
                reveals
                    .entry(share.index)
                    .or_insert_with(BTreeMap::new)
                    .insert(dealer_idx, share);
            }
        }
        for (player_idx, player) in self.contributors.iter().enumerate() {
            let reveals = reveals.remove(&(player_idx as u32)).unwrap_or_default();
            sender
                .send(
                    Recipients::One(player.clone()),
                    Bytes::from(
                        wire::Dkg {
                            round,
                            payload: wire::Payload::<C::Signature>::Success {
                                commitments: commitments.clone(),
                                reveals,
                            },
                        }
                        .encode(),
                    ),
                    true,
                )
                .await
                .expect("failed to send success message");
        }
        (Some(output.public), disqualified)
    }

    pub fn start(
        mut self,
        sender: impl Sender<Codec = Bytes, PublicKey = C>,
        receiver: impl Receiver<Codec = Bytes, PublicKey = C>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(sender, receiver).await)
    }

    async fn run(
        self,
        mut sender: impl Sender<Codec = Bytes, PublicKey = C>,
        mut receiver: impl Receiver<Codec = Bytes, PublicKey = C>,
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
                        ?public,
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
