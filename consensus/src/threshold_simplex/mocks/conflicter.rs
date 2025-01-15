//! Byzantine participant that sends conflicting notarize/finalize messages.

use crate::{
    threshold_simplex::{
        encoder::{
            finalize_namespace, notarize_namespace, proposal_message, seed_message, seed_namespace,
        },
        wire, View,
    },
    ThresholdSupervisor,
};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{group, ops},
    Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::hex;
use prost::Message;
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Conflicter<
    E: Clock + Rng + CryptoRng + Spawner,
    H: Hasher,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    runtime: E,
    supervisor: S,
    _hasher: PhantomData<H>,

    seed_namespace: Vec<u8>,
    notarize_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        H: Hasher,
        S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
    > Conflicter<E, H, S>
{
    pub fn new(runtime: E, cfg: Config<S>) -> Self {
        Self {
            runtime,
            supervisor: cfg.supervisor,
            _hasher: PhantomData,

            seed_namespace: seed_namespace(&cfg.namespace),
            notarize_namespace: notarize_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
        }
    }

    pub async fn run(
        mut self,
        voter_network: (impl Sender, impl Receiver),
        _backfiller_network: (impl Sender, impl Receiver),
    ) {
        let (mut sender, mut receiver) = voter_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match wire::Voter::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = hex(&s), "failed to decode message");
                    continue;
                }
            };
            let payload = match msg.payload {
                Some(payload) => payload,
                None => {
                    debug!(sender = hex(&s), "message missing payload");
                    continue;
                }
            };

            // Process message
            match payload {
                wire::voter::Payload::Notarize(notarize) => {
                    // Get our index
                    let proposal = match notarize.proposal {
                        Some(proposal) => proposal,
                        None => {
                            debug!(sender = hex(&s), "notarize missing proposal");
                            continue;
                        }
                    };
                    let view = proposal.view;

                    // Notarize received digest
                    let share = self.supervisor.share(view).unwrap();
                    let parent = proposal.parent;
                    let message = proposal_message(proposal.view, parent, &proposal.payload);
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.notarize_namespace), &message)
                            .serialize()
                            .into();
                    let message = seed_message(view);
                    let seed_signature: Bytes =
                        ops::partial_sign_message(share, Some(&self.seed_namespace), &message)
                            .serialize()
                            .into();
                    let n = wire::Notarize {
                        proposal: Some(proposal),
                        proposal_signature,
                        seed_signature: seed_signature.clone(),
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Notarize(n)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Notarize random digest
                    let digest = H::random(&mut self.runtime);
                    let message = proposal_message(view, parent, &digest);
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.notarize_namespace), &message)
                            .serialize()
                            .into();
                    let n = wire::Notarize {
                        proposal: Some(wire::Proposal {
                            view,
                            parent,
                            payload: digest,
                        }),
                        proposal_signature,
                        seed_signature,
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Notarize(n)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                wire::voter::Payload::Finalize(finalize) => {
                    // Get our index
                    let proposal = match finalize.proposal {
                        Some(proposal) => proposal,
                        None => {
                            debug!(sender = hex(&s), "notarize missing proposal");
                            continue;
                        }
                    };
                    let view = proposal.view;

                    // Finalize provided digest
                    let share = self.supervisor.share(view).unwrap();
                    let parent = proposal.parent;
                    let message = proposal_message(proposal.view, parent, &proposal.payload);
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.finalize_namespace), &message)
                            .serialize()
                            .into();
                    let f = wire::Finalize {
                        proposal: Some(proposal),
                        proposal_signature,
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Finalize(f)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize random digest
                    let digest = H::random(&mut self.runtime);
                    let message = proposal_message(view, parent, &digest);
                    let signature =
                        ops::partial_sign_message(share, Some(&self.finalize_namespace), &message);
                    let proposal_signature = signature.serialize().into();
                    let f = wire::Finalize {
                        proposal: Some(wire::Proposal {
                            view,
                            parent,
                            payload: digest,
                        }),
                        proposal_signature,
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Finalize(f)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();
                }
                _ => continue,
            }
        }
    }
}
