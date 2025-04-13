//! Byzantine participant that sends conflicting notarize/finalize messages.

use std::marker::PhantomData;

use bytes::Bytes;
use commonware_codec::ReadExt;
use commonware_cryptography::{
    bls12381::primitives::{group, ops},
    Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use prost::Message;
use rand::{CryptoRng, Rng};
use tracing::debug;

use crate::{
    threshold_simplex::{
        encoder::{
            finalize_namespace,
            notarize_namespace,
            proposal_message,
            seed_message,
            seed_namespace,
        },
        wire,
        View,
    },
    ThresholdSupervisor,
};

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
    context: E,
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
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            supervisor: cfg.supervisor,
            _hasher: PhantomData,

            seed_namespace: seed_namespace(&cfg.namespace),
            notarize_namespace: notarize_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
        }
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(mut self, voter_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = voter_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match wire::Voter::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };
            let payload = match msg.payload {
                Some(payload) => payload,
                None => {
                    debug!(sender = ?s, "message missing payload");
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
                            debug!(sender = ?s, "notarize missing proposal");
                            continue;
                        }
                    };
                    let Ok(payload) = H::Digest::read(&mut proposal.payload.as_ref()) else {
                        debug!(sender = ?s, "invalid payload");
                        continue;
                    };
                    let view = proposal.view;

                    // Notarize received digest
                    let share = self.supervisor.share(view).unwrap();
                    let parent = proposal.parent;
                    let message = proposal_message(proposal.view, parent, &payload);
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.notarize_namespace), &message)
                            .serialize();
                    let message = seed_message(view);
                    let seed_signature: Bytes =
                        ops::partial_sign_message(share, Some(&self.seed_namespace), &message)
                            .serialize()
                            .into();
                    let n = wire::Notarize {
                        proposal: Some(proposal),
                        proposal_signature,
                        seed_signature: seed_signature.to_vec(),
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Notarize(n)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Notarize random digest
                    let payload = H::random(&mut self.context);
                    let message = proposal_message(view, parent, &payload);
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.notarize_namespace), &message)
                            .serialize();
                    let n = wire::Notarize {
                        proposal: Some(wire::Proposal {
                            view,
                            parent,
                            payload: payload.to_vec(),
                        }),
                        proposal_signature,
                        seed_signature: seed_signature.to_vec(),
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
                            debug!(sender = ?s, "notarize missing proposal");
                            continue;
                        }
                    };
                    let Ok(payload) = H::Digest::read(&mut proposal.payload.as_ref()) else {
                        debug!(sender = ?s, "invalid payload");
                        continue;
                    };
                    let view = proposal.view;

                    // Finalize provided digest
                    let share = self.supervisor.share(view).unwrap();
                    let parent = proposal.parent;
                    let message = proposal_message(proposal.view, parent, &payload);
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.finalize_namespace), &message)
                            .serialize();
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
                    let payload = H::random(&mut self.context);
                    let message = proposal_message(view, parent, &payload);
                    let signature =
                        ops::partial_sign_message(share, Some(&self.finalize_namespace), &message);
                    let proposal_signature = signature.serialize();
                    let f = wire::Finalize {
                        proposal: Some(wire::Proposal {
                            view,
                            parent,
                            payload: payload.to_vec(),
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
