//! Byzantine participant that sends nullify and finalize messages for the same view.

use crate::{
    threshold_simplex::{
        encoder::{
            finalize_namespace, nullify_message, nullify_namespace, proposal_message, seed_message,
            seed_namespace,
        },
        wire, View,
    },
    ThresholdSupervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{group, ops},
    Hasher,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use prost::Message;
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Nuller<
    E: Spawner,
    H: Hasher,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    context: E,
    supervisor: S,
    _hasher: PhantomData<H>,

    seed_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<
        E: Spawner,
        H: Hasher,
        S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
    > Nuller<E, H, S>
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context,
            supervisor: cfg.supervisor,
            _hasher: PhantomData,

            seed_namespace: seed_namespace(&cfg.namespace),
            nullify_namespace: nullify_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
        }
    }

    pub fn start(mut self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref()(self.run(voter_network))
    }

    async fn run(self, voter_network: (impl Sender, impl Receiver)) {
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
                    let Ok(payload) = H::Digest::try_from(&proposal.payload) else {
                        debug!(sender = ?s, "invalid payload");
                        continue;
                    };
                    let view = proposal.view;

                    // Nullify
                    let share = self.supervisor.share(view).unwrap();
                    let message = nullify_message(view);
                    let view_signature =
                        ops::partial_sign_message(share, Some(&self.nullify_namespace), &message)
                            .serialize();
                    let message = seed_message(view);
                    let seed_signature =
                        ops::partial_sign_message(share, Some(&self.seed_namespace), &message)
                            .serialize();
                    let n = wire::Nullify {
                        view,
                        view_signature,
                        seed_signature,
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Nullify(n)),
                    }
                    .encode_to_vec()
                    .into();
                    sender.send(Recipients::All, msg, true).await.unwrap();

                    // Finalize digest
                    let message = proposal_message(view, proposal.parent, &payload);
                    let proposal_signature =
                        ops::partial_sign_message(share, Some(&self.finalize_namespace), &message)
                            .serialize();
                    let f = wire::Finalize {
                        proposal: Some(proposal.clone()),
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
