//! Byzantine participant that sends conflicting notarize/finalize messages.

use crate::{
    simplex::{
        encoder::{finalize_namespace, notarize_namespace, proposal_message},
        wire, View,
    },
    Supervisor,
};
use commonware_cryptography::{Hasher, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use prost::Message;
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<C: Scheme, S: Supervisor<Index = View>> {
    pub crypto: C,
    pub supervisor: S,
    pub namespace: Vec<u8>,
}

pub struct Conflicter<
    E: Clock + Rng + CryptoRng + Spawner,
    C: Scheme,
    H: Hasher,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: E,
    crypto: C,
    supervisor: S,
    _hasher: PhantomData<H>,

    notarize_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<
        E: Clock + Rng + CryptoRng + Spawner,
        C: Scheme,
        H: Hasher,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Conflicter<E, C, H, S>
{
    pub fn new(context: E, cfg: Config<C, S>) -> Self {
        Self {
            context,
            crypto: cfg.crypto,
            supervisor: cfg.supervisor,
            _hasher: PhantomData,

            notarize_namespace: notarize_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
        }
    }

    pub fn start(self, voter_network: (impl Sender, impl Receiver)) -> Handle<()> {
        self.context.spawn_ref(self.run(voter_network))
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
                    let Ok(payload) = H::Digest::try_from(&proposal.payload) else {
                        debug!(sender = ?s, "notarize invalid payload");
                        continue;
                    };
                    let view = proposal.view;
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();

                    // Notarize received digest
                    let parent = proposal.parent;
                    let msg = proposal_message(proposal.view, proposal.parent, &payload);
                    let n = wire::Notarize {
                        proposal: Some(proposal),
                        signature: Some(wire::Signature {
                            public_key: public_key_index,
                            signature: self
                                .crypto
                                .sign(Some(&self.notarize_namespace), &msg)
                                .to_vec(),
                        }),
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Notarize(n)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Notarize random digest
                    let payload = H::random(&mut self.context);
                    let msg = proposal_message(view, parent, &payload);
                    let n = wire::Notarize {
                        proposal: Some(wire::Proposal {
                            view,
                            parent,
                            payload: payload.to_vec(),
                        }),
                        signature: Some(wire::Signature {
                            public_key: public_key_index,
                            signature: self
                                .crypto
                                .sign(Some(&self.notarize_namespace), &msg)
                                .to_vec(),
                        }),
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Notarize(n)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();
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
                    let Ok(payload) = H::Digest::try_from(&proposal.payload) else {
                        debug!(sender = ?s, "notarize invalid payload");
                        continue;
                    };
                    let view = proposal.view;
                    let public_key_index = self
                        .supervisor
                        .is_participant(view, &self.crypto.public_key())
                        .unwrap();

                    // Finalize provided digest
                    let parent = proposal.parent;
                    let msg = proposal_message(proposal.view, proposal.parent, &payload);
                    let f = wire::Finalize {
                        proposal: Some(proposal),
                        signature: Some(wire::Signature {
                            public_key: public_key_index,
                            signature: self
                                .crypto
                                .sign(Some(&self.finalize_namespace), &msg)
                                .to_vec(),
                        }),
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Finalize(f)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Finalize random digest
                    let payload = H::random(&mut self.context);
                    let msg = proposal_message(view, parent, &payload);
                    let f = wire::Finalize {
                        proposal: Some(wire::Proposal {
                            view,
                            parent,
                            payload: payload.to_vec(),
                        }),
                        signature: Some(wire::Signature {
                            public_key: public_key_index,
                            signature: self
                                .crypto
                                .sign(Some(&self.finalize_namespace), &msg)
                                .to_vec(),
                        }),
                    };
                    let msg = wire::Voter {
                        payload: Some(wire::voter::Payload::Finalize(f)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();
                }
                _ => continue,
            }
        }
    }
}
