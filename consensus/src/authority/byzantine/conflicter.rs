use std::marker::PhantomData;

use crate::{
    authority::{
        encoder::{finalize_digest, finalize_namespace, vote_digest, vote_namespace},
        wire,
    },
    Hash, Hasher,
};
use bytes::Bytes;
use commonware_cryptography::Scheme;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::hex;
use prost::Message;
use rand::Rng;
use tracing::debug;

pub struct Config<C: Scheme> {
    pub crypto: C,
    pub namespace: Bytes,
}

pub struct Conflicter<E: Clock + Rng + Spawner, C: Scheme, H: Hasher> {
    runtime: E,
    crypto: C,
    _hasher: PhantomData<H>,

    vote_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<E: Clock + Rng + Spawner, C: Scheme, H: Hasher> Conflicter<E, C, H> {
    pub fn new(runtime: E, cfg: Config<C>) -> Self {
        Self {
            runtime,
            crypto: cfg.crypto,
            _hasher: PhantomData,

            vote_namespace: vote_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
        }
    }

    fn random_hash(&mut self) -> Hash {
        let hash_size = H::size();
        let mut hash = vec![0u8; hash_size];
        self.runtime.fill_bytes(&mut hash);
        hash.into()
    }

    pub async fn run(
        mut self,
        _resolver_network: (impl Sender, impl Receiver),
        voter_network: (impl Sender, impl Receiver),
    ) {
        let (mut sender, mut receiver) = voter_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match wire::Consensus::decode(msg) {
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
                wire::consensus::Payload::Proposal(proposal) => {
                    // Vote for random hash
                    let hash = self.random_hash();
                    let vote = wire::Vote {
                        view: proposal.view,
                        height: Some(proposal.height),
                        hash: Some(hash.clone()),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.vote_namespace,
                                &vote_digest(proposal.view, Some(proposal.height), Some(&hash)),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Vote(vote)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Vote for random hash at different height
                    let hash = self.random_hash();
                    let height = Some(proposal.height + 1);
                    let vote = wire::Vote {
                        view: proposal.view,
                        height,
                        hash: Some(hash.clone()),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.vote_namespace,
                                &vote_digest(proposal.view, height, Some(&hash)),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Vote(vote)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();
                }
                wire::consensus::Payload::Vote(vote) => {
                    // Skip null votes
                    let height = match vote.height {
                        Some(height) => height,
                        None => continue,
                    };
                    let hash = match vote.hash {
                        Some(hash) => hash,
                        None => continue,
                    };

                    // Finalize provided hash
                    let finalize = wire::Finalize {
                        view: vote.view,
                        height,
                        hash: hash.clone(),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.finalize_namespace,
                                &finalize_digest(vote.view, height, &hash),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Finalize(finalize)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Finalize random hash
                    let hash = self.random_hash();
                    let finalize = wire::Finalize {
                        view: vote.view,
                        height,
                        hash: hash.clone(),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.finalize_namespace,
                                &finalize_digest(vote.view, height, &hash),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Finalize(finalize)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    }
}
