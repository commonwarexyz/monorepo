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

pub struct Config<C: Scheme, H: Hasher> {
    pub crypto: C,
    pub hasher: H,
    pub namespace: Bytes,
}

pub struct Conflicter<E: Clock + Rng + Spawner, C: Scheme, H: Hasher> {
    runtime: E,
    crypto: C,
    _hasher: H,

    vote_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<E: Clock + Rng + Spawner, C: Scheme, H: Hasher> Conflicter<E, C, H> {
    pub fn new(runtime: E, cfg: Config<C, H>) -> Self {
        Self {
            runtime,
            crypto: cfg.crypto,
            _hasher: cfg.hasher,

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

                    // Vote for received hash
                    let vo = wire::Vote {
                        view: vote.view,
                        height: Some(height),
                        hash: Some(hash.clone()),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.vote_namespace,
                                &vote_digest(vote.view, Some(height), Some(&hash)),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Vote(vo)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Vote for random hash
                    let hash = self.random_hash();
                    let vo = wire::Vote {
                        view: vote.view,
                        height: Some(height),
                        hash: Some(hash.clone()),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.vote_namespace,
                                &vote_digest(vote.view, Some(height), Some(&hash)),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Vote(vo)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();
                }
                wire::consensus::Payload::Finalize(finalize) => {
                    // Finalize provided hash
                    let fin = wire::Finalize {
                        view: finalize.view,
                        height: finalize.height,
                        hash: finalize.hash.clone(),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.finalize_namespace,
                                &finalize_digest(finalize.view, finalize.height, &finalize.hash),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Finalize(fin)),
                    }
                    .encode_to_vec();
                    sender
                        .send(Recipients::All, msg.into(), true)
                        .await
                        .unwrap();

                    // Finalize random hash
                    let hash = self.random_hash();
                    let fin = wire::Finalize {
                        view: finalize.view,
                        height: finalize.height,
                        hash: hash.clone(),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.finalize_namespace,
                                &finalize_digest(finalize.view, finalize.height, &hash),
                            ),
                        }),
                    };
                    let msg = wire::Consensus {
                        payload: Some(wire::consensus::Payload::Finalize(fin)),
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
