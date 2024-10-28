use crate::authority::{
    encoder::{finalize_digest, finalize_namespace, vote_digest, vote_namespace},
    wire,
};
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::hex;
use prost::Message;
use rand::{CryptoRng, Rng};
use tracing::debug;

pub struct Config<C: Scheme, H: Hasher> {
    pub crypto: C,
    pub hasher: H,
    pub namespace: Bytes,
}

pub struct Nuller<E: Clock + Rng + CryptoRng + Spawner, C: Scheme, H: Hasher> {
    runtime: E,
    crypto: C,
    _hasher: H,

    vote_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, C: Scheme, H: Hasher> Nuller<E, C, H> {
    pub fn new(runtime: E, cfg: Config<C, H>) -> Self {
        Self {
            runtime,
            crypto: cfg.crypto,
            _hasher: cfg.hasher,

            vote_namespace: vote_namespace(&cfg.namespace),
            finalize_namespace: finalize_namespace(&cfg.namespace),
        }
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
                    // If null, vote random
                    if vote.digest.is_none() || vote.height.is_none() {
                        let digest = H::random(&mut self.runtime);
                        let height = self.runtime.gen();
                        let vo = wire::Vote {
                            view: vote.view,
                            height: Some(height),
                            digest: Some(digest.clone()),
                            signature: Some(wire::Signature {
                                public_key: self.crypto.public_key(),
                                signature: self.crypto.sign(
                                    &self.vote_namespace,
                                    &vote_digest(vote.view, Some(height), Some(&digest)),
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
                        continue;
                    }
                    let height = vote.height.unwrap();
                    let digest = vote.digest.unwrap();

                    // If not null, vote null
                    let vo = wire::Vote {
                        view: vote.view,
                        height: None,
                        digest: None,
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self
                                .crypto
                                .sign(&self.vote_namespace, &vote_digest(vote.view, None, None)),
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

                    // Finalize received digest
                    let finalize = wire::Finalize {
                        view: vote.view,
                        height,
                        digest: digest.clone(),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.finalize_namespace,
                                &finalize_digest(vote.view, height, &digest),
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
                _ => continue,
            }
        }
    }
}
