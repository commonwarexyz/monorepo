use crate::authority::{
    encoder::{
        finalize_digest, finalize_namespace, proposal_digest, proposal_namespace, vote_digest,
        vote_namespace,
    },
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

pub struct Conflicter<E: Clock + Rng + CryptoRng + Spawner, C: Scheme, H: Hasher> {
    runtime: E,
    crypto: C,
    hasher: H,

    proposal_namespace: Vec<u8>,
    vote_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<E: Clock + Rng + CryptoRng + Spawner, C: Scheme, H: Hasher> Conflicter<E, C, H> {
    pub fn new(runtime: E, cfg: Config<C, H>) -> Self {
        Self {
            runtime,
            crypto: cfg.crypto,
            hasher: cfg.hasher,

            proposal_namespace: proposal_namespace(&cfg.namespace),
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
                    // If null vote, skip
                    if vote.height.is_none() || vote.digest.is_none() {
                        continue;
                    }
                    let height = vote.height.unwrap();
                    let digest = vote.digest.unwrap();

                    // Vote for received digest
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

                    // Vote for random digest
                    let digest = H::random(&mut self.runtime);
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
                }
                wire::consensus::Payload::Finalize(finalize) => {
                    // Finalize provided digest
                    let fin = wire::Finalize {
                        view: finalize.view,
                        height: finalize.height,
                        digest: finalize.digest.clone(),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.finalize_namespace,
                                &finalize_digest(finalize.view, finalize.height, &finalize.digest),
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

                    // Finalize random digest
                    let digest = H::random(&mut self.runtime);
                    let fin = wire::Finalize {
                        view: finalize.view,
                        height: finalize.height,
                        digest: digest.clone(),
                        signature: Some(wire::Signature {
                            public_key: self.crypto.public_key(),
                            signature: self.crypto.sign(
                                &self.finalize_namespace,
                                &finalize_digest(finalize.view, finalize.height, &digest),
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

                    // Send conflicting proposals for next height and view
                    let view = finalize.view + 1;
                    let height = finalize.height + 1;
                    let parent = finalize.digest;
                    for _ in 0..2 {
                        // Generate random payload
                        let payload = H::random(&mut self.runtime);
                        self.hasher.update(&payload);
                        let payload_hash = self.hasher.finalize();

                        // Construct proposal
                        let proposal_digest = proposal_digest(view, height, &parent, &payload_hash);
                        let proposal = wire::Proposal {
                            view,
                            height,
                            parent: parent.clone(),
                            payload,
                            signature: Some(wire::Signature {
                                public_key: self.crypto.public_key(),
                                signature: self
                                    .crypto
                                    .sign(&self.proposal_namespace, &proposal_digest),
                            }),
                        };
                        let msg = wire::Consensus {
                            payload: Some(wire::consensus::Payload::Proposal(proposal)),
                        }
                        .encode_to_vec();
                        sender
                            .send(Recipients::All, msg.into(), true)
                            .await
                            .unwrap();
                    }
                }
                _ => continue,
            }
        }
    }
}
