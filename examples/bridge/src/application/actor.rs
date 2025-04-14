use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use crate::wire::{self, Inbound, Outbound};
use bytes::BufMut;
use commonware_codec::{DecodeExt, Encode, FixedSize};
use commonware_consensus::threshold_simplex::types::{Activity, Finalization, Viewable};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly,
    },
    Hasher,
};
use commonware_runtime::{Sink, Spawner, Stream};
use commonware_stream::{public_key::Connection, Receiver, Sender};
use commonware_utils::{hex, Array};
use futures::{channel::mpsc, StreamExt};
use rand::Rng;
use tracing::{debug, info};

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng + Spawner, H: Hasher, Si: Sink, St: Stream> {
    context: R,
    indexer: Connection<Si, St>,
    namespace: Vec<u8>,
    public: group::Public,
    other_public: group::Public,
    hasher: H,
    mailbox: mpsc::Receiver<Message<H::Digest>>,
}

impl<R: Rng + Spawner, H: Hasher, Si: Sink, St: Stream> Application<R, H, Si, St> {
    /// Create a new application actor.
    pub fn new<P: Array>(
        context: R,
        config: Config<H, Si, St, P>,
    ) -> (Self, Supervisor<P>, Mailbox<H::Digest>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                indexer: config.indexer,
                namespace: config.namespace,
                public: *poly::public(&config.identity),
                other_public: config.other_public,
                hasher: config.hasher,
                mailbox,
            },
            Supervisor::new(config.identity, config.participants, config.share),
            Mailbox::new(sender),
        )
    }

    /// Run the application actor.
    pub async fn run(mut self) {
        let (mut indexer_sender, mut indexer_receiver) = self.indexer.split();
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Genesis { response } => {
                    // Use the digest of the genesis message as the initial
                    // payload.
                    self.hasher.update(GENESIS);
                    let digest = self.hasher.finalize();
                    let _ = response.send(digest);
                }
                Message::Propose { index, response } => {
                    // Either propose a random message (prefix=0) or include a consensus certificate (prefix=1)
                    let msg = match self.context.gen_bool(0.5) {
                        true => {
                            // Generate a random message
                            let mut msg = vec![0; 17];
                            self.context.fill(&mut msg[1..]);
                            msg
                        }
                        false => {
                            // Fetch a certificate from the indexer for the other network
                            let msg = wire::GetFinalization {
                                network: self.other_public.serialize(),
                            };
                            let msg = wire::Inbound::GetFinalization(msg).encode().into();
                            indexer_sender
                                .send(&msg)
                                .await
                                .expect("failed to send finalization to indexer");
                            let result = indexer_receiver
                                .receive()
                                .await
                                .expect("failed to receive from indexer");
                            let msg = Outbound::decode(result).expect("failed to decode result");
                            let proof = match msg {
                                Outbound::Success(_) => {
                                    debug!("no finalization found");
                                    continue;
                                }
                                Outbound::Finalization(f) => f,
                                _ => panic!("unexpected response"),
                            };

                            // Verify certificate
                            let finalization = Finalization::<H::Digest>::decode(proof.as_ref())
                                .expect("failed to decode finalization");
                            assert!(
                                finalization.verify(&self.namespace, &self.other_public),
                                "indexer is corrupt"
                            );

                            // Use certificate as message
                            let mut msg = Vec::with_capacity(u8::SIZE + proof.len());
                            msg.put_u8(1);
                            msg.extend(proof);
                            msg
                        }
                    };

                    // Hash the message
                    self.hasher.update(&msg);
                    let digest = self.hasher.finalize();
                    info!(msg = hex(&msg), payload = ?digest, "proposed");

                    // Publish to indexer
                    let msg = wire::PutBlock {
                        network: self.public.serialize(),
                        data: msg.into(),
                    })
                    .encode();
                    indexer_sender
                        .send(&msg)
                        .await
                        .expect("failed to send block to indexer");
                    let result = indexer_receiver
                        .receive()
                        .await
                        .expect("failed to receive from indexer");
                    let msg = Outbound::decode(result).expect("failed to decode result");
                    let success = match msg {
                        Outbound::Success(s) => s,
                        _ => panic!("unexpected response"),
                    };
                    debug!(view = index, success, "block published");
                    if !success {
                        continue;
                    }

                    // Send digest to consensus once we confirm indexer has underlying data
                    let _ = response.send(digest);
                }
                Message::Verify { payload, response } => {
                    // Fetch payload from indexer
                    let msg = wire::GetBlock {
                        network: self.public.serialize(),
                        digest: payload.to_vec(),
                    };
                    let msg = wire::Inbound::GetBlock(msg).encode().into();
                    indexer_sender
                        .send(&msg)
                        .await
                        .expect("failed to send block to indexer");
                    let result = indexer_receiver
                        .receive()
                        .await
                        .expect("failed to receive from indexer");
                    let msg = Outbound::decode(result).expect("failed to decode result");
                    let block = match msg {
                        Outbound::Success(b) => {
                            if b {
                                panic!("unexpected success");
                            }
                            let _ = response.send(false);
                            debug!("block not found");
                            continue;
                        }
                        Outbound::Block(b) => b,
                        _ => panic!("unexpected response"),
                    };

                    // If first byte is 0, then its just a hash
                    if block[0] == 0 {
                        let _ = response.send(block.len() == 17);
                        continue;
                    }

                    // Verify consensus certificate
                    let proof = block[1..].to_vec();
                    let finalization = Finalization::<H::Digest>::decode(proof.as_ref())
                        .expect("failed to decode finalization");
                    let result = finalization.verify(&self.namespace, &self.other_public);

                    // If payload exists and is valid, return
                    let _ = response.send(result);
                }
                Message::Report { activity } => {
                    let view = activity.view();
                    match activity {
                        Activity::Notarization(notarization) => {
                            info!(view, payload = ?notarization.proposal.payload, signature=?notarization.proposal_signature, seed=?notarization.seed_signature, "notarized");
                        }
                        Activity::Finalization(finalization) => {
                            info!(view, payload = ?finalization.proposal.payload, signature=?finalization.proposal_signature, seed=?finalization.seed_signature, "finalized");

                            // Post finalization
                            let msg = wire::PutFinalization {
                                network: self.public.serialize(),
                                data: finalization.encode().into(),
                            };
                            let msg = wire::Inbound {
                                payload: Some(wire::inbound::Payload::PutFinalization(msg)),
                            }
                            .encode_to_vec();
                            indexer_sender
                                .send(&msg)
                                .await
                                .expect("failed to send finalization to indexer");
                            let result = indexer_receiver
                                .receive()
                                .await
                                .expect("failed to receive from indexer");
                            let msg =
                                wire::Outbound::decode(result).expect("failed to decode result");
                            let payload = msg.payload.expect("missing payload");
                            let success = match payload {
                                wire::outbound::Payload::Success(s) => s,
                                _ => panic!("unexpected response"),
                            };
                            debug!(view, success, "finalization posted");
                        }
                        Activity::Nullification(nullification) => {
                            info!(view, signature=?nullification.view_signature, seed=?nullification.seed_signature, "nullified");
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
