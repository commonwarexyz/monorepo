use crate::wire;

use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use bytes::BufMut;
use commonware_consensus::threshold_simplex::Prover;
use commonware_cryptography::{
    bls12381::primitives::{group::Element, poly},
    Hasher, FormattedArray,
};
use commonware_runtime::{Sink, Stream};
use commonware_stream::{public_key::Connection, Receiver, Sender};
use commonware_utils::{hex, SizedSerialize};
use futures::{channel::mpsc, StreamExt};
use prost::Message as _;
use rand::Rng;
use tracing::{debug, info};

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng, H: Hasher, Si: Sink, St: Stream> {
    runtime: R,
    indexer: Connection<Si, St>,
    prover: Prover<H::Digest>,
    other_prover: Prover<H::Digest>,
    public: Vec<u8>,
    other_public: Vec<u8>,
    hasher: H,
    mailbox: mpsc::Receiver<Message<H::Digest>>,
}

impl<R: Rng, H: Hasher, Si: Sink, St: Stream> Application<R, H, Si, St> {
    /// Create a new application actor.
    pub fn new<P: FormattedArray>(
        runtime: R,
        config: Config<H, Si, St, P>,
    ) -> (Self, Supervisor<P>, Mailbox<H::Digest>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                runtime,
                indexer: config.indexer,
                prover: config.prover,
                other_prover: config.other_prover,
                public: poly::public(&config.identity).serialize(),
                other_public: config.other_network.serialize(),
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
                    let msg = match self.runtime.gen_bool(0.5) {
                        true => {
                            // Generate a random message
                            let mut msg = vec![0; 17];
                            self.runtime.fill(&mut msg[1..]);
                            msg
                        }
                        false => {
                            // Fetch a certificate from the indexer for the other network
                            let msg = wire::GetFinalization {
                                network: self.other_public.clone(),
                            };
                            let msg = wire::Inbound {
                                payload: Some(wire::inbound::Payload::GetFinalization(msg)),
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
                            let proof = match payload {
                                wire::outbound::Payload::Success(_) => {
                                    debug!("no finalization found");
                                    continue;
                                }
                                wire::outbound::Payload::Finalization(f) => f,
                                _ => panic!("unexpected response"),
                            };

                            // Verify certificate
                            self.other_prover
                                .deserialize_finalization(proof.clone().into())
                                .expect("indexer is corrupt");

                            // Use certificate as message
                            let mut msg = Vec::with_capacity(u8::SERIALIZED_LEN + proof.len());
                            msg.put_u8(1);
                            msg.extend(proof);
                            msg
                        }
                    };

                    // Hash the message
                    self.hasher.update(&msg);
                    let digest = self.hasher.finalize();
                    info!(msg = hex(&msg), payload = hex(&digest), "proposed");

                    // Publish to indexer
                    let msg = wire::PutBlock {
                        network: self.public.clone(),
                        data: msg.into(),
                    };
                    let msg = wire::Inbound {
                        payload: Some(wire::inbound::Payload::PutBlock(msg)),
                    }
                    .encode_to_vec();
                    indexer_sender
                        .send(&msg)
                        .await
                        .expect("failed to send block to indexer");
                    let result = indexer_receiver
                        .receive()
                        .await
                        .expect("failed to receive from indexer");
                    let msg = wire::Outbound::decode(result).expect("failed to decode result");
                    let payload = msg.payload.expect("missing payload");
                    let success = match payload {
                        wire::outbound::Payload::Success(s) => s,
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
                        network: self.public.clone(),
                        digest: payload.to_vec(),
                    };
                    let msg = wire::Inbound {
                        payload: Some(wire::inbound::Payload::GetBlock(msg)),
                    }
                    .encode_to_vec();
                    indexer_sender
                        .send(&msg)
                        .await
                        .expect("failed to send block to indexer");
                    let result = indexer_receiver
                        .receive()
                        .await
                        .expect("failed to receive from indexer");
                    let msg = wire::Outbound::decode(result).expect("failed to decode result");
                    let payload = msg.payload.expect("missing payload");
                    let block = match payload {
                        wire::outbound::Payload::Success(b) => {
                            if b {
                                panic!("unexpected success");
                            }
                            let _ = response.send(false);
                            debug!("block not found");
                            continue;
                        }
                        wire::outbound::Payload::Block(b) => b,
                        _ => panic!("unexpected response"),
                    };

                    // If first byte is 0, then its just a hash
                    if block[0] == 0 {
                        let _ = response.send(block.len() == 17);
                        continue;
                    }

                    // Verify consensus certificate
                    let proof = block[1..].to_vec();
                    let result = self
                        .other_prover
                        .deserialize_finalization(proof.into())
                        .is_some();

                    // If payload exists and is valid, return
                    let _ = response.send(result);
                }
                Message::Prepared { proof, payload } => {
                    let (view, _, _, signature, seed) =
                        self.prover.deserialize_notarization(proof).unwrap();
                    let signature = signature.serialize();
                    let seed = seed.serialize();
                    info!(
                        view,
                        payload = hex(&payload),
                        signature = hex(&signature),
                        seed = hex(&seed),
                        "prepared"
                    )
                }
                Message::Finalized { proof, payload } => {
                    let (view, _, _, signature, seed) =
                        self.prover.deserialize_finalization(proof.clone()).unwrap();
                    let signature = signature.serialize();
                    let seed = seed.serialize();
                    info!(
                        view,
                        payload = hex(&payload),
                        signature = hex(&signature),
                        seed = hex(&seed),
                        "finalized"
                    );

                    // Post finalization
                    let msg = wire::PutFinalization {
                        network: self.public.clone(),
                        data: proof,
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
                    let msg = wire::Outbound::decode(result).expect("failed to decode result");
                    let payload = msg.payload.expect("missing payload");
                    let success = match payload {
                        wire::outbound::Payload::Success(s) => s,
                        _ => panic!("unexpected response"),
                    };
                    debug!(view, success, "finalization posted");
                }
            }
        }
    }
}
