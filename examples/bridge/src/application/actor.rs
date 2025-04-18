use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use crate::types::{
    block::BlockFormat,
    inbound::{self, Inbound},
    outbound::Outbound,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::threshold_simplex::types::{Activity, Viewable};
use commonware_cryptography::{
    bls12381::primitives::{group, poly},
    Hasher,
};
use commonware_runtime::{Sink, Spawner, Stream};
use commonware_stream::{public_key::Connection, Receiver, Sender};
use commonware_utils::Array;
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
                    let block = match self.context.gen_bool(0.5) {
                        true => {
                            // Generate a random message
                            let v1 = self.context.next_u64();
                            let v2 = self.context.next_u64();
                            let value: u128 = ((v1 as u128) << 64) | (v2 as u128);
                            BlockFormat::<H::Digest>::Random(value)
                        }
                        false => {
                            // Fetch a certificate from the indexer for the other network
                            let msg =
                                Inbound::GetFinalization::<H::Digest>(inbound::GetFinalization {
                                    network: self.other_public,
                                })
                                .encode();
                            indexer_sender
                                .send(&msg)
                                .await
                                .expect("failed to send finalization to indexer");
                            let result = indexer_receiver
                                .receive()
                                .await
                                .expect("failed to receive from indexer");
                            let msg = Outbound::<H::Digest>::decode(result)
                                .expect("failed to decode result");
                            let finalization = match msg {
                                Outbound::Success(_) => {
                                    debug!("no finalization found");
                                    continue;
                                }
                                Outbound::Finalization(f) => f,
                                _ => panic!("unexpected response"),
                            };

                            // Verify certificate
                            assert!(
                                finalization.verify(&self.namespace, &self.other_public),
                                "indexer is corrupt"
                            );

                            // Use certificate as message
                            BlockFormat::Bridge(finalization)
                        }
                    };

                    // Hash the message
                    self.hasher.update(&block.encode());
                    let digest = self.hasher.finalize();
                    info!(?block, payload = ?digest, "proposed");

                    // Publish to indexer
                    let msg = Inbound::PutBlock::<H::Digest>(inbound::PutBlock {
                        network: self.public,
                        block,
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
                    let msg =
                        Outbound::<H::Digest>::decode(result).expect("failed to decode result");
                    let Outbound::Success(success) = msg else {
                        panic!("unexpected response");
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
                    let msg = Inbound::GetBlock(inbound::GetBlock {
                        network: self.public,
                        digest: payload,
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
                    let msg =
                        Outbound::<H::Digest>::decode(result).expect("failed to decode result");
                    let block = match msg {
                        Outbound::Block(b) => b,
                        Outbound::Success(false) => {
                            let _ = response.send(false);
                            debug!("block not found");
                            continue;
                        }
                        _ => panic!("unexpected response"),
                    };

                    match block {
                        BlockFormat::Random(_) => {
                            let _ = response.send(true);
                        }
                        BlockFormat::Bridge(finalization) => {
                            let result = finalization.verify(&self.namespace, &self.other_public);
                            let _ = response.send(result);
                        }
                    }
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
                            let msg =
                                Inbound::PutFinalization::<H::Digest>(inbound::PutFinalization {
                                    network: self.public,
                                    finalization,
                                })
                                .encode();
                            indexer_sender
                                .send(&msg)
                                .await
                                .expect("failed to send finalization to indexer");
                            let result = indexer_receiver
                                .receive()
                                .await
                                .expect("failed to receive from indexer");
                            let message = Outbound::<H::Digest>::decode(result)
                                .expect("failed to decode result");
                            let Outbound::Success(success) = message else {
                                panic!("unexpected response");
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
