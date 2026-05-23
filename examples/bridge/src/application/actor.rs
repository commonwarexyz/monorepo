use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    types::{
        block::BlockFormat,
        inbound::{self, Inbound},
        outbound::Outbound,
    },
    Scheme,
};
use commonware_actor::mailbox::{self, Receiver as ActorReceiver};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{simplex::types::Activity, Viewable};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    Hasher,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Metrics, Sink, Spawner, Stream};
use commonware_stream::encrypted::{Receiver, Sender};
use commonware_utils::channel::mpsc;
use rand::Rng;
use rand_core::CryptoRngCore;
use tracing::{debug, info};

/// Application actor.
pub struct Application<R: CryptoRngCore + Spawner + Metrics, H: Hasher, Si: Sink, St: Stream> {
    context: R,
    indexer: (Sender<Si>, Receiver<St>),
    this_network: <MinSig as Variant>::Public,
    other_network: Scheme,
    hasher: H,
    mailbox: ActorReceiver<Message<H::Digest>>,
}

impl<R: CryptoRngCore + Spawner + Metrics, H: Hasher, Si: Sink, St: Stream>
    Application<R, H, Si, St>
{
    /// Create a new application actor.
    pub fn new(context: R, config: Config<H, Si, St>) -> (Self, Scheme, Mailbox<H::Digest>) {
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let this_network = *config.this_network.identity();
        (
            Self {
                context,
                indexer: config.indexer,
                this_network,
                other_network: config.other_network,
                hasher: config.hasher,
                mailbox,
            },
            config.this_network,
            Mailbox::new(sender),
        )
    }

    /// Run the application actor.
    pub async fn run(self) {
        let Self {
            context,
            indexer,
            this_network,
            other_network,
            hasher,
            mut mailbox,
        } = self;
        let (worker_sender, worker_receiver) = mpsc::unbounded_channel();
        let worker = context.child("indexer_worker").spawn(move |context| {
            Self::run_indexer(
                context,
                indexer,
                this_network,
                other_network,
                hasher,
                worker_receiver,
            )
        });

        while let Some(message) = mailbox.recv().await {
            if worker_sender.send(message).is_err() {
                break;
            }
        }
        worker.abort();
    }

    async fn run_indexer(
        mut context: R,
        (mut indexer_sender, mut indexer_receiver): (Sender<Si>, Receiver<St>),
        this_network: <MinSig as Variant>::Public,
        other_network: Scheme,
        mut hasher: H,
        mut messages: mpsc::UnboundedReceiver<Message<H::Digest>>,
    ) {
        while let Some(message) = messages.recv().await {
            match message {
                Message::Propose { round, response } => {
                    // Either propose a random message (prefix=0) or include a consensus certificate (prefix=1)
                    let block = match context.gen_bool(0.5) {
                        true => {
                            // Generate a random message
                            BlockFormat::<H::Digest>::Random(context.gen())
                        }
                        false => {
                            // Fetch a certificate from the indexer for the other network
                            let msg =
                                Inbound::GetFinalization::<H::Digest>(inbound::GetFinalization {
                                    network: *other_network.identity(),
                                })
                                .encode();
                            indexer_sender
                                .send(msg)
                                .await
                                .expect("failed to send finalization to indexer");
                            let result = indexer_receiver
                                .recv()
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
                                finalization.verify(&mut context, &other_network, &Sequential),
                                "indexer is corrupt"
                            );

                            // Use certificate as message
                            BlockFormat::Bridge(finalization)
                        }
                    };

                    // Hash the message
                    hasher.update(&block.encode());
                    let digest = hasher.finalize();
                    info!(?block, payload = ?digest, "proposed");

                    // Publish to indexer
                    let msg = Inbound::PutBlock::<H::Digest>(inbound::PutBlock {
                        network: this_network,
                        block,
                    })
                    .encode();
                    indexer_sender
                        .send(msg)
                        .await
                        .expect("failed to send block to indexer");
                    let result = indexer_receiver
                        .recv()
                        .await
                        .expect("failed to receive from indexer");
                    let msg =
                        Outbound::<H::Digest>::decode(result).expect("failed to decode result");
                    let Outbound::Success(success) = msg else {
                        panic!("unexpected response");
                    };
                    debug!(?round, success, "block published");
                    if !success {
                        continue;
                    }

                    // Send digest to consensus once we confirm indexer has underlying data
                    let _ = response.send(digest);
                }
                Message::Verify { payload, response } => {
                    // Fetch payload from indexer
                    let msg = Inbound::GetBlock(inbound::GetBlock {
                        network: this_network,
                        digest: payload,
                    })
                    .encode();
                    indexer_sender
                        .send(msg)
                        .await
                        .expect("failed to send block to indexer");
                    let result = indexer_receiver
                        .recv()
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
                            let result =
                                finalization.verify(&mut context, &other_network, &Sequential);
                            let _ = response.send(result);
                        }
                    }
                }
                Message::Report { activity } => {
                    let view = activity.view();
                    match activity {
                        Activity::Notarization(notarization) => {
                            info!(%view, payload = ?notarization.proposal.payload, signature = ?notarization.certificate, "notarized");
                        }
                        Activity::Finalization(finalization) => {
                            info!(%view, payload = ?finalization.proposal.payload, signature = ?finalization.certificate, "finalized");

                            // Post finalization
                            let msg =
                                Inbound::PutFinalization::<H::Digest>(inbound::PutFinalization {
                                    network: this_network,
                                    finalization,
                                })
                                .encode();
                            indexer_sender
                                .send(msg)
                                .await
                                .expect("failed to send finalization to indexer");
                            let result = indexer_receiver
                                .recv()
                                .await
                                .expect("failed to receive from indexer");
                            let message = Outbound::<H::Digest>::decode(result)
                                .expect("failed to decode result");
                            let Outbound::Success(success) = message else {
                                panic!("unexpected response");
                            };
                            debug!(%view, success, "finalization posted");
                        }
                        Activity::Nullification(nullification) => {
                            info!(%view, signature = ?nullification.certificate, "nullified");
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
