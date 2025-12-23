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
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{simplex::types::Activity, types::Epoch, Viewable};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    Hasher,
};
use commonware_runtime::{Sink, Spawner, Stream};
use commonware_stream::{Receiver, Sender};
use futures::{channel::mpsc, StreamExt};
use rand::{CryptoRng, Rng};
use tracing::{debug, info};

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng + CryptoRng + Spawner, H: Hasher, Si: Sink, St: Stream> {
    context: R,
    indexer: (Sender<Si>, Receiver<St>),
    namespace: Vec<u8>,
    public: <MinSig as Variant>::Public,
    other_certificate_verifier: Scheme,
    hasher: H,
    mailbox: mpsc::Receiver<Message<H::Digest>>,
}

impl<R: Rng + CryptoRng + Spawner, H: Hasher, Si: Sink, St: Stream> Application<R, H, Si, St> {
    /// Create a new application actor.
    pub fn new(context: R, config: Config<H, Si, St>) -> (Self, Scheme, Mailbox<H::Digest>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                indexer: config.indexer,
                namespace: config.namespace,
                public: *config.identity.public(),
                other_certificate_verifier: Scheme::certificate_verifier(config.other_public),
                hasher: config.hasher,
                mailbox,
            },
            Scheme::signer(config.participants, config.identity, config.share)
                .expect("share must be in participants"),
            Mailbox::new(sender),
        )
    }

    /// Run the application actor.
    pub async fn run(mut self) {
        let (mut indexer_sender, mut indexer_receiver) = self.indexer;
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Genesis { epoch, response } => {
                    // Sanity check. We don't support multiple epochs.
                    assert_eq!(epoch, Epoch::zero(), "epoch must be 0");

                    // Use the digest of the genesis message as the initial payload.
                    self.hasher.update(GENESIS);
                    let digest = self.hasher.finalize();
                    let _ = response.send(digest);
                }
                Message::Propose { round, response } => {
                    // Either propose a random message (prefix=0) or include a consensus certificate (prefix=1)
                    let block = match self.context.gen_bool(0.5) {
                        true => {
                            // Generate a random message
                            BlockFormat::<H::Digest>::Random(self.context.gen())
                        }
                        false => {
                            // Fetch a certificate from the indexer for the other network
                            let msg =
                                Inbound::GetFinalization::<H::Digest>(inbound::GetFinalization {
                                    network: *self.other_certificate_verifier.identity(),
                                })
                                .encode();
                            indexer_sender
                                .send(&msg)
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
                                finalization.verify(
                                    &mut self.context,
                                    &self.other_certificate_verifier,
                                    &self.namespace
                                ),
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
                        network: self.public,
                        digest: payload,
                    })
                    .encode();
                    indexer_sender
                        .send(&msg)
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
                            let result = finalization.verify(
                                &mut self.context,
                                &self.other_certificate_verifier,
                                &self.namespace,
                            );
                            let _ = response.send(result);
                        }
                    }
                }
                Message::Report { activity } => {
                    let view = activity.view();
                    match activity {
                        Activity::Notarization(notarization) => {
                            let proposal_signature = notarization.certificate.vote_signature;
                            let seed_signature = notarization.certificate.seed_signature;

                            info!(%view, payload = ?notarization.proposal.payload, signature = ?proposal_signature, seed = ?seed_signature, "notarized");
                        }
                        Activity::Finalization(finalization) => {
                            let proposal_signature = finalization.certificate.vote_signature;
                            let seed_signature = finalization.certificate.seed_signature;

                            info!(%view, payload = ?finalization.proposal.payload, signature = ?proposal_signature, seed = ?seed_signature, "finalized");

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
                            let round_signature = nullification.certificate.vote_signature;
                            let seed_signature = nullification.certificate.seed_signature;

                            info!(%view, signature = ?round_signature, seed = ?seed_signature, "nullified");
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
