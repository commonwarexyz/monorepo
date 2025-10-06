use super::ingress::{Mailbox, Message};
use crate::{
    orchestrator::EpochCert,
    types::{
        block::{Block, GENESIS_BLOCK, GENESIS_ROUND},
        epoch,
    },
};
use commonware_consensus::{
    marshal,
    threshold_simplex::types::{Context, Finalization},
    types::Round,
    Block as _, Reporter,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest, Committable,
};
use commonware_macros::select;
use commonware_runtime::{Handle, Metrics, Spawner, Storage};
use commonware_utils::futures::ClosedExt;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use rand::Rng;
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

/// Application actor for a single-network epocher.
///
/// This actor is responsible for proposing and verifying blocks.
/// It also tracks the finalized blocks and reports to the orchestrator when the epoch is complete.
pub struct Application<R: Rng + Spawner + Metrics + Storage> {
    context: R,
    mailbox: mpsc::Receiver<Message<Sha256Digest>>,
    marshal: marshal::Mailbox<MinSig, Block>,

    /// Responders for block heights.
    responders: BTreeMap<u64, Vec<oneshot::Sender<Sha256Digest>>>,
}

impl<R: Rng + Spawner + Metrics + Storage> Application<R> {
    pub fn new(
        context: R,
        mailbox_size: usize,
        marshal: marshal::Mailbox<MinSig, Block>,
    ) -> (Self, Mailbox<Sha256Digest>) {
        let (sender, mailbox) = mpsc::channel(mailbox_size);
        (
            Self {
                context,
                mailbox,
                marshal,
                responders: BTreeMap::new(),
            },
            Mailbox::new(sender),
        )
    }

    pub fn start<O: Reporter<Activity = EpochCert>>(mut self, orchestrator: O) -> Handle<()> {
        self.context.spawn_ref()(self.run(orchestrator))
    }

    async fn run<O: Reporter<Activity = EpochCert>>(mut self, mut orchestrator: O) {
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Genesis { epoch, response } => {
                    // Case: Genesis.
                    if epoch == GENESIS_ROUND.epoch() {
                        let _ = response.send(GENESIS_BLOCK.commitment());
                        continue;
                    }

                    // Case: Non-genesis.
                    let height = epoch::get_last_height(epoch - 1);
                    let Some(block) = self.marshal.get_block(height).await else {
                        // No block exists, put the response in the responders map for later.
                        self.responders.entry(height).or_default().push(response);
                        continue;
                    };
                    let _ = response.send(block.commitment());
                }
                Message::Propose {
                    context,
                    mut response,
                } => {
                    select! {
                        _ = response.closed() => {
                            debug!("verify: response channel closed");
                            continue;
                        },
                        digest = self.propose_block(context) => {
                            let _ = response.send(digest);
                        }
                    }
                }
                Message::Verify {
                    context,
                    payload,
                    mut response,
                } => {
                    select! {
                        _ = response.closed() => {
                            debug!("verify: response channel closed");
                            continue;
                        },
                        valid = self.verify_block(context, payload) => {
                            let _ = response.send(valid);
                        }
                    }
                }
                Message::Report { block, response } => {
                    let height = block.height;
                    info!(height, "finalized-delivered-to-app");

                    // Return early if not the last block in the epoch.
                    let Some(epoch) = epoch::is_last_block_in_epoch(height) else {
                        continue;
                    };

                    // Respond to any responders for this block height.
                    if let Some(responders) = self.responders.remove(&height) {
                        for responder in responders {
                            let _ = responder.send(block.commitment());
                        }
                    }

                    // Get the finalization for this block.
                    let cert = match epoch {
                        0 => {
                            let Some(f0) = self.get_finalization(height).await else {
                                continue;
                            };
                            EpochCert::Single(f0)
                        }
                        _ => {
                            let Some(f2) = self.get_finalization(height).await else {
                                continue;
                            };
                            let previous_height = epoch::get_last_height(epoch - 1);
                            let Some(f1) = self.get_finalization(previous_height).await else {
                                continue;
                            };
                            EpochCert::Double(f1, f2)
                        }
                    };

                    orchestrator.report(cert).await;

                    let _ = response.send(());
                }
            }
        }
    }

    /// Gets the finalization for a given height from marshal.
    async fn get_finalization(
        &mut self,
        height: u64,
    ) -> Option<Finalization<MinSig, Sha256Digest>> {
        let Ok(Some((finalization, _block))) = self.marshal.get_finalization(height).await.await
        else {
            warn!("finalization not found for height {}", height);
            return None;
        };
        Some(finalization)
    }

    /// Proposes a new block.
    async fn propose_block(&mut self, context: Context<Sha256Digest>) -> Sha256Digest {
        let round = context.round;
        let epoch = round.epoch();
        let (parent_view, parent_commitment) = context.parent;
        let parent_round = Round::new(epoch, parent_view);

        // Get the parent block from marshal.
        let parent = self.subscribe_block(parent_round, parent_commitment).await;

        // Case: Reproposal.
        if parent.height() == epoch::get_last_height(epoch) {
            debug!(payload=?parent_commitment, "propose: repropose");
            return parent_commitment;
        }

        // Case: New proposal.
        let height = parent.height() + 1;
        let random = self.context.gen::<u64>();
        let block = Block::new(parent_commitment, height, random);
        let digest = block.commitment();
        self.marshal.broadcast(block.clone()).await;
        self.marshal.verified(round, block).await;
        debug!(payload=?digest, "propose: new-proposal");
        digest
    }

    /// Verifies a block.
    async fn verify_block(
        &mut self,
        context: Context<Sha256Digest>,
        payload: Sha256Digest,
    ) -> bool {
        // Get the proposed block from marshal.
        let round = context.round;
        let epoch = round.epoch();
        let block = self.subscribe_block(round, payload).await;
        let height = block.height();

        // Ensure that the height is appropriate for the epoch.
        if !epoch::height_in_epoch(height, epoch) {
            debug!(payload=?payload, "verify: rejected-height-not-in-epoch");
            return false;
        }

        // Case: Reproposal.
        let (parent_view, parent_commitment) = context.parent;
        if block.commitment() == parent_commitment {
            // You can only re-propose the same block if it's the last height in the epoch.
            if height == epoch::get_last_height(epoch) {
                debug!(payload=?payload, "verify: accepted-repropose");
                self.marshal.verified(round, block).await;
                return true;
            } else {
                debug!(payload=?payload, "verify: rejected-repropose-not-at-epoch-end");
                return false;
            }
        }

        // Case: New proposal.

        // Block parent must match the certificate parent.
        if block.parent() != parent_commitment {
            debug!(payload=?payload, "verify: rejected-parent-mismatch");
            return false;
        }

        // Get the parent block from marshal.
        let parent_round = Round::new(epoch, parent_view);
        let parent = self.subscribe_block(parent_round, parent_commitment).await;
        if parent.height() != height - 1 {
            debug!(payload=?payload, "verify: rejected-height-mismatch");
            return false;
        }

        // This is where you might add additional verification of the current block if
        // there are additional "rules" for the block.

        // No checks failed, so accept the proposal.
        debug!(payload=?payload, "verify: accepted-new-proposal");
        self.marshal.verified(round, block).await;
        true
    }

    async fn subscribe_block(&mut self, round: Round, commitment: Sha256Digest) -> Block {
        if round == GENESIS_ROUND {
            return GENESIS_BLOCK;
        }
        let block_rx = self.marshal.subscribe(Some(round), commitment).await;
        block_rx.await.unwrap()
    }
}
