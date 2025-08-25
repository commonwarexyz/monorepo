use super::ingress::{Mailbox, Message};
use crate::{
    orchestrator::EpochUpdate,
    types::{
        block::{Block, GENESIS_BLOCK, GENESIS_ROUND},
        epoch,
    },
};
use commonware_consensus::{
    marshal, threshold_simplex::types::Context, types::Round, Block as _, Reporter,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest, Committable,
};
use commonware_macros::select;
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    task::{Context as FuturesContext, Poll},
    StreamExt,
};
use rand::Rng;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tracing::{debug, info};

/// Application actor for a single-network epocher.
///
/// This actor is responsible for proposing and verifying blocks.
/// It also tracks the finalized blocks and reports to the orchestrator when the epoch is complete.
pub struct Application<R: Rng + Spawner> {
    context: R,
    mailbox: mpsc::Receiver<Message<Sha256Digest>>,
    marshal: marshal::Mailbox<MinSig, Block>,
    finalized: Arc<Mutex<BTreeMap<u64, Block>>>,
}

impl<R: Rng + Spawner> Application<R> {
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
                finalized: Arc::new(Mutex::new(BTreeMap::new())),
            },
            Mailbox::new(sender),
        )
    }

    pub fn start<O: Reporter<Activity = EpochUpdate>>(mut self, orchestrator: O) -> Handle<()> {
        self.context.spawn_ref()(self.run(orchestrator))
    }

    async fn run<O: Reporter<Activity = EpochUpdate>>(mut self, mut orchestrator: O) {
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
                    let finalized = self.finalized.lock().unwrap();
                    let Some(block) = finalized.get(&height) else {
                        // No block exists, drop the response.
                        continue;
                    };
                    let _ = response.send(block.commitment());
                }
                Message::Propose {
                    context,
                    mut response,
                } => {
                    select! {
                        _ = ChannelClosedFuture{ sender: &mut response } => {
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
                        _ = ChannelClosedFuture{ sender: &mut response } => {
                            debug!("verify: response channel closed");
                            continue;
                        },
                        valid = self.verify_block(context, payload) => {
                            let _ = response.send(valid);
                        }
                    }
                }
                Message::Report { block } => {
                    let height = block.height;
                    self.finalized.lock().unwrap().insert(height, block.clone());
                    info!(height, "finalized-delivered-to-app");

                    // Return early if not the last block in the epoch.
                    let Some(epoch) = epoch::is_last_block_in_epoch(height) else {
                        continue;
                    };

                    let seed = if epoch == 0 {
                        GENESIS_BLOCK.commitment()
                    } else {
                        let seed_height = epoch::get_last_height(epoch - 1);
                        self.finalized
                            .lock()
                            .unwrap()
                            .get(&seed_height)
                            .expect("seed block should exist")
                            .commitment()
                    };

                    orchestrator
                        .report(EpochUpdate {
                            epoch: epoch + 1,
                            seed,
                        })
                        .await;
                }
            }
        }
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
        self.marshal
            .subscribe(Some(round), commitment)
            .await
            .await
            .unwrap()
    }
}

// Define a future that checks if the oneshot channel is closed using a mutable reference
struct ChannelClosedFuture<'a, T> {
    sender: &'a mut oneshot::Sender<T>,
}

impl<T> Future for ChannelClosedFuture<'_, T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut FuturesContext<'_>) -> Poll<Self::Output> {
        // Use poll_canceled to check if the receiver has dropped the channel
        match self.sender.poll_canceled(cx) {
            Poll::Ready(()) => Poll::Ready(()), // Receiver dropped, channel closed
            Poll::Pending => Poll::Pending,     // Channel still open
        }
    }
}
