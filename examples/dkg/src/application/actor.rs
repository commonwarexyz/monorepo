use crate::{
    application::{types::genesis_block, Block, Mailbox, Message},
    dkg,
    utils::{get_last_height, height_in_epoch, BLOCKS_PER_EPOCH},
};
use commonware_consensus::{marshal, threshold_simplex::types::SigningScheme, types::Round};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, Committable, Digestible, Hasher, Signer,
};
use commonware_macros::select;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use futures::{
    channel::mpsc,
    future::{try_join, Either},
    lock::Mutex,
    StreamExt,
};
use rand::Rng;
use std::{future, sync::Arc, time::Duration};
use tracing::{info, warn};

/// The application [Actor].
pub struct Actor<E, H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
}

impl<E, H, C, V> Actor<E, H, C, V>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new application [Actor] and its associated [Mailbox].
    pub fn new(context: E, mailbox_size: usize) -> (Self, Mailbox<H, C, V>) {
        let (sender, mailbox) = mpsc::channel(mailbox_size);

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the application.
    pub fn start<S: SigningScheme>(
        mut self,
        marshal: marshal::Mailbox<S, Block<H, C, V>>,
        dkg: dkg::Mailbox<H, C, V>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(marshal, dkg).await)
    }

    /// Application control loop
    async fn run<S: SigningScheme>(
        mut self,
        mut marshal: marshal::Mailbox<S, Block<H, C, V>>,
        dkg: dkg::Mailbox<H, C, V>,
    ) {
        let genesis = genesis_block();
        let genesis_digest = genesis.digest();
        let built = Arc::new(Mutex::new(None));
        let stopped = &mut self.context.stopped();

        loop {
            select! {
                _ = stopped => {
                    info!("context stopped; exiting.");
                    break;
                },
                message = self.mailbox.next() => {
                    let Some(message) = message else {
                        info!("mailbox closed, exiting.");
                        break;
                    };

                    match message {
                        Message::Genesis { epoch, response } => {
                            // Case: Genesis.
                            if epoch == 0 {
                                let _ = response.send(genesis_block::<H, C, V>().commitment());
                                continue;
                            }

                            // Case: Non-genesis.
                            let height = get_last_height(epoch - 1);
                            let Some(block) = marshal.get_block(height).await else {
                                // No block exists, put the response in the responders map for later.
                                continue;
                            };
                            let _ = response.send(block.commitment());
                        }
                        Message::Propose {
                            round,
                            parent,
                            response,
                        } => {
                            let (parent_view, parent_digest) = parent;
                            let parent_request = if parent_digest == genesis_digest {
                                Either::Left(future::ready(Ok(genesis.clone())))
                            } else {
                                Either::Right(
                                    marshal
                                        .subscribe(
                                            Some(Round::new(round.epoch(), parent_view)),
                                            parent_digest,
                                        )
                                        .await,
                                )
                            };

                            let built = built.clone();
                            let mut dkg = dkg.clone();
                            self.context
                                .with_label("propose")
                                .spawn(move |context| async move {
                                    let parent = parent_request.await.expect("parent request cancelled");

                                    // Re-propose the parent block if it's already at the last height in the epoch.
                                    if parent.height == get_last_height(round.epoch()) {
                                        let result = response.send(parent.digest());
                                        info!(
                                            ?round,
                                            digest = ?parent.digest(),
                                            success = result.is_ok(),
                                            "re-proposed parent block at epoch boundary"
                                        );
                                        return;
                                    }

                                    // Ask the DKG actor for a result to include
                                    //
                                    // This approach does allow duplicate commitments to be proposed, but
                                    // the arbiter handles this by choosing the first commitment it sees
                                    // from any given dealer.
                                    let reshare = context
                                        .timeout(Duration::from_millis(5), async move { dkg.act().await })
                                        .await
                                        .ok()
                                        .flatten();

                                    // Create a new block
                                    let block = Block::new(parent_digest, parent.height + 1, reshare);
                                    let digest = block.digest();
                                    let mut built = built.lock().await;
                                    *built = Some((round.view(), block));

                                    // Send the digest to the consensus
                                    let result = response.send(digest);
                                    info!(
                                        ?round,
                                        ?digest,
                                        success = result.is_ok(),
                                        "proposed new block"
                                    );
                                });
                        }
                        Message::Verify {
                            round,
                            parent,
                            digest,
                            response,
                        } => {
                            let (parent_view, parent_digest) = parent;
                            let parent_request = if parent_digest == genesis_digest {
                                Either::Left(future::ready(Ok(genesis.clone())))
                            } else {
                                Either::Right(
                                    marshal
                                        .subscribe(
                                            Some(Round::new(round.epoch(), parent_view)),
                                            parent_digest,
                                        )
                                        .await,
                                )
                            };

                            let mut marshal = marshal.clone();
                            self.context
                                .with_label("verify")
                                .spawn(move |_| async move {
                                    let (parent, block) =
                                        try_join(parent_request, marshal.subscribe(None, digest).await)
                                            .await
                                            .unwrap();

                                    // You can only re-propose the same block if it's the last height in the epoch.
                                    if block.parent == block.commitment() {
                                        if block.height == get_last_height(round.epoch()) {
                                            marshal.verified(round, block).await;
                                            let _ = response.send(true);
                                        } else {
                                            let _ = response.send(false);
                                        }
                                        return;
                                    }

                                    // Verify the block
                                    if block.height != parent.height + 1
                                        || block.parent != parent.digest()
                                        || !height_in_epoch(block.height, round.epoch())
                                    {
                                        let _ = response.send(false);
                                        return;
                                    }

                                    marshal.verified(round, block).await;
                                    let _ = response.send(true);
                                });
                        }
                        Message::Broadcast { digest } => {
                            let Some((_, block)) = built.lock().await.clone() else {
                                warn!(%digest, "no built block to broadcast");
                                continue;
                            };

                            if block.digest() != digest {
                                warn!(
                                    want = %digest,
                                    have = %block.digest(),
                                    "Broadcast request digest does not match built block"
                                );
                                continue;
                            }

                            marshal.broadcast(block).await;
                        }
                        Message::Finalized { block } => {
                            info!(
                                height = block.height,
                                epoch = block.height / BLOCKS_PER_EPOCH,
                                "finalized block"
                            );
                        }
                    }
                }
            }
        }
    }
}
