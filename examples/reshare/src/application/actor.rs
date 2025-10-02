use crate::{
    application::{types::B, Mailbox, Message, H},
    dkg,
};
use commonware_consensus::{marshal, types::Round};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, ed25519::PrivateKey, Digestible, Hasher, Sha256,
};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use futures::{
    channel::mpsc,
    future::{try_join, Either},
    lock::Mutex,
    StreamExt,
};
use rand::Rng;
use std::{future, sync::Arc, time::Duration};
use tracing::{info, warn};

const GENESIS_MESSAGE: &[u8] = b"reshare spell";

/// The application [Actor].
pub struct Actor<E> {
    context: E,
    mailbox: mpsc::Receiver<Message>,
}

impl<E> Actor<E>
where
    E: Rng + Spawner + Metrics + Clock,
{
    /// Create a new application [Actor] and its associated [Mailbox].
    pub fn new(context: E, mailbox_size: usize) -> (Self, Mailbox) {
        let (sender, mailbox) = mpsc::channel(mailbox_size);

        (Self { context, mailbox }, Mailbox::new(sender))
    }

    /// Start the application.
    pub fn start(
        mut self,
        marshal: marshal::Mailbox<MinSig, B>,
        dkg: dkg::Mailbox<Sha256, PrivateKey, MinSig>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(marshal, dkg))
    }

    /// Application control loop
    async fn run(
        mut self,
        mut marshal: marshal::Mailbox<MinSig, B>,
        dkg: dkg::Mailbox<Sha256, PrivateKey, MinSig>,
    ) {
        let genesis = B::new(H::hash(GENESIS_MESSAGE), 0, None);
        let genesis_digest = genesis.digest();
        let built = Arc::new(Mutex::new(None));

        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Genesis { response } => {
                    let _ = response.send(genesis_digest);
                }
                Message::Propose {
                    view,
                    parent,
                    response,
                } => {
                    let (parent_view, parent_digest) = parent;
                    let parent_request = if parent_digest == genesis_digest {
                        Either::Left(future::ready(Ok(genesis.clone())))
                    } else {
                        Either::Right(
                            marshal
                                .subscribe(Some(Round::new(0, parent_view)), parent_digest)
                                .await,
                        )
                    };

                    let built = built.clone();
                    let mut dkg = dkg.clone();
                    self.context
                        .with_label("propose")
                        .spawn(move |context| async move {
                            let parent = parent_request.await.expect("parent request cancelled");

                            // Ask the DKG actor for a result to include
                            let reshare = context
                                .timeout(Duration::from_millis(5), async move { dkg.act().await })
                                .await
                                .ok()
                                .flatten();

                            // Create a new block
                            let block = B::new(parent_digest, parent.height + 1, reshare);
                            let digest = block.digest();
                            let mut built = built.lock().await;
                            *built = Some((view, block));

                            // Send the digest to the consensus
                            let result = response.send(digest);
                            info!(
                                view,
                                ?digest,
                                success = result.is_ok(),
                                "proposed new block"
                            );
                        });
                }
                Message::Verify {
                    view,
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
                                .subscribe(Some(Round::new(0, parent_view)), parent_digest)
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

                            // Verify the block
                            if block.height != parent.height + 1 || block.parent != parent.digest()
                            {
                                let _ = response.send(false);
                                return;
                            }

                            marshal.verified(Round::new(0, view), block).await;
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
                    info!(height = block.height, "finalized block");
                }
            }
        }

        info!(target: "application", "mailbox closed, exiting.");
    }
}
