use crate::Block;
use commonware_broadcast::{buffered, Broadcaster};
use commonware_cryptography::PublicKey;
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::future::Future;

/// Minimal buffer interface required by marshal.
pub trait Buffer<B: Block>: Send + Sync + 'static {
    /// Broadcast a locally proposed block.
    fn broadcast(&mut self, block: B) -> impl Future<Output = ()> + Send;

    /// Lookup a block by commitment.
    fn get(&self, commitment: B::Commitment) -> impl Future<Output = Option<B>> + Send;

    /// Subscribe for a block becoming available by commitment.
    ///
    /// Returning `None` indicates that subscriptions are unsupported.
    fn subscribe(
        &self,
        commitment: B::Commitment,
    ) -> impl Future<Output = Option<oneshot::Receiver<B>>> + Send;
}

impl<K: PublicKey, B: Block> Buffer<B> for buffered::Mailbox<K, B> {
    async fn broadcast(&mut self, block: B) {
        let _peers =
            <buffered::Mailbox<K, B> as Broadcaster>::broadcast(self, Recipients::All, block).await;
    }

    async fn get(&self, commitment: B::Commitment) -> Option<B> {
        self.get(None, commitment, None).await.into_iter().next()
    }

    async fn subscribe(&self, commitment: B::Commitment) -> Option<oneshot::Receiver<B>> {
        let (tx, rx) = oneshot::channel();
        self.subscribe_prepared(None, commitment, None, tx).await;
        Some(rx)
    }
}

/// Buffer implementation for environments where network broadcast is disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOp;

impl<B: Block> Buffer<B> for NoOp {
    async fn broadcast(&mut self, _block: B) {}

    async fn get(&self, _commitment: B::Commitment) -> Option<B> {
        None
    }

    async fn subscribe(&self, _commitment: B::Commitment) -> Option<oneshot::Receiver<B>> {
        None
    }
}
