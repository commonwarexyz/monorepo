//! Actor-facing buffered dissemination of complete transaction blocks.

use crate::Block;
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_cryptography::PublicKey;
use commonware_p2p::Recipients;
use std::{future::Future, sync::Arc};

/// Typed access to the buffered mailbox keyed by canonical block digest.
pub(in crate::multimmit::marshal) struct Mailbox<P: PublicKey, B: Block> {
    inner: buffered::Mailbox<P, B>,
}

impl<P: PublicKey, B: Block> Mailbox<P, B> {
    pub(in crate::multimmit::marshal) const fn new(inner: buffered::Mailbox<P, B>) -> Self {
        Self { inner }
    }

    /// Broadcasts a complete block without copying it.
    pub(in crate::multimmit::marshal) fn broadcast(
        &self,
        recipients: Recipients<P>,
        block: Arc<B>,
    ) -> Feedback {
        self.inner.broadcast_shared(recipients, block)
    }

    /// Returns a cached block by its canonical digest.
    pub(in crate::multimmit::marshal) async fn get(&self, digest: B::Digest) -> Option<Arc<B>> {
        self.inner.get(digest).await
    }

    /// Waits for a block identified by its canonical digest.
    pub(in crate::multimmit::marshal) fn subscribe(
        &self,
        digest: B::Digest,
    ) -> impl Future<Output = Option<Arc<B>>> + Send + 'static {
        let receiver = self.inner.subscribe(digest);
        async move { receiver.await.ok() }
    }
}

impl<P: PublicKey, B: Block> Clone for Mailbox<P, B> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}
