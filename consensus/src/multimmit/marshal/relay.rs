//! A consensus [`Relay`](crate::Relay) that broadcasts this node's staged blocks.
//!
//! Consensus asks its relay to disseminate a block by header digest right after the application
//! proposes it, and again while the block's publication is pending. Marshal already holds every
//! block the application staged, so the relay looks the block up by digest and hands it to
//! buffered broadcast, and the application keeps no copy.

use crate::multimmit::types::{Body, ChainId, TransactionBlock};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::sync::Mutex;
use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::debug;

/// This node's most recently staged blocks, by header digest.
pub(super) struct Staged<H: Hasher, B: Body<H>> {
    blocks: HashMap<H::Digest, Arc<TransactionBlock<H, B>>>,
    order: VecDeque<H::Digest>,
    retention: NonZeroUsize,
    chain: Option<ChainId>,
}

impl<H: Hasher, B: Body<H>> Staged<H, B> {
    /// Creates an empty set that keeps the `retention` most recently staged blocks of this node,
    /// whose producer chain is `chain`.
    pub(super) fn new(retention: NonZeroUsize, chain: Option<ChainId>) -> Self {
        Self {
            blocks: HashMap::with_capacity(retention.get()),
            order: VecDeque::with_capacity(retention.get()),
            retention,
            chain,
        }
    }

    /// Keeps a subscribed `block` when it belongs to this node's producer chain.
    ///
    /// After a restart, this node's own blocks come back through subscriptions rather than
    /// staging, and consensus may still ask the relay to publish them.
    pub(super) fn remember(&mut self, block: Arc<TransactionBlock<H, B>>) {
        if Some(block.reference().chain()) == self.chain {
            self.insert(block);
        }
    }

    /// Keeps `block`, evicting the oldest staged block beyond the retention bound.
    pub(super) fn insert(&mut self, block: Arc<TransactionBlock<H, B>>) {
        let digest = block.reference().digest();
        if self.blocks.insert(digest, block).is_some() {
            return;
        }
        self.order.push_back(digest);
        if self.order.len() > self.retention.get() {
            let evicted = self
                .order
                .pop_front()
                .expect("order exceeds a non-zero bound");
            self.blocks.remove(&evicted);
        }
    }

    /// Returns the staged block with header digest `digest`.
    fn get(&self, digest: &H::Digest) -> Option<Arc<TransactionBlock<H, B>>> {
        self.blocks.get(digest).cloned()
    }
}

/// A [`Relay`](crate::Relay) that broadcasts blocks staged through the marshal
/// [`Mailbox`](super::Mailbox) to every peer.
///
/// Created by [`Service::relay`](super::Service::relay). A digest that was never staged, or was
/// staged more than the configured retention ago, is not broadcast. A subscribed block on this
/// node's producer chain counts as staged.
pub struct Relay<H: Hasher, B: Body<H>, P: PublicKey> {
    staged: Arc<Mutex<Staged<H, B>>>,
    broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
}

impl<H: Hasher, B: Body<H>, P: PublicKey> Relay<H, B, P> {
    pub(super) const fn new(
        staged: Arc<Mutex<Staged<H, B>>>,
        broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
    ) -> Self {
        Self { staged, broadcast }
    }
}

impl<H: Hasher, B: Body<H>, P: PublicKey> Clone for Relay<H, B, P> {
    fn clone(&self) -> Self {
        Self {
            staged: Arc::clone(&self.staged),
            broadcast: self.broadcast.clone(),
        }
    }
}

impl<H: Hasher, B: Body<H>, P: PublicKey> crate::Relay for Relay<H, B, P> {
    type Digest = H::Digest;
    type PublicKey = P;
    type Plan = ();

    fn broadcast(&mut self, digest: Self::Digest, (): Self::Plan) -> Feedback {
        let Some(block) = self.staged.lock().get(&digest) else {
            debug!(?digest, "relay requested a block that is not staged");
            return Feedback::Ok;
        };
        self.broadcast.broadcast_shared(Recipients::All, block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{ChainId, Context},
        simplex::marshal::mocks::block::EmptyBlock,
        types::{Epoch, Height},
    };
    use commonware_cryptography::Sha256;

    fn block(marker: u8) -> Arc<TransactionBlock<Sha256, EmptyBlock<Sha256>>> {
        let context = Context::new(
            Epoch::new(1),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"parent"]),
        )
        .unwrap();
        let body = EmptyBlock::new(Sha256::hash(&[&[marker]]), Height::new(1), 0);
        Arc::new(TransactionBlock::from_context(context, body))
    }

    #[test]
    fn staged_blocks_keep_only_the_most_recent() {
        let mut staged = Staged::new(NonZeroUsize::new(2).unwrap(), None);
        let [first, second, third] = [block(1), block(2), block(3)];
        let digest =
            |block: &Arc<TransactionBlock<Sha256, EmptyBlock<Sha256>>>| block.reference().digest();
        staged.insert(Arc::clone(&first));
        staged.insert(Arc::clone(&second));
        // Restaging a retained block does not refresh or duplicate it.
        staged.insert(Arc::clone(&first));
        assert_eq!(staged.get(&digest(&first)), Some(Arc::clone(&first)));
        assert_eq!(staged.get(&digest(&second)), Some(Arc::clone(&second)));

        staged.insert(Arc::clone(&third));
        assert_eq!(staged.get(&digest(&first)), None);
        assert_eq!(staged.get(&digest(&second)), Some(second));
        assert_eq!(staged.get(&digest(&third)), Some(third));
    }

    #[test]
    fn subscribed_blocks_are_kept_only_for_the_local_chain() {
        let mut staged = Staged::new(NonZeroUsize::new(4).unwrap(), Some(ChainId::new(0)));
        let local = block(1);
        staged.remember(Arc::clone(&local));
        assert_eq!(
            staged.get(&local.reference().digest()),
            Some(Arc::clone(&local))
        );

        let mut validator = Staged::new(NonZeroUsize::new(4).unwrap(), None);
        validator.remember(Arc::clone(&local));
        assert_eq!(validator.get(&local.reference().digest()), None);
        let mut other = Staged::new(NonZeroUsize::new(4).unwrap(), Some(ChainId::new(1)));
        other.remember(Arc::clone(&local));
        assert_eq!(other.get(&local.reference().digest()), None);
    }
}
