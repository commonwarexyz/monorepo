//! Block bodies held in memory ahead of delivery or a reply.

use crate::multimmit::{
    marshal::store::blocks::Block,
    types::{BlockRef, Body},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::Hasher;
use std::collections::{HashMap, HashSet, VecDeque};

/// A block's body held in memory ahead of delivery or a reply.
///
/// Bodies are evicted oldest first beyond the byte bound, except the pinned ones: the bodies of
/// the next positions to dispatch, so read-ahead for final reports or lookups never evicts what
/// delivery is about to need. At most as many bodies are pinned as maximum-size blocks fit the
/// bound (at least one), so pinned bodies alone never exceed it. The eviction queue is lazy: a
/// removed body leaves a stale entry that eviction skips, so removal is O(1).
pub(super) struct Hot<H: Hasher, B: Body<H>> {
    pub(super) blocks: HashMap<H::Digest, (u64, Block<H, B>)>,
    pub(super) order: VecDeque<(u64, H::Digest)>,
    pinned: HashSet<H::Digest>,
    max_pinned: usize,
    next: u64,
    pub(super) bytes: usize,
    max_bytes: usize,
}

impl<H: Hasher, B: Body<H>> Hot<H, B> {
    /// Creates a cache of at most `max_bytes` of bodies, each at most `max_block_bytes`.
    pub(super) fn new(max_bytes: usize, max_block_bytes: usize) -> Self {
        Self {
            blocks: HashMap::new(),
            order: VecDeque::new(),
            pinned: HashSet::new(),
            max_pinned: (max_bytes / max_block_bytes.max(1)).max(1),
            next: 0,
            bytes: 0,
            max_bytes,
        }
    }

    pub(super) fn get(&self, reference: BlockRef<H::Digest>) -> Option<&Block<H, B>> {
        self.blocks
            .get(&reference.digest())
            .map(|(_, block)| block)
            .filter(|block| block.reference() == reference)
    }

    /// Holds `block`, evicting the oldest unpinned bodies beyond the byte bound.
    pub(super) fn insert(&mut self, block: Block<H, B>) {
        let digest = block.reference().digest();
        if self.blocks.contains_key(&digest) {
            return;
        }
        self.bytes += block.encode_size();
        self.next += 1;
        self.blocks.insert(digest, (self.next, block));
        self.order.push_back((self.next, digest));
        // Each entry is looked at once per call: pinned ones go to the back.
        let mut budget = self.order.len();
        while self.bytes > self.max_bytes && self.blocks.len() > 1 && budget > 0 {
            budget -= 1;
            let (seq, oldest) = self.order.pop_front().expect("bodies are queued");
            if self
                .blocks
                .get(&oldest)
                .is_none_or(|(held, _)| *held != seq)
            {
                continue;
            }
            if self.pinned.contains(&oldest) {
                self.order.push_back((seq, oldest));
                continue;
            }
            let (_, evicted) = self.blocks.remove(&oldest).expect("checked above");
            self.bytes -= evicted.encode_size();
        }
        if self.order.len() > 2 * self.blocks.len() + 16 {
            let blocks = &self.blocks;
            self.order
                .retain(|(seq, digest)| blocks.get(digest).is_some_and(|(held, _)| held == seq));
        }
    }

    /// Returns the most bodies [`Self::pin`] holds.
    pub(super) const fn max_pinned(&self) -> usize {
        self.max_pinned
    }

    /// Pins exactly the bodies of the first [`Self::max_pinned`] of `blocks` (the next
    /// positions to dispatch).
    pub(super) fn pin(&mut self, blocks: impl IntoIterator<Item = BlockRef<H::Digest>>) {
        self.pinned.clear();
        self.pinned.extend(
            blocks
                .into_iter()
                .take(self.max_pinned)
                .map(|block| block.digest()),
        );
    }

    /// Keeps only the bodies of blocks `keep` admits.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&Block<H, B>) -> bool) {
        let mut freed = 0;
        self.blocks.retain(|_, (_, block)| {
            let kept = keep(block);
            if !kept {
                freed += block.encode_size();
            }
            kept
        });
        self.bytes -= freed;
    }

    /// Releases the body of a delivered block: the update owns it now.
    pub(super) fn remove(&mut self, reference: BlockRef<H::Digest>) {
        if let Some((_, block)) = self.blocks.remove(&reference.digest()) {
            self.bytes -= block.encode_size();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Hot;
    use crate::{
        multimmit::{
            testing::TestBody,
            types::{ChainId, TransactionBlock, TransactionBlockHeader},
        },
        types::{Epoch, Height},
    };
    use commonware_codec::EncodeSize as _;
    use commonware_cryptography::{Digestible as _, Hasher as _, Sha256};
    use std::sync::Arc;

    type Block = Arc<TransactionBlock<Sha256, TestBody>>;

    fn block(height: u64) -> Block {
        let body = TestBody::new(Sha256::hash(&[b"app"]), Height::new(height), 0);
        let header = TransactionBlockHeader::new(
            Epoch::new(1),
            ChainId::new(0),
            Height::new(height),
            Sha256::hash(&[&height.to_be_bytes()]),
            body.digest(),
        )
        .unwrap();
        Arc::new(TransactionBlock::new(header, body).unwrap())
    }

    #[test]
    fn the_oldest_unpinned_bodies_are_evicted_beyond_the_bound() {
        let blocks = (1..=4).map(block).collect::<Vec<_>>();
        let size = blocks[0].encode_size();
        let mut hot = Hot::<Sha256, TestBody>::new(2 * size, size);
        hot.insert(Arc::clone(&blocks[0]));
        hot.insert(Arc::clone(&blocks[1]));
        // The next delivery's body is pinned, so the second oldest goes instead.
        hot.pin([blocks[0].reference()]);
        hot.insert(Arc::clone(&blocks[2]));
        assert!(hot.get(blocks[0].reference()).is_some());
        assert!(hot.get(blocks[1].reference()).is_none());
        assert!(hot.get(blocks[2].reference()).is_some());
        assert_eq!(hot.bytes, 2 * size);

        // A delivered body leaves at once; its stale queue entry is skipped later.
        hot.remove(blocks[0].reference());
        assert_eq!(hot.bytes, size);
        hot.insert(Arc::clone(&blocks[3]));
        assert!(hot.get(blocks[2].reference()).is_some());
        assert!(hot.get(blocks[3].reference()).is_some());
        assert_eq!(hot.bytes, 2 * size);
    }

    #[test]
    fn pinned_bodies_never_exceed_the_byte_bound() {
        let blocks = (1..=4).map(block).collect::<Vec<_>>();
        let size = blocks[0].encode_size();
        let mut hot = Hot::<Sha256, TestBody>::new(2 * size, size);
        assert_eq!(hot.max_pinned(), 2);
        // Delivery asks to pin more bodies than fit: only the first ones stay pinned.
        hot.pin(blocks.iter().map(|block| block.reference()));
        for block in &blocks {
            hot.insert(Arc::clone(block));
            assert!(hot.bytes <= 2 * size);
        }
        assert!(hot.get(blocks[0].reference()).is_some());
        assert!(hot.get(blocks[1].reference()).is_some());

        // A bound below one block still pins the next body.
        let hot = Hot::<Sha256, TestBody>::new(size / 2, size);
        assert_eq!(hot.max_pinned(), 1);
    }

    #[test]
    fn removed_bodies_never_accumulate_in_the_eviction_queue() {
        let size = block(1).encode_size();
        let mut hot = Hot::<Sha256, TestBody>::new(4 * size, size);
        for height in 1..=1_000 {
            let block = block(height);
            hot.insert(Arc::clone(&block));
            hot.remove(block.reference());
        }
        assert_eq!(hot.bytes, 0);
        assert!(hot.order.len() <= 2 * hot.blocks.len() + 16 + 1);
    }

    #[test]
    fn retain_drops_bodies_and_their_bytes() {
        let blocks = (1..=3).map(block).collect::<Vec<_>>();
        let size = blocks[0].encode_size();
        let mut hot = Hot::<Sha256, TestBody>::new(8 * size, size);
        for block in &blocks {
            hot.insert(Arc::clone(block));
        }
        hot.retain(|block| block.header().height() > Height::new(1));
        assert!(hot.get(blocks[0].reference()).is_none());
        assert_eq!(hot.bytes, 2 * size);
    }
}
