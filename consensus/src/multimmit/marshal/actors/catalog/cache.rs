//! Advisory byte-bounded cache of recently admitted and materialized blocks.

use crate::multimmit::{
    marshal::storage::{blocks::BlockMeta, commit::CustodyRef},
    types::{BlockRef, Body, ChainId, TransactionBlock},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::Hasher;
use std::{
    collections::{HashMap, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

/// One cached block and its encoded length.
pub(super) struct CachedBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    encoded_len: usize,
    block: Arc<TransactionBlock<H, B>>,
}

/// A non-authoritative byte-bounded cache of validated producer blocks.
pub(super) struct BlockCache<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    max_bytes: NonZeroUsize,
    encoded_bytes: usize,
    order: VecDeque<BlockRef<H::Digest>>,
    blocks: HashMap<BlockRef<H::Digest>, CachedBlock<H, B>>,
    by_digest: HashMap<(ChainId, H::Digest), BlockRef<H::Digest>>,
}

impl<H, B> BlockCache<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(super) fn new(max_bytes: NonZeroUsize) -> Self {
        Self {
            max_bytes,
            encoded_bytes: 0,
            order: VecDeque::new(),
            blocks: HashMap::new(),
            by_digest: HashMap::new(),
        }
    }

    /// Returns the number of cached blocks.
    pub(super) fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the encoded bytes of every cached block.
    pub(super) const fn bytes(&self) -> usize {
        self.encoded_bytes
    }

    /// Returns the encoded-byte bound.
    pub(super) fn max_bytes(&self) -> NonZeroU64 {
        NonZeroU64::try_from(self.max_bytes).unwrap_or(NonZeroU64::MAX)
    }

    /// Retains unique references in insertion order. Oversized blocks are skipped.
    pub(super) fn insert(
        &mut self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> u64 {
        if self.blocks.contains_key(&reference) {
            return 0;
        }
        let encoded_len = block.encode_size();
        if encoded_len > self.max_bytes.get() {
            return 0;
        }
        let mut evictions = 0u64;
        while self
            .encoded_bytes
            .checked_add(encoded_len)
            .is_none_or(|total| total > self.max_bytes.get())
        {
            let evicted_reference = self
                .order
                .pop_front()
                .expect("a non-empty cache exceeds its byte bound");
            let block = self
                .blocks
                .remove(&evicted_reference)
                .expect("cache order names a retained block");
            self.by_digest
                .remove(&(evicted_reference.chain(), evicted_reference.digest()));
            self.encoded_bytes -= block.encoded_len;
            evictions = evictions.saturating_add(1);
        }
        self.encoded_bytes += encoded_len;
        self.order.push_back(reference);
        self.by_digest
            .insert((reference.chain(), reference.digest()), reference);
        self.blocks
            .insert(reference, CachedBlock { encoded_len, block });
        evictions
    }

    pub(super) fn get(
        &self,
        reference: &BlockRef<H::Digest>,
    ) -> Option<Arc<TransactionBlock<H, B>>> {
        self.blocks
            .get(reference)
            .map(|entry| Arc::clone(&entry.block))
    }

    pub(super) fn custody(&self, reference: BlockRef<H::Digest>) -> Option<CustodyRef<H::Digest>> {
        let entry = self.blocks.get(&reference)?;
        let encoded_len = u64::try_from(entry.encoded_len).ok()?;
        Some(CustodyRef::new(
            reference,
            BlockMeta::new(entry.block.header().clone(), encoded_len),
        ))
    }

    pub(super) fn get_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Option<Arc<TransactionBlock<H, B>>> {
        self.by_digest
            .get(&(chain, digest))
            .and_then(|reference| self.get(reference))
    }

    pub(super) fn clear(&mut self) {
        self.encoded_bytes = 0;
        self.order.clear();
        self.blocks.clear();
        self.by_digest.clear();
    }

    /// Evicts every block at or below its chain's frontier.
    pub(super) fn prune(&mut self, frontiers: &[BlockRef<H::Digest>]) {
        let Self {
            encoded_bytes,
            order,
            blocks,
            by_digest,
            ..
        } = self;
        order.retain(|reference| {
            let promoted = frontiers
                .get(reference.chain().get() as usize)
                .is_some_and(|frontier| reference.height() <= frontier.height());
            if promoted {
                let block = blocks
                    .remove(reference)
                    .expect("cache order names a retained block");
                by_digest.remove(&(reference.chain(), reference.digest()));
                *encoded_bytes -= block.encoded_len;
            }
            !promoted
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{super::tests::producer_block, *};
    use crate::{
        multimmit::{mocks::Committee, types::PathLimits},
        types::{Height, Participant},
    };
    use commonware_cryptography::bls12381::primitives::variant::MinPk;

    #[test]
    fn block_cache_is_byte_bounded_and_idempotent() {
        let committee = Committee::<MinPk>::builder(7, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BLOCK_CACHE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 10);
        let second = producer_block(&committee, 0, 11);
        let third = producer_block(&committee, 0, 12);
        let block_len = first.encode_size();
        assert_eq!(second.encode_size(), block_len);
        assert_eq!(third.encode_size(), block_len);

        let mut cache = BlockCache::new(NonZeroUsize::new(block_len * 2).unwrap());
        cache.insert(first.reference(), Arc::clone(&first));
        cache.insert(first.reference(), Arc::clone(&first));
        assert_eq!(cache.bytes(), block_len);
        assert_eq!(cache.len(), 1);

        cache.insert(second.reference(), Arc::clone(&second));
        assert_eq!(
            cache
                .get_by_digest(second.reference().chain(), second.reference().digest())
                .as_deref(),
            Some(second.as_ref())
        );
        cache.insert(third.reference(), Arc::clone(&third));
        assert!(cache.get(&first.reference()).is_none());
        assert_eq!(
            cache.get(&second.reference()).as_deref(),
            Some(second.as_ref())
        );
        assert_eq!(
            cache.get(&third.reference()).as_deref(),
            Some(third.as_ref())
        );
        assert_eq!(cache.bytes(), block_len * 2);

        let mut oversized = BlockCache::new(NonZeroUsize::new(block_len - 1).unwrap());
        oversized.insert(first.reference(), first);
        assert_eq!(oversized.len(), 0);
    }

    #[test]
    fn prune_evicts_blocks_at_or_below_their_chain_frontier() {
        let committee = Committee::<MinPk>::builder(7, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BLOCK_CACHE_PRUNE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let promoted = producer_block(&committee, 0, 10);
        let retained = producer_block(&committee, 1, 11);
        let later = producer_block(&committee, 2, 12);
        let block_len = promoted.encode_size();
        let mut cache = BlockCache::new(NonZeroUsize::new(block_len * 3).unwrap());
        for block in [&promoted, &retained, &later] {
            cache.insert(block.reference(), Arc::clone(block));
        }

        let frontier = |reference: BlockRef<_>, height| {
            BlockRef::new(reference.chain(), Height::new(height), reference.digest())
        };
        cache.prune(&[
            frontier(promoted.reference(), 1),
            frontier(retained.reference(), 0),
            frontier(later.reference(), 0),
        ]);
        assert!(cache.get(&promoted.reference()).is_none());
        let digest = promoted.reference().digest();
        assert!(cache.get_by_digest(ChainId::new(0), digest).is_none());
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.bytes(), block_len * 2);
        assert_eq!(
            cache.order,
            VecDeque::from([retained.reference(), later.reference()])
        );
    }
}
