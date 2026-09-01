//! Constant-space producer-chain ancestry validation.

use crate::{
    Epochable as _,
    multimmit::types::{BlockRef, TransactionBlockHeader},
    types::Epoch,
};
use commonware_cryptography::{Digest, Hasher};
use std::cmp::Ordering;

/// A producer-chain ancestry step is inconsistent with its request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    /// The two frontiers name different chains.
    #[error("producer-chain frontiers name different chains")]
    Chain,
    /// A parent is not one height below the requested reference on its chain.
    #[error("producer block does not match the requested coordinate")]
    Coordinate,
    /// The walk needs no more headers.
    #[error("ancestry walk is already complete")]
    Complete,
    /// The walk reached the lower frontier's height at another block.
    #[error("producer-chain frontiers fork")]
    Fork,
    /// A header belongs to another epoch.
    #[error("producer header belongs to another epoch")]
    Epoch,
}

/// The unauthenticated interval of an [`Ancestry`] walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds<D: Digest> {
    /// The lower reference the walk must reach.
    pub low: BlockRef<D>,
    /// The next reference whose header is required.
    pub high: BlockRef<D>,
}

/// A restartable walk from a producer-chain tip to a lower height.
///
/// Each response authenticates the next request through its header's parent digest. Application
/// bodies are not needed to prove protocol ancestry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ancestry<D: Digest> {
    cursor: BlockRef<D>,
    expected: BlockRef<D>,
}

impl<D: Digest> Ancestry<D> {
    /// Starts proving the common frontier of `target` and `emitted`.
    ///
    /// The higher reference is descended to the lower height. Equal heights must already name the
    /// same header, and completion requires the discovered ancestor to equal the lower reference.
    pub(crate) fn common(target: BlockRef<D>, emitted: BlockRef<D>) -> Result<Self, Error> {
        if target.chain() != emitted.chain() {
            return Err(Error::Chain);
        }
        let (cursor, expected) = match target.height().cmp(&emitted.height()) {
            Ordering::Greater => (target, emitted),
            Ordering::Less => (emitted, target),
            Ordering::Equal => {
                if target.digest() != emitted.digest() {
                    return Err(Error::Fork);
                }
                (target, target)
            }
        };
        Ok(Self { cursor, expected })
    }

    /// Returns the next block reference whose header is required.
    pub(crate) fn next(&self) -> Option<BlockRef<D>> {
        (self.cursor.height() != self.expected.height()).then_some(self.cursor)
    }

    /// Returns the number of headers still required to reach the common frontier.
    pub(crate) fn remaining(&self) -> usize {
        usize::try_from(
            self.cursor
                .height()
                .get()
                .checked_sub(self.expected.height().get())
                .expect("the ancestry cursor does not cross its frontier"),
        )
        .unwrap_or(usize::MAX)
    }

    /// Returns the interval the walk has yet to authenticate.
    pub(crate) const fn bounds(&self) -> Bounds<D> {
        Bounds {
            low: self.expected,
            high: self.cursor,
        }
    }

    /// Accepts the header of the next required reference and advances exactly one parent.
    ///
    /// The caller supplies a header already authenticated as the requested block: validated at
    /// backfill delivery, read from local storage, or found by its own identity. Debug builds
    /// assert its digest.
    pub(crate) fn accept<H>(
        &mut self,
        epoch: Epoch,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
    {
        // Header hints reach the walk through a cache keyed by block reference alone.
        if header.epoch() != epoch {
            return Err(Error::Epoch);
        }
        debug_assert!(
            self.next()
                .is_none_or(|request| header.digest::<H>() == request.digest())
        );
        self.accept_parent(header.parent_ref())
    }

    /// Advances through an authenticated parent edge.
    pub(crate) fn accept_parent(&mut self, parent: BlockRef<D>) -> Result<(), Error> {
        let request = self.next().ok_or(Error::Complete)?;
        if parent.chain() != request.chain() || Some(parent.height()) != request.height().previous()
        {
            return Err(Error::Coordinate);
        }
        if parent.height() == self.expected.height() && self.expected != parent {
            return Err(Error::Fork);
        }
        self.cursor = parent;
        Ok(())
    }

    /// Returns the target reference once no more headers are required.
    pub(crate) fn finish(&self) -> Option<BlockRef<D>> {
        if self.cursor == self.expected {
            Some(self.cursor)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{ChainId, TransactionBlockHeader},
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
    use proptest::prelude::*;

    type TestHeader = TransactionBlockHeader<Sha256Digest>;

    fn genesis(chain: u32) -> Sha256Digest {
        Sha256::hash(&[b"ancestry genesis", &chain.to_be_bytes()])
    }

    fn header(chain: u32, height: u64, parent: Sha256Digest, salt: u64) -> TestHeader {
        TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(chain),
            Height::new(height),
            parent,
            Sha256::hash(&[b"ancestry body", &salt.to_be_bytes()]),
        )
        .unwrap()
    }

    fn chain(chain: u32, length: u64, salt: u64) -> Vec<TestHeader> {
        let mut parent = genesis(chain);
        (1..=length)
            .map(|height| {
                let header = header(chain, height, parent, salt + height);
                parent = header.block_ref::<Sha256>().digest();
                header
            })
            .collect()
    }

    fn walk(blocks: &[TestHeader], target: u64) -> BlockRef<Sha256Digest> {
        let tip = blocks.last().unwrap().block_ref::<Sha256>();
        let expected = if target == 0 {
            BlockRef::new(tip.chain(), Height::zero(), genesis(tip.chain().get()))
        } else {
            blocks[target as usize - 1].block_ref::<Sha256>()
        };
        let mut ancestry = Ancestry::common(tip, expected).unwrap();
        while let Some(request) = ancestry.next() {
            ancestry
                .accept::<Sha256>(Epoch::new(7), &blocks[request.height().get() as usize - 1])
                .unwrap();
        }
        ancestry.finish().unwrap()
    }

    #[test]
    fn resolves_genesis_without_retaining_the_gap() {
        let blocks = chain(2, 20_000, 10);
        let resolved = walk(&blocks, 0);
        assert_eq!(
            resolved,
            BlockRef::new(ChainId::new(2), Height::zero(), genesis(2))
        );
        assert_eq!(
            std::mem::size_of::<Ancestry<Sha256Digest>>(),
            std::mem::size_of::<(BlockRef<Sha256Digest>, BlockRef<Sha256Digest>)>(),
        );
    }

    #[test]
    fn rejects_wrong_coordinate() {
        let blocks = chain(0, 3, 20);
        let tip = blocks[2].block_ref::<Sha256>();
        let mut ancestry = Ancestry::common(
            tip,
            BlockRef::new(ChainId::new(0), Height::zero(), genesis(0)),
        )
        .unwrap();

        assert_eq!(
            ancestry.accept_parent(BlockRef::new(ChainId::new(1), Height::new(2), genesis(1))),
            Err(Error::Coordinate)
        );
        assert_eq!(
            ancestry.accept_parent(BlockRef::new(ChainId::new(0), Height::new(1), genesis(0))),
            Err(Error::Coordinate)
        );
        assert_eq!(ancestry.next(), Some(tip));
        ancestry
            .accept::<Sha256>(Epoch::new(7), &blocks[2])
            .unwrap();
        assert_eq!(ancestry.next(), Some(blocks[1].block_ref::<Sha256>()));
    }

    #[test]
    fn rejects_a_header_from_another_epoch() {
        let blocks = chain(0, 3, 20);
        let tip = blocks[2].block_ref::<Sha256>();
        let mut ancestry = Ancestry::common(
            tip,
            BlockRef::new(ChainId::new(0), Height::zero(), genesis(0)),
        )
        .unwrap();

        assert_eq!(
            ancestry.accept::<Sha256>(Epoch::new(8), &blocks[2]),
            Err(Error::Epoch)
        );
        assert_eq!(ancestry.next(), Some(tip));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn debug_asserts_the_header_digest() {
        let blocks = chain(0, 3, 20);
        let mut ancestry = Ancestry::common(
            blocks[2].block_ref::<Sha256>(),
            BlockRef::new(ChainId::new(0), Height::zero(), genesis(0)),
        )
        .unwrap();
        let other = header(0, 3, genesis(0), 30);
        let _ = ancestry.accept::<Sha256>(Epoch::new(7), &other);
    }

    #[test]
    fn common_frontier_rejects_coordinates_and_forks() {
        let canonical = chain(0, 3, 40);
        let fork = chain(0, 1, 50);
        let high = canonical[2].block_ref::<Sha256>();
        let low = fork[0].block_ref::<Sha256>();
        let mut ancestry = Ancestry::common(high, low).unwrap();
        ancestry
            .accept::<Sha256>(Epoch::new(7), &canonical[2])
            .unwrap();
        assert_eq!(
            ancestry.accept::<Sha256>(Epoch::new(7), &canonical[1]),
            Err(Error::Fork)
        );
        assert_eq!(
            Ancestry::common(
                high,
                BlockRef::new(ChainId::new(1), low.height(), low.digest())
            ),
            Err(Error::Chain)
        );
        assert_eq!(
            Ancestry::common(canonical[0].block_ref::<Sha256>(), low),
            Err(Error::Fork)
        );
    }

    proptest! {
        #[test]
        fn exact_walks_and_common_frontiers_are_restartable(
            length in 1u64..128,
            target in 0u64..128,
            split in 0u64..128,
        ) {
            let target = target.min(length);
            let split = split.min(length);
            let blocks = chain(3, length, 60);
            let resolved = walk(&blocks, target);
            let expected = if target == 0 {
                BlockRef::new(ChainId::new(3), Height::zero(), genesis(3))
            } else {
                blocks[target as usize - 1].block_ref::<Sha256>()
            };
            prop_assert_eq!(resolved, expected);

            let left = if split == 0 {
                BlockRef::new(ChainId::new(3), Height::zero(), genesis(3))
            } else {
                blocks[split as usize - 1].block_ref::<Sha256>()
            };
            let right = blocks[length as usize - 1].block_ref::<Sha256>();
            let mut common = Ancestry::common(left, right).unwrap();
            while let Some(request) = common.next() {
                let restart = common;
                common.accept::<Sha256>(
                    Epoch::new(7),
                    &blocks[request.height().get() as usize - 1],
                ).unwrap();
                prop_assert_eq!(restart.next(), Some(request));
            }
            prop_assert_eq!(common.finish(), Some(left));
        }
    }
}
