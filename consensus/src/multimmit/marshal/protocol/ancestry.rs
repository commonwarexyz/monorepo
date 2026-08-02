//! Constant-space producer-chain ancestry validation.

use crate::{
    Epochable as _,
    multimmit::types::{BlockRef, TransactionBlockHeader},
    types::Epoch,
};
use commonware_cryptography::{Digest, Hasher};

/// A producer-chain ancestry response is inconsistent with its request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("producer-chain frontiers name different chains")]
    Chain,
    #[error("producer block does not match the requested coordinate")]
    Coordinate,
    #[error("producer block does not match the requested header digest")]
    Digest,
    #[error("producer header belongs to another epoch")]
    Epoch,
    #[error("ancestry walk is already complete")]
    Complete,
    #[error("producer-chain frontiers fork")]
    Fork,
}

/// A restartable walk from an exact producer-chain tip to a lower height.
///
/// Each response authenticates the next request through its header's parent digest. Application
/// bodies are not needed to prove protocol ancestry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct Ancestry<D: Digest> {
    cursor: BlockRef<D>,
    expected: BlockRef<D>,
}

impl<D: Digest> Ancestry<D> {
    /// Starts proving the exact common frontier of `target` and `emitted`.
    ///
    /// The higher reference is descended to the lower height. Equal heights must already name the
    /// same header, and completion requires the discovered ancestor to equal the lower reference.
    pub(in crate::multimmit::marshal) fn common(
        target: BlockRef<D>,
        emitted: BlockRef<D>,
    ) -> Result<Self, Error> {
        if target.chain().get() != emitted.chain().get() {
            return Err(Error::Chain);
        }
        let (cursor, expected) = if target.height().get() > emitted.height().get() {
            (target, emitted)
        } else if emitted.height().get() > target.height().get() {
            (emitted, target)
        } else {
            if target.digest() != emitted.digest() {
                return Err(Error::Fork);
            }
            (target, target)
        };
        Ok(Self { cursor, expected })
    }

    /// Returns the next exact block reference whose header is required.
    pub(in crate::multimmit::marshal) const fn next(&self) -> Option<BlockRef<D>> {
        if self.cursor.height().get() == self.expected.height().get() {
            None
        } else {
            Some(self.cursor)
        }
    }

    /// Returns the number of headers still required to reach the common frontier.
    pub(in crate::multimmit::marshal) fn remaining(&self) -> usize {
        usize::try_from(
            self.cursor
                .height()
                .get()
                .checked_sub(self.expected.height().get())
                .expect("the ancestry cursor does not cross its frontier"),
        )
        .unwrap_or(usize::MAX)
    }

    /// Accepts one authenticated producer header and advances exactly one parent.
    pub(in crate::multimmit::marshal) fn accept<H>(
        &mut self,
        epoch: Epoch,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
    {
        let request = self.next().ok_or(Error::Complete)?;
        if header.epoch() != epoch {
            return Err(Error::Epoch);
        }
        if header.chain() != request.chain() || header.height() != request.height() {
            return Err(Error::Coordinate);
        }
        if header.digest::<H>() != request.digest() {
            return Err(Error::Digest);
        }
        let height = request
            .height()
            .previous()
            .expect("an incomplete ancestry walk is above height zero");
        let parent = BlockRef::new(request.chain(), height, header.parent());
        if height == self.expected.height() && self.expected != parent {
            return Err(Error::Fork);
        }
        self.cursor = parent;
        Ok(())
    }

    /// Returns the exact target reference once no more headers are required.
    pub(in crate::multimmit::marshal) fn finish(&self) -> Option<BlockRef<D>> {
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
    fn rejects_wrong_epoch_coordinate_and_digest() {
        let blocks = chain(0, 3, 20);
        let tip = blocks[2].block_ref::<Sha256>();
        let mut ancestry = Ancestry::common(
            tip,
            BlockRef::new(ChainId::new(0), Height::zero(), genesis(0)),
        )
        .unwrap();

        let wrong_epoch = TransactionBlockHeader::new(
            Epoch::new(8),
            ChainId::new(0),
            Height::new(3),
            blocks[1].block_ref::<Sha256>().digest(),
            Sha256::hash(&[b"wrong epoch body"]),
        )
        .unwrap();
        assert_eq!(
            ancestry.accept::<Sha256>(Epoch::new(7), &wrong_epoch),
            Err(Error::Epoch)
        );
        let wrong_coordinate = header(1, 3, genesis(1), 30);
        assert_eq!(
            ancestry.accept::<Sha256>(Epoch::new(7), &wrong_coordinate),
            Err(Error::Coordinate)
        );
        let wrong_header = header(0, 3, genesis(0), 30);
        assert_eq!(
            ancestry.accept::<Sha256>(Epoch::new(7), &wrong_header),
            Err(Error::Digest)
        );
        assert_eq!(ancestry.next(), Some(tip));
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
