//! One block reference per producer chain, in canonical chain order.

use super::{BlockRef, ChainId, MisplacedChain, ensure_canonical_chains};
use commonware_cryptography::Digest;

/// A frontier could not be constructed or compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrontierError {
    /// A frontier must name at least one chain.
    #[error("frontier is empty")]
    Empty,
    /// The reference at `index` does not name chain `index`.
    #[error("frontier reference {index} names chain {actual}")]
    Chain {
        /// Position of the misplaced reference.
        index: usize,
        /// Chain the reference names.
        actual: ChainId,
    },
    /// Two frontiers cover different chain counts.
    #[error("frontiers cover different chain counts")]
    Length,
    /// A chain is lower than the frontier it must dominate.
    #[error("frontier regresses on chain {0}")]
    Regression(ChainId),
    /// A chain names a different block at the same height.
    #[error("frontier conflicts on chain {0}")]
    Conflict(ChainId),
}

/// One block reference per producer chain, in canonical chain order.
///
/// Construction checks that the frontier is non-empty and that the reference at position `i`
/// names chain `i`. A frontier dominates another when every chain is strictly higher or names the
/// identical block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Frontier<D: Digest>(Vec<BlockRef<D>>);

impl<D: Digest> Frontier<D> {
    /// Validates one reference per chain in canonical chain order.
    pub fn new(references: Vec<BlockRef<D>>) -> Result<Self, FrontierError> {
        if references.is_empty() {
            return Err(FrontierError::Empty);
        }
        ensure_canonical_chains(references.iter().map(BlockRef::chain))
            .map_err(|MisplacedChain { index, actual }| FrontierError::Chain { index, actual })?;
        Ok(Self(references))
    }

    /// Returns the number of producer chains.
    pub const fn chains(&self) -> usize {
        self.0.len()
    }

    /// Returns the references in canonical chain order.
    pub fn references(&self) -> &[BlockRef<D>] {
        &self.0
    }

    /// Returns the reference for `chain`, if the frontier covers it.
    pub fn get(&self, chain: ChainId) -> Option<&BlockRef<D>> {
        self.0.get(chain.get() as usize)
    }

    /// Consumes the frontier and returns its references in canonical chain order.
    pub fn into_references(self) -> Vec<BlockRef<D>> {
        self.0
    }

    /// Checks that every chain is strictly above `lower` or names the identical block.
    pub fn dominates(&self, lower: &Self) -> Result<(), FrontierError> {
        if self.0.len() != lower.0.len() {
            return Err(FrontierError::Length);
        }
        for (upper, lower) in self.0.iter().zip(&lower.0) {
            if upper.height() < lower.height() {
                return Err(FrontierError::Regression(upper.chain()));
            }
            if upper.height() == lower.height() && upper != lower {
                return Err(FrontierError::Conflict(upper.chain()));
            }
        }
        Ok(())
    }

    /// Returns whether `next` dominates this frontier.
    pub fn advances_to(&self, next: &Self) -> bool {
        next.dominates(self).is_ok()
    }

    /// Raises every chain to the higher of the two references and returns whether any chain
    /// changed.
    ///
    /// A chain naming different blocks at the same height is a conflict; on error the frontier is
    /// unchanged.
    pub fn merge_max(&mut self, other: &Self) -> Result<bool, FrontierError> {
        if self.0.len() != other.0.len() {
            return Err(FrontierError::Length);
        }
        if let Some(conflict) = self
            .0
            .iter()
            .zip(&other.0)
            .find(|(current, other)| current.height() == other.height() && current != other)
        {
            return Err(FrontierError::Conflict(conflict.0.chain()));
        }
        let mut changed = false;
        for (current, other) in self.0.iter_mut().zip(&other.0) {
            if other.height() > current.height() {
                *current = *other;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Replaces the reference on `reference.chain()` and returns the previous one, or returns
    /// `None` and leaves the frontier unchanged if it does not cover that chain.
    pub fn replace(&mut self, reference: BlockRef<D>) -> Option<BlockRef<D>> {
        let slot = self.0.get_mut(reference.chain().get() as usize)?;
        Some(std::mem::replace(slot, reference))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Height;
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    fn reference(chain: u32, height: u64, label: &[u8]) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[label]),
        )
    }

    fn frontier(heights: &[(u64, &[u8])]) -> Frontier<Sha256Digest> {
        Frontier::new(
            heights
                .iter()
                .enumerate()
                .map(|(chain, (height, label))| reference(chain as u32, *height, label))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn construction_requires_one_reference_per_chain_in_order() {
        assert_eq!(
            Frontier::<Sha256Digest>::new(Vec::new()),
            Err(FrontierError::Empty)
        );
        assert_eq!(
            Frontier::new(vec![reference(0, 1, b"a"), reference(2, 1, b"b")]),
            Err(FrontierError::Chain {
                index: 1,
                actual: ChainId::new(2),
            })
        );
        let valid = frontier(&[(1, b"a"), (4, b"b")]);
        assert_eq!(valid.chains(), 2);
        assert_eq!(valid.get(ChainId::new(1)), Some(&reference(1, 4, b"b")));
        assert_eq!(valid.get(ChainId::new(2)), None);
        assert_eq!(valid.references().len(), 2);
    }

    #[test]
    fn dominance_accepts_higher_or_identical_chains() {
        let lower = frontier(&[(1, b"a"), (4, b"b")]);
        assert_eq!(lower.dominates(&lower), Ok(()));
        assert_eq!(frontier(&[(2, b"c"), (4, b"b")]).dominates(&lower), Ok(()));
        assert_eq!(
            frontier(&[(0, b"c"), (4, b"b")]).dominates(&lower),
            Err(FrontierError::Regression(ChainId::new(0)))
        );
        assert_eq!(
            frontier(&[(1, b"a"), (4, b"other")]).dominates(&lower),
            Err(FrontierError::Conflict(ChainId::new(1)))
        );
        assert_eq!(
            frontier(&[(1, b"a")]).dominates(&lower),
            Err(FrontierError::Length)
        );
        assert!(lower.advances_to(&frontier(&[(1, b"a"), (5, b"d")])));
        assert!(!lower.advances_to(&frontier(&[(1, b"a"), (3, b"d")])));
    }

    #[test]
    fn replace_swaps_one_covered_chain() {
        let mut current = frontier(&[(3, b"a"), (1, b"b")]);
        assert_eq!(
            current.replace(reference(1, 2, b"c")),
            Some(reference(1, 1, b"b"))
        );
        assert_eq!(current, frontier(&[(3, b"a"), (2, b"c")]));
        assert_eq!(current.replace(reference(2, 1, b"d")), None);
        assert_eq!(current, frontier(&[(3, b"a"), (2, b"c")]));
    }

    #[test]
    fn merge_raises_each_chain_and_rejects_conflicts_without_mutation() {
        let mut current = frontier(&[(3, b"a"), (1, b"b")]);
        assert_eq!(
            current.merge_max(&frontier(&[(2, b"c"), (5, b"d")])),
            Ok(true)
        );
        assert_eq!(current, frontier(&[(3, b"a"), (5, b"d")]));
        assert_eq!(current.merge_max(&current.clone()), Ok(false));

        let before = current.clone();
        assert_eq!(
            current.merge_max(&frontier(&[(9, b"e"), (5, b"other")])),
            Err(FrontierError::Conflict(ChainId::new(1)))
        );
        assert_eq!(current, before);
        assert_eq!(
            current.merge_max(&frontier(&[(9, b"e")])),
            Err(FrontierError::Length)
        );
        assert_eq!(current, before);
    }
}
