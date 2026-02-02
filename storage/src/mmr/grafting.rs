//! Hasher and Storage implementations for a merkle tree _grafted_ onto another MMR.
//!
//! ## Terminology
//!
//! * **Peak Tree**: The MMR or Merkle tree that is being grafted.
//! * **Base MMR**: The MMR onto which we are grafting (cannot be a Merkle tree).
//!
//! Grafting involves mapping the leaves of the peak tree to corresponding nodes in the base MMR. It
//! allows for shorter inclusion proofs over the combined trees compared to treating them as
//! independent.
//!
//! One example use case is the [crate::qmdb::current] authenticated database, where a MMR is built
//! over a log of operations, and a merkle tree over a bitmap indicating the activity state of each
//! operation. If we were to treat the two trees as independent, then an inclusion proof for an
//! operation and its activity state would involve a full branch from each structure. When using
//! grafting, we can trim the branch from the base MMR at the point it "flows" up into the peak
//! tree, reducing the size of the proof by a constant factor up to 2.
//!
//! For concreteness, let's assume we have a base MMR over a log of 8 operations represented by the
//! 8 leaves:
//!
//! ```text
//!    Height
//!      3              14
//!                   /    \
//!                  /      \
//!                 /        \
//!                /          \
//!      2        6            13
//!             /   \        /    \
//!      1     2     5      9     12
//!           / \   / \    / \   /  \
//!      0   0   1 3   4  7   8 10  11
//! ```
//!
//! Let's assume each leaf in our peak tree corresponds to 4 leaves in the base MMR. The structure
//! of the peak tree can be obtained by chopping off the bottom log2(4)=2 levels of the base MMR
//! structure:
//!
//!
//! ```text
//!    Height
//!      1              2 (was 14)
//!                   /    \
//!                  /      \
//!                 /        \
//!                /          \
//!      0        0 (was 6)    1 (was 13)
//! ```
//!
//! The inverse of this procedure provides our algorithm for mapping a peak tree leaf's position to
//! a base MMR node position: take the leaf's position in the peak tree, map it to any of the
//! corresponding leaves in the base MMR, then walk up the base MMR structure exactly the number of
//! levels we removed.
//!
//! In this example, leaf 0 in the peak tree corresponds to leaves \[0,1,3,4\] in the base MMR.
//! Walking up two levels from any of these base MMR leaves produces node 6 of the base MMR, which
//! is thus its grafting point. Leaf 1 in the peak tree corresponds to leaves \[7,8,10,11\] in the
//! base MMR, yielding node 13 as its grafting point.

use crate::mmr::{
    hasher::Hasher as HasherTrait,
    iterator::{pos_to_height, PeakIterator},
    storage::Storage as StorageTrait,
    Error, Location, Position, StandardHasher,
};
use commonware_cryptography::Hasher as CHasher;
use futures::future::try_join_all;
use tracing::debug;

/// Compute the position of the node in the base tree onto which we should graft the node at
/// position `pos` in the source tree.
///
/// This algorithm performs walks down corresponding branches of the peak and base trees. When we
/// find the node in the peak tree we are looking for, we return the position of the corresponding
/// node reached in the base tree.
pub(crate) fn destination_pos(peak_node_pos: Position, height: u32) -> Position {
    let peak_node_pos = *peak_node_pos;
    let leading_zeros = (peak_node_pos + 1).leading_zeros();
    assert!(leading_zeros >= height, "destination_pos > u64::MAX");
    let mut peak_pos = u64::MAX >> leading_zeros;
    let mut base_pos = u64::MAX >> (leading_zeros - height);
    let mut peak_height = peak_pos.trailing_ones() - 1;
    let mut base_height = peak_height + height;
    peak_pos -= 1;
    base_pos -= 1;

    while base_height >= height {
        if peak_pos == peak_node_pos {
            break;
        }

        let left_pos = peak_pos - (1 << peak_height);
        if left_pos < peak_node_pos {
            peak_pos -= 1;
            base_pos -= 1;
        } else {
            peak_pos = left_pos;
            base_pos -= 1 << base_height;
        }

        peak_height -= 1;
        base_height -= 1;
    }

    Position::new(base_pos)
}

/// Inverse computation of destination_pos, with an analogous implementation involving walks down
/// corresponding branches of both trees. Returns none if there is no corresponding node.
pub(super) fn source_pos(base_node_pos: Position, height: u32) -> Option<Position> {
    if pos_to_height(base_node_pos) < height {
        // Nodes below the grafting height do not have a corresponding peak tree node.
        return None;
    }

    let leading_zeros = (base_node_pos + 1).leading_zeros();
    let mut base_pos = u64::MAX >> leading_zeros;
    let mut peak_pos = u64::MAX >> (leading_zeros + height);
    let mut base_height = base_pos.trailing_ones() - 1;
    let mut peak_height = base_height - height;
    base_pos -= 1;
    peak_pos -= 1;

    while base_pos != base_node_pos {
        let left_pos = base_pos - (1 << base_height);
        if left_pos < base_node_pos {
            base_pos -= 1;
            peak_pos -= 1;
        } else {
            base_pos = left_pos;
            peak_pos -= 1 << peak_height;
        }

        base_height -= 1;
        peak_height -= 1;
    }

    Some(Position::new(peak_pos))
}

/// A hasher implementation to use when verifying proofs over GraftedStorage.
pub struct Verifier<'a, H: CHasher> {
    hasher: StandardHasher<H>,
    height: u32,

    /// The required leaf elements from the peak tree that we are verifying.
    elements: Vec<&'a [u8]>,

    /// The location of the first element we are verifying
    loc: Location,
}

impl<'a, H: CHasher> Verifier<'a, H> {
    /// Create a new Verifier.
    ///
    /// # Panics
    ///
    /// Panics if `loc` is too large to be safely converted to a Position (> MAX_LOCATION).
    pub fn new(height: u32, loc: Location, elements: Vec<&'a [u8]>) -> Self {
        assert!(loc.is_valid(), "location {loc} > MAX_LOCATION");
        Self {
            hasher: StandardHasher::new(),
            height,
            elements,
            loc,
        }
    }

    pub const fn standard(&mut self) -> &mut StandardHasher<H> {
        &mut self.hasher
    }
}

impl<H: CHasher> HasherTrait for Verifier<'_, H> {
    type Digest = H::Digest;
    type Inner = H;

    fn leaf_digest(&mut self, pos: Position, element: &[u8]) -> H::Digest {
        self.hasher.leaf_digest(pos, element)
    }

    fn fork(&self) -> impl HasherTrait<Digest = H::Digest> {
        Verifier::<H> {
            hasher: StandardHasher::new(),
            height: self.height,
            elements: self.elements.clone(),
            loc: self.loc,
        }
    }

    fn node_digest(
        &mut self,
        pos: Position,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        let node_height = pos_to_height(pos);

        // For nodes ABOVE the grafting height, we need to use the source_pos (peak-tree position)
        // when computing the hash, because the grafted_mmr was built with peak-tree positions.
        // This ensures verification produces the same digests as the grafted_mmr.
        if node_height > self.height {
            let peak_pos = source_pos(pos, self.height)
                .expect("node above grafting height should have source_pos");
            return self.hasher.node_digest(peak_pos, left_digest, right_digest);
        }

        let digest = self.hasher.node_digest(pos, left_digest, right_digest);
        if node_height != self.height {
            // If we're below the grafting boundary we use the digest as-is.
            return digest;
        }

        // This base tree node corresponds to a peak-tree leaf, so we need to perform the peak-tree
        // leaf digest computation.
        let source_pos = source_pos(pos, self.height);
        let Some(source_pos) = source_pos else {
            // malformed proof input
            debug!(?pos, "no grafting source pos");
            return digest;
        };
        let Ok(index) = Location::try_from(source_pos) else {
            // malformed proof input
            debug!(?source_pos, "grafting source pos is not a leaf");
            return digest;
        };
        if index < self.loc {
            // malformed proof input
            debug!(
                ?index,
                ?self.loc,
                "grafting index is negative"
            );
            return digest;
        };
        let index = index - self.loc;
        if index >= self.elements.len() as u64 {
            // malformed proof input
            debug!(
                ?index,
                len = self.elements.len(),
                "grafting index is out of bounds"
            );
            return digest;
        }
        self.hasher
            .update_with_element(self.elements[*index as usize]);
        self.hasher.update_with_digest(&digest);

        self.hasher.finalize()
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.hasher.root(leaves, peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.digest(data)
    }

    fn inner(&mut self) -> &mut H {
        self.hasher.inner()
    }
}

/// A [Storage] implementation that makes grafted trees look like a single MMR for conveniently
/// generating inclusion proofs.
pub struct Storage<'a, H: CHasher, S1: StorageTrait<H::Digest>, S2: StorageTrait<H::Digest>> {
    peak_tree: &'a S1,
    base_mmr: &'a S2,
    height: u32,

    _marker: std::marker::PhantomData<H>,
}

impl<'a, H: CHasher, S1: StorageTrait<H::Digest>, S2: StorageTrait<H::Digest>>
    Storage<'a, H, S1, S2>
{
    /// Creates a new grafted [Storage] instance.
    pub const fn new(peak_tree: &'a S1, base_mmr: &'a S2, height: u32) -> Self {
        Self {
            peak_tree,
            base_mmr,
            height,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn root(&self, hasher: &mut StandardHasher<H>) -> Result<H::Digest, Error> {
        let size = self.size();
        let leaves = Location::try_from(size).expect("size should be valid leaves");
        let peak_futures = PeakIterator::new(size).map(|(peak_pos, _)| self.get_node(peak_pos));
        let peaks = try_join_all(peak_futures).await?;
        let unwrapped_peaks = peaks.iter().map(|p| {
            p.as_ref()
                .expect("peak should be non-none, are the trees unaligned?")
        });
        let digest = hasher.root(leaves, unwrapped_peaks);

        Ok(digest)
    }
}

impl<H: CHasher, S1: StorageTrait<H::Digest>, S2: StorageTrait<H::Digest>> StorageTrait<H::Digest>
    for Storage<'_, H, S1, S2>
{
    fn size(&self) -> Position {
        self.base_mmr.size()
    }

    async fn get_node(&self, pos: Position) -> Result<Option<H::Digest>, Error> {
        let height = pos_to_height(pos);
        if height < self.height {
            return self.base_mmr.get_node(pos).await;
        }

        let source_pos = source_pos(pos, self.height);
        let Some(source_pos) = source_pos else {
            return Ok(None);
        };

        self.peak_tree.get_node(source_pos).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::Position;
    use commonware_macros::test_traced;

    /// For a variety of grafting heights and node positions, check that destination_pos and
    /// source_pos are inverse functions.
    #[test_traced]
    fn test_dest_source_pos_conversion() {
        for grafting_height in 1..10 {
            for pos in 0..10000 {
                let pos = Position::new(pos);
                let dest_pos = destination_pos(pos, grafting_height);
                let source_pos = source_pos(dest_pos, grafting_height).unwrap();
                assert_eq!(pos, source_pos);
            }
        }
    }

    #[test_traced]
    fn test_source_dest_pos_conversion() {
        for grafting_height in 1..10 {
            for pos in 0..10000 {
                let pos = Position::new(pos);
                if pos_to_height(pos) < grafting_height {
                    // Base tree nodes below the grafting height do not have a corresponding peak
                    // tree node.
                    assert!(source_pos(pos, grafting_height).is_none());
                    continue;
                }
                let source_pos = source_pos(pos, grafting_height).unwrap();
                let dest_pos = destination_pos(source_pos, grafting_height);
                assert_eq!(pos, dest_pos);
            }
        }
    }
}
