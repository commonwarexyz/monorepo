//! Bounded-memory Binary Merkle Tree root construction.

use super::{Error, MAX_LEVELS, hash_parent_level, hash_positioned_leaves};
use alloc::vec::Vec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use core::{marker::PhantomData, ops::Range};

/// Constructs a Binary Merkle Tree root from an exact, ordered stream of leaves.
///
/// The builder buffers at most one configured subtree and retains one digest per
/// tree height. It returns the same root as [`super::Builder`] without retaining
/// the levels required to construct proofs.
///
/// `subtree_size` must be a non-zero power of two that fits in a `u32`. The
/// builder retains at most `subtree_size + subtree_size.div_ceil(2) + MAX_LEVELS + 1`
/// digest values, independent of `leaves`.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{Hasher as _, Sha256};
/// use commonware_parallel::Sequential;
/// use commonware_storage::bmt::StreamingBuilder;
///
/// let leaves = [Sha256::hash(&[b"a"]), Sha256::hash(&[b"b"])];
/// let mut builder = StreamingBuilder::<Sha256>::new(2, 1024).unwrap();
/// builder.extend(&leaves, &Sequential).unwrap();
/// let root = builder.finish(&Sequential).unwrap();
/// assert_ne!(root, Sha256::hash(&[]));
/// ```
#[must_use = "a streaming builder must be finished to produce a root"]
pub struct StreamingBuilder<H: Hasher> {
    expected: u32,
    added: u32,
    subtree_size: usize,
    buffer: Vec<H::Digest>,
    scratch: Vec<H::Digest>,
    frontier: [Option<H::Digest>; MAX_LEVELS + 1],
    _hasher: PhantomData<H>,
}

impl<H: Hasher> StreamingBuilder<H> {
    /// Creates a builder that accepts exactly `leaves` ordered leaf digests.
    ///
    /// `subtree_size` controls the maximum buffered subtree and must be a
    /// non-zero power of two representable as a `u32`.
    pub fn new(leaves: u32, subtree_size: usize) -> Result<Self, Error> {
        if !subtree_size.is_power_of_two() || u32::try_from(subtree_size).is_err() {
            return Err(Error::InvalidSubtreeSize(subtree_size));
        }

        // If the declared total does not fit in usize, it is necessarily larger
        // than the already-validated subtree size on this platform.
        let capacity = usize::try_from(leaves)
            .unwrap_or(subtree_size)
            .min(subtree_size);
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| Error::InsufficientCapacity)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(capacity.div_ceil(2))
            .map_err(|_| Error::InsufficientCapacity)?;

        Ok(Self {
            expected: leaves,
            added: 0,
            subtree_size,
            buffer,
            scratch,
            frontier: [None; MAX_LEVELS + 1],
            _hasher: PhantomData,
        })
    }

    /// Adds one leaf and returns its global position.
    ///
    /// Returns [`Error::MismatchedLeafCount`] without mutation if the declared
    /// number of leaves has already been reached.
    pub fn add(&mut self, leaf: &H::Digest, strategy: &impl Strategy) -> Result<u32, Error> {
        let position = self.added;
        self.extend(core::slice::from_ref(leaf), strategy)?;
        Ok(position)
    }

    /// Adds a contiguous ordered chunk and returns its global position range.
    ///
    /// The complete chunk is checked against the declared leaf count before any
    /// state is changed.
    pub fn extend(
        &mut self,
        leaves: &[H::Digest],
        strategy: &impl Strategy,
    ) -> Result<Range<u32>, Error> {
        let incoming = u64::try_from(leaves.len()).unwrap_or(u64::MAX);
        let actual = u64::from(self.added).saturating_add(incoming);
        if actual > u64::from(self.expected) {
            return Err(Error::MismatchedLeafCount {
                expected: self.expected,
                actual,
            });
        }

        let start = self.added;
        let mut remaining = leaves;
        while !remaining.is_empty() {
            let available = self.subtree_size - self.buffer.len();
            let take = available.min(remaining.len());
            self.buffer.extend_from_slice(&remaining[..take]);
            self.added = self
                .added
                .checked_add(u32::try_from(take).expect("subtree size fits in u32"))
                .expect("validated leaf count fits in u32");
            remaining = &remaining[take..];

            if self.buffer.len() == self.subtree_size {
                self.flush(strategy);
            }
        }

        Ok(start..self.added)
    }

    /// Finishes construction and returns the finalized root.
    ///
    /// Returns [`Error::MismatchedLeafCount`] if fewer than the declared number
    /// of leaves were added.
    pub fn finish(mut self, strategy: &impl Strategy) -> Result<H::Digest, Error> {
        if self.added != self.expected {
            return Err(Error::MismatchedLeafCount {
                expected: self.expected,
                actual: u64::from(self.added),
            });
        }

        if self.expected == 0 {
            let tree_root = H::hash(&[]);
            return Ok(super::finalize::<H>(0, &tree_root));
        }

        if !self.buffer.is_empty() {
            self.flush(strategy);
        }

        // Frontier entries are ordered from the newest/rightmost subtree at the
        // lowest occupied height to older/leftward subtrees at greater heights.
        // Raise the right accumulator through empty heights by applying the BMT's
        // odd-node duplication rule before combining it with each older subtree.
        let mut frontier = self
            .frontier
            .into_iter()
            .enumerate()
            .filter_map(|(height, digest)| digest.map(|digest| (height, digest)));
        let (mut accumulator_height, mut accumulator) =
            frontier.next().expect("non-empty tree has a frontier");
        for (height, left) in frontier {
            while accumulator_height < height {
                accumulator = H::hash(&[accumulator.as_ref(), accumulator.as_ref()]);
                accumulator_height += 1;
            }
            debug_assert_eq!(accumulator_height, height);
            accumulator = H::hash(&[left.as_ref(), accumulator.as_ref()]);
            accumulator_height += 1;
        }

        Ok(super::finalize::<H>(self.expected, &accumulator))
    }

    /// Reduces the buffered full subtree, or the final ragged suffix, into the frontier.
    fn flush(&mut self, strategy: &impl Strategy) {
        let leaves = self.buffer.len();
        debug_assert!(leaves > 0 && leaves <= self.subtree_size);
        let start =
            self.added - u32::try_from(leaves).expect("the configured subtree size fits in u32");
        let height = leaves.next_power_of_two().trailing_zeros() as usize;
        hash_positioned_leaves::<H>(&mut self.buffer, start, strategy);

        let mut current = core::mem::take(&mut self.buffer);
        let mut next = core::mem::take(&mut self.scratch);
        while current.len() > 1 {
            next.clear();
            next.resize(current.len().div_ceil(2), H::Digest::EMPTY);
            hash_parent_level::<H>(&current, &mut next, strategy);
            core::mem::swap(&mut current, &mut next);
        }
        let root = current[0];

        // Reduction swaps the two allocations at each level. Returning the larger allocation to
        // the input buffer lets every later full subtree reuse the fallible reservation made by
        // the constructor, while the other allocation remains sufficient for the first parent
        // level.
        current.clear();
        next.clear();
        if current.capacity() >= next.capacity() {
            self.buffer = current;
            self.scratch = next;
        } else {
            self.buffer = next;
            self.scratch = current;
        }

        self.insert(height, root);
    }

    /// Inserts one canonical subtree, carrying through occupied heights.
    fn insert(&mut self, mut height: usize, mut root: H::Digest) {
        loop {
            let Some(left) = self.frontier[height].take() else {
                self.frontier[height] = Some(root);
                return;
            };
            root = H::hash(&[left.as_ref(), root.as_ref()]);
            height += 1;
            debug_assert!(height < self.frontier.len());
        }
    }
}
