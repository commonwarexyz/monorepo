//! Shared layered bitmap types for speculative batch chains.
//!
//! `BitmapBatch` provides an immutable, layered bitmap that allows speculative batches to
//! push thin diff layers (pushed bits + cleared bits) on top of a parent's bitmap without
//! cloning. Reads walk the layer chain.

use crate::merkle::{Family, Location};
use commonware_utils::bitmap::{Prunable as PrunableBitMap, Readable as BitmapReadable};
use std::{collections::BTreeMap, sync::Arc};

/// Cleared bitmap bits tracked in two synchronized views.
///
/// `locations` preserves the original clear operations so batch chaining, flattening, and
/// finalization can replay them in order. `masks` indexes the same clears by chunk, allowing
/// [`apply_push_clear`] to zero an entire chunk without rescanning every cleared location.
#[derive(Clone, Debug)]
pub(crate) struct ClearSet<F: Family, const N: usize> {
    locations: Vec<Location<F>>,
    masks: BTreeMap<usize, [u8; N]>,
}

impl<F: Family, const N: usize> Default for ClearSet<F, N> {
    fn default() -> Self {
        Self {
            locations: Vec::new(),
            masks: BTreeMap::new(),
        }
    }
}

impl<F: Family, const N: usize> ClearSet<F, N> {
    /// Push a location to the clear set.
    pub(crate) fn push(&mut self, loc: Location<F>) {
        let raw = *loc;
        self.locations.push(loc);

        let chunk_idx = PrunableBitMap::<N>::to_chunk_index(raw);
        let rel = (raw % PrunableBitMap::<N>::CHUNK_SIZE_BITS) as usize;
        let chunk = self.masks.entry(chunk_idx).or_insert([0u8; N]);
        chunk[rel / 8] |= 1 << (rel % 8);
    }

    /// Whether the clear set is empty.
    pub(crate) const fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Return the locations in the clear set.
    pub(crate) fn locations(&self) -> &[Location<F>] {
        &self.locations
    }

    /// Return the mask for the given chunk index.
    pub(crate) fn mask(&self, idx: usize) -> Option<&[u8; N]> {
        self.masks.get(&idx)
    }
}

/// Apply pushed bits and cleared bits to `chunk` at absolute position `chunk_start`.
///
/// `push_start` is the absolute bit index where pushes begin (i.e. the parent's length).
/// `clear_mask` is the chunk-local view returned by [`ClearSet::mask`].
fn apply_push_clear<const N: usize>(
    chunk: &mut [u8; N],
    chunk_start: u64,
    push_start: u64,
    pushed_bits: &[bool],
    clear_mask: Option<&[u8; N]>,
) {
    let chunk_end = chunk_start + PrunableBitMap::<N>::CHUNK_SIZE_BITS;

    let push_end = push_start + pushed_bits.len() as u64;
    if push_start < chunk_end && push_end > chunk_start {
        let abs_start = push_start.max(chunk_start);
        let abs_end = push_end.min(chunk_end);
        let from = (abs_start - push_start) as usize;
        let to = (abs_end - push_start) as usize;
        let rel_offset = (abs_start - chunk_start) as usize;
        for (j, &bit) in pushed_bits[from..to].iter().enumerate() {
            if bit {
                let rel = rel_offset + j;
                chunk[rel / 8] |= 1 << (rel % 8);
            }
        }
    }

    if let Some(clear_mask) = clear_mask {
        for (byte, mask) in chunk.iter_mut().zip(clear_mask) {
            *byte &= !mask;
        }
    }
}

/// Immutable bitmap state at any point in a batch chain.
///
/// Mirrors the [`crate::merkle::mmr::batch::MerkleizedBatch`] pattern.
#[derive(Clone, Debug)]
pub(crate) enum BitmapBatch<F: Family, const N: usize> {
    /// Committed bitmap (chain terminal).
    Base(Arc<PrunableBitMap<N>>),
    /// Speculative layer on top of a parent batch.
    Layer(Arc<BitmapBatchLayer<F, N>>),
}

/// The data behind a [`BitmapBatch::Layer`].
#[derive(Debug)]
pub(crate) struct BitmapBatchLayer<F: Family, const N: usize> {
    parent: BitmapBatch<F, N>,
    /// Cached `parent.len()` at layer creation time.
    parent_len: u64,
    /// New bits appended contiguously from `parent_len`.
    pushed_bits: Arc<Vec<bool>>,
    /// Bit indices of parent bits that were deactivated, with per-chunk masks.
    clears: Arc<ClearSet<F, N>>,
}

impl<F: Family, const N: usize> BitmapBatch<F, N> {
    const CHUNK_SIZE_BITS: u64 = PrunableBitMap::<N>::CHUNK_SIZE_BITS;
}

impl<F: Family, const N: usize> BitmapReadable<N> for BitmapBatch<F, N> {
    fn complete_chunks(&self) -> usize {
        (self.len() / Self::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        match self {
            Self::Base(bm) => *bm.get_chunk(idx),
            Self::Layer(layer) => {
                let chunk_start = idx as u64 * Self::CHUNK_SIZE_BITS;

                // Start with parent's data, or zeroed if this chunk is
                // entirely beyond the parent's range (created by pushes).
                let parent_chunks = layer.parent_len.div_ceil(Self::CHUNK_SIZE_BITS);
                let mut chunk = if (idx as u64) < parent_chunks {
                    layer.parent.get_chunk(idx)
                } else {
                    [0u8; N]
                };

                apply_push_clear(
                    &mut chunk,
                    chunk_start,
                    layer.parent_len,
                    &layer.pushed_bits,
                    layer.clears.mask(idx),
                );
                chunk
            }
        }
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let total = self.len();
        if total == 0 {
            return ([0u8; N], 0);
        }
        let rem = total % Self::CHUNK_SIZE_BITS;
        let bits_in_last = if rem == 0 { Self::CHUNK_SIZE_BITS } else { rem };
        let idx = if rem == 0 {
            self.complete_chunks().saturating_sub(1)
        } else {
            self.complete_chunks()
        };
        (self.get_chunk(idx), bits_in_last)
    }

    fn pruned_chunks(&self) -> usize {
        match self {
            Self::Base(bm) => bm.pruned_chunks(),
            Self::Layer(layer) => layer.parent.pruned_chunks(),
        }
    }

    fn len(&self) -> u64 {
        match self {
            Self::Base(bm) => BitmapReadable::<N>::len(bm.as_ref()),
            Self::Layer(layer) => layer.parent_len + layer.pushed_bits.len() as u64,
        }
    }
}

impl<F: Family, const N: usize> BitmapBatch<F, N> {
    /// Push a changeset as a new layer on top of this bitmap, mutating `self` in place.
    ///
    /// The old value becomes the parent of the new layer.
    pub(crate) fn push_changeset(&mut self, pushed_bits: Vec<bool>, clears: ClearSet<F, N>) {
        if pushed_bits.is_empty() && clears.locations().is_empty() {
            return;
        }
        let parent_len = self.len();
        let parent = self.clone();
        *self = Self::Layer(Arc::new(BitmapBatchLayer {
            parent,
            parent_len,
            pushed_bits: Arc::new(pushed_bits),
            clears: Arc::new(clears),
        }));
    }

    /// Flatten all layers back to a single `Base(Arc<PrunableBitMap<N>>)`.
    ///
    /// After flattening, the new `Base` Arc has refcount 1 (assuming no external clones
    /// are held).
    pub(crate) fn flatten(&mut self) {
        if matches!(self, Self::Base(_)) {
            return;
        }

        // Take ownership of the chain so that Arc refcounts are not
        // artificially inflated by a clone.
        let mut owned = std::mem::replace(self, Self::Base(Arc::new(PrunableBitMap::default())));

        // Collect layers from tip to base.
        let mut layers = Vec::new();
        let base = loop {
            match owned {
                Self::Base(bm) => break bm,
                Self::Layer(layer) => match Arc::try_unwrap(layer) {
                    Ok(inner) => {
                        layers.push((inner.pushed_bits, inner.clears));
                        owned = inner.parent;
                    }
                    Err(arc) => {
                        layers.push((arc.pushed_bits.clone(), arc.clears.clone()));
                        owned = arc.parent.clone();
                    }
                },
            }
        };

        // Replay mutations from base to tip.
        let mut bitmap = Arc::try_unwrap(base).unwrap_or_else(|arc| (*arc).clone());
        for (pushed, clears) in layers.into_iter().rev() {
            for &bit in pushed.iter() {
                bitmap.push(bit);
            }
            for &bit_idx in clears.locations() {
                bitmap.set_bit(*bit_idx, false);
            }
        }
        *self = Self::Base(Arc::new(bitmap));
    }
}
