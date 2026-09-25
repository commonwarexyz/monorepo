//! Owned shard storage and mutable shard views, laid out as flat arrays of chunks.

use crate::reed_solomon::engine::SHARD_CHUNK_BYTES;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::ops::{Bound, Index, IndexMut, Range, RangeBounds};

/// Owned work buffer of `shard_count` shards, each `shard_chunk_count` chunks long.
///
/// Shard `i` occupies chunks `i * shard_chunk_count..(i + 1) * shard_chunk_count` of `data`.
pub(crate) struct Shards {
    shard_count: usize,
    /// Shard length in `SHARD_CHUNK_BYTES` chunks.
    shard_chunk_count: usize,

    /// Flat Vec of `shard_count * shard_chunk_count * SHARD_CHUNK_BYTES` bytes.
    data: Vec<[u8; SHARD_CHUNK_BYTES]>,
}

impl Shards {
    /// Returns a [`ShardsRefMut`] view of all shards.
    pub(crate) fn as_ref_mut(&mut self) -> ShardsRefMut<'_> {
        ShardsRefMut::new(self.shard_count, self.shard_chunk_count, self.data.as_mut())
    }

    /// Creates an empty buffer with zero shards and no allocation.
    pub(crate) const fn new() -> Self {
        Self {
            shard_count: 0,
            shard_chunk_count: 0,
            data: Vec::new(),
        }
    }

    /// Sets the dimensions to `shard_count` shards of `shard_chunk_count` chunks each.
    ///
    /// Existing chunks keep their bytes at the same flat positions and chunks added by growth
    /// are zeroed. A change in `shard_chunk_count` moves shard boundaries across old data.
    pub(crate) fn resize(&mut self, shard_count: usize, shard_chunk_count: usize) {
        self.shard_count = shard_count;
        self.shard_chunk_count = shard_chunk_count;

        self.data.resize(
            self.shard_count * self.shard_chunk_count,
            [0; SHARD_CHUNK_BYTES],
        );
    }

    /// Copies `shard` into shard `index` using the last-chunk encoding.
    ///
    /// Whole chunks are copied verbatim. A partial tail of `2 * n` bytes places `n` low bytes at
    /// offset 0 and `n` high bytes at offset `SHARD_CHUNK_BYTES / 2` of the final chunk.
    /// Bytes of shard `index` past the copied data keep their previous values.
    ///
    /// `shard` must fit in shard `index`.
    ///
    /// # Panics
    ///
    /// If `shard.len()` is odd.
    pub(crate) fn insert(&mut self, index: usize, shard: &[u8]) {
        assert_eq!(shard.len() % 2, 0);

        let whole_chunk_count = shard.len() / SHARD_CHUNK_BYTES;
        let tail_len = shard.len() % SHARD_CHUNK_BYTES;

        let (src_chunks, src_tail) = shard.split_at(shard.len() - tail_len);

        let dst = &mut self[index];
        dst[..whole_chunk_count]
            .as_flattened_mut()
            .copy_from_slice(src_chunks);

        // A partial final chunk holds a tail of `2 * n` bytes: `n` low bytes at offset 0 and
        // `n` high bytes at offset `SHARD_CHUNK_BYTES / 2`. See `reed_solomon/algorithm.md`.
        if tail_len > 0 {
            let (src_lo, src_hi) = src_tail.split_at(tail_len / 2);
            let (dst_lo, dst_hi) = dst[whole_chunk_count].split_at_mut(SHARD_CHUNK_BYTES / 2);
            dst_lo[..src_lo.len()].copy_from_slice(src_lo);
            dst_hi[..src_hi.len()].copy_from_slice(src_hi);
        }
    }

    /// Undoes the last-chunk encoding for the shards in `range`.
    ///
    /// Moves the high bytes of a partial final chunk to directly follow its low bytes.
    pub(crate) fn undo_last_chunk_encoding(&mut self, shard_bytes: usize, range: Range<usize>) {
        let whole_chunk_count = shard_bytes / SHARD_CHUNK_BYTES;
        let tail_len = shard_bytes % SHARD_CHUNK_BYTES;

        if tail_len == 0 {
            return;
        }

        for idx in range {
            let last_chunk = &mut self[idx][whole_chunk_count];
            last_chunk.copy_within(
                SHARD_CHUNK_BYTES / 2..SHARD_CHUNK_BYTES / 2 + tail_len / 2,
                tail_len / 2,
            );
        }
    }
}

impl Index<usize> for Shards {
    type Output = [[u8; SHARD_CHUNK_BYTES]];
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index * self.shard_chunk_count..(index + 1) * self.shard_chunk_count]
    }
}

impl IndexMut<usize> for Shards {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index * self.shard_chunk_count..(index + 1) * self.shard_chunk_count]
    }
}

/// Mutable reference to a shard array.
pub struct ShardsRefMut<'a> {
    shard_count: usize,
    /// Shard length in `SHARD_CHUNK_BYTES` chunks.
    shard_chunk_count: usize,

    /// Exactly `shard_count * shard_chunk_count` chunks. Shard `i` starts at chunk
    /// `i * shard_chunk_count`.
    data: &'a mut [[u8; SHARD_CHUNK_BYTES]],
}

/// Four mutable shards returned by [`ShardsRefMut::dist4_mut`].
type FourShardsMut<'a> = (
    &'a mut [[u8; SHARD_CHUNK_BYTES]],
    &'a mut [[u8; SHARD_CHUNK_BYTES]],
    &'a mut [[u8; SHARD_CHUNK_BYTES]],
    &'a mut [[u8; SHARD_CHUNK_BYTES]],
);

impl<'a> ShardsRefMut<'a> {
    /// Returns mutable references to shards at `pos` and `pos + dist`.
    ///
    /// See source code of [`Naive::fft`] for an example.
    ///
    /// # Panics
    ///
    /// If `dist` is `0` or either shard index is out of bounds.
    ///
    /// [`Naive::fft`]: crate::reed_solomon::engine::Naive#method.fft
    pub fn dist2_mut(
        &mut self,
        mut pos: usize,
        mut dist: usize,
    ) -> (
        &mut [[u8; SHARD_CHUNK_BYTES]],
        &mut [[u8; SHARD_CHUNK_BYTES]],
    ) {
        assert!(pos < self.shard_count && dist > 0 && dist < self.shard_count - pos);
        pos *= self.shard_chunk_count;
        dist *= self.shard_chunk_count;

        let (a, b) = self.data[pos..].split_at_mut(dist);
        (
            &mut a[..self.shard_chunk_count],
            &mut b[..self.shard_chunk_count],
        )
    }

    /// Returns mutable references to shards at
    /// `pos`, `pos + dist`, `pos + dist * 2` and `pos + dist * 3`.
    ///
    /// See source code of [`NoSimd::fft`] for an example
    /// (specifically the private method `fft_butterfly_two_layers`).
    ///
    /// # Panics
    ///
    /// If `dist` is `0` or any shard index is out of bounds.
    ///
    /// [`NoSimd::fft`]: crate::reed_solomon::engine::NoSimd#method.fft
    pub fn dist4_mut(&mut self, mut pos: usize, mut dist: usize) -> FourShardsMut<'_> {
        assert!(pos < self.shard_count && dist > 0 && dist <= (self.shard_count - 1 - pos) / 3);
        pos *= self.shard_chunk_count;
        dist *= self.shard_chunk_count;

        let (ab, cd) = self.data[pos..].split_at_mut(dist * 2);
        let (a, b) = ab.split_at_mut(dist);
        let (c, d) = cd.split_at_mut(dist);

        (
            &mut a[..self.shard_chunk_count],
            &mut b[..self.shard_chunk_count],
            &mut c[..self.shard_chunk_count],
            &mut d[..self.shard_chunk_count],
        )
    }

    /// Returns `true` if this contains no shards.
    pub const fn is_empty(&self) -> bool {
        self.shard_count == 0
    }

    /// Returns number of shards.
    pub const fn len(&self) -> usize {
        self.shard_count
    }

    /// Creates new [`ShardsRefMut`] that references given `data`.
    ///
    /// Each shard contains `shard_chunk_count` chunks. Zero-length shards are supported.
    ///
    /// # Panics
    ///
    /// If `shard_count * shard_chunk_count` overflows or exceeds `data.len()`.
    pub fn new(
        shard_count: usize,
        shard_chunk_count: usize,
        data: &'a mut [[u8; SHARD_CHUNK_BYTES]],
    ) -> Self {
        let chunk_count = shard_count
            .checked_mul(shard_chunk_count)
            .expect("shard dimensions overflow");
        assert!(data.len() >= chunk_count);

        Self {
            shard_count,
            shard_chunk_count,
            data: &mut data[..chunk_count],
        }
    }

    /// Splits this [`ShardsRefMut`] into two so that
    /// first includes shards `0..mid` and second includes shards `mid..`.
    ///
    /// # Panics
    ///
    /// If `mid > self.len()`.
    pub fn split_at_mut(&mut self, mid: usize) -> (ShardsRefMut<'_>, ShardsRefMut<'_>) {
        assert!(mid <= self.shard_count);
        let (a, b) = self.data.split_at_mut(mid * self.shard_chunk_count);

        (
            ShardsRefMut::new(mid, self.shard_chunk_count, a),
            ShardsRefMut::new(self.shard_count - mid, self.shard_chunk_count, b),
        )
    }

    /// Fills the shards in `range` with zero bytes.
    ///
    /// # Panics
    ///
    /// If the range is reversed or extends beyond `self.len()`.
    pub fn zero<R: RangeBounds<usize>>(&mut self, range: R) {
        let start = match range.start_bound() {
            Bound::Included(start) => *start,
            Bound::Excluded(start) => start.checked_add(1).expect("shard range start overflow"),
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(end) => end.checked_add(1).expect("shard range end overflow"),
            Bound::Excluded(end) => *end,
            Bound::Unbounded => self.shard_count,
        };

        assert!(start <= end && end <= self.shard_count);
        self.data[start * self.shard_chunk_count..end * self.shard_chunk_count]
            .fill([0; SHARD_CHUNK_BYTES]);
    }
}

impl Index<usize> for ShardsRefMut<'_> {
    type Output = [[u8; SHARD_CHUNK_BYTES]];
    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < self.shard_count);
        &self.data[index * self.shard_chunk_count..(index + 1) * self.shard_chunk_count]
    }
}

impl IndexMut<usize> for ShardsRefMut<'_> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index < self.shard_count);
        &mut self.data[index * self.shard_chunk_count..(index + 1) * self.shard_chunk_count]
    }
}

impl ShardsRefMut<'_> {
    /// Copies shards `src..src + count` to `dest..dest + count`.
    ///
    /// The ranges may overlap. Both must lie within `0..self.len()`.
    pub(crate) fn copy_within(&mut self, mut src: usize, mut dest: usize, mut count: usize) {
        src *= self.shard_chunk_count;
        dest *= self.shard_chunk_count;
        count *= self.shard_chunk_count;

        self.data.copy_within(src..src + count, dest);
    }

    /// Returns mutable flat slices of shard ranges `x..x + count` and `y..y + count`.
    ///
    /// # Panics
    ///
    /// If either range extends beyond `self.len()` or the ranges overlap.
    pub(crate) fn flat2_mut(
        &mut self,
        mut x: usize,
        mut y: usize,
        mut count: usize,
    ) -> (
        &mut [[u8; SHARD_CHUNK_BYTES]],
        &mut [[u8; SHARD_CHUNK_BYTES]],
    ) {
        assert!(x <= self.shard_count && count <= self.shard_count - x);
        assert!(y <= self.shard_count && count <= self.shard_count - y);
        assert!(x.abs_diff(y) >= count);
        x *= self.shard_chunk_count;
        y *= self.shard_chunk_count;
        count *= self.shard_chunk_count;

        if x < y {
            let (head, tail) = self.data.split_at_mut(y);
            (&mut head[x..x + count], &mut tail[..count])
        } else {
            let (head, tail) = self.data.split_at_mut(x);
            (&mut tail[..count], &mut head[y..y + count])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::engine::utils::xor_within;

    #[test]
    #[should_panic]
    fn dimensions_overflow() {
        ShardsRefMut::new(usize::MAX / 2 + 1, 2, &mut []);
    }

    #[test]
    #[should_panic]
    fn empty_shard_index_out_of_bounds() {
        let shards = ShardsRefMut::new(2, 0, &mut []);
        let _ = &shards[2];
    }

    #[test]
    #[should_panic]
    fn empty_shard_mutable_index_out_of_bounds() {
        let mut shards = ShardsRefMut::new(2, 0, &mut []);
        let _ = &mut shards[2];
    }

    #[test]
    #[should_panic]
    fn empty_shard_split_out_of_bounds() {
        ShardsRefMut::new(2, 0, &mut []).split_at_mut(3);
    }

    #[test]
    #[should_panic]
    fn empty_shard_range_out_of_bounds() {
        ShardsRefMut::new(2, 0, &mut []).zero(0..3);
    }

    #[test]
    #[should_panic]
    fn empty_shard_range_reversed() {
        ShardsRefMut::new(2, 0, &mut []).zero((Bound::Included(2), Bound::Excluded(1)));
    }

    #[test]
    #[should_panic]
    fn empty_shard_range_start_overflow() {
        ShardsRefMut::new(2, 0, &mut []).zero((Bound::Excluded(usize::MAX), Bound::Unbounded));
    }

    #[test]
    #[should_panic]
    fn empty_shard_range_end_overflow() {
        ShardsRefMut::new(2, 0, &mut []).zero(..=usize::MAX);
    }

    #[test]
    #[should_panic]
    fn empty_shard_xor_out_of_bounds() {
        xor_within(&mut ShardsRefMut::new(4, 0, &mut []), 0, 3, 2);
    }

    #[test]
    #[should_panic]
    fn empty_shard_xor_overlapping() {
        xor_within(&mut ShardsRefMut::new(4, 0, &mut []), 0, 1, 2);
    }

    #[test]
    #[should_panic]
    fn empty_shard_dist2_zero() {
        ShardsRefMut::new(2, 0, &mut []).dist2_mut(0, 0);
    }

    #[test]
    #[should_panic]
    fn empty_shard_dist4_zero() {
        ShardsRefMut::new(4, 0, &mut []).dist4_mut(0, 0);
    }

    #[test]
    #[should_panic]
    fn empty_shard_dist2_out_of_bounds() {
        ShardsRefMut::new(2, 0, &mut []).dist2_mut(1, 1);
    }

    #[test]
    #[should_panic]
    fn empty_shard_dist4_out_of_bounds() {
        ShardsRefMut::new(4, 0, &mut []).dist4_mut(1, 1);
    }

    #[test]
    fn empty_shards() {
        let mut shards = ShardsRefMut::new(4, 0, &mut []);
        assert_eq!(shards.len(), 4);
        assert!(!shards.is_empty());
        assert!(shards[3].is_empty());
        shards.dist2_mut(1, 2);
        shards.dist4_mut(0, 1);
        shards.zero(1..=3);
        let (left, right) = shards.split_at_mut(4);
        assert_eq!(left.len(), 4);
        assert!(right.is_empty());
    }

    #[test]
    fn views_preserve_shard_boundaries() {
        let mut data = [[9; SHARD_CHUNK_BYTES]; 14];
        let mut shards = ShardsRefMut::new(6, 2, &mut data);
        shards.zero(2..4);
        assert_eq!(shards[2], [[0; SHARD_CHUNK_BYTES]; 2]);
        assert_eq!(shards[3], [[0; SHARD_CHUNK_BYTES]; 2]);
        let (first, last) = shards.dist2_mut(0, 5);
        first.fill([1; SHARD_CHUNK_BYTES]);
        last.fill([6; SHARD_CHUNK_BYTES]);
        let (a, b, c, d) = shards.dist4_mut(0, 1);
        for (index, shard) in [a, b, c, d].into_iter().enumerate() {
            shard.fill([index as u8 + 1; SHARD_CHUNK_BYTES]);
        }
        let (_, mut right) = shards.split_at_mut(3);
        right[1].fill([5; SHARD_CHUNK_BYTES]);
        for (index, shard) in data.as_chunks::<2>().0.iter().enumerate() {
            let expected = if index < 6 { index as u8 + 1 } else { 9 };
            assert_eq!(shard, &[[expected; SHARD_CHUNK_BYTES]; 2]);
        }
    }
}
