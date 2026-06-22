#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::ops::{Bound, Index, IndexMut, Range, RangeBounds};

// ======================================================================
// Shards - CRATE

pub(crate) struct Shards {
    shard_count: usize,
    // Shard length in 64 byte chunks
    shard_len_64: usize,

    // Flat Vec of `shard_count * shard_len_64 * 64` bytes.
    data: Vec<[u8; 64]>,
}

impl Shards {
    pub(crate) fn as_ref_mut(&mut self) -> ShardsRefMut<'_> {
        ShardsRefMut::new(self.shard_count, self.shard_len_64, self.data.as_mut())
    }

    pub(crate) fn new() -> Self {
        Self {
            shard_count: 0,
            shard_len_64: 0,
            data: Vec::new(),
        }
    }

    pub(crate) fn resize(&mut self, shard_count: usize, shard_len_64: usize) {
        self.shard_count = shard_count;
        self.shard_len_64 = shard_len_64;

        self.data
            .resize(self.shard_count * self.shard_len_64, [0; 64]);
    }

    pub(crate) fn insert(&mut self, index: usize, shard: &[u8]) {
        debug_assert_eq!(shard.len() % 2, 0);

        let whole_chunk_count = shard.len() / 64;
        let tail_len = shard.len() % 64;

        let (src_chunks, src_tail) = shard.split_at(shard.len() - tail_len);

        let dst = &mut self[index];
        dst[..whole_chunk_count]
            .as_flattened_mut()
            .copy_from_slice(src_chunks);

        // Last chunk is special if shard.len() % 64 != 0.
        // See src/algorithm.md for an explanation.
        if tail_len > 0 {
            let (src_lo, src_hi) = src_tail.split_at(tail_len / 2);
            let (dst_lo, dst_hi) = dst[whole_chunk_count].split_at_mut(32);
            dst_lo[..src_lo.len()].copy_from_slice(src_lo);
            dst_hi[..src_hi.len()].copy_from_slice(src_hi);
        }
    }

    // Undoes the encoding of the last chunk for the given range of shards
    pub(crate) fn undo_last_chunk_encoding(&mut self, shard_bytes: usize, range: Range<usize>) {
        let whole_chunk_count = shard_bytes / 64;
        let tail_len = shard_bytes % 64;

        if tail_len == 0 {
            return;
        }

        for idx in range {
            let last_chunk = &mut self[idx][whole_chunk_count];
            last_chunk.copy_within(32..32 + tail_len / 2, tail_len / 2);
        }
    }
}

// ======================================================================
// Shards - IMPL Index

impl Index<usize> for Shards {
    type Output = [[u8; 64]];
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index * self.shard_len_64..(index + 1) * self.shard_len_64]
    }
}

// ======================================================================
// Shards - IMPL IndexMut

impl IndexMut<usize> for Shards {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index * self.shard_len_64..(index + 1) * self.shard_len_64]
    }
}

// ======================================================================
// ShardsRefMut - PUBLIC

/// Mutable reference to a shard array.
pub struct ShardsRefMut<'a> {
    shard_count: usize,
    shard_len_64: usize,

    data: &'a mut [[u8; 64]],
}

impl<'a> ShardsRefMut<'a> {
    /// Returns mutable references to shards at `pos` and `pos + dist`.
    ///
    /// See source code of [`Naive::fft`] for an example.
    ///
    /// # Panics
    ///
    /// If `dist` is `0`.
    ///
    /// [`Naive::fft`]: crate::reed_solomon::engine::Naive#method.fft
    pub fn dist2_mut(
        &mut self,
        mut pos: usize,
        mut dist: usize,
    ) -> (&mut [[u8; 64]], &mut [[u8; 64]]) {
        pos *= self.shard_len_64;
        dist *= self.shard_len_64;

        let (a, b) = self.data[pos..].split_at_mut(dist);
        (&mut a[..self.shard_len_64], &mut b[..self.shard_len_64])
    }

    /// Returns mutable references to shards at
    /// `pos`, `pos + dist`, `pos + dist * 2` and `pos + dist * 3`.
    ///
    /// See source code of [`NoSimd::fft`] for an example
    /// (specifically the private method `fft_butterfly_two_layers`).
    ///
    /// # Panics
    ///
    /// If `dist` is `0`.
    ///
    /// [`NoSimd::fft`]: crate::reed_solomon::engine::NoSimd#method.fft
    #[allow(clippy::type_complexity)]
    pub fn dist4_mut(
        &mut self,
        mut pos: usize,
        mut dist: usize,
    ) -> (
        &mut [[u8; 64]],
        &mut [[u8; 64]],
        &mut [[u8; 64]],
        &mut [[u8; 64]],
    ) {
        pos *= self.shard_len_64;
        dist *= self.shard_len_64;

        let (ab, cd) = self.data[pos..].split_at_mut(dist * 2);
        let (a, b) = ab.split_at_mut(dist);
        let (c, d) = cd.split_at_mut(dist);

        (
            &mut a[..self.shard_len_64],
            &mut b[..self.shard_len_64],
            &mut c[..self.shard_len_64],
            &mut d[..self.shard_len_64],
        )
    }

    /// Returns `true` if this contains no shards.
    pub fn is_empty(&self) -> bool {
        self.shard_count == 0
    }

    /// Returns number of shards.
    pub fn len(&self) -> usize {
        self.shard_count
    }

    /// Creates new [`ShardsRefMut`] that references given `data`.
    ///
    /// # Panics
    ///
    /// If `data.len() < shard_count * shard_len_64`.
    pub fn new(shard_count: usize, shard_len_64: usize, data: &'a mut [[u8; 64]]) -> Self {
        assert!(data.len() >= shard_count * shard_len_64);

        Self {
            shard_count,
            shard_len_64,
            data: &mut data[..shard_count * shard_len_64],
        }
    }

    /// Splits this [`ShardsRefMut`] into two so that
    /// first includes shards `0..mid` and second includes shards `mid..`.
    pub fn split_at_mut(&mut self, mid: usize) -> (ShardsRefMut<'_>, ShardsRefMut<'_>) {
        let (a, b) = self.data.split_at_mut(mid * self.shard_len_64);

        (
            ShardsRefMut::new(mid, self.shard_len_64, a),
            ShardsRefMut::new(self.shard_count - mid, self.shard_len_64, b),
        )
    }

    /// Fills the given shard-range with `0u8`:s.
    pub fn zero<R: RangeBounds<usize>>(&mut self, range: R) {
        let start = match range.start_bound() {
            Bound::Included(start) => start * self.shard_len_64,
            Bound::Excluded(start) => (start + 1) * self.shard_len_64,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(end) => (end + 1) * self.shard_len_64,
            Bound::Excluded(end) => end * self.shard_len_64,
            Bound::Unbounded => self.shard_count * self.shard_len_64,
        };

        self.data[start..end].fill([0; 64]);
    }
}

// ======================================================================
// ShardsRefMut - IMPL Index

impl Index<usize> for ShardsRefMut<'_> {
    type Output = [[u8; 64]];
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index * self.shard_len_64..(index + 1) * self.shard_len_64]
    }
}

// ======================================================================
// ShardsRefMut - IMPL IndexMut

impl IndexMut<usize> for ShardsRefMut<'_> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index * self.shard_len_64..(index + 1) * self.shard_len_64]
    }
}

// ======================================================================
// ShardsRefMut - CRATE

impl ShardsRefMut<'_> {
    pub(crate) fn copy_within(&mut self, mut src: usize, mut dest: usize, mut count: usize) {
        src *= self.shard_len_64;
        dest *= self.shard_len_64;
        count *= self.shard_len_64;

        self.data.copy_within(src..src + count, dest);
    }

    // Returns mutable references to flat-arrays of shard-ranges
    // `x .. x + count` and `y .. y + count`.
    //
    // Ranges must not overlap.
    pub(crate) fn flat2_mut(
        &mut self,
        mut x: usize,
        mut y: usize,
        mut count: usize,
    ) -> (&mut [[u8; 64]], &mut [[u8; 64]]) {
        x *= self.shard_len_64;
        y *= self.shard_len_64;
        count *= self.shard_len_64;

        if x < y {
            let (head, tail) = self.data.split_at_mut(y);
            (&mut head[x..x + count], &mut tail[..count])
        } else {
            let (head, tail) = self.data.split_at_mut(x);
            (&mut tail[..count], &mut head[y..y + count])
        }
    }
}
