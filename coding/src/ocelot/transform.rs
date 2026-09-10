//! Additive transforms shared by encoding and decoding.

use super::code::Impl;
use commonware_math::algebra::Additive;

/// A fixed number of equally sized shards, in one allocation.
pub(super) struct Shards {
    pub(super) data: Vec<u8>,
    pub(super) len: usize,
}

impl Shards {
    pub(super) fn new(shards: usize, len: usize) -> Self {
        Self {
            data: vec![0; shards * len],
            len,
        }
    }

    pub(super) fn shards(&self) -> impl Iterator<Item = &[u8]> {
        self.data.chunks_exact(self.len)
    }

    pub(super) fn shards_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        self.data.chunks_exact_mut(self.len)
    }

    /// Split shards `[r, r + 2 * dist)` into two halves of `dist` shards each.
    pub(super) fn halves_mut(
        &mut self,
        r: usize,
        dist: usize,
    ) -> impl Iterator<Item = (&mut [u8], &mut [u8])> {
        let (lo, hi) =
            self.data[r * self.len..(r + 2 * dist) * self.len].split_at_mut(dist * self.len);
        lo.chunks_exact_mut(self.len)
            .zip(hi.chunks_exact_mut(self.len))
    }
}

pub(super) struct Transform<I: Impl> {
    pub(super) imp: I,
    /// The twiddle factors of the transform, indexed by codeword position.
    ///
    /// Let `j` be the number of trailing zeros of `x`, and `b` be `x` with
    /// bit `j` cleared. Then `skews[x]` is `s_j(w_b)`, where `w_b` is the
    /// point at position `b`, and `s_j` is the polynomial vanishing on the
    /// span of the first `j` basis elements, normalized so `s_j(v_j) = 1`.
    /// Index 0 is unused.
    skews: Box<[I::Element]>,
}

impl<I: Impl> Transform<I> {
    /// Compute the transform's twiddle factors.
    pub(super) fn new(imp: I) -> Self {
        let basis = I::basis();
        assert_eq!(basis.len(), I::BITS, "basis has the wrong size");

        // subspace[i] holds s_j(v_i) for the current layer j. At j = 0, s_0 is
        // the identity. Each layer, s_(j+1)(X) = s_j(X) * s_j(X - v_j), and
        // since s_j is linear with s_j(v_j) = 1, this is s_j(X)^2 - s_j(X).
        let mut subspace = basis.to_vec();
        let mut skews = vec![I::Element::zero(); I::ORDER];
        for j in 0..I::BITS {
            // Fill every position whose lowest set bit is j. By linearity,
            // s_j(w_b) is the sum of s_j(v_i) over the bits i of b, and bits
            // below j contribute nothing, so we build the table one bit at a
            // time, from the entries already filled with smaller bits.
            let low = 1 << j;
            skews[low] = I::Element::zero();
            for (i, s) in subspace.iter().enumerate().skip(j + 1) {
                let bit = 1 << i;
                for b in (0..bit).step_by(low << 1) {
                    skews[b + bit + low] = skews[b + low] + s;
                }
            }
            for s in subspace.iter_mut() {
                let squared = *s * &*s;
                *s = squared - &*s;
            }
        }

        Self {
            imp,
            skews: skews.into_boxed_slice(),
        }
    }

    /// Inverse transform `work` in place at `shift`.
    ///
    /// Shards at or past `nonzero` must be zero.
    pub(super) fn ifft(&self, work: &mut Shards, nonzero: usize, shift: usize) {
        let m = work.data.len() / work.len;
        assert!(nonzero <= m);

        let mut dist = 1;
        while dist < m {
            // Blocks starting at or past nonzero are all zero, and each
            // layer only mixes shards within a block, so they stay zero.
            for r in (0..nonzero).step_by(2 * dist) {
                let c = self.skews[shift + r + dist];
                for (x, y) in work.halves_mut(r, dist) {
                    self.imp.ifft_butterfly(x, y, c);
                }
            }
            dist <<= 1;
        }
    }

    /// Forward transform `work` in place, at position 0.
    ///
    /// Only the first `needed` outputs are guaranteed to be computed.
    pub(super) fn fft(&self, work: &mut Shards, needed: usize) {
        let m = work.data.len() / work.len;
        assert!(needed <= m);

        let mut dist = m / 2;
        while dist >= 1 {
            // Outputs in a block depend only on inputs in that block, so
            // blocks starting at or past `needed` can be skipped.
            for r in (0..needed).step_by(2 * dist) {
                let c = self.skews[r + dist];
                for (x, y) in work.halves_mut(r, dist) {
                    self.imp.fft_butterfly(x, y, c);
                }
            }
            dist >>= 1;
        }
    }
}
