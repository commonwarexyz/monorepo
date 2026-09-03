//! Reed-Solomon encoding over an arbitrary [`Impl`].
//!
//! This follows the construction of Lin, Chung, and Han ("Novel polynomial
//! basis and its application to Reed-Solomon erasure codes",
//! <https://arxiv.org/abs/1404.3458>), as implemented in Leopard-RS
//! (<https://github.com/catid/leopard>): an additive FFT over a Cantor basis,
//! which encodes in O(n log n) field operations rather than O(n^2).
//!
//! # Binary fields
//!
//! The transform only makes sense over a binary field. Each layer splits a
//! GF(2)-subspace into exactly two cosets, and a Cantor basis only exists when
//! the field has characteristic 2. That said, the arithmetic here is written
//! against a generic [`Field`], with `+`, `-`, and `*`, and never assumes
//! that `-a = a`. An implementation is free to exploit that internally.
//!
//! # Layout
//!
//! With `k` original shards and `r` recovery shards, let `m` be the smallest
//! power of two at least `r`. Codeword positions `[0, r)` hold the recovery
//! shards, and positions `[m, m + k)` hold the original shards. Encoding
//! inverse transforms each block of `m` originals at its own position, sums
//! the results, and forward transforms that sum at position 0.
//!
//! Every operation on shards is elementwise, so the transform on one byte
//! range of every shard is independent of every other byte range.

use commonware_math::algebra::{Additive, Field};

/// A concrete implementation of Ocelot's arithmetic over one field.
///
/// This bundles the scalar field, used for tables, with vectorized operations
/// on whole shards, which is all the transform needs. How shards are laid out,
/// and how the vectorized operations are performed, is entirely up to the
/// implementation, which must handle shards of any length that is a multiple
/// of [`Self::ALIGN`], including any tail shorter than its vector width.
///
/// Implementations should be zero-sized handles, so passing them by value is
/// free.
pub trait Impl: Copy + Send + Sync + 'static {
    /// A scalar field element, used for tables and twiddle factors.
    type Element: Field + Copy;

    /// The log2 of the field order.
    const BITS: usize;

    /// The number of elements in the field.
    ///
    /// The total number of shards, original and recovery, cannot exceed this.
    const ORDER: usize = 1 << Self::BITS;

    /// The number of bytes in one element.
    ///
    /// Shard lengths must be a multiple of this, so that every shard holds a
    /// whole number of elements. This is 1 for GF(2^8) and 2 for GF(2^16).
    const ALIGN: usize = Self::BITS / 8;

    /// A Cantor basis for the field over GF(2), with [`Self::BITS`] elements.
    ///
    /// Writing `v_i` for the `i`th element, we require `v_0 = 1` and
    /// `v_i^2 - v_i = v_(i-1)` for `i > 0`. This is what makes the twiddle
    /// factors take the simple form computed in [`Encoder::new`].
    fn basis() -> &'static [Self::Element];

    /// `dst += src`, elementwise.
    fn add_into(self, dst: &mut [u8], src: &[u8]);

    /// `dst -= src`, elementwise.
    fn sub_into(self, dst: &mut [u8], src: &[u8]);

    /// `dst += c * src`, elementwise.
    fn mul_add(self, dst: &mut [u8], src: &[u8], c: Self::Element);

    /// `dst -= c * src`, elementwise.
    fn mul_sub(self, dst: &mut [u8], src: &[u8], c: Self::Element);

    /// The forward butterfly: `x += c * y`, then `y += x`.
    ///
    /// The default performs two passes over memory. Implementations can
    /// override it with a single fused pass.
    fn fft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
        if c != Self::Element::zero() {
            self.mul_add(x, y, c);
        }
        self.add_into(y, x);
    }

    /// The inverse butterfly: `y -= x`, then `x -= c * y`.
    ///
    /// This undoes [`Self::fft_butterfly`] with the same `c`. As with that
    /// method, implementations can override it with a single fused pass.
    fn ifft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
        self.sub_into(y, x);
        if c != Self::Element::zero() {
            self.mul_sub(x, y, c);
        }
    }
}

/// A fixed number of equally sized shards, in one allocation.
struct Shards {
    data: Vec<u8>,
    len: usize,
}

impl Shards {
    fn new(shards: usize, len: usize) -> Self {
        Self {
            data: vec![0; shards * len],
            len,
        }
    }

    fn shards(&self) -> impl Iterator<Item = &[u8]> {
        self.data.chunks_exact(self.len)
    }

    fn shards_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        self.data.chunks_exact_mut(self.len)
    }

    /// Split shards `[r, r + 2 * dist)` into two halves of `dist` shards each.
    fn halves_mut(
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

/// Produces recovery shards using the arithmetic of some [`Impl`].
///
/// Constructing an encoder computes tables of size [`Impl::ORDER`], so one
/// should be created once and reused.
pub struct Encoder<I: Impl> {
    imp: I,
    /// The twiddle factors of the transform, indexed by codeword position.
    ///
    /// Let `j` be the number of trailing zeros of `x`, and `b` be `x` with
    /// bit `j` cleared. Then `skews[x]` is `s_j(w_b)`, where `w_b` is the
    /// point at position `b`, and `s_j` is the polynomial vanishing on the
    /// span of the first `j` basis elements, normalized so `s_j(v_j) = 1`.
    /// Index 0 is unused.
    skews: Box<[I::Element]>,
}

impl<I: Impl> Encoder<I> {
    /// Create an encoder, computing its tables.
    pub fn new(imp: I) -> Self {
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

    /// Produce `recovery` shards from the `original` shards.
    ///
    /// # Panics
    ///
    /// If there are no original shards, if their lengths differ or are not
    /// a multiple of [`Impl::ALIGN`], or if the total shard count exceeds
    /// [`Impl::ORDER`].
    pub fn encode(&self, original: &[&[u8]], recovery: usize) -> Vec<Vec<u8>> {
        let k = original.len();
        assert!(k > 0, "no original shards");
        assert!(k + recovery <= I::ORDER, "too many shards");
        let len = original[0].len();
        assert!(len.is_multiple_of(I::ALIGN), "shard length is not aligned");
        assert!(
            original.iter().all(|s| s.len() == len),
            "shard lengths differ"
        );
        if recovery == 0 {
            return Vec::new();
        }

        let m = recovery.next_power_of_two();
        let mut acc = Shards::new(m, len);
        let mut tmp = Shards::new(m, len);
        for (i, block) in original.chunks(m).enumerate() {
            let shift = m * (i + 1);
            if i == 0 {
                self.ifft(block, &mut acc, shift);
            } else {
                self.ifft(block, &mut tmp, shift);
                for (a, t) in acc.shards_mut().zip(tmp.shards()) {
                    self.imp.add_into(a, t);
                }
            }
        }
        self.fft(&mut acc, recovery);

        acc.shards().take(recovery).map(<[u8]>::to_vec).collect()
    }

    /// Inverse transform `data`, viewed as values at positions
    /// `[shift, shift + m)`, into `work`, which holds `m` shards.
    ///
    /// Inputs past the end of `data` are taken to be zero.
    fn ifft(&self, data: &[&[u8]], work: &mut Shards, shift: usize) {
        let m = work.data.len() / work.len;
        assert!(data.len() <= m);
        for (i, w) in work.shards_mut().enumerate() {
            match data.get(i) {
                Some(d) => w.copy_from_slice(d),
                None => w.fill(0),
            }
        }

        let mut dist = 1;
        while dist < m {
            // Blocks starting at or past data.len() are all zero, and each
            // layer only mixes shards within a block, so they stay zero.
            for r in (0..data.len()).step_by(2 * dist) {
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
    fn fft(&self, work: &mut Shards, needed: usize) {
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
