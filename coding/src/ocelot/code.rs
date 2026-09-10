//! Reed-Solomon encoding and erasure decoding over an arbitrary [`Impl`].
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
//!
//! # Erasure decoding
//!
//! Let `n = (m + k).next_power_of_two()`. The codeword evaluates a
//! polynomial `f` of degree less than `n - m`. The unused recovery positions
//! `[r, m)` are erasures, while the padded original positions `[m + k, n)`
//! are known zeros.
//!
//! If `L` vanishes at all erased positions, at most `m` erasures ensure that
//! `f * L` has degree less than `n`. Its evaluations are known everywhere:
//! zero at erasures, and `f(x) * L(x)` elsewhere. An inverse FFT, formal
//! derivative, and forward FFT give `(f * L)'`. At an erased position `x`,
//! `f(x) = (f * L)'(x) / L'(x)`.

use super::transform::{Shards, Transform};
use commonware_math::algebra::{Additive, Field, Ring};
use thiserror::Error;

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
    /// The original count plus the recovery count rounded up to a power of
    /// two cannot exceed this.
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

/// Produces recovery shards using the arithmetic of some [`Impl`].
///
/// Constructing an encoder computes tables of size [`Impl::ORDER`], so one
/// should be created once and reused.
pub struct Encoder<I: Impl> {
    transform: Transform<I>,
}

impl<I: Impl> Encoder<I> {
    /// Create an encoder, computing its tables.
    pub fn new(imp: I) -> Self {
        Self {
            transform: Transform::new(imp),
        }
    }

    /// Produce `recovery` shards from the `original` shards.
    ///
    /// # Panics
    ///
    /// - There are no original shards.
    /// - Shard lengths differ.
    /// - Shard lengths are not a multiple of [`Impl::ALIGN`].
    /// - The total shard count exceeds [`Impl::ORDER`] after rounding the
    ///   recovery count up to a power of two.
    pub fn encode(&self, original: &[&[u8]], recovery: usize) -> Vec<Vec<u8>> {
        let k = original.len();
        assert!(k > 0, "no original shards");
        let m = recovery
            .checked_next_power_of_two()
            .expect("too many shards");
        assert!(
            k <= I::ORDER && (recovery == 0 || m <= I::ORDER - k),
            "too many shards"
        );
        let len = original[0].len();
        assert!(len.is_multiple_of(I::ALIGN), "shard length is not aligned");
        assert!(
            original.iter().all(|s| s.len() == len),
            "shard lengths differ"
        );
        if recovery == 0 {
            return Vec::new();
        }

        if len == 0 {
            return vec![Vec::new(); recovery];
        }
        let mut acc = Shards::new(m, len);
        let mut tmp = Shards::new(m, len);
        for (i, block) in original.chunks(m).enumerate() {
            let shift = m * (i + 1);
            let work = if i == 0 { &mut acc } else { &mut tmp };
            for (j, shard) in work.shards_mut().enumerate() {
                match block.get(j) {
                    Some(data) => shard.copy_from_slice(data),
                    None => shard.fill(0),
                }
            }
            self.transform.ifft(work, block.len(), shift);
            if i != 0 {
                for (a, t) in acc.shards_mut().zip(tmp.shards()) {
                    self.transform.imp.add_into(a, t);
                }
            }
        }
        self.transform.fft(&mut acc, recovery);

        acc.shards().take(recovery).map(<[u8]>::to_vec).collect()
    }
}

/// An invalid erasure-decoding request.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// There must be at least one original, and the padded layout must fit.
    #[error("invalid shard counts")]
    InvalidShardCount,
    /// Every present shard must have the same aligned length.
    #[error("invalid shard length")]
    InvalidShardLength,
    /// At least as many shards as original positions must be present.
    #[error("insufficient shards: {present} present, {required} required")]
    InsufficientShards { present: usize, required: usize },
}

/// Recovers missing original shards using the arithmetic of some [`Impl`].
///
/// Construction computes tables of size [`Impl::ORDER`]; reuse a decoder
/// across calls. Decoding only repairs erasures. Callers must authenticate
/// present shards before passing them in: corrupted or inconsistent shards
/// can silently produce incorrect output.
pub struct Decoder<I: Impl> {
    transform: Transform<I>,
    /// Field points in codeword order, expressed in the Cantor basis.
    points: Box<[I::Element]>,
}

impl<I: Impl> Decoder<I> {
    /// Create a decoder, computing its tables.
    pub fn new(imp: I) -> Self {
        let transform = Transform::new(imp);
        let mut points = vec![I::Element::zero(); I::ORDER];
        for (i, basis) in I::basis().iter().enumerate() {
            let bit = 1 << i;
            for j in 0..bit {
                points[bit + j] = points[j] + basis;
            }
        }
        Self {
            transform,
            points: points.into_boxed_slice(),
        }
    }

    /// Recover missing originals from borrowed original and recovery shards.
    ///
    /// The slice lengths must match the counts used for encoding. Each entry
    /// corresponds to its encoder index; `None` marks an erasure. All present
    /// shards must have the same length, a multiple of [`Impl::ALIGN`], and
    /// belong to the same codeword. Empty shards are supported.
    ///
    /// Returns `(original_index, data)` pairs in increasing index order for
    /// missing originals only. Present originals are neither returned nor
    /// modified. If every original is present, no shard buffers are allocated.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid counts or lengths, or if fewer than
    /// `original.len()` shards are present. The original count plus the
    /// recovery count rounded up to a power of two must fit in [`Impl::ORDER`].
    /// With no recovery shards, the original count alone must fit.
    ///
    /// # Complexity
    ///
    /// For `n` padded codeword positions and `e` erasures (including unused
    /// recovery positions), locator evaluation takes `O(n * e)` scalar field
    /// operations. Shard transforms take `O(n log n)` operations on whole
    /// shards and use one workspace of `n` shards, plus the returned data.
    pub fn decode(
        &self,
        original: &[Option<&[u8]>],
        recovery: &[Option<&[u8]>],
    ) -> Result<Vec<(usize, Vec<u8>)>, Error> {
        let k = original.len();
        let m = if recovery.is_empty() {
            0
        } else {
            recovery
                .len()
                .checked_next_power_of_two()
                .ok_or(Error::InvalidShardCount)?
        };
        if k == 0 || k > I::ORDER || m > I::ORDER - k {
            return Err(Error::InvalidShardCount);
        }

        let present = original.iter().chain(recovery).flatten().count();
        if present < k {
            return Err(Error::InsufficientShards {
                present,
                required: k,
            });
        }
        let len = original
            .iter()
            .chain(recovery)
            .flatten()
            .next()
            .unwrap()
            .len();
        if !len.is_multiple_of(I::ALIGN)
            || original
                .iter()
                .chain(recovery)
                .flatten()
                .any(|s| s.len() != len)
        {
            return Err(Error::InvalidShardLength);
        }

        let missing: Vec<_> = original
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.is_none().then_some(i))
            .collect();
        if missing.is_empty() {
            return Ok(Vec::new());
        }
        if len == 0 {
            return Ok(missing.into_iter().map(|i| (i, Vec::new())).collect());
        }

        let n = (m + k).next_power_of_two();
        n.checked_mul(len).ok_or(Error::InvalidShardLength)?;
        let erased: Vec<_> = recovery
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.is_none().then_some(i))
            .chain(recovery.len()..m)
            .chain(missing.iter().map(|i| m + i))
            .collect();
        // Skipping the zero factor at an erased position evaluates L' there;
        // elsewhere this is L. Cantor coordinates add by XOR.
        let locator: Vec<_> = (0..m + k)
            .map(|i| {
                erased
                    .iter()
                    .filter(|&&e| e != i)
                    .fold(I::Element::one(), |acc, &e| acc * &self.points[i ^ e])
            })
            .collect();

        let imp = self.transform.imp;
        let mut work = Shards::new(n, len);
        for (i, shard) in recovery
            .iter()
            .enumerate()
            .chain(original.iter().enumerate().map(|(i, shard)| (m + i, shard)))
        {
            if let Some(shard) = shard {
                imp.mul_add(&mut work.data[i * len..(i + 1) * len], shard, locator[i]);
            }
        }
        self.transform.ifft(&mut work, m + k, 0);
        derivative(imp, &mut work.data, len);
        self.transform.fft(&mut work, m + k);

        Ok(missing
            .into_iter()
            .map(|i| {
                let mut data = vec![0; len];
                imp.mul_add(
                    &mut data,
                    &work.data[(m + i) * len..(m + i + 1) * len],
                    locator[m + i].inv(),
                );
                (i, data)
            })
            .collect())
    }
}

/// Differentiate novel-basis coefficients in place.
fn derivative<I: Impl>(imp: I, data: &mut [u8], len: usize) {
    if data.len() == len {
        data.fill(0);
        return;
    }
    // For f = a + s_j * b, f' = a' + b + s_j * b', since s_j' = 1
    // in the Cantor basis. Preserve b until it has been added to a'.
    let (a, b) = data.split_at_mut(data.len() / 2);
    derivative(imp, a, len);
    imp.add_into(a, b);
    derivative(imp, b, len);
}
