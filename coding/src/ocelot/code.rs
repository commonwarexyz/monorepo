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

#[cfg(any(test, feature = "arbitrary"))]
pub mod test_suites {
    //! Property tests for implementations of Ocelot's shard arithmetic.

    use super::{Decoder, Encoder, Error, Impl};
    use arbitrary::Unstructured;
    use commonware_math::algebra::{Additive, Field, Ring};

    fn point<I: Impl>(i: usize) -> I::Element {
        I::basis()
            .iter()
            .enumerate()
            .filter(|(bit, _)| i & (1 << bit) != 0)
            .fold(I::Element::zero(), |acc, (_, b)| acc + b)
    }

    fn check_basis<I: Impl>(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let basis = I::basis();
        assert_eq!(basis.len(), I::BITS);
        assert_eq!(basis[0], I::Element::one());
        assert_eq!(basis[0] + &basis[0], I::Element::zero());
        for pair in basis.windows(2) {
            assert_eq!(pair[1] * &pair[1] - &pair[1], pair[0]);
        }
        let a = u.int_in_range(0..=I::ORDER - 1)?;
        let b = u.int_in_range(0..=I::ORDER - 1)?;
        assert_eq!(point::<I>(a) + &point::<I>(b), point::<I>(a ^ b));
        assert_eq!(point::<I>(a) == point::<I>(b), a == b);
        Ok(())
    }

    /// Evaluate the Lagrange interpolant directly, independently of the FFT.
    fn encode_reference<I: Impl>(imp: I, original: &[&[u8]], r: usize) -> Vec<Vec<u8>> {
        if r == 0 {
            return Vec::new();
        }
        let m = r.next_power_of_two();
        let n = (m + original.len()).next_power_of_two();
        // Padded original positions are evaluations fixed to zero.
        let nodes: Vec<_> = (m..n).map(point::<I>).collect();
        let weights: Vec<_> = nodes
            .iter()
            .take(original.len())
            .enumerate()
            .map(|(j, x)| {
                nodes
                    .iter()
                    .enumerate()
                    .filter(|(t, _)| *t != j)
                    .fold(I::Element::one(), |acc, (_, y)| acc * &(*x - y))
                    .inv()
            })
            .collect();
        (0..r)
            .map(|i| {
                let x = point::<I>(i);
                let product = nodes
                    .iter()
                    .fold(I::Element::one(), |acc, y| acc * &(x - y));
                let mut out = vec![0; original[0].len()];
                for (j, shard) in original.iter().enumerate() {
                    let weight = product * &weights[j] * &(x - &nodes[j]).inv();
                    imp.mul_add(&mut out, shard, weight);
                }
                out
            })
            .collect()
    }

    fn check_invalid_counts<I: Impl>(
        u: &mut Unstructured<'_>,
        decoder: &Decoder<I>,
    ) -> arbitrary::Result<()> {
        let k = u.int_in_range(0..=I::ORDER + 1)?;
        let r = u.int_in_range(0..=I::ORDER + 1)?;
        let m = if r == 0 { 0 } else { r.next_power_of_two() };
        let expected = if k == 0 || k + m > I::ORDER {
            Error::InvalidShardCount
        } else {
            Error::InsufficientShards {
                present: 0,
                required: k,
            }
        };
        assert_eq!(
            decoder.decode(&vec![None; k], &vec![None; r]),
            Err(expected)
        );
        Ok(())
    }

    /// Check the Cantor basis, encoding, erasure recovery, and input validation
    /// with arbitrary counts, lengths, shard contents, and erasure positions.
    ///
    /// Pass this function to `commonware_invariants::minifuzz::test`, capturing
    /// the implementation to test in the closure. Counts are capped at 256
    /// padded positions to keep each case bounded for larger fields. Cases
    /// with at most 32 padded positions also check direct interpolation.
    pub fn fuzz_code<I: Impl>(u: &mut Unstructured<'_>, imp: I) -> arbitrary::Result<()> {
        check_basis::<I>(u)?;
        let encoder = Encoder::new(imp);
        let decoder = Decoder::new(imp);
        assert_eq!(encoder.encode(&[&[], &[]], 3), vec![Vec::<u8>::new(); 3]);
        check_invalid_counts(u, &decoder)?;
        let limit = I::ORDER.min(256);
        let r: usize = u.int_in_range(0..=limit / 2)?;
        let m = if r == 0 { 0 } else { r.next_power_of_two() };
        let k = u.int_in_range(1..=limit - m)?;
        let len = u.int_in_range(0..=65)? * I::ALIGN;
        let mut original = vec![vec![0; len]; k];
        for shard in &mut original {
            u.fill_buffer(shard)?;
        }
        let mut positions: Vec<_> = (0..k + r).collect();
        for i in (1..positions.len()).rev() {
            positions.swap(i, u.int_in_range(0..=i)?);
        }
        let erased = u.int_in_range(0..=k + r)?;

        let refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
        let recovery = encoder.encode(&refs, r);
        assert_eq!(recovery.len(), r);
        assert!(recovery.iter().all(|s| s.len() == len));
        assert_eq!(encoder.encode(&refs, r), recovery);
        if m + k <= 32 {
            assert_eq!(recovery, encode_reference(imp, &refs, r));
        }

        let input: Vec<_> = original
            .iter()
            .chain(&recovery)
            .map(|s| Some(s.as_slice()))
            .collect();
        if k + r > 1 || I::ALIGN > 1 {
            let mut malformed = original[0].clone();
            malformed.push(0);
            let mut input = input.clone();
            input[0] = Some(&malformed);
            assert_eq!(
                decoder.decode(&input[..k], &input[k..]),
                Err(Error::InvalidShardLength)
            );
        }

        // Recovery from parity alone must work when enough parity is present.
        if r >= k {
            let recovered = decoder.decode(&vec![None; k], &input[k..]).unwrap();
            assert_eq!(
                recovered,
                original.iter().cloned().enumerate().collect::<Vec<_>>()
            );
        }

        // Exercise both sides of the recovery threshold, as well as an
        // arbitrary erasure count, using the same encoder and decoder.
        for count in [0, r, r + 1, erased] {
            let mut input = input.clone();
            for &i in &positions[..count] {
                input[i] = None;
            }
            let result = decoder.decode(&input[..k], &input[k..]);
            if count > r {
                assert_eq!(
                    result,
                    Err(Error::InsufficientShards {
                        present: k + r - count,
                        required: k,
                    })
                );
                continue;
            }
            let recovered = result.unwrap();
            let missing: Vec<_> = (0..k).filter(|&i| input[i].is_none()).collect();
            assert_eq!(recovered.len(), missing.len());
            for ((i, shard), expected) in recovered.iter().zip(missing) {
                assert_eq!(*i, expected);
                assert_eq!(shard, &original[*i]);
            }
        }
        Ok(())
    }
}
