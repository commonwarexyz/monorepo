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
//! Every operation on shards is elementwise. Stripe boundaries preserve the
//! implementation's byte layout, so each stripe can be transformed independently.
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

use super::transform::{Shards, Tables, Transform};
use commonware_math::algebra::{Additive, Field};
use commonware_parallel::Strategy;
use commonware_utils::Cached;
use std::{cell::RefCell, ops::Range, sync::Arc, thread::LocalKey};
use thiserror::Error;

commonware_utils::thread_local_cache!(static ENCODE_ACC: Shards);
commonware_utils::thread_local_cache!(static ENCODE_TMP: Shards);
commonware_utils::thread_local_cache!(static DECODE_WORK: Shards);

/// Target width of independently scheduled shard stripes.
///
/// This is large enough to amortize scheduling and transform setup while
/// exposing parallelism for large shards. The actual width is rounded down to
/// a layout boundary, or raised to one layout block for unusually wide blocks.
const STRIPE_BYTES: usize = 16 * 1024;

/// Target total size of the encoder's transform buffers per worker.
const ENCODE_WORK_BYTES: usize = 512 * 1024;

/// Target total size of the decoder's transform buffer per worker.
const DECODE_WORK_BYTES: usize = 512 * 1024;

fn workspace(
    cache: &'static LocalKey<RefCell<(bool, Option<Shards>)>>,
    count: usize,
    len: usize,
) -> Cached<Shards> {
    Cached::take(
        cache,
        || Ok::<_, ()>(Shards::new(count, len)),
        |work| {
            work.reset(count, len);
            Ok(())
        },
    )
    .expect("infallible workspace reset")
}

pub fn stripe_bytes<I: Impl>() -> usize {
    const {
        assert!(I::ALIGN > 0);
        assert!(I::STRIPE_ALIGN > 0);
        assert!(I::STRIPE_ALIGN.is_multiple_of(I::ALIGN));
    }
    (STRIPE_BYTES / I::STRIPE_ALIGN).max(1) * I::STRIPE_ALIGN
}

fn decode_stripe_bytes<I: Impl>(count: usize) -> usize {
    let workspace = (DECODE_WORK_BYTES / count / I::STRIPE_ALIGN).max(1) * I::STRIPE_ALIGN;
    let width = stripe_bytes::<I>().min(workspace);
    let skew = (128 / I::STRIPE_ALIGN).max(1) * I::STRIPE_ALIGN;
    // Avoid shard strides that map the derivative's simultaneous accesses to
    // the same cache sets. Keep every stripe boundary aligned to the layout.
    if width.is_multiple_of(4096) && width > skew {
        width - skew
    } else {
        width
    }
}

/// Split shard-major output buffers into disjoint mutable slices in stripe-major
/// order. Tasks write these slices directly, without gathering stripe results.
fn stripe_columns<T: AsMut<[u8]>>(outputs: &mut [T], stripe_bytes: usize) -> Vec<&mut [u8]> {
    let output_count = outputs.len();
    let stripes = outputs
        .first_mut()
        .map_or(0, |output| output.as_mut().len().div_ceil(stripe_bytes));
    let slots = stripes
        .checked_mul(output_count)
        .expect("stripe metadata length overflow");
    let mut columns: Vec<&mut [u8]> = std::iter::repeat_with(|| &mut [][..]).take(slots).collect();
    for (output_index, output) in outputs.iter_mut().enumerate() {
        for (stripe, shard) in output.as_mut().chunks_mut(stripe_bytes).enumerate() {
            columns[stripe * output_count + output_index] = shard;
        }
    }
    columns
}

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
    type Element: Field + Copy + 'static;

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

    /// Byte alignment of every stripe boundary except the end of a shard.
    ///
    /// This must be a positive multiple of [`Self::ALIGN`]. Splitting a shard
    /// at these boundaries must preserve its symbol ordering and byte layout
    /// within each stripe, including a shorter final stripe.
    const STRIPE_ALIGN: usize = Self::ALIGN;

    /// Globally unique transcript namespace for this field and code variant.
    const NAMESPACE: &'static [u8];

    /// Return the field tables used by this implementation.
    fn tables() -> Arc<Tables<Self::Element>> {
        Arc::new(Tables::new::<Self>())
    }

    /// A Cantor basis for the field over GF(2), with [`Self::BITS`] elements.
    ///
    /// Writing `v_i` for the `i`th element, we require `v_0 = 1` and
    /// `v_i^2 - v_i = v_(i-1)` for `i > 0`. This is what makes the twiddle
    /// factors take the simple form computed in [`Encoder::new`].
    fn basis() -> &'static [Self::Element];

    /// `dst += src`, elementwise.
    ///
    /// This must support both individual shards and concatenations of shards.
    fn add_into(self, dst: &mut [u8], src: &[u8]);

    /// `dst -= src`, elementwise.
    ///
    /// This has the same layout requirements as [`Self::add_into`].
    fn sub_into(self, dst: &mut [u8], src: &[u8]);

    /// `dst += c * src`, elementwise, for one shard.
    fn mul_add(self, dst: &mut [u8], src: &[u8], c: Self::Element);

    /// `dst = c * src`, elementwise, for one shard.
    fn mul_into(self, dst: &mut [u8], src: &[u8], c: Self::Element) {
        dst.fill(0);
        self.mul_add(dst, src, c);
    }

    /// `dst -= c * src`, elementwise, for one shard.
    fn mul_sub(self, dst: &mut [u8], src: &[u8], c: Self::Element);

    /// Differentiate four consecutive shard groups in place.
    ///
    /// Each quarter contains the same number of bytes. For quarters
    /// `[a, b, c, d]`, this computes `[b + c, d, d, 0]`.
    fn derivative_four(self, quarters: [&mut [u8]; 4]) {
        let [a, b, c, d] = quarters;
        assert_eq!(a.len(), b.len(), "quarter lengths differ");
        assert_eq!(a.len(), c.len(), "quarter lengths differ");
        assert_eq!(a.len(), d.len(), "quarter lengths differ");
        a.copy_from_slice(b);
        self.add_into(a, c);
        b.copy_from_slice(d);
        c.copy_from_slice(d);
        d.fill(0);
    }

    /// Differentiate sixteen equal-length consecutive shard groups in place.
    ///
    /// Output block `i` is the sum of input blocks `i | (1 << bit)` for every
    /// bit not set in `i`.
    fn derivative_sixteen(self, mut blocks: [&mut [u8]; 16]) {
        let len = blocks[0].len();
        assert!(
            blocks.iter().all(|block| block.len() == len),
            "block lengths differ"
        );
        for output in 0..16 {
            let (done, sources) = blocks.split_at_mut(output + 1);
            let dst = &mut *done[output];
            let mut contributors = (0..4).filter_map(|bit| {
                let mask = 1 << bit;
                (output & mask == 0).then(|| (output | mask) - output - 1)
            });
            if let Some(source) = contributors.next() {
                dst.copy_from_slice(sources[source]);
                for source in contributors {
                    self.add_into(dst, sources[source]);
                }
            } else {
                dst.fill(0);
            }
        }
    }

    /// The forward butterfly: `x += c * y`, then `y += x`.
    fn fft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
        if c != Self::Element::zero() {
            self.mul_add(x, y, c);
        }
        self.add_into(y, x);
    }

    /// The inverse butterfly: `y -= x`, then `x -= c * y`.
    ///
    /// This undoes [`Self::fft_butterfly`] with the same `c`.
    fn ifft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
        self.sub_into(y, x);
        if c != Self::Element::zero() {
            self.mul_sub(x, y, c);
        }
    }

    /// Compute two forward-transform layers on four equal shard groups.
    ///
    /// Each quarter contains a whole number of `shard_len`-byte shards. The
    /// outer pairs (0, 2) and (1, 3) use `coefficients[2]` first, followed by
    /// the inner pairs (0, 1) and (2, 3) using `coefficients[0]` and
    /// `coefficients[1]`, respectively.
    fn fft_butterfly_two_layers(
        self,
        quarters: [&mut [u8]; 4],
        shard_len: usize,
        coefficients: [Self::Element; 3],
    ) {
        let [q0, q1, q2, q3] = quarters;
        assert!(shard_len > 0, "shard length is zero");
        assert_eq!(q0.len(), q1.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q2.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q3.len(), "quarter lengths differ");
        assert!(q0.len().is_multiple_of(shard_len), "partial shard group");
        let [c0, c1, c2] = coefficients;
        for (((x0, x1), x2), x3) in q0
            .chunks_exact_mut(shard_len)
            .zip(q1.chunks_exact_mut(shard_len))
            .zip(q2.chunks_exact_mut(shard_len))
            .zip(q3.chunks_exact_mut(shard_len))
        {
            self.fft_butterfly(x0, x2, c2);
            self.fft_butterfly(x1, x3, c2);
            self.fft_butterfly(x0, x1, c0);
            self.fft_butterfly(x2, x3, c1);
        }
    }

    /// Compute two inverse-transform layers on four equal shard groups.
    ///
    /// This undoes [`Self::fft_butterfly_two_layers`] with the same shard
    /// grouping and coefficients.
    fn ifft_butterfly_two_layers(
        self,
        quarters: [&mut [u8]; 4],
        shard_len: usize,
        coefficients: [Self::Element; 3],
    ) {
        let [q0, q1, q2, q3] = quarters;
        assert!(shard_len > 0, "shard length is zero");
        assert_eq!(q0.len(), q1.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q2.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q3.len(), "quarter lengths differ");
        assert!(q0.len().is_multiple_of(shard_len), "partial shard group");
        let [c0, c1, c2] = coefficients;
        for (((x0, x1), x2), x3) in q0
            .chunks_exact_mut(shard_len)
            .zip(q1.chunks_exact_mut(shard_len))
            .zip(q2.chunks_exact_mut(shard_len))
            .zip(q3.chunks_exact_mut(shard_len))
        {
            self.ifft_butterfly(x0, x1, c0);
            self.ifft_butterfly(x2, x3, c1);
            self.ifft_butterfly(x0, x2, c2);
            self.ifft_butterfly(x1, x3, c2);
        }
    }

    /// Compute the contribution of `range` to the randomized checksums of `shard`.
    ///
    /// `coefficients` is uniformly sampled random input. Implementations should
    /// use it directly to select the checksum map; it does not need to be
    /// hashed or passed through another randomness extractor. There is one byte
    /// of randomness per input code symbol for each output code symbol, so its
    /// length is
    /// `(shard.len() / Self::ALIGN) * (out.len() / Self::ALIGN)`.
    ///
    /// For fixed `coefficients`, the map from `shard` to `out` must be linear
    /// and must commute with this implementation's encoder: encoding checksums
    /// of the original shards must produce the checksums of the encoded shards.
    /// The random maps must detect any nonzero shard difference, except with
    /// probability 2^-8 per output code symbol. Output symbols use the code
    /// field's shard byte layout.
    ///
    /// `shard` and `coefficients` are the complete buffers. Overwrite `out`
    /// with the projection onto symbols in
    /// `range.start / Self::ALIGN..range.end / Self::ALIGN`. These logical
    /// symbol positions need not occupy consecutive bytes. Adding
    /// contributions from a disjoint partition with
    /// [`Self::add_into`] must yield the full-shard checksum. An empty range
    /// must write zero.
    ///
    /// `shard`, `out`, and both endpoints of `range` must be aligned to
    /// [`Self::ALIGN`], with `range.start <= range.end <= shard.len()`.
    fn checksum_range(self, shard: &[u8], coefficients: &[u8], range: Range<usize>, out: &mut [u8]);
}

/// Produces recovery shards using the arithmetic of some [`Impl`].
///
/// Construction obtains tables of size [`Impl::ORDER`] from the implementation.
pub struct Encoder<I: Impl> {
    transform: Transform<I>,
}

impl<I: Impl> Encoder<I> {
    /// Create an encoder using the implementation's field tables.
    pub fn new(imp: I) -> Self {
        Self {
            transform: Transform::new(imp),
        }
    }

    /// Produce `recovery` shards from the `original` shards using `strategy`.
    ///
    /// # Panics
    ///
    /// - There are no original shards.
    /// - Shard lengths differ.
    /// - Shard lengths are not a multiple of [`Impl::ALIGN`].
    /// - The total shard count exceeds [`Impl::ORDER`] after rounding the
    ///   recovery count up to a power of two.
    pub fn encode(
        &self,
        original: &[&[u8]],
        recovery: usize,
        strategy: &impl Strategy,
    ) -> Vec<Vec<u8>> {
        let (m, len) = Self::validate(original, recovery);
        if recovery == 0 {
            return Vec::new();
        }
        let mut output = vec![vec![0; len]; recovery];
        self.encode_into_validated(original, &mut output, m, len, strategy);
        output
    }

    /// Fill caller-owned recovery shards using `strategy`.
    ///
    /// # Panics
    ///
    /// - There are no original shards.
    /// - Original or recovery shard lengths differ.
    /// - Shard lengths are not a multiple of [`Impl::ALIGN`].
    /// - The total shard count exceeds [`Impl::ORDER`] after rounding the
    ///   recovery count up to a power of two.
    pub fn encode_into<T: AsMut<[u8]>>(
        &self,
        original: &[&[u8]],
        output: &mut [T],
        strategy: &impl Strategy,
    ) {
        let (m, len) = Self::validate(original, output.len());
        assert!(
            output.iter_mut().all(|shard| shard.as_mut().len() == len),
            "recovery shard lengths differ"
        );
        self.encode_into_validated(original, output, m, len, strategy);
    }

    fn validate(original: &[&[u8]], recovery: usize) -> (usize, usize) {
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
        (m, len)
    }

    fn encode_into_validated<T: AsMut<[u8]>>(
        &self,
        original: &[&[u8]],
        output: &mut [T],
        m: usize,
        len: usize,
        strategy: &impl Strategy,
    ) {
        let recovery = output.len();
        if recovery == 0 || len == 0 {
            return;
        }
        let k = original.len();
        let buffers = 1 + usize::from(k > m);
        let workspace_stripe =
            (ENCODE_WORK_BYTES / buffers / m / I::STRIPE_ALIGN).max(1) * I::STRIPE_ALIGN;
        let stripe_bytes = stripe_bytes::<I>().min(workspace_stripe);
        let work_bytes = stripe_bytes.min(len);
        let mut columns = stripe_columns(output, stripe_bytes);
        strategy.map_collect_vec_with_multiplier(
            columns.chunks_mut(recovery).enumerate(),
            work_bytes.saturating_mul(k + m),
            |(stripe, column)| {
                let mut acc = workspace(&ENCODE_ACC, m, work_bytes);
                let mut tmp = (k > m).then(|| workspace(&ENCODE_TMP, m, work_bytes));
                let width = column[0].len();
                let start = stripe * stripe_bytes;
                let end = start + width;
                acc.resize(width);
                if let Some(tmp) = tmp.as_mut() {
                    tmp.resize(width);
                }

                for (i, block) in original.chunks(m).enumerate() {
                    let shift = m * (i + 1);
                    let work: &mut Shards = if i == 0 {
                        &mut acc
                    } else {
                        tmp.as_mut().expect("multiple original blocks")
                    };
                    for (j, shard) in work.shards_mut().enumerate() {
                        match block.get(j) {
                            Some(data) => shard.copy_from_slice(&data[start..end]),
                            None => shard.fill(0),
                        }
                    }
                    self.transform.ifft(work, block.len(), shift);
                    if i != 0 {
                        self.transform.imp.add_into(
                            acc.data_mut(),
                            tmp.as_ref().expect("multiple original blocks").data(),
                        );
                    }
                }
                self.transform.fft(&mut acc, recovery);
                for (dst, src) in column.iter_mut().zip(acc.shards()) {
                    dst.copy_from_slice(src);
                }
            },
        );
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
/// Construction obtains tables of size [`Impl::ORDER`] from the implementation.
/// Decoding only repairs erasures. Callers must authenticate present shards
/// before passing them in: corrupted or inconsistent shards can silently
/// produce incorrect output.
pub struct Decoder<I: Impl> {
    transform: Transform<I>,
}

impl<I: Impl> Decoder<I> {
    /// Create a decoder using the implementation's field tables.
    pub fn new(imp: I) -> Self {
        Self {
            transform: Transform::new(imp),
        }
    }

    /// Recover missing originals from borrowed original and recovery shards
    /// using `strategy`.
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
    /// For `e` erasures partitioned into `b` aligned dyadic blocks and `q`
    /// consumed codeword positions, locator evaluation takes `O(e + q * b)`
    /// operations, with `b <= e`. For fields up to 16 bits, fragmented sets use
    /// `O(n log n)` integer operations after lazily building field-sized tables.
    /// Shard transforms take `O(n log n)` operations on whole shards for `n`
    /// padded positions. Work is split into aligned byte
    /// stripes; each strategy partition reuses one workspace of `n` stripe
    /// shards and writes directly into a disjoint range of the returned data.
    pub fn decode(
        &self,
        original: &[Option<&[u8]>],
        recovery: &[Option<&[u8]>],
        strategy: &impl Strategy,
    ) -> Result<Vec<(usize, Vec<u8>)>, Error> {
        self.decode_inner(original, recovery, strategy, false)
            .map(|(original, _)| original)
    }

    /// Recover missing originals and every unselected recovery shard using
    /// `strategy`.
    ///
    /// Input layout and validation are the same as for [`Self::decode`]. The
    /// decoder selects exactly `original.len()` inputs: every present original
    /// and the earliest present recovery shards needed to make up the balance.
    /// Later supplied recovery shards are surplus and are treated as erasures,
    /// though their lengths are still validated.
    ///
    /// Returns two lists of `(index, data)` pairs in increasing index order.
    /// The first contains missing originals, with indices relative to
    /// `original`. The second contains every recovery not selected as an input,
    /// with indices relative to `recovery`. This includes both absent recovery
    /// shards and supplied surplus shards. Every returned shard is the canonical
    /// codeword value implied by the selected inputs.
    ///
    /// If every original is present, no recovery shard is selected and the
    /// second list contains a canonical reconstruction of every recovery shard.
    /// With no recovery shards, both lists are empty. Empty shards are supported.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    ///
    /// # Complexity
    ///
    /// Original and recovery outputs are recovered from the same inverse FFT,
    /// derivative, and forward FFT. No separate encoding pass is performed.
    #[allow(clippy::type_complexity)]
    pub fn decode_with_recovery(
        &self,
        original: &[Option<&[u8]>],
        recovery: &[Option<&[u8]>],
        strategy: &impl Strategy,
    ) -> Result<(Vec<(usize, Vec<u8>)>, Vec<(usize, Vec<u8>)>), Error> {
        self.decode_inner(original, recovery, strategy, true)
    }

    #[allow(clippy::type_complexity)]
    fn decode_inner(
        &self,
        original: &[Option<&[u8]>],
        recovery: &[Option<&[u8]>],
        strategy: &impl Strategy,
        recover_recovery: bool,
    ) -> Result<(Vec<(usize, Vec<u8>)>, Vec<(usize, Vec<u8>)>), Error> {
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
        if missing.is_empty() && !recover_recovery {
            return Ok((Vec::new(), Vec::new()));
        }

        // Each missing original requires one recovery shard. Treat surplus
        // recovery shards as erasures so decoding does not process more shard
        // bytes than necessary. All supplied shards have already been
        // validated above.
        let recovery_end = if missing.is_empty() {
            0
        } else {
            recovery
                .iter()
                .enumerate()
                .filter(|(_, shard)| shard.is_some())
                .nth(missing.len() - 1)
                .map(|(i, _)| i + 1)
                .expect("present count checked above")
        };
        let missing_recovery: Vec<_> = if recover_recovery {
            recovery
                .iter()
                .enumerate()
                .filter_map(|(i, shard)| (i >= recovery_end || shard.is_none()).then_some(i))
                .collect()
        } else {
            Vec::new()
        };
        if missing.is_empty() && missing_recovery.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if len == 0 {
            return Ok((
                missing.into_iter().map(|i| (i, Vec::new())).collect(),
                missing_recovery
                    .into_iter()
                    .map(|i| (i, Vec::new()))
                    .collect(),
            ));
        }

        let n = (m + k).next_power_of_two();
        // Keep every offset into the logical shard matrix representable, even
        // though the decoder materializes it one stripe at a time.
        n.checked_mul(len).ok_or(Error::InvalidShardLength)?;
        let erased: Vec<_> = recovery
            .iter()
            .enumerate()
            .filter_map(|(i, s)| (i >= recovery_end || s.is_none()).then_some(i))
            .chain(recovery.len()..m)
            .chain(missing.iter().map(|i| m + i))
            .collect();
        debug_assert_eq!(erased.len(), m);

        let imp = self.transform.imp;
        let mut inputs = Vec::with_capacity(k);
        for (i, shard) in recovery
            .iter()
            .take(recovery_end)
            .enumerate()
            .chain(original.iter().enumerate().map(|(i, shard)| (m + i, shard)))
        {
            if let Some(shard) = shard {
                inputs.push((i, *shard, I::Element::zero()));
            }
        }
        debug_assert_eq!(inputs.len(), k);
        let nonzero = inputs.last().map_or(0, |&(i, _, _)| i + 1);
        let mut locators = self
            .transform
            .locator(
                &erased,
                inputs
                    .iter()
                    .map(|&(i, _, _)| i)
                    .chain(missing.iter().map(|&i| m + i))
                    .chain(missing_recovery.iter().copied()),
            )
            .into_iter();
        for (_, _, locator) in &mut inputs {
            *locator = locators.next().expect("locator count matches inputs");
        }
        let inverses: Vec<_> = locators.map(|locator| locator.inv()).collect();
        debug_assert_eq!(inverses.len(), missing.len() + missing_recovery.len());
        let needed = missing
            .last()
            .map(|&i| m + i + 1)
            .or_else(|| missing_recovery.last().map(|&i| i + 1))
            .expect("output requested");
        let stripe_bytes = decode_stripe_bytes::<I>(n);
        let work_bytes = stripe_bytes.min(len);
        let mut output = vec![vec![0; len]; inverses.len()];
        let mut columns = stripe_columns(&mut output, stripe_bytes);
        strategy.map_collect_vec_with_multiplier(
            columns.chunks_mut(inverses.len()).enumerate(),
            n * work_bytes,
            |(stripe, column)| {
                let mut work = workspace(&DECODE_WORK, n, work_bytes);
                let width = column[0].len();
                let start = stripe * stripe_bytes;
                let end = start + width;
                work.resize(width);
                work.data_mut().fill(0);
                for &(i, shard, coefficient) in &inputs {
                    imp.mul_into(
                        &mut work.data_mut()[i * width..(i + 1) * width],
                        &shard[start..end],
                        coefficient,
                    );
                }
                self.transform.ifft(&mut work, nonzero, 0);
                derivative(imp, work.data_mut(), width);
                self.transform.fft(&mut work, needed);
                for (output_index, (dst, &inverse)) in column.iter_mut().zip(&inverses).enumerate()
                {
                    let i = if output_index < missing.len() {
                        m + missing[output_index]
                    } else {
                        missing_recovery[output_index - missing.len()]
                    };
                    imp.mul_into(dst, &work.data()[i * width..(i + 1) * width], inverse);
                }
            },
        );

        let recovery_output = output.split_off(missing.len());
        Ok((
            missing.into_iter().zip(output).collect(),
            missing_recovery.into_iter().zip(recovery_output).collect(),
        ))
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
    // Amortize the larger leaf's setup over at least eight native vectors.
    if a.len() == 8 * len && len >= 512 {
        let (a0, a1) = a.split_at_mut(4 * len);
        let (b0, b1) = b.split_at_mut(4 * len);
        let (a00, a01) = a0.split_at_mut(2 * len);
        let (a10, a11) = a1.split_at_mut(2 * len);
        let (b00, b01) = b0.split_at_mut(2 * len);
        let (b10, b11) = b1.split_at_mut(2 * len);
        let (q0, q1) = a00.split_at_mut(len);
        let (q2, q3) = a01.split_at_mut(len);
        let (q4, q5) = a10.split_at_mut(len);
        let (q6, q7) = a11.split_at_mut(len);
        let (q8, q9) = b00.split_at_mut(len);
        let (q10, q11) = b01.split_at_mut(len);
        let (q12, q13) = b10.split_at_mut(len);
        let (q14, q15) = b11.split_at_mut(len);
        imp.derivative_sixteen([
            q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15,
        ]);
        return;
    }
    if a.len() == len {
        a.copy_from_slice(b);
        b.fill(0);
        return;
    }
    if a.len() == 2 * len {
        let (q0, q1) = a.split_at_mut(len);
        let (q2, q3) = b.split_at_mut(len);
        imp.derivative_four([q0, q1, q2, q3]);
        return;
    }
    derivative(imp, a, len);
    imp.add_into(a, b);
    derivative(imp, b, len);
}

#[cfg(any(test, feature = "fuzz"))]
pub mod test_suites {
    //! Property tests for implementations of Ocelot's shard arithmetic.
    //!
    //! Check each trait operation against scalar arithmetic on the portable kernel,
    //! then compare dispatched implementations with that reference. Encoding and
    //! decoding properties only need the portable implementations.

    use super::{Decoder, Encoder, Error, Impl, Tables};
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::algebra::{Additive, Field, Ring};
    use commonware_parallel::Sequential;
    use std::{ops::Range, sync::Arc};

    /// One independently fuzzed part of Ocelot's shard arithmetic contract.
    #[derive(Arbitrary, Clone, Copy, Debug)]
    pub enum ImplPlan {
        /// Add shards element by element.
        Add,
        /// Subtract shards element by element.
        Sub,
        /// Add a scalar multiple of a shard.
        MulAdd,
        /// Multiply a shard by a scalar.
        MulInto,
        /// Subtract a scalar multiple of a shard.
        MulSub,
        /// Compute the derivative of four shards.
        DerivativeFour,
        /// Compute the derivative of sixteen shards.
        DerivativeSixteen,
        /// Check a single butterfly layer.
        Butterfly,
        /// Check two fused butterfly layers.
        ButterflyTwoLayers,
        /// Check shard checksums.
        Checksum,
    }

    impl ImplPlan {
        #[cfg(test)]
        pub const ALL: [Self; 10] = [
            Self::Add,
            Self::Sub,
            Self::MulAdd,
            Self::MulInto,
            Self::MulSub,
            Self::DerivativeFour,
            Self::DerivativeSixteen,
            Self::Butterfly,
            Self::ButterflyTwoLayers,
            Self::Checksum,
        ];

        #[cfg(test)]
        pub const DEFAULTS: [Self; 5] = [
            Self::MulInto,
            Self::DerivativeFour,
            Self::DerivativeSixteen,
            Self::Butterfly,
            Self::ButterflyTwoLayers,
        ];
    }

    /// An adapter that deliberately inherits the arithmetic default [`Impl`] methods.
    #[derive(Clone, Copy)]
    pub struct DefaultImpl<I>(pub I);

    impl<I: Impl> Impl for DefaultImpl<I> {
        type Element = I::Element;

        const BITS: usize = I::BITS;
        const STRIPE_ALIGN: usize = I::STRIPE_ALIGN;
        const NAMESPACE: &'static [u8] = I::NAMESPACE;

        fn tables() -> Arc<Tables<Self::Element>> {
            I::tables()
        }

        fn basis() -> &'static [Self::Element] {
            I::basis()
        }

        fn add_into(self, dst: &mut [u8], src: &[u8]) {
            self.0.add_into(dst, src);
        }

        fn sub_into(self, dst: &mut [u8], src: &[u8]) {
            self.0.sub_into(dst, src);
        }

        fn mul_add(self, dst: &mut [u8], src: &[u8], c: Self::Element) {
            self.0.mul_add(dst, src, c);
        }

        fn mul_sub(self, dst: &mut [u8], src: &[u8], c: Self::Element) {
            self.0.mul_sub(dst, src, c);
        }

        fn checksum_range(
            self,
            shard: &[u8],
            coefficients: &[u8],
            range: Range<usize>,
            out: &mut [u8],
        ) {
            self.0.checksum_range(shard, coefficients, range, out);
        }
    }

    fn fuzz_len<I: Impl>(
        u: &mut Unstructured<'_>,
        vector_bytes: usize,
    ) -> arbitrary::Result<usize> {
        assert!(vector_bytes.is_multiple_of(I::ALIGN));
        let vector = vector_bytes / I::ALIGN;
        let stripe = I::STRIPE_ALIGN / I::ALIGN;
        let candidates = [
            0,
            1,
            vector.saturating_sub(1),
            vector,
            vector + 1,
            2 * vector + 1,
            stripe.saturating_sub(1),
            stripe,
            stripe + 1,
            2 * stripe + 1,
        ];
        let index = u.int_in_range(0..=candidates.len())?;
        let symbols = if index == candidates.len() {
            u.int_in_range(0..=2 * vector.max(stripe) + 1)?
        } else {
            candidates[index]
        };
        Ok(symbols * I::ALIGN)
    }

    fn fuzz_element<I: Impl>(
        u: &mut Unstructured<'_>,
        elements: impl Fn(&[u8]) -> Vec<I::Element>,
    ) -> arbitrary::Result<I::Element> {
        let class = u.int_in_range(0..=2)?;
        let mut bytes = vec![0; I::ALIGN];
        if class != 0 {
            u.fill_buffer(&mut bytes)?;
            if class == 1 {
                bytes[1..].fill(0);
            }
        }
        Ok(elements(&bytes)[0])
    }

    fn fuzz_backing(
        u: &mut Unstructured<'_>,
        len: usize,
    ) -> arbitrary::Result<(Vec<u8>, Range<usize>)> {
        let offset = u.int_in_range(0..=7)?;
        let mut bytes = vec![0; offset + len + 7];
        u.fill_buffer(&mut bytes)?;
        Ok((bytes, offset..offset + len))
    }

    fn checksum_reference<I: Impl>(
        shard: &[u8],
        coefficients: &[u8],
        range: Range<usize>,
        output_symbols: usize,
        elements: impl Fn(&[u8]) -> Vec<I::Element>,
        layout: impl Fn(&[I::Element]) -> Vec<u8>,
        coefficient: impl Fn(u8) -> I::Element,
    ) -> Vec<u8> {
        let input_symbols = shard.len() / I::ALIGN;
        let values = elements(shard);
        let range = range.start / I::ALIGN..range.end / I::ALIGN;
        let output = (0..output_symbols)
            .map(|output| {
                let row = &coefficients[output * input_symbols..][..input_symbols];
                range.clone().fold(I::Element::zero(), |sum, i| {
                    sum + &(values[i] * &coefficient(row[i]))
                })
            })
            .collect::<Vec<_>>();
        layout(&output)
    }

    fn fuzz_arithmetic<I: Impl>(
        u: &mut Unstructured<'_>,
        imp: I,
        plan: ImplPlan,
        vector_bytes: usize,
        elements: impl Copy + Fn(&[u8]) -> Vec<I::Element>,
        layout: impl Copy + Fn(&[I::Element]) -> Vec<u8>,
    ) -> arbitrary::Result<()> {
        let len = fuzz_len::<I>(u, vector_bytes)?;
        let (dst, dst_range) = fuzz_backing(u, len)?;
        let (src, src_range) = fuzz_backing(u, len)?;
        let dst_elements = elements(&dst[dst_range.clone()]);
        let src_elements = elements(&src[src_range.clone()]);
        let c = fuzz_element::<I>(u, elements)?;

        let check = |actual: Vec<u8>, expected_elements: Vec<I::Element>, operation: &str| {
            let mut expected = dst.clone();
            expected[dst_range.clone()].copy_from_slice(&layout(&expected_elements));
            assert_eq!(actual, expected, "{operation}");
        };

        let products = src_elements.iter().map(|&src| src * &c).collect::<Vec<_>>();
        match plan {
            ImplPlan::Add => {
                let mut actual = dst.clone();
                imp.add_into(&mut actual[dst_range.clone()], &src[src_range]);
                check(
                    actual,
                    dst_elements
                        .iter()
                        .zip(&src_elements)
                        .map(|(&dst, src)| dst + src)
                        .collect(),
                    "add_into",
                );
            }
            ImplPlan::Sub => {
                let mut actual = dst.clone();
                imp.sub_into(&mut actual[dst_range.clone()], &src[src_range]);
                check(
                    actual,
                    dst_elements
                        .iter()
                        .zip(&src_elements)
                        .map(|(&dst, src)| dst - src)
                        .collect(),
                    "sub_into",
                );
            }
            ImplPlan::MulAdd => {
                let mut actual = dst.clone();
                imp.mul_add(&mut actual[dst_range.clone()], &src[src_range], c);
                check(
                    actual,
                    dst_elements
                        .iter()
                        .zip(&products)
                        .map(|(&dst, product)| dst + product)
                        .collect(),
                    "mul_add",
                );
            }
            ImplPlan::MulInto => {
                let mut actual = dst.clone();
                imp.mul_into(&mut actual[dst_range.clone()], &src[src_range], c);
                check(actual, products, "mul_into");
            }
            ImplPlan::MulSub => {
                let mut actual = dst.clone();
                imp.mul_sub(&mut actual[dst_range.clone()], &src[src_range], c);
                check(
                    actual,
                    dst_elements
                        .iter()
                        .zip(&products)
                        .map(|(&dst, product)| dst - product)
                        .collect(),
                    "mul_sub",
                );
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn fuzz_derivatives<I: Impl>(
        u: &mut Unstructured<'_>,
        imp: I,
        plan: ImplPlan,
        vector_bytes: usize,
    ) -> arbitrary::Result<()> {
        let len = fuzz_len::<I>(u, vector_bytes)?;
        let blocks = match plan {
            ImplPlan::DerivativeFour => 4,
            ImplPlan::DerivativeSixteen => 16,
            _ => unreachable!(),
        };
        let mut actual = (0..blocks).map(|_| vec![0; len]).collect::<Vec<_>>();
        for block in &mut actual {
            u.fill_buffer(block)?;
        }
        let original = actual.clone();
        if matches!(plan, ImplPlan::DerivativeFour) {
            let [a, b, c, d] = actual.as_mut_slice() else {
                unreachable!()
            };
            imp.derivative_four([
                a.as_mut_slice(),
                b.as_mut_slice(),
                c.as_mut_slice(),
                d.as_mut_slice(),
            ]);
            for i in 0..len {
                assert_eq!(actual[0][i], original[1][i] ^ original[2][i]);
                assert_eq!(actual[1][i], original[3][i]);
                assert_eq!(actual[2][i], original[3][i]);
                assert_eq!(actual[3][i], 0);
            }
        } else {
            let blocks: &mut [Vec<u8>; 16] = actual.as_mut_slice().try_into().unwrap();
            imp.derivative_sixteen(blocks.each_mut().map(Vec::as_mut_slice));
            for output in 0..16 {
                for i in 0..len {
                    let expected = (0..4)
                        .filter(|bit| output & (1 << bit) == 0)
                        .fold(0, |sum, bit| sum ^ original[output | (1 << bit)][i]);
                    assert_eq!(actual[output][i], expected);
                }
            }
        }
        Ok(())
    }

    fn fuzz_butterflies<I: Impl>(
        u: &mut Unstructured<'_>,
        imp: I,
        plan: ImplPlan,
        vector_bytes: usize,
        elements: impl Copy + Fn(&[u8]) -> Vec<I::Element>,
        layout: impl Copy + Fn(&[I::Element]) -> Vec<u8>,
    ) -> arbitrary::Result<()> {
        if matches!(plan, ImplPlan::Butterfly) {
            let len = fuzz_len::<I>(u, vector_bytes)?;
            let (mut x, x_range) = fuzz_backing(u, len)?;
            let (mut y, y_range) = fuzz_backing(u, len)?;
            let original_x = x.clone();
            let original_y = y.clone();
            let mut expected_x = elements(&x[x_range.clone()]);
            let mut expected_y = elements(&y[y_range.clone()]);
            let c = fuzz_element::<I>(u, elements)?;
            for (x, y) in expected_x.iter_mut().zip(&mut expected_y) {
                *x += &(*y * &c);
                *y += x;
            }
            imp.fft_butterfly(&mut x[x_range.clone()], &mut y[y_range.clone()], c);
            assert_eq!(&x[x_range.clone()], layout(&expected_x).as_slice());
            assert_eq!(&y[y_range.clone()], layout(&expected_y).as_slice());
            imp.ifft_butterfly(&mut x[x_range], &mut y[y_range], c);
            assert_eq!(x, original_x);
            assert_eq!(y, original_y);
            return Ok(());
        }
        assert!(matches!(plan, ImplPlan::ButterflyTwoLayers));
        let shard_len = fuzz_len::<I>(u, vector_bytes)?.max(I::ALIGN);
        let shard_count = u.int_in_range(1..=3)?;
        let len = shard_len * shard_count;
        let mut quarters: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; len]);
        for quarter in &mut quarters {
            u.fill_buffer(quarter)?;
        }
        let original = quarters.clone();
        let mut coefficients = [I::Element::zero(); 3];
        for coefficient in &mut coefficients {
            *coefficient = fuzz_element::<I>(u, elements)?;
        }
        for shard in 0..shard_count {
            let range = shard * shard_len..(shard + 1) * shard_len;
            let mut values: [Vec<I::Element>; 4] =
                std::array::from_fn(|quarter| elements(&quarters[quarter][range.clone()]));
            for i in 0..values[0].len() {
                let mut lanes = [values[0][i], values[1][i], values[2][i], values[3][i]];
                let apply = |lanes: &mut [I::Element; 4], x: usize, y: usize, c: I::Element| {
                    let mut a = lanes[x];
                    let mut b = lanes[y];
                    a += &(b * &c);
                    b += &a;
                    lanes[x] = a;
                    lanes[y] = b;
                };
                apply(&mut lanes, 0, 2, coefficients[2]);
                apply(&mut lanes, 1, 3, coefficients[2]);
                apply(&mut lanes, 0, 1, coefficients[0]);
                apply(&mut lanes, 2, 3, coefficients[1]);
                for (values, value) in values.iter_mut().zip(lanes) {
                    values[i] = value;
                }
            }
            for (quarter, values) in quarters.iter_mut().zip(values) {
                quarter[range.clone()].copy_from_slice(&layout(&values));
            }
        }
        let expected = quarters.clone();
        quarters = original.clone();
        imp.fft_butterfly_two_layers(
            quarters.each_mut().map(Vec::as_mut_slice),
            shard_len,
            coefficients,
        );
        assert_eq!(quarters, expected);
        imp.ifft_butterfly_two_layers(
            quarters.each_mut().map(Vec::as_mut_slice),
            shard_len,
            coefficients,
        );
        assert_eq!(quarters, original);
        Ok(())
    }

    fn fuzz_checksum<I: Impl>(
        u: &mut Unstructured<'_>,
        imp: I,
        vector_bytes: usize,
        elements: impl Copy + Fn(&[u8]) -> Vec<I::Element>,
        layout: impl Copy + Fn(&[I::Element]) -> Vec<u8>,
        coefficient: impl Copy + Fn(u8) -> I::Element,
    ) -> arbitrary::Result<()> {
        let len = fuzz_len::<I>(u, vector_bytes)?.max(I::ALIGN);
        let mut shard = vec![0; len];
        u.fill_buffer(&mut shard)?;
        let input_symbols = len / I::ALIGN;
        let vector_symbols = vector_bytes / I::ALIGN;
        let stripe_symbols = I::STRIPE_ALIGN / I::ALIGN;
        let output_candidates = [1, 3, vector_symbols + 1, stripe_symbols + 3];
        let output_symbols = output_candidates[u.int_in_range(0..=3)?];
        let mut coefficients = vec![0; input_symbols * output_symbols];
        u.fill_buffer(&mut coefficients)?;
        let start = u.int_in_range(0..=input_symbols - 1)?;
        let end = u.int_in_range(start + 1..=input_symbols)?;
        let range = start * I::ALIGN..end * I::ALIGN;
        let mut actual = vec![0; output_symbols * I::ALIGN];
        imp.checksum_range(&shard, &coefficients, range.clone(), &mut actual);
        assert_eq!(
            actual,
            checksum_reference::<I>(
                &shard,
                &coefficients,
                range.clone(),
                output_symbols,
                elements,
                layout,
                coefficient,
            )
        );

        let mut empty = vec![0xff; actual.len()];
        imp.checksum_range(&shard, &coefficients, range.start..range.start, &mut empty);
        assert_eq!(empty, vec![0; actual.len()]);

        let mut full = vec![0; actual.len()];
        imp.checksum_range(&shard, &coefficients, 0..len, &mut full);
        let mut partitioned = vec![0; actual.len()];
        for part in [0..range.start, range.clone(), range.end..len] {
            let mut contribution = vec![0; actual.len()];
            imp.checksum_range(&shard, &coefficients, part, &mut contribution);
            imp.add_into(&mut partitioned, &contribution);
        }
        assert_eq!(partitioned, full);

        let mut original = vec![vec![0; len]; 3];
        for shard in &mut original {
            u.fill_buffer(shard)?;
        }
        let original_refs = original.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let recovery = Encoder::new(imp).encode(&original_refs, 2, &Sequential);
        let checksums = original
            .iter()
            .map(|shard| {
                let mut out = vec![0; output_symbols * I::ALIGN];
                imp.checksum_range(shard, &coefficients, 0..len, &mut out);
                out
            })
            .collect::<Vec<_>>();
        let checksum_refs = checksums.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let encoded_checksums = Encoder::new(imp).encode(&checksum_refs, 2, &Sequential);
        for (shard, expected) in recovery.iter().zip(encoded_checksums) {
            let mut actual = vec![0; output_symbols * I::ALIGN];
            imp.checksum_range(shard, &coefficients, 0..len, &mut actual);
            assert_eq!(actual, expected);
        }
        Ok(())
    }

    /// Check the shard-arithmetic contract against scalar field operations.
    pub fn fuzz_impl<I: Impl>(
        u: &mut Unstructured<'_>,
        imp: I,
        plan: ImplPlan,
        vector_bytes: usize,
        elements: impl Copy + Fn(&[u8]) -> Vec<I::Element>,
        layout: impl Copy + Fn(&[I::Element]) -> Vec<u8>,
        coefficient: impl Copy + Fn(u8) -> I::Element,
    ) -> arbitrary::Result<()> {
        match plan {
            ImplPlan::Add
            | ImplPlan::Sub
            | ImplPlan::MulAdd
            | ImplPlan::MulInto
            | ImplPlan::MulSub => fuzz_arithmetic(u, imp, plan, vector_bytes, elements, layout),
            ImplPlan::DerivativeFour | ImplPlan::DerivativeSixteen => {
                fuzz_derivatives(u, imp, plan, vector_bytes)
            }
            ImplPlan::Butterfly | ImplPlan::ButterflyTwoLayers => {
                fuzz_butterflies(u, imp, plan, vector_bytes, elements, layout)
            }
            ImplPlan::Checksum => {
                fuzz_checksum(u, imp, vector_bytes, elements, layout, coefficient)
            }
        }
    }

    /// Check an implementation's specialized methods against a reference implementation.
    pub fn fuzz_impl_matches_reference<I, R>(
        u: &mut Unstructured<'_>,
        imp: I,
        reference: R,
        plan: ImplPlan,
        vector_bytes: usize,
        elements: impl Copy + Fn(&[u8]) -> Vec<I::Element>,
    ) -> arbitrary::Result<()>
    where
        I: Impl,
        R: Impl<Element = I::Element>,
    {
        assert_eq!(I::ALIGN, R::ALIGN);
        assert_eq!(I::STRIPE_ALIGN, R::STRIPE_ALIGN);
        match plan {
            ImplPlan::Add
            | ImplPlan::Sub
            | ImplPlan::MulAdd
            | ImplPlan::MulInto
            | ImplPlan::MulSub => {
                let len = fuzz_len::<I>(u, vector_bytes)?;
                let (dst, dst_range) = fuzz_backing(u, len)?;
                let (src, src_range) = fuzz_backing(u, len)?;
                let c = fuzz_element::<I>(u, elements)?;
                let compare_mul =
                    |operation: fn(I, &mut [u8], &[u8], I::Element),
                     reference_operation: fn(R, &mut [u8], &[u8], I::Element)| {
                        let mut actual = dst.clone();
                        let mut expected = dst.clone();
                        operation(
                            imp,
                            &mut actual[dst_range.clone()],
                            &src[src_range.clone()],
                            c,
                        );
                        reference_operation(
                            reference,
                            &mut expected[dst_range.clone()],
                            &src[src_range.clone()],
                            c,
                        );
                        assert_eq!(actual, expected);
                    };
                match plan {
                    ImplPlan::Add | ImplPlan::Sub => {
                        let mut actual = dst.clone();
                        let mut expected = dst.clone();
                        if matches!(plan, ImplPlan::Add) {
                            imp.add_into(&mut actual[dst_range.clone()], &src[src_range.clone()]);
                            reference.add_into(&mut expected[dst_range.clone()], &src[src_range]);
                        } else {
                            imp.sub_into(&mut actual[dst_range.clone()], &src[src_range.clone()]);
                            reference.sub_into(&mut expected[dst_range], &src[src_range]);
                        }
                        assert_eq!(actual, expected);
                    }
                    ImplPlan::MulAdd => compare_mul(I::mul_add, R::mul_add),
                    ImplPlan::MulInto => compare_mul(I::mul_into, R::mul_into),
                    ImplPlan::MulSub => compare_mul(I::mul_sub, R::mul_sub),
                    _ => unreachable!(),
                }
            }
            ImplPlan::DerivativeFour | ImplPlan::DerivativeSixteen => {
                let len = fuzz_len::<I>(u, vector_bytes)?;
                let mut actual: [Vec<u8>; 16] = std::array::from_fn(|_| vec![0; len]);
                for block in &mut actual {
                    u.fill_buffer(block)?;
                }
                let mut expected = actual.clone();
                if matches!(plan, ImplPlan::DerivativeFour) {
                    let [a, b, c, d, ..] = &mut actual;
                    imp.derivative_four([
                        a.as_mut_slice(),
                        b.as_mut_slice(),
                        c.as_mut_slice(),
                        d.as_mut_slice(),
                    ]);
                    let [a, b, c, d, ..] = &mut expected;
                    reference.derivative_four([
                        a.as_mut_slice(),
                        b.as_mut_slice(),
                        c.as_mut_slice(),
                        d.as_mut_slice(),
                    ]);
                } else {
                    imp.derivative_sixteen(actual.each_mut().map(Vec::as_mut_slice));
                    reference.derivative_sixteen(expected.each_mut().map(Vec::as_mut_slice));
                }
                assert_eq!(actual, expected);
            }
            ImplPlan::Butterfly => {
                let len = fuzz_len::<I>(u, vector_bytes)?;
                let (mut actual_x, x_range) = fuzz_backing(u, len)?;
                let (mut actual_y, y_range) = fuzz_backing(u, len)?;
                let mut expected_x = actual_x.clone();
                let mut expected_y = actual_y.clone();
                let c = fuzz_element::<I>(u, elements)?;
                imp.fft_butterfly(
                    &mut actual_x[x_range.clone()],
                    &mut actual_y[y_range.clone()],
                    c,
                );
                reference.fft_butterfly(
                    &mut expected_x[x_range.clone()],
                    &mut expected_y[y_range.clone()],
                    c,
                );
                assert_eq!(actual_x, expected_x);
                assert_eq!(actual_y, expected_y);
                imp.ifft_butterfly(
                    &mut actual_x[x_range.clone()],
                    &mut actual_y[y_range.clone()],
                    c,
                );
                reference.ifft_butterfly(&mut expected_x[x_range], &mut expected_y[y_range], c);
                assert_eq!(actual_x, expected_x);
                assert_eq!(actual_y, expected_y);
            }
            ImplPlan::ButterflyTwoLayers => {
                let shard_len = fuzz_len::<I>(u, vector_bytes)?.max(I::ALIGN);
                let len = shard_len * u.int_in_range(1..=3)?;
                let mut actual: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; len]);
                for quarter in &mut actual {
                    u.fill_buffer(quarter)?;
                }
                let mut expected = actual.clone();
                let mut coefficients = [I::Element::zero(); 3];
                for coefficient in &mut coefficients {
                    *coefficient = fuzz_element::<I>(u, elements)?;
                }
                imp.fft_butterfly_two_layers(
                    actual.each_mut().map(Vec::as_mut_slice),
                    shard_len,
                    coefficients,
                );
                reference.fft_butterfly_two_layers(
                    expected.each_mut().map(Vec::as_mut_slice),
                    shard_len,
                    coefficients,
                );
                assert_eq!(actual, expected);
                imp.ifft_butterfly_two_layers(
                    actual.each_mut().map(Vec::as_mut_slice),
                    shard_len,
                    coefficients,
                );
                reference.ifft_butterfly_two_layers(
                    expected.each_mut().map(Vec::as_mut_slice),
                    shard_len,
                    coefficients,
                );
                assert_eq!(actual, expected);
            }
            ImplPlan::Checksum => {
                let len = fuzz_len::<I>(u, vector_bytes)?.max(I::ALIGN);
                let mut shard = vec![0; len];
                u.fill_buffer(&mut shard)?;
                let input_symbols = len / I::ALIGN;
                let output_symbols = u.int_in_range(1..=vector_bytes / I::ALIGN + 3)?;
                let mut coefficients = vec![0; input_symbols * output_symbols];
                u.fill_buffer(&mut coefficients)?;
                let start = u.int_in_range(0..=input_symbols - 1)?;
                let end = u.int_in_range(start + 1..=input_symbols)?;
                let range = start * I::ALIGN..end * I::ALIGN;
                let mut actual = vec![0; output_symbols * I::ALIGN];
                let mut expected = vec![0; actual.len()];
                imp.checksum_range(&shard, &coefficients, range.clone(), &mut actual);
                reference.checksum_range(&shard, &coefficients, range, &mut expected);
                assert_eq!(actual, expected);
            }
        }
        Ok(())
    }

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
        let expected = || {
            if k == 0 || k + m > I::ORDER {
                Error::InvalidShardCount
            } else {
                Error::InsufficientShards {
                    present: 0,
                    required: k,
                }
            }
        };
        assert_eq!(
            decoder.decode(&vec![None; k], &vec![None; r], &Sequential),
            Err(expected())
        );
        assert_eq!(
            decoder.decode_with_recovery(&vec![None; k], &vec![None; r], &Sequential),
            Err(expected())
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
        assert_eq!(
            encoder.encode(&[&[], &[]], 3, &Sequential),
            vec![Vec::<u8>::new(); 3]
        );
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
        let recovery = encoder.encode(&refs, r, &Sequential);
        assert_eq!(recovery.len(), r);
        assert!(recovery.iter().all(|s| s.len() == len));
        assert_eq!(encoder.encode(&refs, r, &Sequential), recovery);
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
                decoder.decode(&input[..k], &input[k..], &Sequential),
                Err(Error::InvalidShardLength)
            );
            assert_eq!(
                decoder.decode_with_recovery(&input[..k], &input[k..], &Sequential),
                Err(Error::InvalidShardLength)
            );
        }

        // Recovery from parity alone must work when enough parity is present.
        if r >= k {
            let recovered = decoder
                .decode(&vec![None; k], &input[k..], &Sequential)
                .unwrap();
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
            let result = decoder.decode(&input[..k], &input[k..], &Sequential);
            if count > r {
                assert_eq!(
                    result,
                    Err(Error::InsufficientShards {
                        present: k + r - count,
                        required: k,
                    })
                );
                assert_eq!(
                    decoder.decode_with_recovery(&input[..k], &input[k..], &Sequential),
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

            let (recovered_original, recovered_recovery) = decoder
                .decode_with_recovery(&input[..k], &input[k..], &Sequential)
                .unwrap();
            assert_eq!(recovered_original, recovered);

            let mut recovery_needed = recovered_original.len();
            let unselected: Vec<_> = input[k..]
                .iter()
                .enumerate()
                .filter_map(|(i, shard)| {
                    if recovery_needed > 0 && shard.is_some() {
                        recovery_needed -= 1;
                        None
                    } else {
                        Some(i)
                    }
                })
                .collect();
            assert_eq!(recovery_needed, 0);
            assert_eq!(recovered_recovery.len(), unselected.len());
            for ((i, shard), expected) in recovered_recovery.iter().zip(unselected) {
                assert_eq!(*i, expected);
                assert_eq!(shard, &recovery[*i]);
            }
        }
        Ok(())
    }
}

/// Fuzz plans for internal coding operations.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::{Impl, derivative};
    use crate::ocelot::{Impl8, kernel::portable::Portable};
    use arbitrary::{Arbitrary, Unstructured};

    /// A bounded shape for exercising the recursive derivative.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum DerivativeShape {
        /// One one-byte shard.
        OneByOne,
        /// Two three-byte shards.
        TwoByThree,
        /// Four 65-byte shards.
        FourBy65,
        /// Eight 129-byte shards.
        EightBy129,
        /// Sixteen 511-byte shards.
        SixteenBy511,
        /// Sixteen 512-byte shards.
        SixteenBy512,
        /// Sixteen 513-byte shards.
        SixteenBy513,
        /// Thirty-two 513-byte shards.
        ThirtyTwoBy513,
    }

    impl DerivativeShape {
        const fn dimensions(&self) -> (usize, usize) {
            match self {
                Self::OneByOne => (1, 1),
                Self::TwoByThree => (2, 3),
                Self::FourBy65 => (4, 65),
                Self::EightBy129 => (8, 129),
                Self::SixteenBy511 => (16, 511),
                Self::SixteenBy512 => (16, 512),
                Self::SixteenBy513 => (16, 513),
                Self::ThirtyTwoBy513 => (32, 513),
            }
        }
    }

    /// A bounded property check for coding internals.
    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        /// Compare the optimized derivative with its recursive definition.
        Derivative(DerivativeShape),
    }

    impl Plan {
        /// Run this fuzz plan using additional structured input from `u`.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Derivative(shape) => {
                    let imp = Impl8::new(Portable);
                    let (count, len) = shape.dimensions();
                    let mut actual = vec![0; count * len];
                    u.fill_buffer(&mut actual)?;
                    let mut expected = actual.clone();
                    derivative(imp, &mut actual, len);
                    derivative_reference(imp, &mut expected, len);
                    assert_eq!(actual, expected);
                    Ok(())
                }
            }
        }
    }

    fn derivative_reference<I: Impl>(imp: I, data: &mut [u8], len: usize) {
        if data.len() == len {
            data.fill(0);
            return;
        }
        let (a, b) = data.split_at_mut(data.len() / 2);
        if a.len() == len {
            a.copy_from_slice(b);
            b.fill(0);
            return;
        }
        derivative_reference(imp, a, len);
        imp.add_into(a, b);
        derivative_reference(imp, b, len);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Decoder, Encoder, Impl, STRIPE_BYTES, decode_stripe_bytes,
        fuzz::{DerivativeShape, Plan},
        stripe_bytes,
    };
    use crate::ocelot::{Impl8, field::gf8::GF8, impl16::Impl16, kernel::portable::Portable};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use rand::Rng as _;
    use std::{
        ops::Range,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn minifuzz_derivative() {
        // Exercise both fused leaves, the 512-byte cutoff, and recursion explicitly.
        for shape in [
            DerivativeShape::OneByOne,
            DerivativeShape::TwoByThree,
            DerivativeShape::FourBy65,
            DerivativeShape::EightBy129,
            DerivativeShape::SixteenBy511,
            DerivativeShape::SixteenBy512,
            DerivativeShape::SixteenBy513,
            DerivativeShape::ThirtyTwoBy513,
        ] {
            commonware_invariants::minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(100)
                .test(|u| Plan::Derivative(shape).run(u));
        }
    }

    #[test]
    fn recovers_across_stripe_boundary() {
        const OCELOT8: Impl8<Portable> = Impl8::new(Portable);
        let mut rng = test_rng();
        let mut original = vec![vec![0; 2 * STRIPE_BYTES + 1]; 3];
        for shard in &mut original {
            rng.fill_bytes(shard);
        }
        let original_refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
        let recovery = Encoder::new(OCELOT8).encode(&original_refs, 2, &Sequential);
        let encoded_original = [None, Some(original[1].as_slice()), None];
        let encoded_recovery: Vec<_> = recovery
            .iter()
            .map(|shard| Some(shard.as_slice()))
            .collect();

        let recovered = Decoder::new(OCELOT8)
            .decode(&encoded_original, &encoded_recovery, &Sequential)
            .unwrap();

        assert_eq!(
            recovered,
            vec![(0, original[0].clone()), (2, original[2].clone())]
        );
    }

    #[test]
    fn decode_capped_stripes_with_short_tail() {
        const OCELOT16: Impl16<Portable> = Impl16::new(Portable);
        let original_count = 17usize;
        let recovery_count = 17usize;
        let m = recovery_count.next_power_of_two();
        let n = (m + original_count).next_power_of_two();
        let capped_stripe = decode_stripe_bytes::<Impl16<Portable>>(n);
        assert!(capped_stripe < stripe_bytes::<Impl16<Portable>>());

        let len = capped_stripe + Impl16::<Portable>::ALIGN;
        let mut original = vec![vec![0; len]; original_count];
        for (shard, data) in original.iter_mut().enumerate() {
            for (offset, byte) in data.iter_mut().enumerate() {
                *byte = (shard.wrapping_mul(157) ^ offset.wrapping_mul(41)) as u8;
            }
        }
        let original_refs: Vec<_> = original.iter().map(Vec::as_slice).collect();
        let recovery = Encoder::new(OCELOT16).encode(&original_refs, recovery_count, &Sequential);
        let mut encoded_original: Vec<_> = original
            .iter()
            .map(|shard| Some(shard.as_slice()))
            .collect();
        encoded_original[8] = None;
        let encoded_recovery: Vec<_> = recovery
            .iter()
            .map(|shard| Some(shard.as_slice()))
            .collect();

        assert_eq!(
            Decoder::new(OCELOT16)
                .decode(&encoded_original, &encoded_recovery, &Sequential)
                .unwrap(),
            vec![(8, original[8].clone())]
        );
    }

    #[test]
    fn decode_ignores_surplus_recovery_shards() {
        const OCELOT8: Impl8<Portable> = Impl8::new(Portable);
        static MUL_ADDS: AtomicUsize = AtomicUsize::new(0);

        #[derive(Clone, Copy)]
        struct CountingImpl;

        impl Impl for CountingImpl {
            type Element = GF8;
            const BITS: usize = <Impl8<Portable> as Impl>::BITS;
            const NAMESPACE: &'static [u8] = <Impl8<Portable> as Impl>::NAMESPACE;

            fn basis() -> &'static [Self::Element] {
                <Impl8<Portable> as Impl>::basis()
            }

            fn add_into(self, dst: &mut [u8], src: &[u8]) {
                OCELOT8.add_into(dst, src);
            }

            fn sub_into(self, dst: &mut [u8], src: &[u8]) {
                OCELOT8.sub_into(dst, src);
            }

            fn mul_add(self, dst: &mut [u8], src: &[u8], c: Self::Element) {
                MUL_ADDS.fetch_add(1, Ordering::Relaxed);
                OCELOT8.mul_add(dst, src, c);
            }

            fn mul_sub(self, dst: &mut [u8], src: &[u8], c: Self::Element) {
                OCELOT8.mul_sub(dst, src, c);
            }

            fn checksum_range(
                self,
                shard: &[u8],
                coefficients: &[u8],
                range: Range<usize>,
                out: &mut [u8],
            ) {
                OCELOT8.checksum_range(shard, coefficients, range, out);
            }

            fn fft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
                OCELOT8.fft_butterfly(x, y, c);
            }

            fn ifft_butterfly(self, x: &mut [u8], y: &mut [u8], c: Self::Element) {
                OCELOT8.ifft_butterfly(x, y, c);
            }
        }

        let original = [[1; 16], [2; 16], [3; 16]];
        let original_refs: Vec<_> = original.iter().map(<[u8; 16]>::as_slice).collect();
        let recovery = Encoder::new(OCELOT8).encode(&original_refs, 4, &Sequential);
        let original = [Some(original[0].as_slice()), None, None];
        let recovery: Vec<_> = recovery
            .iter()
            .map(|shard| Some(shard.as_slice()))
            .collect();

        MUL_ADDS.store(0, Ordering::Relaxed);
        let recovered = Decoder::new(CountingImpl)
            .decode(&original, &recovery, &Sequential)
            .unwrap();

        assert_eq!(recovered, vec![(1, vec![2; 16]), (2, vec![3; 16])]);
        // Three input shards and two recovered outputs are multiplied. The
        // other two supplied recovery shards must not be touched.
        assert_eq!(MUL_ADDS.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn decode_with_recovery_reconstructs_surplus_shards() {
        const OCELOT8: Impl8<Portable> = Impl8::new(Portable);
        let original = [[1; 16], [2; 16], [3; 16]];
        let original_refs: Vec<_> = original.iter().map(<[u8; 16]>::as_slice).collect();
        let recovery = Encoder::new(OCELOT8).encode(&original_refs, 4, &Sequential);
        let encoded_original = [Some(original[0].as_slice()), None, None];

        let mut corrupted = recovery.clone();
        corrupted[2][0] ^= 1;
        corrupted[3][0] ^= 1;
        let encoded_recovery: Vec<_> = corrupted
            .iter()
            .map(|shard| Some(shard.as_slice()))
            .collect();
        let (recovered_original, recovered_recovery) = Decoder::new(OCELOT8)
            .decode_with_recovery(&encoded_original, &encoded_recovery, &Sequential)
            .unwrap();

        assert_eq!(
            recovered_original,
            vec![(1, original[1].to_vec()), (2, original[2].to_vec())]
        );
        assert_eq!(
            recovered_recovery,
            vec![(2, recovery[2].clone()), (3, recovery[3].clone())]
        );

        corrupted[3].push(0);
        let malformed_recovery: Vec<_> = corrupted
            .iter()
            .map(|shard| Some(shard.as_slice()))
            .collect();
        assert_eq!(
            Decoder::new(OCELOT8).decode_with_recovery(
                &encoded_original,
                &malformed_recovery,
                &Sequential,
            ),
            Err(super::Error::InvalidShardLength)
        );
    }
}
