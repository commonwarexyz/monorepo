mod code;
mod field;
mod kernel;
mod scheme;
mod transform;

use crate::{Config, PhasedScheme};
use bytes::Buf;
use code::Impl;
use commonware_cryptography::{Hasher, transcript::Summary};
use commonware_parallel::Strategy;
use field::gf8::{GF8, GF8Vec};
use kernel::{Kernel, WithKernel, with_kernel};
pub use scheme::Error;
use scheme::{CheckedShard, CheckingData, OcelotX, StrongShard, WeakShard};
use std::{fmt, marker::PhantomData, ops::Range};

/// Reed-Solomon coding over GF(2^8), with commitments using `H`.
///
/// Arithmetic kernels are selected internally for the current CPU.
/// The encoder commits to all encoded shards before deriving 16 independent
/// checksum projections with Fiat-Shamir. A strong shard carries the unencoded
/// checksums; participants encode them locally and use the resulting checksum
/// codeword alongside Merkle proofs to check forwarded shards.
///
/// Encoding and decoding process large shards in independent byte stripes
/// using the supplied strategy. Checksums use tiles spanning shards and column
/// ranges, including when checking a single shard. Encoding also parallelizes
/// shard hashing through that strategy.
///
/// A successful shard check does not prove that the entire encoding is
/// available. Availability is established only when decoding succeeds from
/// enough checked shards, so this type does not implement `ValidatingScheme`.
pub struct Ocelot8<H> {
    _marker: PhantomData<H>,
}

impl<H> Clone for Ocelot8<H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H> Copy for Ocelot8<H> {}

impl<H> fmt::Debug for Ocelot8<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ocelot8").finish()
    }
}

impl<H: Hasher> PhasedScheme for Ocelot8<H> {
    type Commitment = Summary;
    type StrongShard = StrongShard<H::Digest>;
    type WeakShard = WeakShard<H::Digest>;
    type CheckingData = CheckingData<H::Digest>;
    type CheckedShard = CheckedShard;
    type Error = Error;

    fn encode(
        namespace: &[u8],
        config: &Config,
        data: impl Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::StrongShard>), Self::Error> {
        with_kernel(Encode::<H, _, _> {
            namespace,
            config,
            data,
            strategy,
            _marker: PhantomData,
        })
    }

    fn weaken(
        namespace: &[u8],
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::StrongShard,
        strategy: &impl Strategy,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::WeakShard), Self::Error> {
        with_kernel(Weaken::<H, _> {
            namespace,
            config,
            commitment,
            index,
            shard,
            strategy,
        })
    }

    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        checking_data: &Self::CheckingData,
        index: u16,
        weak_shard: Self::WeakShard,
        strategy: &impl Strategy,
    ) -> Result<Self::CheckedShard, Self::Error> {
        with_kernel(Check::<H, _> {
            config,
            commitment,
            checking_data,
            index,
            weak_shard,
            strategy,
        })
    }

    fn decode<'a>(
        config: &Config,
        commitment: &Self::Commitment,
        checking_data: Self::CheckingData,
        shards: impl Iterator<Item = &'a Self::CheckedShard>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        with_kernel(Decode::<H, _, _> {
            config,
            commitment,
            checking_data,
            shards,
            strategy,
        })
    }
}

struct Encode<'a, H, B, S> {
    namespace: &'a [u8],
    config: &'a Config,
    data: B,
    strategy: &'a S,
    _marker: PhantomData<H>,
}

impl<H: Hasher, B: Buf, S: Strategy> WithKernel for Encode<'_, H, B, S> {
    type Output = Result<(Summary, Vec<StrongShard<H::Digest>>), Error>;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        OcelotX::<_, H, 16>::new(Impl8::new(kernel)).encode(
            self.namespace,
            self.config,
            self.data,
            self.strategy,
        )
    }
}

struct Decode<'a, H: Hasher, T, S> {
    config: &'a Config,
    commitment: &'a Summary,
    checking_data: CheckingData<H::Digest>,
    shards: T,
    strategy: &'a S,
}

impl<'a, H: Hasher, T: Iterator<Item = &'a CheckedShard>, S: Strategy> WithKernel
    for Decode<'_, H, T, S>
{
    type Output = Result<Vec<u8>, Error>;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        OcelotX::<_, H, 16>::new(Impl8::new(kernel)).decode(
            self.config,
            self.commitment,
            self.checking_data,
            self.shards,
            self.strategy,
        )
    }
}

struct Weaken<'a, H: Hasher, S> {
    namespace: &'a [u8],
    config: &'a Config,
    commitment: &'a Summary,
    index: u16,
    shard: StrongShard<H::Digest>,
    strategy: &'a S,
}

impl<H: Hasher, S: Strategy> WithKernel for Weaken<'_, H, S> {
    type Output = Result<(CheckingData<H::Digest>, CheckedShard, WeakShard<H::Digest>), Error>;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        OcelotX::<_, H, 16>::new(Impl8::new(kernel)).weaken(
            self.namespace,
            self.config,
            self.commitment,
            self.index,
            self.shard,
            self.strategy,
        )
    }
}

struct Check<'a, H: Hasher, S> {
    config: &'a Config,
    commitment: &'a Summary,
    checking_data: &'a CheckingData<H::Digest>,
    index: u16,
    weak_shard: WeakShard<H::Digest>,
    strategy: &'a S,
}

impl<H: Hasher, S: Strategy> WithKernel for Check<'_, H, S> {
    type Output = Result<CheckedShard, Error>;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        OcelotX::<_, H, 16>::new(Impl8::new(kernel)).check(
            self.config,
            self.commitment,
            self.checking_data,
            self.index,
            self.weak_shard,
            self.strategy,
        )
    }
}

/// Ocelot's GF(2^8) arithmetic, using a concrete byte kernel.
#[derive(Clone, Copy)]
pub struct Impl8<K: Kernel> {
    kernel: K,
}

impl<K: Kernel> Impl8<K> {
    /// Use `kernel` for operations on whole shards.
    pub const fn new(kernel: K) -> Self {
        Self { kernel }
    }
}

impl<K: Kernel> Impl for Impl8<K> {
    type Element = GF8;
    const BITS: usize = 8;
    const NAMESPACE: &'static [u8] = b"_COMMONWARE_CODING_OCELOT8";

    fn basis() -> &'static [GF8] {
        &[
            GF8(1),
            GF8(188),
            GF8(92),
            GF8(12),
            GF8(174),
            GF8(90),
            GF8(14),
            GF8(132),
        ]
    }

    fn add_into(self, dst: &mut [u8], src: &[u8]) {
        self.kernel.run(AddInto { dst, src });
    }

    fn sub_into(self, dst: &mut [u8], src: &[u8]) {
        self.add_into(dst, src);
    }

    fn mul_add(self, dst: &mut [u8], src: &[u8], c: GF8) {
        self.kernel.run(MulAdd { dst, src, c });
    }

    fn mul_sub(self, dst: &mut [u8], src: &[u8], c: GF8) {
        self.mul_add(dst, src, c);
    }

    fn fft_butterfly(self, x: &mut [u8], y: &mut [u8], c: GF8) {
        if c == GF8(0) {
            self.add_into(y, x);
        } else if K::FUSED_BUTTERFLY {
            self.kernel.run(Butterfly::<false> { x, y, c });
        } else {
            self.mul_add(x, y, c);
            self.add_into(y, x);
        }
    }

    fn ifft_butterfly(self, x: &mut [u8], y: &mut [u8], c: GF8) {
        if c == GF8(0) {
            self.add_into(y, x);
        } else if K::FUSED_BUTTERFLY {
            self.kernel.run(Butterfly::<true> { x, y, c });
        } else {
            self.add_into(y, x);
            self.mul_add(x, y, c);
        }
    }

    fn checksum_range(
        self,
        shard: &[u8],
        coefficients: &[u8],
        range: Range<usize>,
        out: &mut [u8],
    ) {
        self.kernel.run(ChecksumRange {
            shard,
            coefficients,
            range,
            out,
        });
    }
}

// Inline only the byte loops into the kernel's feature-enabled entry point.
// Worker callbacks can enter these without inlining the surrounding protocol.
struct AddInto<'a> {
    dst: &'a mut [u8],
    src: &'a [u8],
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
impl WithKernel for AddInto<'_> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self { dst, src } = self;
        assert_eq!(dst.len(), src.len(), "shard lengths differ");
        let mut dst = dst.chunks_exact_mut(K::LANES);
        let mut src = src.chunks_exact(K::LANES);
        for (d, s) in dst.by_ref().zip(src.by_ref()) {
            let sum = GF8Vec::load_bytes(kernel, d) + GF8Vec::load_bytes(kernel, s);
            sum.store_bytes(d);
        }
        for (d, s) in dst.into_remainder().iter_mut().zip(src.remainder()) {
            *d = (GF8::from(*d) + GF8::from(*s)).into();
        }
    }
}

struct MulAdd<'a> {
    dst: &'a mut [u8],
    src: &'a [u8],
    c: GF8,
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
impl WithKernel for MulAdd<'_> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self { dst, src, c } = self;
        assert_eq!(dst.len(), src.len(), "shard lengths differ");
        let mut dst = dst.chunks_exact_mut(K::LANES);
        let mut src = src.chunks_exact(K::LANES);
        for (d, s) in dst.by_ref().zip(src.by_ref()) {
            let sum = GF8Vec::load_bytes(kernel, d) + GF8Vec::load_bytes(kernel, s) * c;
            sum.store_bytes(d);
        }
        for (d, s) in dst.into_remainder().iter_mut().zip(src.remainder()) {
            *d = (GF8::from(*d) + GF8::from(*s) * c).into();
        }
    }
}

struct Butterfly<'a, const INVERSE: bool> {
    x: &'a mut [u8],
    y: &'a mut [u8],
    c: GF8,
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
impl<const INVERSE: bool> WithKernel for Butterfly<'_, INVERSE> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self { x, y, c } = self;
        assert_eq!(x.len(), y.len(), "shard lengths differ");
        if x.len() < K::LANES {
            for (x, y) in x.iter_mut().zip(y) {
                let mut a = GF8::from(*x);
                let mut b = GF8::from(*y);
                if INVERSE {
                    b += &a;
                    a += &(b * c);
                } else {
                    a += &(b * c);
                    b += &a;
                }
                *x = a.into();
                *y = b.into();
            }
            return;
        }

        let constant = kernel.splat(c.0);
        // Save the final full vector before updating overlapping prefix bytes.
        let tail = if x.len().is_multiple_of(K::LANES) {
            None
        } else {
            let start = x.len() - K::LANES;
            Some((start, kernel.load(&x[start..]), kernel.load(&y[start..])))
        };
        for (x, y) in x
            .chunks_exact_mut(K::LANES)
            .zip(y.chunks_exact_mut(K::LANES))
        {
            let (a, b) = Self::apply(kernel, kernel.load(x), kernel.load(y), constant);
            kernel.store(a, x);
            kernel.store(b, y);
        }
        if let Some((start, a, b)) = tail {
            // Each lane is independent, so recomputing the overlap gives the same bytes.
            let (a, b) = Self::apply(kernel, a, b, constant);
            kernel.store(a, &mut x[start..]);
            kernel.store(b, &mut y[start..]);
        }
    }
}

impl<const INVERSE: bool> Butterfly<'_, INVERSE> {
    #[inline(always)]
    fn apply<K: Kernel>(
        kernel: K,
        mut a: K::Vector,
        mut b: K::Vector,
        c: K::Constant,
    ) -> (K::Vector, K::Vector) {
        if INVERSE {
            b = kernel.xor(b, a);
            a = kernel.xor(a, kernel.gf8_mul_constant(b, c));
        } else {
            a = kernel.xor(a, kernel.gf8_mul_constant(b, c));
            b = kernel.xor(b, a);
        }
        (a, b)
    }
}

struct ChecksumRange<'a> {
    shard: &'a [u8],
    coefficients: &'a [u8],
    range: Range<usize>,
    out: &'a mut [u8],
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
impl WithKernel for ChecksumRange<'_> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self {
            shard,
            coefficients,
            range,
            out,
        } = self;
        assert_eq!(coefficients.len(), shard.len() * out.len());
        let input = &shard[range.clone()];
        if input.is_empty() {
            out.fill(0);
            return;
        }
        for (result, coefficients) in out.iter_mut().zip(coefficients.chunks_exact(shard.len())) {
            let mut shard_chunks = input.chunks_exact(K::LANES);
            let mut coefficient_chunks = coefficients[range.clone()].chunks_exact(K::LANES);
            let mut chunks = shard_chunks.by_ref().zip(coefficient_chunks.by_ref());
            let mut sum = if let Some((shard, coefficients)) = chunks.next() {
                let mut sum = kernel.gf8_mul_vec(kernel.load(shard), kernel.load(coefficients));
                for (shard, coefficients) in chunks {
                    let product = kernel.gf8_mul_vec(kernel.load(shard), kernel.load(coefficients));
                    sum = kernel.xor(sum, product);
                }
                kernel.xor_fold(sum)
            } else {
                0
            };
            for (&shard, &coefficient) in shard_chunks
                .remainder()
                .iter()
                .zip(coefficient_chunks.remainder())
            {
                sum ^= GF8::from(shard).mul_inner(GF8::from(coefficient)).0;
            }
            *result = sum;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Impl8,
        code::{Encoder, Impl, test_suites::fuzz_code},
        field::gf8::GF8,
        kernel::{Kernel, WithKernel, portable::Portable, with_kernel},
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use rand_core::Rng as _;

    const OCELOT8: Impl8<Portable> = Impl8::new(Portable);

    struct TestCode;

    impl WithKernel for TestCode {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            commonware_invariants::minifuzz::test(|u| fuzz_code(u, Impl8::new(kernel)));
        }
    }

    #[test]
    fn test_ocelot8() {
        with_kernel(TestCode);
    }

    struct TestButterflies;

    impl WithKernel for TestButterflies {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            let imp = Impl8::new(kernel);
            let mut rng = test_rng();
            for len in (0..=2 * K::LANES + 1).chain([3 * K::LANES + 1]) {
                let mut x = vec![0; len + 2];
                let mut y = vec![0; len + 2];
                rng.fill_bytes(&mut x);
                rng.fill_bytes(&mut y);
                for c in 0..=255 {
                    let mut actual_x = x.clone();
                    let mut actual_y = y.clone();
                    let mut expected_x = x.clone();
                    let mut expected_y = y.clone();
                    for i in 1..=len {
                        let a = GF8(x[i]) + GF8(y[i]) * GF8(c);
                        let b = GF8(y[i]) + a;
                        expected_x[i] = a.into();
                        expected_y[i] = b.into();
                    }
                    imp.fft_butterfly(&mut actual_x[1..1 + len], &mut actual_y[1..1 + len], GF8(c));
                    assert_eq!(actual_x, expected_x);
                    assert_eq!(actual_y, expected_y);
                    imp.ifft_butterfly(
                        &mut actual_x[1..1 + len],
                        &mut actual_y[1..1 + len],
                        GF8(c),
                    );
                    assert_eq!(actual_x, x);
                    assert_eq!(actual_y, y);
                }
            }
        }
    }

    #[test]
    fn butterflies_match_scalar() {
        TestButterflies.call(Portable);
        with_kernel(TestButterflies);
    }

    struct TestUnalignedArithmetic;

    impl WithKernel for TestUnalignedArithmetic {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            let mut rng = test_rng();
            let imp = Impl8::new(kernel);
            for len in [0, 1, 63, 64, 65, 129] {
                let mut src = vec![0; len + K::LANES];
                let mut actual = vec![0; len + K::LANES];
                rng.fill_bytes(&mut src);
                rng.fill_bytes(&mut actual);
                let unaligned =
                    |bytes: &[u8]| (K::LANES - bytes.as_ptr() as usize % K::LANES) % K::LANES + 1;
                let src_offset = unaligned(&src);
                let dst_offset = unaligned(&actual);
                let src = &src[src_offset..src_offset + len];
                let range = dst_offset..dst_offset + len;
                let mut expected = actual.clone();
                imp.add_into(&mut actual[range.clone()], src);
                OCELOT8.add_into(&mut expected[range.clone()], src);
                assert_eq!(actual, expected);
                for c in [0, 1, 0x53, 255] {
                    imp.mul_add(&mut actual[range.clone()], src, GF8(c));
                    OCELOT8.mul_add(&mut expected[range.clone()], src, GF8(c));
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn unaligned_arithmetic_matches_portable() {
        with_kernel(TestUnalignedArithmetic);
    }

    #[test]
    #[should_panic(expected = "too many shards")]
    fn encode_rejects_padded_count_overflow() {
        Encoder::new(OCELOT8).encode(&[&[1][..]; 127], 129, &Sequential);
    }
}
