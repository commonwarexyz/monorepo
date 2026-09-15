mod code;
mod field;
mod impl16;
mod kernel;
mod scheme;
mod transform;

use crate::{Config, PhasedScheme, Scheme};
use bytes::Buf;
use code::Impl;
use commonware_cryptography::{Hasher, transcript::Summary};
use commonware_parallel::Strategy;
use field::gf8::{GF8, GF8Vec};
use impl16::Impl16;
use kernel::{Kernel, WithKernel, with_kernel};
pub use scheme::Error;
use scheme::{
    BasicCheckedShard, CheckedShard, CheckingData, OcelotHintedX, OcelotX, StrongShard, WeakShard,
};
use std::{
    fmt,
    marker::PhantomData,
    ops::Range,
    sync::{Arc, OnceLock},
};
use transform::Tables;

macro_rules! ocelot {
    ($module:ident, $name:ident, $implementation:ident, $field:literal, $order:literal) => {
        mod $module {
            use super::*;

            #[doc = concat!("Reed-Solomon coding over ", $field, ", with Merkle commitments using `H`.")]
            ///
            /// The original count plus the extra count rounded up to a power of two must
            #[doc = concat!("not exceed ", $order, ".")]
            ///
            /// Shards are checked independently through Merkle inclusion proofs. Decoding
            /// reconstructs the canonical codeword and verifies its commitment before
            /// returning the payload, rejecting inconsistent encodings.
            ///
            /// Arithmetic kernels are selected internally for the current CPU. Large
            /// shards are processed in independent byte stripes using the supplied strategy.
            pub struct $name<H> {
                _marker: PhantomData<H>,
            }

            impl<H> Clone for $name<H> {
                fn clone(&self) -> Self {
                    *self
                }
            }

            impl<H> Copy for $name<H> {}

            impl<H> fmt::Debug for $name<H> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_struct(stringify!($name)).finish()
                }
            }

            impl<H: Hasher> Scheme for $name<H> {
                type Commitment = H::Digest;
                type Shard = WeakShard<H::Digest>;
                type CheckedShard = BasicCheckedShard<H::Digest>;
                type Error = Error;

                fn encode(
                    config: &Config,
                    data: impl Buf,
                    strategy: &impl Strategy,
                ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
                    with_kernel(Encode::<H, _, _> {
                        config,
                        data,
                        strategy,
                        _marker: PhantomData,
                    })
                }

                fn check(
                    config: &Config,
                    commitment: &Self::Commitment,
                    index: u16,
                    shard: &Self::Shard,
                    strategy: &impl Strategy,
                ) -> Result<Self::CheckedShard, Self::Error> {
                    with_kernel(Check::<H, _> {
                        config,
                        commitment,
                        index,
                        shard,
                        strategy,
                    })
                }

                fn decode<'a>(
                    config: &Config,
                    commitment: &Self::Commitment,
                    shards: impl Iterator<Item = &'a Self::CheckedShard>,
                    strategy: &impl Strategy,
                ) -> Result<Vec<u8>, Self::Error> {
                    with_kernel(Decode::<H, _, _> {
                        config,
                        commitment,
                        shards,
                        strategy,
                    })
                }
            }

            struct Encode<'a, H, B, S> {
                config: &'a Config,
                data: B,
                strategy: &'a S,
                _marker: PhantomData<H>,
            }

            impl<H: Hasher, B: Buf, S: Strategy> WithKernel for Encode<'_, H, B, S> {
                type Output = Result<(H::Digest, Vec<WeakShard<H::Digest>>), Error>;

                fn call<K: Kernel>(self, kernel: K) -> Self::Output {
                    OcelotX::<_, H>::new($implementation::new(kernel))
                        .encode(self.config, self.data, self.strategy)
                }
            }

            struct Check<'a, H: Hasher, S> {
                config: &'a Config,
                commitment: &'a H::Digest,
                index: u16,
                shard: &'a WeakShard<H::Digest>,
                strategy: &'a S,
            }

            impl<H: Hasher, S: Strategy> WithKernel for Check<'_, H, S> {
                type Output = Result<BasicCheckedShard<H::Digest>, Error>;

                fn call<K: Kernel>(self, kernel: K) -> Self::Output {
                    OcelotX::<_, H>::new($implementation::new(kernel)).check(
                        self.config,
                        self.commitment,
                        self.index,
                        self.shard,
                        self.strategy,
                    )
                }
            }

            struct Decode<'a, H: Hasher, T, S> {
                config: &'a Config,
                commitment: &'a H::Digest,
                shards: T,
                strategy: &'a S,
            }

            impl<'a, H: Hasher, T: Iterator<Item = &'a BasicCheckedShard<H::Digest>>, S: Strategy>
                WithKernel for Decode<'_, H, T, S>
            {
                type Output = Result<Vec<u8>, Error>;

                fn call<K: Kernel>(self, kernel: K) -> Self::Output {
                    OcelotX::<_, H>::new($implementation::new(kernel))
                        .decode(self.config, self.commitment, self.shards, self.strategy)
                }
            }
        }
        pub use $module::$name;
    };
}

ocelot!(ocelot8, Ocelot8, Impl8, "GF(2^8)", "256");
ocelot!(ocelot16, Ocelot16, Impl16, "GF(2^16)", "65,536");

macro_rules! ocelot_hinted {
    ($module:ident, $name:ident, $implementation:ident, $checksum_bytes:literal, $field:literal, $order:literal) => {
        mod $module {
            use super::*;

            #[doc = concat!("Reed-Solomon coding over ", $field, ", with commitments using `H`.")]
            ///
            /// The original count plus the extra count rounded up to a power of two must
            #[doc = concat!("not exceed ", $order, ".")]
            ///
            /// Arithmetic kernels are selected internally for the current CPU.
            /// The encoder commits to all encoded shards before deriving 16 independent
            /// checksum projections with Fiat-Shamir, each providing 8 bits of soundness.
            /// A strong shard carries the unencoded checksums; participants encode
            /// them locally and use the resulting checksum
            /// codeword alongside Merkle proofs to check forwarded shards.
            #[doc = concat!("Each original shard contributes ", stringify!($checksum_bytes), " bytes of checksums.")]
            ///
            /// Encoding and decoding process large shards in independent byte stripes
            /// using the supplied strategy. Checksums use tiles spanning shards and column
            /// ranges, including when checking a single shard. Encoding also parallelizes
            /// shard hashing through that strategy.
            ///
            /// A successful shard check does not prove that the entire encoding is
            /// available. Availability is established only when decoding succeeds from
            /// enough checked shards, so this type does not implement `ValidatingScheme`.
            pub struct $name<H> {
                _marker: PhantomData<H>,
            }

            impl<H> Clone for $name<H> {
                fn clone(&self) -> Self {
                    *self
                }
            }

            impl<H> Copy for $name<H> {}

            impl<H> fmt::Debug for $name<H> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_struct(stringify!($name)).finish()
                }
            }

            impl<H: Hasher> PhasedScheme for $name<H> {
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
                    OcelotHintedX::<_, H, $checksum_bytes>::new($implementation::new(kernel)).encode(
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
                    OcelotHintedX::<_, H, $checksum_bytes>::new($implementation::new(kernel)).decode(
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
                    OcelotHintedX::<_, H, $checksum_bytes>::new($implementation::new(kernel)).weaken(
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
                    OcelotHintedX::<_, H, $checksum_bytes>::new($implementation::new(kernel)).check(
                        self.config,
                        self.commitment,
                        self.checking_data,
                        self.index,
                        self.weak_shard,
                        self.strategy,
                    )
                }
            }
        }
        pub use $module::$name;
    };
}

ocelot_hinted!(ocelot_hinted8, OcelotHinted8, Impl8, 16, "GF(2^8)", "256");
ocelot_hinted!(
    ocelot_hinted16,
    OcelotHinted16,
    Impl16,
    32,
    "GF(2^16)",
    "65,536"
);

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

    fn tables() -> Arc<Tables<GF8>> {
        static TABLES: OnceLock<Arc<Tables<GF8>>> = OnceLock::new();
        TABLES
            .get_or_init(|| Arc::new(Tables::new::<Self>()))
            .clone()
    }

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

    fn derivative_four(self, quarters: [&mut [u8]; 4]) {
        self.kernel.run(DerivativeFour { quarters });
    }

    fn derivative_sixteen(self, blocks: [&mut [u8]; 16]) {
        self.kernel.run(DerivativeSixteen { blocks });
    }

    fn sub_into(self, dst: &mut [u8], src: &[u8]) {
        self.add_into(dst, src);
    }

    fn mul_add(self, dst: &mut [u8], src: &[u8], c: GF8) {
        self.kernel.run(MulAdd::<true> { dst, src, c });
    }

    fn mul_into(self, dst: &mut [u8], src: &[u8], c: GF8) {
        self.kernel.run(MulAdd::<false> { dst, src, c });
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

    fn fft_butterfly_two_layers(
        self,
        quarters: [&mut [u8]; 4],
        shard_len: usize,
        coefficients: [GF8; 3],
    ) {
        self.kernel.run(ButterflyTwoLayers::<false> {
            quarters,
            shard_len,
            coefficients,
        });
    }

    fn ifft_butterfly_two_layers(
        self,
        quarters: [&mut [u8]; 4],
        shard_len: usize,
        coefficients: [GF8; 3],
    ) {
        self.kernel.run(ButterflyTwoLayers::<true> {
            quarters,
            shard_len,
            coefficients,
        });
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
struct DerivativeFour<'a> {
    quarters: [&'a mut [u8]; 4],
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
impl WithKernel for DerivativeFour<'_> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let [q0, q1, q2, q3] = self.quarters;
        assert_eq!(q0.len(), q1.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q2.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q3.len(), "quarter lengths differ");
        let mut q0 = q0.chunks_exact_mut(K::LANES);
        let mut q1 = q1.chunks_exact_mut(K::LANES);
        let mut q2 = q2.chunks_exact_mut(K::LANES);
        let mut q3 = q3.chunks_exact_mut(K::LANES);
        for (((out0, out1), out2), out3) in q0
            .by_ref()
            .zip(q1.by_ref())
            .zip(q2.by_ref())
            .zip(q3.by_ref())
        {
            let b = GF8Vec::load_bytes(kernel, out1);
            let c = GF8Vec::load_bytes(kernel, out2);
            let d = GF8Vec::load_bytes(kernel, out3);
            (b + c).store_bytes(out0);
            d.store_bytes(out1);
            d.store_bytes(out2);
            (d + d).store_bytes(out3);
        }

        let [q0, q1, q2, q3] = [
            q0.into_remainder(),
            q1.into_remainder(),
            q2.into_remainder(),
            q3.into_remainder(),
        ];
        for i in 0..q0.len() {
            let d = q3[i];
            q0[i] = q1[i] ^ q2[i];
            q1[i] = d;
            q2[i] = d;
            q3[i] = 0;
        }
    }
}

struct DerivativeSixteen<'a> {
    blocks: [&'a mut [u8]; 16],
}

impl WithKernel for DerivativeSixteen<'_> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let blocks = self.blocks;
        let len = blocks[0].len();
        assert!(
            blocks.iter().all(|block| block.len() == len),
            "block lengths differ"
        );
        let full = len / K::LANES * K::LANES;
        for start in (0..full).step_by(K::LANES) {
            let end = start + K::LANES;
            let first = GF8Vec::load_bytes(kernel, &blocks[1][start..end]);
            let zero = first + first;
            let mut sources = [zero; 16];
            sources[1] = first;
            for source in 2..16 {
                sources[source] = GF8Vec::load_bytes(kernel, &blocks[source][start..end]);
            }
            // Fixed destinations keep the source vectors in registers.
            macro_rules! store {
                ($($output:expr),* $(,)?) => {{$(
                    let output = $output;
                    let mut sum = zero;
                    for bit in 0..4 {
                        let mask = 1 << bit;
                        if output & mask == 0 {
                            sum += &sources[output | mask];
                        }
                    }
                    sum.store_bytes(&mut blocks[output][start..end]);
                )*}};
            }
            store!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        }
        // Each byte offset is shared by all source and destination blocks.
        #[allow(clippy::needless_range_loop)]
        for offset in full..len {
            for output in 0..16 {
                let mut sum = 0;
                for bit in 0..4 {
                    let mask = 1 << bit;
                    if output & mask == 0 {
                        sum ^= blocks[output | mask][offset];
                    }
                }
                blocks[output][offset] = sum;
            }
        }
    }
}

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

struct MulAdd<'a, const ADD: bool> {
    dst: &'a mut [u8],
    src: &'a [u8],
    c: GF8,
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
impl<const ADD: bool> WithKernel for MulAdd<'_, ADD> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self { dst, src, c } = self;
        assert_eq!(dst.len(), src.len(), "shard lengths differ");
        let mut dst = dst.chunks_exact_mut(K::LANES);
        let mut src = src.chunks_exact(K::LANES);
        for (d, s) in dst.by_ref().zip(src.by_ref()) {
            let product = GF8Vec::load_bytes(kernel, s) * c;
            let sum = if ADD {
                GF8Vec::load_bytes(kernel, d) + product
            } else {
                product
            };
            sum.store_bytes(d);
        }
        for (d, s) in dst.into_remainder().iter_mut().zip(src.remainder()) {
            let product = GF8::from(*s) * c;
            *d = if ADD {
                (GF8::from(*d) + product).into()
            } else {
                product.into()
            };
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

struct ButterflyTwoLayers<'a, const INVERSE: bool> {
    quarters: [&'a mut [u8]; 4],
    shard_len: usize,
    coefficients: [GF8; 3],
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
impl<const INVERSE: bool> WithKernel for ButterflyTwoLayers<'_, INVERSE> {
    type Output = ();

    #[inline(always)]
    fn call<K: Kernel>(self, kernel: K) {
        let Self {
            quarters,
            shard_len,
            coefficients,
        } = self;
        let [q0, q1, q2, q3] = quarters;
        assert!(shard_len > 0, "shard length is zero");
        assert_eq!(q0.len(), q1.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q2.len(), "quarter lengths differ");
        assert_eq!(q0.len(), q3.len(), "quarter lengths differ");
        assert!(q0.len().is_multiple_of(shard_len), "partial shard group");

        let constants = coefficients.map(|c| kernel.splat(c.0));
        let mut q0 = q0.chunks_exact_mut(K::LANES);
        let mut q1 = q1.chunks_exact_mut(K::LANES);
        let mut q2 = q2.chunks_exact_mut(K::LANES);
        let mut q3 = q3.chunks_exact_mut(K::LANES);
        for (((x0, x1), x2), x3) in q0
            .by_ref()
            .zip(q1.by_ref())
            .zip(q2.by_ref())
            .zip(q3.by_ref())
        {
            let values = [
                kernel.load(x0),
                kernel.load(x1),
                kernel.load(x2),
                kernel.load(x3),
            ];
            let values = Self::apply(kernel, values, coefficients, constants);
            kernel.store(values[0], x0);
            kernel.store(values[1], x1);
            kernel.store(values[2], x2);
            kernel.store(values[3], x3);
        }

        let [x0, x1, x2, x3] = [
            q0.into_remainder(),
            q1.into_remainder(),
            q2.into_remainder(),
            q3.into_remainder(),
        ];
        let partial = x0.len() / K::PARTIAL_GRANULARITY * K::PARTIAL_GRANULARITY;
        if partial > 0 {
            let values = [
                kernel.load_partial(&x0[..partial]),
                kernel.load_partial(&x1[..partial]),
                kernel.load_partial(&x2[..partial]),
                kernel.load_partial(&x3[..partial]),
            ];
            let values = Self::apply(kernel, values, coefficients, constants);
            kernel.store_partial(values[0], &mut x0[..partial]);
            kernel.store_partial(values[1], &mut x1[..partial]);
            kernel.store_partial(values[2], &mut x2[..partial]);
            kernel.store_partial(values[3], &mut x3[..partial]);
        }
        for i in partial..x0.len() {
            let mut values = [GF8(x0[i]), GF8(x1[i]), GF8(x2[i]), GF8(x3[i])];
            Self::apply_scalar(&mut values, coefficients);
            x0[i] = values[0].0;
            x1[i] = values[1].0;
            x2[i] = values[2].0;
            x3[i] = values[3].0;
        }
    }
}

impl<const INVERSE: bool> ButterflyTwoLayers<'_, INVERSE> {
    #[inline(always)]
    fn apply<K: Kernel>(
        kernel: K,
        mut values: [K::Vector; 4],
        coefficients: [GF8; 3],
        constants: [K::Constant; 3],
    ) -> [K::Vector; 4] {
        if INVERSE {
            Self::apply_pair(kernel, &mut values, 0, 1, coefficients[0], constants[0]);
            Self::apply_pair(kernel, &mut values, 2, 3, coefficients[1], constants[1]);
            Self::apply_pair(kernel, &mut values, 0, 2, coefficients[2], constants[2]);
            Self::apply_pair(kernel, &mut values, 1, 3, coefficients[2], constants[2]);
        } else {
            Self::apply_pair(kernel, &mut values, 0, 2, coefficients[2], constants[2]);
            Self::apply_pair(kernel, &mut values, 1, 3, coefficients[2], constants[2]);
            Self::apply_pair(kernel, &mut values, 0, 1, coefficients[0], constants[0]);
            Self::apply_pair(kernel, &mut values, 2, 3, coefficients[1], constants[1]);
        }
        values
    }

    #[inline(always)]
    fn apply_pair<K: Kernel>(
        kernel: K,
        values: &mut [K::Vector; 4],
        x: usize,
        y: usize,
        c: GF8,
        constant: K::Constant,
    ) {
        let mut a = values[x];
        let mut b = values[y];
        if INVERSE {
            b = kernel.xor(b, a);
            if c != GF8(0) {
                a = kernel.xor(a, kernel.gf8_mul_constant(b, constant));
            }
        } else {
            if c != GF8(0) {
                a = kernel.xor(a, kernel.gf8_mul_constant(b, constant));
            }
            b = kernel.xor(b, a);
        }
        values[x] = a;
        values[y] = b;
    }

    #[inline(always)]
    fn apply_scalar(values: &mut [GF8; 4], coefficients: [GF8; 3]) {
        let apply_pair = |values: &mut [GF8; 4], x: usize, y: usize, c: GF8| {
            let mut a = values[x];
            let mut b = values[y];
            if INVERSE {
                b += &a;
                a += &(b * c);
            } else {
                a += &(b * c);
                b += &a;
            }
            values[x] = a;
            values[y] = b;
        };
        if INVERSE {
            apply_pair(values, 0, 1, coefficients[0]);
            apply_pair(values, 2, 3, coefficients[1]);
            apply_pair(values, 0, 2, coefficients[2]);
            apply_pair(values, 1, 3, coefficients[2]);
        } else {
            apply_pair(values, 0, 2, coefficients[2]);
            apply_pair(values, 1, 3, coefficients[2]);
            apply_pair(values, 0, 1, coefficients[0]);
            apply_pair(values, 2, 3, coefficients[1]);
        }
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

            for len in (0..=2 * K::LANES + 1).chain([3 * K::LANES + 1]) {
                let mut original: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; len + 2]);
                for quarter in &mut original {
                    rng.fill_bytes(quarter);
                }
                let mut actual = original.clone();
                let mut expected = original.clone();
                for i in 1..=len {
                    let d = original[3][i];
                    expected[0][i] = original[1][i] ^ original[2][i];
                    expected[1][i] = d;
                    expected[2][i] = d;
                    expected[3][i] = 0;
                }
                let [q0, q1, q2, q3] = &mut actual;
                imp.derivative_four([
                    &mut q0[1..=len],
                    &mut q1[1..=len],
                    &mut q2[1..=len],
                    &mut q3[1..=len],
                ]);
                assert_eq!(actual, expected);
            }

            for len in (0..=2 * K::LANES + 1).chain([3 * K::LANES + 1]) {
                let mut original: [Vec<u8>; 16] = std::array::from_fn(|_| vec![0; len + 2]);
                for block in &mut original {
                    rng.fill_bytes(block);
                }
                let mut actual = original.clone();
                let mut expected = original.clone();
                for output in 0..16 {
                    for i in 1..=len {
                        expected[output][i] = (0..4)
                            .filter(|bit| output & (1 << bit) == 0)
                            .fold(0, |sum, bit| sum ^ original[output | (1 << bit)][i]);
                    }
                }
                imp.derivative_sixteen(actual.each_mut().map(|block| &mut block[1..=len]));
                assert_eq!(actual, expected);
            }

            for shard_len in [1, 3, K::LANES, K::LANES + 1, 2 * K::LANES + 3] {
                let shard_count = 3;
                let len = shard_len * shard_count;
                let mut original: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; len + 2]);
                for quarter in &mut original {
                    rng.fill_bytes(quarter);
                }
                for coefficients in [[GF8(0), GF8(1), GF8(0)], [GF8(0x53), GF8(0xff), GF8(0x80)]] {
                    let mut actual = original.clone();
                    let mut expected = original.clone();
                    for i in 1..=len {
                        let mut values = [
                            GF8(expected[0][i]),
                            GF8(expected[1][i]),
                            GF8(expected[2][i]),
                            GF8(expected[3][i]),
                        ];
                        let [c0, c1, c2] = coefficients;
                        let apply = |values: &mut [GF8; 4], x: usize, y: usize, c: GF8| {
                            let mut a = values[x];
                            let mut b = values[y];
                            a += &(b * c);
                            b += &a;
                            values[x] = a;
                            values[y] = b;
                        };
                        apply(&mut values, 0, 2, c2);
                        apply(&mut values, 1, 3, c2);
                        apply(&mut values, 0, 1, c0);
                        apply(&mut values, 2, 3, c1);
                        for (quarter, value) in expected.iter_mut().zip(values) {
                            quarter[i] = value.0;
                        }
                    }
                    let [q0, q1, q2, q3] = &mut actual;
                    imp.fft_butterfly_two_layers(
                        [
                            &mut q0[1..=len],
                            &mut q1[1..=len],
                            &mut q2[1..=len],
                            &mut q3[1..=len],
                        ],
                        shard_len,
                        coefficients,
                    );
                    assert_eq!(actual, expected);
                    let [q0, q1, q2, q3] = &mut actual;
                    imp.ifft_butterfly_two_layers(
                        [
                            &mut q0[1..=len],
                            &mut q1[1..=len],
                            &mut q2[1..=len],
                            &mut q3[1..=len],
                        ],
                        shard_len,
                        coefficients,
                    );
                    assert_eq!(actual, original);
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
                    let mut overwritten = actual.clone();
                    overwritten[range.clone()].fill(0xa5);
                    imp.mul_into(&mut overwritten[range.clone()], src, GF8(c));
                    let mut expected_overwrite = overwritten.clone();
                    for (dst, &src) in expected_overwrite[range.clone()].iter_mut().zip(src) {
                        *dst = (GF8::from(src) * GF8(c)).into();
                    }
                    assert_eq!(overwritten, expected_overwrite);

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
