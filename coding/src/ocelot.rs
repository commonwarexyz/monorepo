mod code;
mod field;
mod kernel;
mod scheme;
mod transform;

use crate::{
    Config, PhasedScheme,
};
use bytes::Buf;
use code::Impl;
use commonware_cryptography::{Hasher, transcript::Summary};
use commonware_parallel::Strategy;
use field::gf8::{GF8, GF8Vec};
use kernel::{Kernel, WithKernel, with_kernel};
pub use scheme::Error;
use scheme::{CheckedShard, CheckingData, OcelotX, StrongShard, WeakShard};
use std::{fmt, marker::PhantomData};

/// Reed-Solomon coding over GF(2^8), with commitments using `H`.
///
/// Arithmetic kernels are selected internally for the current CPU.
/// The encoder commits to all encoded shards before deriving 16 independent
/// checksum projections with Fiat-Shamir. A strong shard carries the unencoded
/// checksums; participants encode them locally and use the resulting checksum
/// codeword alongside Merkle proofs to check forwarded shards.
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
    ) -> Result<
        (Self::CheckingData, Self::CheckedShard, Self::WeakShard),
        Self::Error,
    > {
        with_kernel(Weaken::<H> {
            namespace,
            config,
            commitment,
            index,
            shard,
        })
    }

    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        checking_data: &Self::CheckingData,
        index: u16,
        weak_shard: Self::WeakShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        with_kernel(Check::<H> {
            config,
            commitment,
            checking_data,
            index,
            weak_shard,
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
        OcelotX::<_, H>::new(Impl8::new(kernel)).encode(
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
        OcelotX::<_, H>::new(Impl8::new(kernel)).decode(
            self.config,
            self.commitment,
            self.checking_data,
            self.shards,
            self.strategy,
        )
    }
}

struct Weaken<'a, H: Hasher> {
    namespace: &'a [u8],
    config: &'a Config,
    commitment: &'a Summary,
    index: u16,
    shard: StrongShard<H::Digest>,
}

impl<H: Hasher> WithKernel for Weaken<'_, H> {
    type Output = Result<
        (CheckingData<H::Digest>, CheckedShard, WeakShard<H::Digest>),
        Error,
    >;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        OcelotX::<_, H>::new(Impl8::new(kernel)).weaken(
            self.namespace,
            self.config,
            self.commitment,
            self.index,
            self.shard,
        )
    }
}

struct Check<'a, H: Hasher> {
    config: &'a Config,
    commitment: &'a Summary,
    checking_data: &'a CheckingData<H::Digest>,
    index: u16,
    weak_shard: WeakShard<H::Digest>,
}

impl<H: Hasher> WithKernel for Check<'_, H> {
    type Output = Result<CheckedShard, Error>;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        OcelotX::<_, H>::new(Impl8::new(kernel)).check(
            self.config,
            self.commitment,
            self.checking_data,
            self.index,
            self.weak_shard,
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

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(clippy::chunks_exact_to_as_chunks)]
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
        assert_eq!(dst.len(), src.len(), "shard lengths differ");
        let mut dst = dst.chunks_exact_mut(K::LANES);
        let mut src = src.chunks_exact(K::LANES);
        for (d, s) in dst.by_ref().zip(src.by_ref()) {
            let sum = GF8Vec::load_bytes(self.kernel, d) + GF8Vec::load_bytes(self.kernel, s);
            sum.store_bytes(d);
        }
        for (d, s) in dst.into_remainder().iter_mut().zip(src.remainder()) {
            *d = (GF8::from(*d) + GF8::from(*s)).into();
        }
    }

    fn sub_into(self, dst: &mut [u8], src: &[u8]) {
        self.add_into(dst, src);
    }

    fn mul_add(self, dst: &mut [u8], src: &[u8], c: GF8) {
        assert_eq!(dst.len(), src.len(), "shard lengths differ");
        let mut dst = dst.chunks_exact_mut(K::LANES);
        let mut src = src.chunks_exact(K::LANES);
        for (d, s) in dst.by_ref().zip(src.by_ref()) {
            let sum = GF8Vec::load_bytes(self.kernel, d) + GF8Vec::load_bytes(self.kernel, s) * c;
            sum.store_bytes(d);
        }
        for (d, s) in dst.into_remainder().iter_mut().zip(src.remainder()) {
            *d = (GF8::from(*d) + GF8::from(*s) * c).into();
        }
    }

    fn mul_sub(self, dst: &mut [u8], src: &[u8], c: GF8) {
        self.mul_add(dst, src, c);
    }

    fn checksum(self, shard: &[u8], coefficients: &[u8], out: &mut [u8]) {
        assert_eq!(coefficients.len(), shard.len() * out.len());
        for (result, coefficients) in out.iter_mut().zip(coefficients.chunks_exact(shard.len())) {
            let mut sum = 0;
            let mut shard_chunks = shard.chunks_exact(K::LANES);
            let mut coefficient_chunks = coefficients.chunks_exact(K::LANES);
            for (shard, coefficients) in shard_chunks.by_ref().zip(coefficient_chunks.by_ref()) {
                let product = self
                    .kernel
                    .gf8_mul_vec(self.kernel.load(shard), self.kernel.load(coefficients));
                sum ^= self.kernel.xor_fold(product);
            }
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
        code::{Encoder, test_suites::fuzz_code},
        kernel::{Kernel, WithKernel, portable::Portable, with_kernel},
    };

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

    #[test]
    #[should_panic(expected = "too many shards")]
    fn encode_rejects_padded_count_overflow() {
        Encoder::new(OCELOT8).encode(&[&[1][..]; 127], 129);
    }
}
