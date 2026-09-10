mod code;
mod field;
mod kernel;
mod transform;

use code::Impl;
use field::gf8::{GF8, GF8Vec};
use kernel::Kernel;

/// Ocelot's GF(2^8) arithmetic, using a concrete byte kernel.
#[derive(Clone, Copy)]
pub struct Ocelot8<K: Kernel> {
    kernel: K,
}

impl<K: Kernel> Ocelot8<K> {
    /// Use `kernel` for operations on whole shards.
    pub const fn new(kernel: K) -> Self {
        Self { kernel }
    }
}

// K::LANES cannot be used as a const generic argument to as_chunks.
#[allow(clippy::chunks_exact_to_as_chunks)]
impl<K: Kernel> Impl for Ocelot8<K> {
    type Element = GF8;
    const BITS: usize = 8;

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
}

#[cfg(test)]
mod tests {
    use super::{
        Ocelot8,
        code::{Encoder, test_suites::fuzz_code},
        kernel::{Kernel, WithKernel, portable::Portable, with_kernel},
    };

    const OCELOT8: Ocelot8<Portable> = Ocelot8::new(Portable);

    struct TestCode;

    impl WithKernel for TestCode {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            commonware_invariants::minifuzz::test(|u| fuzz_code(u, Ocelot8::new(kernel)));
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
