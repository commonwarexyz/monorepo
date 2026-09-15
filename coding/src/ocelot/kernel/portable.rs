//! A portable kernel, using only scalar operations.

use super::Kernel;
use crate::ocelot::field::gf8::GF8;

/// A [`Kernel`] that works on any platform, operating one byte at a time.
#[derive(Clone, Copy, Debug, Default)]
pub struct Portable;

impl Kernel for Portable {
    type Vector = [u8; 16];
    type Constant = u8;
    const LANES: usize = 16;

    #[inline]
    fn splat(self, x: u8) -> u8 {
        x
    }

    #[inline]
    fn load(self, bytes: &[u8]) -> [u8; 16] {
        bytes.try_into().expect("bytes.len() != LANES")
    }

    #[inline]
    fn store(self, a: [u8; 16], out: &mut [u8]) {
        out.copy_from_slice(&a);
    }

    #[inline]
    fn xor(self, a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    #[inline]
    fn xor_fold(self, a: [u8; 16]) -> u8 {
        a.iter().fold(0, |acc, x| acc ^ x)
    }

    #[inline]
    fn gf8_mul_vec(self, a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
        core::array::from_fn(|i| GF8::mul_inner(GF8(a[i]), GF8(b[i])).0)
    }

    #[inline]
    fn gf8_mul_constant(self, a: [u8; 16], b: u8) -> [u8; 16] {
        core::array::from_fn(|i| GF8::mul_inner(GF8(a[i]), GF8(b)).0)
    }
}
