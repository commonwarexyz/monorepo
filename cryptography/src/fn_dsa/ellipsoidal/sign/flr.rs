// Adapted from fn-dsa-sign 0.4.0, by Thomas Pornin (Unlicense).
//! Integer implementation of finite, normal binary64 arithmetic.
//!
//! Callers own operand bounds; NaNs, infinities and subnormals are unsupported.
//! Operation order and round-to-nearest, ties-to-even are part of the profile.
#![allow(non_snake_case, non_upper_case_globals)]

use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::DefaultIsZeroes;

#[path = "flr_emu.rs"]
mod backend;
pub(crate) use backend::FLR;

impl Default for FLR {
    fn default() -> Self {
        Self::ZERO
    }
}

impl DefaultIsZeroes for FLR {}

impl Add<Self> for FLR {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        let mut r = self;
        r.set_add(other);
        r
    }
}

impl AddAssign<Self> for FLR {
    #[inline(always)]
    fn add_assign(&mut self, other: Self) {
        self.set_add(other);
    }
}

impl Div<Self> for FLR {
    type Output = Self;

    #[inline(always)]
    fn div(self, other: Self) -> Self {
        let mut r = self;
        r.set_div(other);
        r
    }
}

impl Mul<Self> for FLR {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        let mut r = self;
        r.set_mul(other);
        r
    }
}

impl MulAssign<Self> for FLR {
    #[inline(always)]
    fn mul_assign(&mut self, other: Self) {
        self.set_mul(other);
    }
}

impl Neg for FLR {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self {
        let mut r = self;
        r.set_neg();
        r
    }
}

impl Sub<Self> for FLR {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self {
        let mut r = self;
        r.set_sub(other);
        r
    }
}

impl SubAssign<Self> for FLR {
    #[inline(always)]
    fn sub_assign(&mut self, other: Self) {
        self.set_sub(other);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use fn_dsa_comm::{
        PRNG,
        shake::{SHAKE256, SHAKE256_PRNG},
    };

    fn rand_u64(rng: &mut SHAKE256_PRNG) -> u64 {
        let mut x = 0;
        for _ in 0..4 {
            x = (x << 16) | (rng.next_u16() as u64);
        }
        x
    }

    fn rand_fp(rng: &mut SHAKE256_PRNG) -> FLR {
        // For tests, we randomize sign, mantissa and exponent, but we
        // force the exponent to be in [-80,+80] so that we do not get
        // overflows or underflows. We thus force the _encoded_ exponent
        // into [943,1103].
        let m = rand_u64(rng);
        let e = (((m >> 52) & 0x7FF) % 161) + 943;
        let m = (m & 0x800FFFFFFFFFFFFF) | (e << 52);
        FLR::decode(&m.to_le_bytes()).unwrap()
    }

    #[test]
    fn binary64_reference_vectors() {
        let mut sh = SHAKE256::new();
        sh.inject(&FLR::ZERO.encode());
        sh.inject(&(-FLR::ZERO).encode());
        sh.inject(&FLR::ZERO.half().encode());
        sh.inject(&FLR::ZERO.double().encode());
        let zero = FLR::ZERO;
        let nzero = -FLR::ZERO;
        sh.inject(&(zero + zero).encode());
        sh.inject(&(zero + nzero).encode());
        sh.inject(&(nzero + zero).encode());
        sh.inject(&(nzero + nzero).encode());
        sh.inject(&(zero - zero).encode());
        sh.inject(&(zero - nzero).encode());
        sh.inject(&(nzero - zero).encode());
        sh.inject(&(nzero - nzero).encode());

        for e in -60..=60 {
            for i in -5..=5 {
                let a = FLR::from_i64((1i64 << 53) + i);
                sh.inject(&a.encode());
                for j in -5..=5 {
                    let b = FLR::scaled((1i64 << 53) + j, e);
                    sh.inject(&b.encode());
                    sh.inject(&(a + b).encode());
                    let a = a.neg();
                    sh.inject(&(a + b).encode());
                    let b = b.neg();
                    sh.inject(&(a + b).encode());
                    let a = a.neg();
                    sh.inject(&(a + b).encode());
                }
            }
        }

        let mut rng = SHAKE256_PRNG::new(&b"fpemu"[..]);
        for ctr in 1..=65536 {
            let j = (rand_u64(&mut rng) as i64) >> (ctr & 63);
            assert!(j != -9223372036854775808);
            let a = FLR::from_i64(j);
            sh.inject(&a.encode());

            let sc = ((rng.next_u16() as i32) & 0xFF) - 128;
            sh.inject(&FLR::scaled(j, sc).encode());

            let j = rand_u64(&mut rng) as i64;
            let a = FLR::scaled(j, -8);
            sh.inject(&a.rint().to_le_bytes());

            let a = FLR::scaled(j, -52);
            sh.inject(&a.trunc().to_le_bytes());
            sh.inject(&a.floor().to_le_bytes());

            let a = rand_fp(&mut rng);
            let b = rand_fp(&mut rng);

            sh.inject(&(a + b).encode());
            sh.inject(&(b + a).encode());
            sh.inject(&(a + zero).encode());
            sh.inject(&(zero + a).encode());
            sh.inject(&(a + (-a)).encode());
            sh.inject(&((-a) + a).encode());

            sh.inject(&(a - b).encode());
            sh.inject(&(b - a).encode());
            sh.inject(&(a - zero).encode());
            sh.inject(&(zero - a).encode());
            sh.inject(&(a - a).encode());

            sh.inject(&(-a).encode());
            sh.inject(&a.half().encode());
            sh.inject(&a.double().encode());

            sh.inject(&(a * b).encode());
            sh.inject(&(b * a).encode());
            sh.inject(&(a * zero).encode());
            sh.inject(&(zero * a).encode());

            sh.inject(&(a / b).encode());

            sh.inject(&a.abs().sqrt().encode());
        }

        // Reference hash was computed on 64-bit x86, where all
        // operations have been verified by comparing with the native
        // SSE2 support.
        let mut buf = [0u8; 32];
        sh.flip();
        sh.extract(&mut buf);
        assert!(
            buf[..]
                == [
                    89, 72, 166, 50, 160, 121, 116, 57, 170, 142, 126, 217, 171, 197, 84, 81, 42,
                    147, 116, 129, 32, 87, 104, 69, 101, 246, 14, 106, 66, 112, 41, 148
                ]
        );
    }
}
