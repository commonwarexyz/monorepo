use rand_core::CryptoRngCore;

fn gf16_mul(a: u16, b: u16) -> u16 {
    #[inline(always)]
    fn mul_u(a: u16, mut b: u16) -> (u16, u16) {
        let mut a = u32::from(a);
        let mut u = 0u32;
        while b > 0 {
            u ^= a & (0u32.wrapping_sub(u32::from(b & 1)));
            b >>= 1;
            a <<= 1;
        }
        (u as u16, (u >> 16) as u16)
    }
    let (mut out, mut hi) = mul_u(a, b);
    while hi > 0 {
        // 0x2D is the irreducible polynomial used in the RS Simd crate.
        let (l, h) = mul_u(hi, 0x2D);
        out ^= l;
        hi = h
    }
    out
}

#[derive(Clone, Copy, PartialEq)]
pub struct Gf16x8 {
    inner: u128,
}

impl std::fmt::Debug for Gf16x8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:0128b}", self.inner)
    }
}

impl Gf16x8 {
    pub fn zero() -> Self {
        Self { inner: 0u128 }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            inner: self.inner ^ other.inner,
        }
    }

    pub fn scale(&self, s: u16) -> Self {
        let mut inner = 0u128;
        for i in 0..8 {
            inner |= u128::from(gf16_mul(s, (self.inner >> 16 * i) as u16)) << 16 * i;
        }
        Self { inner }
    }

    pub fn rand(mut rng: impl CryptoRngCore) -> Self {
        let mut data = [0u8; 16];
        rng.fill_bytes(&mut data);
        Self {
            inner: u128::from_le_bytes(data),
        }
    }

    pub fn bytes(&self) -> [u8; 16] {
        self.inner.to_le_bytes()
    }
}

impl TryFrom<&[u8]> for Gf16x8 {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: u128::from_le_bytes(value.try_into().map_err(|_| ())?),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    fn any_fe() -> impl Strategy<Value = Gf16x8> {
        any::<u128>().prop_map(|inner| Gf16x8 { inner })
    }

    proptest! {
        #[test]
        fn test_mul_commutative(a: u16, b: u16) {
            assert_eq!(gf16_mul(a, b), gf16_mul(b, a));
        }

        #[test]
        fn test_mul_associative(a: u16, b: u16, c: u16) {
            assert_eq!(gf16_mul(a, gf16_mul(b, c)), gf16_mul(gf16_mul(a, b), c));
        }

        #[test]
        fn test_mul_distributive(a: u16, b: u16, c: u16) {
            assert_eq!(gf16_mul(a, b ^ c), gf16_mul(a, b) ^ gf16_mul(a, c));
        }

        #[test]
        fn test_mul_0_eq_0(a: u16) {
            assert_eq!(gf16_mul(0, a), 0);
        }

        #[test]
        fn test_mul_1_does_nothing(a: u16) {
            assert_eq!(gf16_mul(1, a), a);
        }

        #[test]
        fn test_scale_associative(a: u16, b: u16, x in any_fe()) {
            assert_eq!(x.scale(gf16_mul(a, b)), x.scale(a).scale(b));
        }

        #[test]
        fn test_scale_distributive(a: u16, b: u16, x in any_fe()) {
            assert_eq!(x.scale(a ^ b), x.scale(a).add(&x.scale(b)));
        }

        #[test]
        fn test_scale_1_does_nothing(x in any_fe()) {
            assert_eq!(x, x.scale(1));
        }

        #[test]
        fn test_scale_0_eq_0(x in any_fe()) {
            assert_eq!(x.scale(0), Gf16x8::zero());
        }
    }
}
