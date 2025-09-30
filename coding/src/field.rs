use std::ops::{Add, Mul, Neg, Sub};

/// The modulus P := 2^64 - 2^32 + 1.
///
/// This is a prime number, and we use it to form a field of this order.
const P: u64 = u64::wrapping_neg(1 << 32) + 1;

/// An element of the [Goldilocks field](https://xn--2-umb.com/22/goldilocks/).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct F(u64);

impl std::fmt::Debug for F {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016X}", self.0)
    }
}

impl F {
    /// The zero element of the field.
    ///
    /// This is the identity for addition.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// The one element of the field.
    ///
    /// This is the identity for multiplication.
    pub const fn one() -> Self {
        Self(1)
    }

    const fn add_inner(self, b: Self) -> Self {
        // We want to calculate self + b mod P.
        // At a high level, this can be done by adding self + b, as integers,
        // and then subtracting P as long as the result >= P.
        //
        // How many times do we need to do this?
        //
        // self <= P - 1
        // b <= P - 1
        // ∴ self + b <= 2P - 2
        // ∴ self + b - P <= P - 1
        //
        // So, we need to subtract P at most once.

        // addition + 2^64 * overflow = self + b
        let (addition, overflow) = self.0.overflowing_add(b.0);
        // In the case of overflow = 1, addition + 2^64 > P, so we need to
        // subtract. The result of this subtraction will be < 2^64,
        // so we can compute it by calculating addition - P, wrapping around.
        let (subtraction, underflow) = addition.overflowing_sub(P);
        // In the case of overflow, we use the subtraction (as mentioned above).
        // Otherwise, use the subtraction as long as we didn't underflow
        if overflow || !underflow {
            Self(subtraction)
        } else {
            Self(addition)
        }
    }

    const fn sub_inner(self, b: Self) -> Self {
        // The strategy here is to perform the subtraction, and then (maybe) add back P.
        // If no underflow happened, the result is reduced, since both values were < P.
        // If an underflow happened, the largest result we can have is -1. Adding
        // P gives us P - 1, which is < P, so everything works.
        let (subtraction, underflow) = self.0.overflowing_sub(b.0);
        if underflow {
            Self(subtraction.wrapping_add(P))
        } else {
            Self(subtraction)
        }
    }

    const fn reduce_64(x: u64) -> Self {
        // 2 * P > 2^64 - 1 (by a long margin)
        // We thus need to subtract P at most once.
        let (subtraction, underflow) = x.overflowing_sub(P);
        if underflow {
            Self(x)
        } else {
            Self(subtraction)
        }
    }

    /// Reduce a 128 bit integer into a field element.
    const fn reduce_128(x: u128) -> Self {
        // We exploit special properties of the field.
        //
        // First, 2^64 = 2^32 - 1 mod P.
        //
        // Second, 2^96 = 2^32(2^32 - 1) = 2^64 - 2^32 = -1 mod P.
        //
        // Thus, if we write a 128 bit integer x as:
        //     x = c 2^96 + b 2^64 + a
        // We have:
        //     x = b (2^32 - 1) + (a - c) mod P
        // And this expression will be our strategy for performing the reduction.
        let a = x as u64;
        let b = ((x >> 64) & 0xFF_FF_FF_FF) as u64;
        let c = (x >> 96) as u64;

        // While we lean on existing code, we need to be careful because some of
        // these types are partially reduced.
        //
        // First, if we look at a - c, the end result with our field code can
        // be any 64 bit value (consider c = 0). We can also make the same assumption
        // for (b << 32) - b. The question then becomes, is Field(x) + Field(y)
        // ok even if both x and y are arbitrary u64 values?
        //
        // Yes. Even if x and y have the maximum value, a single subtraction of P
        // would suffice to make their sum < P. Thus, our strategy for field addition
        // will always work.
        Self(a).sub_inner(Self(c)).add_inner(Self((b << 32) - b))
    }

    const fn mul_inner(self, b: Self) -> Self {
        // We do a u64 x u64 -> u128 multiplication, then reduce mod P
        Self::reduce_128((self.0 as u128) * (b.0 as u128))
    }

    const fn neg_inner(self) -> Self {
        Self::zero().sub_inner(self)
    }

    /// Calculate self ^ k.
    pub const fn exp(self, mut k: u64) -> Self {
        let mut acc = Self::one();
        // w will contain self, self^2, self^4, ...
        let mut w = self;
        while k > 0 {
            // If the ith bit of exponent is 1, multiply by self^(2^i)
            if k & 1 != 0 {
                acc = acc.mul_inner(w);
            }
            w = w.mul_inner(w);
            k >>= 1;
        }
        acc
    }

    // These could be computed at compile time, but I'm choosing to just test
    // their calculation instead.

    /// Any non-zero element x = GENERATOR^k, for some k.
    ///
    /// This is chosen such that GENERATOR^((P - 1) / 64) = 8.
    pub const GENERATOR: Self = Self(0xd64f951101aff9bf);

    /// An element of order 2^32.
    ///
    /// This is specifically chosen such that ROOT_OF_UNITY^(2^26) = 8.
    ///
    /// That enables optimizations when doing NTTs, and things like that.
    pub const ROOT_OF_UNITY: Self = Self(0xee41f5320c4ea145);

    /// Construct a 2^lg_k root of unity.
    ///
    /// This will fail for lg_k > 32.
    pub fn root_of_unity(lg_k: u8) -> Option<Self> {
        if lg_k > 32 {
            return None;
        }
        let mut out = Self::ROOT_OF_UNITY;
        for _ in 0..(32 - lg_k) {
            out = out * out;
        }
        Some(out)
    }

    /// Return self / 2.
    pub fn div_2(self) -> Self {
        // Check the first bit of self
        if self.0 & 1 == 0 {
            // self is even, just divide by 2.
            Self(self.0 >> 1)
        } else {
            // P is odd, so adding it creates an even number, and doesn't
            // change the value mod P.
            // Is (x + P) / 2 < P?
            // x < P, so x + P < 2P, therefore (x + P) / 2 < P.
            let (addition, carry) = self.0.overflowing_add(P);
            // This is doing the above operation, treating carry .. addition as
            // a 65 bit integer.
            Self((u64::from(carry) << 63) | (addition >> 1))
        }
    }
}

impl Add for F {
    type Output = Self;

    fn add(self, b: Self) -> Self::Output {
        self.add_inner(b)
    }
}

impl Sub for F {
    type Output = Self;

    fn sub(self, b: Self) -> Self::Output {
        self.sub_inner(b)
    }
}

impl Mul for F {
    type Output = Self;

    fn mul(self, b: Self) -> Self::Output {
        Self::mul_inner(self, b)
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg_inner()
    }
}

impl From<u64> for F {
    fn from(value: u64) -> Self {
        Self::reduce_64(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_generator_calculation() {
        assert_eq!(F::GENERATOR, F(7).exp(133));
    }

    #[test]
    fn test_root_of_unity_calculation() {
        assert_eq!(F::ROOT_OF_UNITY, F::GENERATOR.exp((P - 1) >> 32));
    }

    #[test]
    fn test_root_of_unity_exp() {
        assert_eq!(F::ROOT_OF_UNITY.exp(1 << 26), F(8));
    }

    fn any_f() -> impl Strategy<Value = F> {
        any::<u64>().prop_map(F)
    }

    proptest! {
        #[test]
        fn test_add_zero_does_nothing(x in any_f()) {
            assert_eq!(x + F::zero(), x);
        }

        #[test]
        fn test_add_commutative(x in any_f(), y in any_f()) {
            assert_eq!(x + y, y + x);
        }

        #[test]
        fn test_add_associative(x in any_f(), y in any_f(), z in any_f()) {
            assert_eq!(x + (y + z), (x + y) + z);
        }

        #[test]
        fn test_mul_one_does_nothing(x in any_f()) {
            assert_eq!(x * F::one(), x);
        }

        #[test]
        fn test_mul_commutative(x in any_f(), y in any_f()) {
            assert_eq!(x * y, y * x);
        }

        #[test]
        fn test_mul_associative(x in any_f(), y in any_f(), z in any_f()) {
            assert_eq!(x * (y * z), (x * y) * z);
        }

        #[test]
        fn test_sub_eq_mul_minus_one(x in any_f(), y in any_f()) {
            assert_eq!(x - y, x + -F::one() * y);
        }

        #[test]
        fn test_exp(x in any_f(), k: u8) {
            let mut naive = F::one();
            for _ in 0..k {
                naive = naive * x;
            }
            assert_eq!(naive, x.exp(k as u64));
        }

        #[test]
        fn test_div2(x in any_f()) {
            assert_eq!((x + x).div_2(), x)
        }
    }
}
