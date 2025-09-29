use std::ops::{Add, Mul, Neg, Sub};

/// The modulus P := 2^64 - 2^32 + 1.
///
/// This is a prime number, and we use it to form a field of this order.
const P: u64 = u64::wrapping_neg(1 << 32) + 1;

/// An element of the [Goldilocks field](https://xn--2-umb.com/22/goldilocks/).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct F(u64);

impl F {
    /// The zero element of the field.
    ///
    /// This is the identity for addition.
    pub fn zero() -> Self {
        Self(0)
    }

    /// The one element of the field.
    ///
    /// This is the identity for multiplication.
    pub fn one() -> Self {
        Self(1)
    }

    /// Reduce a 128 bit integer into a field element.
    fn reduce_128(x: u128) -> Self {
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
        (Self(a) - Self(c)) + Self((b << 32) - b)
    }
}

impl Add for F {
    type Output = Self;

    fn add(self, b: Self) -> Self::Output {
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
}

impl Sub for F {
    type Output = Self;

    fn sub(self, b: Self) -> Self::Output {
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
}

impl Mul for F {
    type Output = Self;

    fn mul(self, b: Self) -> Self::Output {
        // We do a u64 x u64 -> u128 multiplication, then reduce mod P
        Self::reduce_128((self.0 as u128) * (b.0 as u128))
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::zero() - self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

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
    }
}
