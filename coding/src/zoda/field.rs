use std::ops::Add;

/// The modulus P := 2^64 - 2^32 + 1.
///
/// This is a prime number, and we use it to form a field of this order.
const P: u64 = u64::wrapping_neg(1 << 32) + 1;

/// An element of the [Goldilocks field](https://xn--2-umb.com/22/goldilocks/).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct F(u64);

impl F {
    /// The zero element of the field.
    ///
    /// This is the identity for addition.
    pub fn zero() -> Self {
        Self(0)
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
    }
}
