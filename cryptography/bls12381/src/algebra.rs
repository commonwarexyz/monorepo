//! Implementations of the `commonware-math` algebra traits for the scalar field types.

/// Implements the `commonware-math` field traits for a type with `const fn` arithmetic
/// methods `add`, `sub`, `neg`, `mul`, `square`, and `invert`, and constants `ZERO` and `ONE`.
macro_rules! field_traits {
    ($type:ty) => {
        impl<'a> core::ops::AddAssign<&'a Self> for $type {
            fn add_assign(&mut self, rhs: &'a Self) {
                *self = Self::add(*self, *rhs);
            }
        }

        impl<'a> core::ops::Add<&'a Self> for $type {
            type Output = Self;

            fn add(self, rhs: &'a Self) -> Self {
                Self::add(self, *rhs)
            }
        }

        impl<'a> core::ops::SubAssign<&'a Self> for $type {
            fn sub_assign(&mut self, rhs: &'a Self) {
                *self = Self::sub(*self, *rhs);
            }
        }

        impl<'a> core::ops::Sub<&'a Self> for $type {
            type Output = Self;

            fn sub(self, rhs: &'a Self) -> Self {
                Self::sub(self, *rhs)
            }
        }

        impl core::ops::Neg for $type {
            type Output = Self;

            fn neg(self) -> Self {
                Self::neg(self)
            }
        }

        impl<'a> core::ops::MulAssign<&'a Self> for $type {
            fn mul_assign(&mut self, rhs: &'a Self) {
                *self = Self::mul(*self, *rhs);
            }
        }

        impl<'a> core::ops::Mul<&'a Self> for $type {
            type Output = Self;

            fn mul(self, rhs: &'a Self) -> Self {
                Self::mul(self, *rhs)
            }
        }

        impl commonware_math::algebra::Object for $type {}

        impl commonware_math::algebra::Additive for $type {
            fn zero() -> Self {
                Self::ZERO
            }

            fn double(&mut self) {
                *self = Self::add(*self, *self);
            }
        }

        impl commonware_math::algebra::Multiplicative for $type {
            fn square(&mut self) {
                *self = Self::square(*self);
            }
        }

        impl commonware_math::algebra::Ring for $type {
            fn one() -> Self {
                Self::ONE
            }
        }

        impl commonware_math::algebra::Field for $type {
            fn inv(&self) -> Self {
                Self::invert(*self)
            }
        }
    };
}

pub(crate) use field_traits;
