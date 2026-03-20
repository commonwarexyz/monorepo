use super::BinaryPolynomial;

// Macro to implement binary polynomials for different sizes
macro_rules! impl_binary_poly {
    ($name:ident, $value_type:ty, $double_name:ident) => {
        #[repr(transparent)]
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
        pub struct $name($value_type);

        // SAFETY: $name is repr(transparent) over $value_type (a primitive integer type).
        unsafe impl bytemuck::Pod for $name {}
        unsafe impl bytemuck::Zeroable for $name {}

        impl $name {
            pub const fn new(val: $value_type) -> Self {
                Self(val)
            }

            pub fn value(&self) -> $value_type {
                self.0
            }

            pub fn shl(&self, n: u32) -> Self {
                Self(self.0 << n)
            }

            pub fn shr(&self, n: u32) -> Self {
                Self(self.0 >> n)
            }

            pub fn leading_zeros(&self) -> u32 {
                self.0.leading_zeros()
            }

            #[allow(dead_code)]
            pub fn split(&self) -> (Self, Self) {
                let half_bits = core::mem::size_of::<$value_type>() * 4;
                let mask = ((1u64 << half_bits) - 1) as $value_type;
                let lo = Self(self.0 & mask);
                let hi = Self(self.0 >> half_bits);
                (hi, lo)
            }
        }

        impl BinaryPolynomial for $name {
            type Value = $value_type;

            fn zero() -> Self {
                Self(0)
            }

            fn one() -> Self {
                Self(1)
            }

            fn from_value(val: u64) -> Self {
                Self(val as $value_type)
            }

            fn value(&self) -> Self::Value {
                self.0
            }

            fn add(&self, other: &Self) -> Self {
                Self(self.0 ^ other.0)
            }

            fn mul(&self, other: &Self) -> Self {
                // constant-time carryless multiplication
                let mut result = 0 as $value_type;
                let a = self.0;
                let b = other.0;
                let bits = core::mem::size_of::<$value_type>() * 8;

                for i in 0..bits {
                    // constant-time conditional xor
                    let mask = (0 as $value_type).wrapping_sub((b >> i) & 1);
                    result ^= a.wrapping_shl(i as u32) & mask;
                }

                Self(result)
            }

            fn div_rem(&self, divisor: &Self) -> (Self, Self) {
                assert_ne!(divisor.0, 0, "Division by zero");

                let mut quotient = Self::zero();
                let mut remainder = *self;

                if remainder.0 == 0 {
                    return (quotient, remainder);
                }

                let divisor_bits =
                    (core::mem::size_of::<$value_type>() * 8) as u32 - divisor.leading_zeros();
                let mut remainder_bits =
                    (core::mem::size_of::<$value_type>() * 8) as u32 - remainder.leading_zeros();

                while remainder_bits >= divisor_bits && remainder.0 != 0 {
                    let shift = remainder_bits - divisor_bits;
                    quotient.0 |= 1 << shift;
                    remainder.0 ^= divisor.0 << shift;
                    remainder_bits = (core::mem::size_of::<$value_type>() * 8) as u32
                        - remainder.leading_zeros();
                }

                (quotient, remainder)
            }
        }

        impl From<$value_type> for $name {
            fn from(val: $value_type) -> Self {
                Self(val)
            }
        }
    };
}

// Define polynomial types
impl_binary_poly!(BinaryPoly16, u16, BinaryPoly32);
impl_binary_poly!(BinaryPoly32, u32, BinaryPoly64);

// BinaryPoly64 with SIMD support
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BinaryPoly64(u64);

// SAFETY: BinaryPoly64 is repr(transparent) over u64 (a primitive).
unsafe impl bytemuck::Pod for BinaryPoly64 {}
unsafe impl bytemuck::Zeroable for BinaryPoly64 {}

impl BinaryPoly64 {
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn shl(&self, n: u32) -> Self {
        Self(self.0 << n)
    }

    pub fn shr(&self, n: u32) -> Self {
        Self(self.0 >> n)
    }

    pub fn leading_zeros(&self) -> u32 {
        self.0.leading_zeros()
    }

    pub fn split(&self) -> (BinaryPoly32, BinaryPoly32) {
        let lo = BinaryPoly32::new(self.0 as u32);
        let hi = BinaryPoly32::new((self.0 >> 32) as u32);
        (hi, lo)
    }
}

impl BinaryPolynomial for BinaryPoly64 {
    type Value = u64;

    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn from_value(val: u64) -> Self {
        Self(val)
    }

    fn value(&self) -> Self::Value {
        self.0
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0 ^ other.0)
    }

    fn mul(&self, other: &Self) -> Self {
        use super::simd::carryless_mul_64;
        carryless_mul_64(*self, *other).truncate_to_64()
    }

    fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert_ne!(divisor.0, 0, "Division by zero");

        let mut quotient = Self::zero();
        let mut remainder = *self;

        if remainder.0 == 0 {
            return (quotient, remainder);
        }

        let divisor_bits = 64 - divisor.leading_zeros();
        let mut remainder_bits = 64 - remainder.leading_zeros();

        while remainder_bits >= divisor_bits && remainder.0 != 0 {
            let shift = remainder_bits - divisor_bits;
            quotient.0 |= 1 << shift;
            remainder.0 ^= divisor.0 << shift;
            remainder_bits = 64 - remainder.leading_zeros();
        }

        (quotient, remainder)
    }
}

impl From<u64> for BinaryPoly64 {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

// BinaryPoly128
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BinaryPoly128(u128);

// SAFETY: BinaryPoly128 is repr(transparent) over u128 (a primitive).
unsafe impl bytemuck::Pod for BinaryPoly128 {}
unsafe impl bytemuck::Zeroable for BinaryPoly128 {}

impl BinaryPoly128 {
    pub const fn new(val: u128) -> Self {
        Self(val)
    }

    pub fn value(&self) -> u128 {
        self.0
    }

    pub fn truncate_to_64(&self) -> BinaryPoly64 {
        BinaryPoly64::new(self.0 as u64)
    }

    pub fn split(&self) -> (BinaryPoly64, BinaryPoly64) {
        let lo = BinaryPoly64::new(self.0 as u64);
        let hi = BinaryPoly64::new((self.0 >> 64) as u64);
        (hi, lo)
    }

    pub fn leading_zeros(&self) -> u32 {
        self.0.leading_zeros()
    }

    // full 128x128 -> 256 bit multiplication
    pub fn mul_full(&self, other: &Self) -> BinaryPoly256 {
        use super::simd::carryless_mul_128_full;
        carryless_mul_128_full(*self, *other)
    }
}

impl BinaryPolynomial for BinaryPoly128 {
    type Value = u128;

    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn from_value(val: u64) -> Self {
        Self(val as u128)
    }

    fn value(&self) -> Self::Value {
        self.0
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0 ^ other.0)
    }

    fn mul(&self, other: &Self) -> Self {
        use super::simd::carryless_mul_128;
        carryless_mul_128(*self, *other)
    }

    fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert_ne!(divisor.0, 0, "Division by zero");

        let mut quotient = Self::zero();
        let mut remainder = *self;

        if remainder.0 == 0 {
            return (quotient, remainder);
        }

        let divisor_bits = 128 - divisor.leading_zeros();
        let mut remainder_bits = 128 - remainder.leading_zeros();

        while remainder_bits >= divisor_bits && remainder.0 != 0 {
            let shift = remainder_bits - divisor_bits;
            quotient.0 |= 1u128 << shift;
            remainder.0 ^= divisor.0 << shift;
            remainder_bits = 128 - remainder.leading_zeros();
        }

        (quotient, remainder)
    }
}

impl From<u128> for BinaryPoly128 {
    fn from(val: u128) -> Self {
        Self(val)
    }
}

// BinaryPoly256 for intermediate calculations
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BinaryPoly256 {
    hi: u128,
    lo: u128,
}

impl BinaryPoly256 {
    pub fn from_parts(hi: u128, lo: u128) -> Self {
        Self { hi, lo }
    }

    pub fn split(&self) -> (BinaryPoly128, BinaryPoly128) {
        (BinaryPoly128::new(self.hi), BinaryPoly128::new(self.lo))
    }

    /// reduce modulo a 128-bit polynomial (for field operations)
    pub fn reduce_mod(&self, modulus: &BinaryPoly128) -> BinaryPoly128 {
        // for irreducible polynomials of form x^128 + lower terms,
        // we can use efficient reduction

        // special case for GF(2^128) with x^128 + x^7 + x^2 + x + 1
        if modulus.value() == (1u128 << 127) | 0x87 {
            // efficient reduction for gcm polynomial
            let mut result = self.lo;
            let mut high = self.hi;

            // reduce 128 bits at a time
            while high != 0 {
                // x^128 = x^7 + x^2 + x + 1
                let feedback =
                    high.wrapping_shl(7) ^ high.wrapping_shl(2) ^ high.wrapping_shl(1) ^ high;

                result ^= feedback;
                high >>= 121; // process remaining bits
            }

            return BinaryPoly128::new(result);
        }

        // general case: polynomial long division
        if self.hi == 0 {
            // already reduced
            return BinaryPoly128::new(self.lo);
        }

        // work with a copy
        let mut remainder_hi = self.hi;
        let mut remainder_lo = self.lo;

        // get modulus without the leading bit
        let mod_bits = 128 - modulus.leading_zeros();
        let mod_val = modulus.value();
        let mod_mask = mod_val ^ (1u128 << (mod_bits - 1));

        // reduce high 128 bits
        while remainder_hi != 0 {
            let shift = remainder_hi.leading_zeros();

            if shift < 128 {
                // align the leading bit
                let bit_pos = 127 - shift;

                // xor with modulus shifted appropriately
                remainder_hi ^= 1u128 << bit_pos;

                // xor lower bits of modulus into result
                if bit_pos >= (mod_bits - 1) {
                    remainder_hi ^= mod_mask << (bit_pos - (mod_bits - 1));
                } else {
                    let right_shift = (mod_bits - 1) - bit_pos;
                    remainder_hi ^= mod_mask >> right_shift;
                    remainder_lo ^= mod_mask << (128 - right_shift);
                }
            } else {
                break;
            }
        }

        // now reduce remainder_lo if needed
        let mut remainder = BinaryPoly128::new(remainder_lo);

        if remainder.leading_zeros() < modulus.leading_zeros() {
            let (_, r) = remainder.div_rem(modulus);
            remainder = r;
        }

        remainder
    }

    /// get the high 128 bits
    pub fn high(&self) -> BinaryPoly128 {
        BinaryPoly128::new(self.hi)
    }

    /// get the low 128 bits
    pub fn low(&self) -> BinaryPoly128 {
        BinaryPoly128::new(self.lo)
    }

    pub fn leading_zeros(&self) -> u32 {
        if self.hi == 0 {
            128 + self.lo.leading_zeros()
        } else {
            self.hi.leading_zeros()
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            hi: self.hi ^ other.hi,
            lo: self.lo ^ other.lo,
        }
    }

    pub fn shl(&self, n: u32) -> Self {
        if n == 0 {
            *self
        } else if n >= 256 {
            Self { hi: 0, lo: 0 }
        } else if n >= 128 {
            Self {
                hi: self.lo << (n - 128),
                lo: 0,
            }
        } else {
            Self {
                hi: (self.hi << n) | (self.lo >> (128 - n)),
                lo: self.lo << n,
            }
        }
    }

    pub fn shr(&self, n: u32) -> Self {
        if n == 0 {
            *self
        } else if n >= 256 {
            Self { hi: 0, lo: 0 }
        } else if n >= 128 {
            Self {
                hi: 0,
                lo: self.hi >> (n - 128),
            }
        } else {
            Self {
                hi: self.hi >> n,
                lo: (self.lo >> n) | (self.hi << (128 - n)),
            }
        }
    }
}
