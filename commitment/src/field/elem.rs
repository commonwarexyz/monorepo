use super::poly::{BinaryPoly128, BinaryPoly16, BinaryPoly32, BinaryPoly64};
use super::{BinaryFieldElement, BinaryPolynomial};

// Irreducible polynomials for field reduction
const IRREDUCIBLE_16: u32 = 0x1002D; // x^16 + x^5 + x^3 + x^2 + 1 (need to store in larger type)
const IRREDUCIBLE_32: u64 = (1u64 << 32) | 0b11001 | (1 << 7) | (1 << 9) | (1 << 15); // x^32 + Conway polynomial

macro_rules! impl_binary_elem {
    ($name:ident, $poly_type:ident, $poly_double:ident, $value_type:ty, $value_double:ty, $irreducible:expr, $bitsize:expr) => {
        #[repr(transparent)]
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
        pub struct $name($poly_type);

        // SAFETY: $name is repr(transparent) over $poly_type which wraps $value_type (a primitive integer).
        // Both Pod and Zeroable are valid because the inner type is a primitive.
        unsafe impl bytemuck::Pod for $name {}
        unsafe impl bytemuck::Zeroable for $name {}

        impl $name {
            pub const fn from_value(val: $value_type) -> Self {
                Self($poly_type::new(val))
            }

            fn mod_irreducible_wide(poly: $poly_double) -> Self {
                // Reduction using leading_zeros (lzcnt)
                let mut p = poly.value();
                let irr = $irreducible;
                let n = $bitsize;

                // Use leading_zeros for efficient reduction
                let total_bits = core::mem::size_of::<$value_double>() * 8;

                loop {
                    if p == 0 {
                        break; // avoid underflow when p is zero
                    }

                    let lz = p.leading_zeros() as usize;
                    let high_bit = total_bits - lz - 1;

                    if high_bit < n {
                        break;
                    }

                    p ^= irr << (high_bit - n);
                }

                Self($poly_type::new(p as $value_type))
            }
        }

        impl BinaryFieldElement for $name {
            type Poly = $poly_type;

            fn zero() -> Self {
                Self($poly_type::zero())
            }

            fn one() -> Self {
                Self($poly_type::one())
            }

            fn from_poly(poly: Self::Poly) -> Self {
                // For from_poly, we assume the polynomial is already reduced
                Self(poly)
            }

            fn poly(&self) -> Self::Poly {
                self.0
            }

            fn add(&self, other: &Self) -> Self {
                Self(self.0.add(&other.0))
            }

            fn mul(&self, other: &Self) -> Self {
                // Perform full multiplication using double-width type
                let a_wide = $poly_double::from_value(self.0.value() as u64);
                let b_wide = $poly_double::from_value(other.0.value() as u64);
                let prod_wide = a_wide.mul(&b_wide);

                // Reduce modulo irreducible polynomial
                Self::mod_irreducible_wide(prod_wide)
            }

            fn inv(&self) -> Self {
                assert_ne!(self.0.value(), 0, "Cannot invert zero");

                // For binary fields, we can use Fermat's little theorem efficiently
                // a^(2^n - 2) = a^(-1) in GF(2^n)

                // For small fields, use direct exponentiation
                if $bitsize <= 16 {
                    let exp = (1u64 << $bitsize) - 2;
                    return self.pow(exp);
                }

                // For larger fields, use the addition chain method
                // 2^n - 2 = 2 + 4 + 8 + ... + 2^(n-1)

                // Start with a^2
                let mut acc = self.mul(self);
                let mut result = acc; // a^2

                // Compute a^4, a^8, ..., a^(2^(n-1)) and multiply them all
                for _ in 2..$bitsize {
                    acc = acc.mul(&acc); // Square to get next power of 2
                    result = result.mul(&acc);
                }

                result
            }

            fn pow(&self, mut exp: u64) -> Self {
                if *self == Self::zero() {
                    return Self::zero();
                }

                let mut result = Self::one();
                let mut base = *self;

                while exp > 0 {
                    if exp & 1 == 1 {
                        result = result.mul(&base);
                    }
                    base = base.mul(&base);
                    exp >>= 1;
                }

                result
            }
        }

        impl From<$value_type> for $name {
            fn from(val: $value_type) -> Self {
                Self::from_value(val)
            }
        }

        impl rand::distributions::Distribution<$name> for rand::distributions::Standard {
            fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                $name::from_value(rng.gen())
            }
        }
    };
}

impl_binary_elem!(
    BinaryElem16,
    BinaryPoly16,
    BinaryPoly32,
    u16,
    u32,
    IRREDUCIBLE_16,
    16
);
impl_binary_elem!(
    BinaryElem32,
    BinaryPoly32,
    BinaryPoly64,
    u32,
    u64,
    IRREDUCIBLE_32,
    32
);

// BinaryElem128 needs special handling since we don't have BinaryPoly256
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BinaryElem128(BinaryPoly128);

// SAFETY: BinaryElem128 is repr(transparent) over BinaryPoly128 which wraps u128 (a primitive).
unsafe impl bytemuck::Pod for BinaryElem128 {}
unsafe impl bytemuck::Zeroable for BinaryElem128 {}

impl BinaryElem128 {
    pub const fn from_value(val: u128) -> Self {
        Self(BinaryPoly128::new(val))
    }
}

impl BinaryFieldElement for BinaryElem128 {
    type Poly = BinaryPoly128;

    fn zero() -> Self {
        Self(BinaryPoly128::zero())
    }

    fn one() -> Self {
        Self(BinaryPoly128::one())
    }

    fn from_poly(poly: Self::Poly) -> Self {
        Self(poly)
    }

    fn poly(&self) -> Self::Poly {
        self.0
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    fn mul(&self, other: &Self) -> Self {
        // Use SIMD carryless multiplication + reduction for performance
        use super::simd::{carryless_mul_128_full, reduce_gf128};

        let product = carryless_mul_128_full(self.0, other.0);
        let reduced = reduce_gf128(product);

        Self(reduced)
    }

    fn inv(&self) -> Self {
        assert_ne!(self.0.value(), 0, "Cannot invert zero");

        // Use Itoh-Tsujii fast inversion with precomputed nibble tables
        // Reduces from ~127 multiplications to ~9
        let result = super::fast_inverse::invert_gf128(self.0.value());
        Self(BinaryPoly128::new(result))
    }

    fn pow(&self, mut exp: u64) -> Self {
        if *self == Self::zero() {
            return Self::zero();
        }

        let mut result = Self::one();
        let mut base = *self;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            exp >>= 1;
        }

        result
    }
}

impl BinaryElem128 {
    /// Multiply by x (field element 2) - very fast special case
    ///
    /// In GF(2^128) with irreducible x^128 + x^7 + x^2 + x + 1,
    /// multiplying by x is just a left shift with conditional reduction.
    /// This is ~10x faster than general multiplication.
    #[inline]
    pub fn mul_by_x(&self) -> Self {
        let val = self.0.value();

        // Shift left by 1 (multiply by x in polynomial ring)
        let shifted = val << 1;

        // If bit 128 would be set (overflow), reduce by the irreducible polynomial
        // x^128 = x^7 + x^2 + x + 1 (mod irreducible)
        // So we add 0x87 if the high bit was set
        let overflow = (val >> 127) & 1;
        let reduced = shifted ^ (overflow * 0x87);

        Self(BinaryPoly128::new(reduced))
    }
}

impl From<u128> for BinaryElem128 {
    fn from(val: u128) -> Self {
        Self::from_value(val)
    }
}

impl rand::distributions::Distribution<BinaryElem128> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BinaryElem128 {
        BinaryElem128::from_value(rng.gen())
    }
}

// BinaryElem64 needs special handling
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BinaryElem64(BinaryPoly64);

// SAFETY: BinaryElem64 is repr(transparent) over BinaryPoly64 which wraps u64 (a primitive).
unsafe impl bytemuck::Pod for BinaryElem64 {}
unsafe impl bytemuck::Zeroable for BinaryElem64 {}

impl BinaryElem64 {
    pub const fn from_value(val: u64) -> Self {
        Self(BinaryPoly64::new(val))
    }
}

impl BinaryFieldElement for BinaryElem64 {
    type Poly = BinaryPoly64;

    fn zero() -> Self {
        Self(BinaryPoly64::zero())
    }

    fn one() -> Self {
        Self(BinaryPoly64::one())
    }

    fn from_poly(poly: Self::Poly) -> Self {
        // For now, no reduction for 64-bit field
        Self(poly)
    }

    fn poly(&self) -> Self::Poly {
        self.0
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    fn mul(&self, other: &Self) -> Self {
        Self(self.0.mul(&other.0))
    }

    fn inv(&self) -> Self {
        assert_ne!(self.0.value(), 0, "Cannot invert zero");
        // Fermat's little theorem: a^(2^64 - 2) = a^(-1)
        self.pow(0xFFFFFFFFFFFFFFFE)
    }

    fn pow(&self, mut exp: u64) -> Self {
        if *self == Self::zero() {
            return Self::zero();
        }

        let mut result = Self::one();
        let mut base = *self;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            exp >>= 1;
        }

        result
    }
}

// Field embeddings for Ligerito
impl From<BinaryElem16> for BinaryElem32 {
    fn from(elem: BinaryElem16) -> Self {
        BinaryElem32::from(elem.0.value() as u32)
    }
}

impl From<BinaryElem16> for BinaryElem64 {
    fn from(elem: BinaryElem16) -> Self {
        BinaryElem64(BinaryPoly64::new(elem.0.value() as u64))
    }
}

impl From<BinaryElem16> for BinaryElem128 {
    fn from(elem: BinaryElem16) -> Self {
        BinaryElem128::from(elem.0.value() as u128)
    }
}

impl From<BinaryElem32> for BinaryElem64 {
    fn from(elem: BinaryElem32) -> Self {
        BinaryElem64(BinaryPoly64::new(elem.0.value() as u64))
    }
}

impl From<BinaryElem32> for BinaryElem128 {
    fn from(elem: BinaryElem32) -> Self {
        BinaryElem128::from(elem.0.value() as u128)
    }
}

impl From<BinaryElem64> for BinaryElem128 {
    fn from(elem: BinaryElem64) -> Self {
        BinaryElem128::from(elem.0.value() as u128)
    }
}
