use crate::algebra::{Additive, Field, Multiplicative, Object, Ring};
use commonware_codec::{FixedSize, Read, Write};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
#[cfg(test)]
use proptest::prelude::{Arbitrary, BoxedStrategy};
use rand_core::CryptoRngCore;

/// The modulus P := 2^64 - 2^32 + 1.
///
/// This is a prime number, and we use it to form a field of this order.
const P: u64 = u64::wrapping_neg(1 << 32) + 1;

/// An element of the [Goldilocks field](https://xn--2-umb.com/22/goldilocks/).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct F(u64);

impl FixedSize for F {
    const SIZE: usize = u64::SIZE;
}

impl Write for F {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf)
    }
}

impl Read for F {
    type Cfg = <u64 as Read>::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        u64::read_cfg(buf, cfg).map(F)
    }
}

impl core::fmt::Debug for F {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:016X}", self.0)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for F {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let x = u.arbitrary::<u64>()?;
        Ok(F::reduce_64(x))
    }
}

impl F {
    // The following constants are not randomly chosen, but computed in a specific
    // way. They could be computed at compile time, with each definition actually
    // doing the computation, but to avoid burdening compilation, we instead enforce
    // where they originate from with tests.

    /// Any non-zero element x = GENERATOR^k, for some k.
    ///
    /// This is chosen such that GENERATOR^((P - 1) / 64) = 8.
    #[cfg(test)]
    pub const GENERATOR: Self = Self(0xd64f951101aff9bf);

    /// An element of order 2^32.
    ///
    /// This is specifically chosen such that ROOT_OF_UNITY^(2^26) = 8.
    ///
    /// That enables optimizations when doing NTTs, and things like that.
    pub const ROOT_OF_UNITY: Self = Self(0xee41f5320c4ea145);

    /// An element guaranteed not to be any power of [Self::ROOT_OF_UNITY].
    pub const NOT_ROOT_OF_UNITY: Self = Self(0x79bc2f50acd74161);

    /// The inverse of [Self::NOT_ROOT_OF_UNITY].
    pub const NOT_ROOT_OF_UNITY_INV: Self = Self(0x1036c4023580ce8d);

    /// The zero element of the field.
    ///
    /// This is the identity for addition.
    const ZERO: Self = Self(0);

    /// The one element of the field.
    ///
    /// This is the identity for multiplication.
    const ONE: Self = Self(1);

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
        //
        // Note: (b << 32) - b = b * (2^32 - 1). Since b <= 2^32 - 1, this is at most
        // (2^32 - 1)^2 = 2^64 - 2^33 + 1 < 2^64. Since b << 32 >= b always,
        // this subtraction will never underflow.
        Self(a).sub_inner(Self(c)).add_inner(Self((b << 32) - b))
    }

    const fn mul_inner(self, b: Self) -> Self {
        // We do a u64 x u64 -> u128 multiplication, then reduce mod P
        Self::reduce_128((self.0 as u128) * (b.0 as u128))
    }

    const fn neg_inner(self) -> Self {
        Self::ZERO.sub_inner(self)
    }

    /// Return the multiplicative inverse of a field element.
    ///
    /// [Self::zero] will return [Self::zero].
    pub fn inv(self) -> Self {
        self.exp(&[P - 2])
    }

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

    /// Convert a stream of u64s into a stream of field elements.
    pub fn stream_from_u64s(inner: impl Iterator<Item = u64>) -> impl Iterator<Item = Self> {
        struct Iter<I> {
            acc: u128,
            acc_bits: u32,
            inner: I,
        }

        impl<I: Iterator<Item = u64>> Iterator for Iter<I> {
            type Item = F;

            fn next(&mut self) -> Option<Self::Item> {
                while self.acc_bits < 63 {
                    let Some(x) = self.inner.next() else {
                        break;
                    };
                    let x = u128::from(x);
                    self.acc |= x << self.acc_bits;
                    self.acc_bits += 64;
                }
                if self.acc_bits > 0 {
                    self.acc_bits = self.acc_bits.saturating_sub(63);
                    let out = F((self.acc as u64) & ((1 << 63) - 1));
                    self.acc >>= 63;
                    return Some(out);
                }
                None
            }
        }

        Iter {
            acc: 0,
            acc_bits: 0,
            inner,
        }
    }

    /// Convert a stream produced by [F::stream_from_u64s] back to the original stream.
    ///
    /// This may produce a single extra 0 element.
    pub fn stream_to_u64s(inner: impl Iterator<Item = Self>) -> impl Iterator<Item = u64> {
        struct Iter<I> {
            acc: u128,
            acc_bits: u32,
            inner: I,
        }

        impl<I: Iterator<Item = F>> Iterator for Iter<I> {
            type Item = u64;

            fn next(&mut self) -> Option<Self::Item> {
                // Try and fill acc with 64 bits of data.
                while self.acc_bits < 64 {
                    let Some(F(x)) = self.inner.next() else {
                        break;
                    };
                    // Ignore any upper bits of x
                    let x = u128::from(x & ((1 << 63) - 1));
                    self.acc |= x << self.acc_bits;
                    self.acc_bits += 63;
                }
                if self.acc_bits > 0 {
                    self.acc_bits = self.acc_bits.saturating_sub(64);
                    let out = self.acc as u64;
                    self.acc >>= 64;
                    return Some(out);
                }
                None
            }
        }
        Iter {
            acc: 0,
            acc_bits: 0,
            inner,
        }
    }

    /// How many elements are used to encode a given number of bits?
    ///
    /// This is based on what [F::stream_from_u64s] does.
    pub const fn bits_to_elements(bits: usize) -> usize {
        bits.div_ceil(63)
    }

    /// Convert this element to little-endian bytes.
    pub const fn to_le_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Create a random field element.
    ///
    /// This will be uniformly distributed.
    pub fn rand(mut rng: impl CryptoRngCore) -> Self {
        // this fails only about once every 2^32 attempts
        loop {
            let x = rng.next_u64();
            if x < P {
                return Self(x);
            }
        }
    }
}

impl Object for F {}

impl Add for F {
    type Output = Self;

    fn add(self, b: Self) -> Self::Output {
        self.add_inner(b)
    }
}

impl<'a> Add<&'a F> for F {
    type Output = F;

    fn add(self, rhs: &'a F) -> Self::Output {
        self + *rhs
    }
}

impl<'a> AddAssign<&'a F> for F {
    fn add_assign(&mut self, rhs: &'a F) {
        *self = *self + rhs
    }
}

impl<'a> Sub<&'a F> for F {
    type Output = Self;

    fn sub(self, rhs: &'a F) -> Self::Output {
        self - *rhs
    }
}

impl<'a> SubAssign<&'a F> for F {
    fn sub_assign(&mut self, rhs: &'a F) {
        *self = *self - rhs;
    }
}

impl Additive for F {
    fn zero() -> Self {
        Self::ZERO
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

impl<'a> Mul<&'a F> for F {
    type Output = F;

    fn mul(self, rhs: &'a F) -> Self::Output {
        self * *rhs
    }
}

impl<'a> MulAssign<&'a F> for F {
    fn mul_assign(&mut self, rhs: &'a F) {
        *self = *self * rhs;
    }
}

impl Multiplicative for F {}

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

impl Ring for F {
    fn one() -> Self {
        Self::ONE
    }
}

impl Field for F {
    fn inv(&self) -> Self {
        F::inv(*self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::algebra;
    use proptest::prelude::*;

    impl Arbitrary for F {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u64>().prop_map_into().boxed()
        }
    }

    #[test]
    fn test_generator_calculation() {
        assert_eq!(F::GENERATOR, F(7).exp(&[133]));
    }

    #[test]
    fn test_root_of_unity_calculation() {
        assert_eq!(F::ROOT_OF_UNITY, F::GENERATOR.exp(&[(P - 1) >> 32]));
    }

    #[test]
    fn test_not_root_of_unity_calculation() {
        assert_eq!(F::NOT_ROOT_OF_UNITY, F::GENERATOR.exp(&[1 << 32]));
    }

    #[test]
    fn test_not_root_of_unity_inv_calculation() {
        assert_eq!(F::NOT_ROOT_OF_UNITY * F::NOT_ROOT_OF_UNITY_INV, F::one());
    }

    #[test]
    fn test_root_of_unity_exp() {
        assert_eq!(F::ROOT_OF_UNITY.exp(&[1 << 26]), F(8));
    }

    fn test_stream_roundtrip_inner(data: Vec<u64>) {
        let mut roundtrip =
            F::stream_to_u64s(F::stream_from_u64s(data.clone().into_iter())).collect::<Vec<_>>();
        roundtrip.truncate(data.len());
        assert_eq!(data, roundtrip);
    }

    proptest! {
        #[test]
        fn test_exp(x: F, k: u8) {
            let mut naive = F::one();
            for _ in 0..k {
                naive = naive * x;
            }
            assert_eq!(naive, x.exp(&[k as u64]));
        }

        #[test]
        fn test_div2(x: F) {
            assert_eq!((x + x).div_2(), x)
        }

        #[test]
        fn test_stream_roundtrip(xs in proptest::collection::vec(any::<u64>(), 0..128)) {
            test_stream_roundtrip_inner(xs);
        }
    }

    #[test]
    fn test_field() {
        algebra::test_suites::test_field(file!(), &F::arbitrary());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<F>
        }
    }
}
