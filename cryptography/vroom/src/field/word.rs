//! Fixed-width Montgomery arithmetic for the sealed field moduli.

use super::{Element, Modulus, Standard, canonical, from_canonical, inverse};
use core::{marker::PhantomData, mem::MaybeUninit};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

const LIMBS: usize = 6;
const WIDE_LIMBS: usize = 12;

unsafe extern "C" {
    fn cw_word384_add_mod_384(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
    );
    fn cw_word384_sub_mod_384(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
    );
    fn cw_word384_add_mod_384x(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
    );
    fn cw_word384_sub_mod_384x(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
    );
    fn cw_word384_mul_by_3_mod_384x(out: *mut u64, input: *const u64, modulus: *const u64);
    fn cw_word384_mul_by_8_mod_384x(out: *mut u64, input: *const u64, modulus: *const u64);
    fn cw_word384_mul_by_1_plus_i_mod_384x(out: *mut u64, input: *const u64, modulus: *const u64);
    fn cw_word384_cneg_mod_384(out: *mut u64, input: *const u64, flag: u64, modulus: *const u64);
    fn cw_word384_mul_mont_384(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
        n0: u64,
    );
    fn cw_word384_sqr_mont_384(out: *mut u64, input: *const u64, modulus: *const u64, n0: u64);
    fn cw_word384_from_mont_384(out: *mut u64, input: *const u64, modulus: *const u64, n0: u64);
    fn cw_word384_redc_mont_384(out: *mut u64, input: *const u64, modulus: *const u64, n0: u64);
    fn cw_word384_mul_384(out: *mut u64, left: *const u64, right: *const u64);
    fn cw_word384_sqr_384(out: *mut u64, input: *const u64);
    fn cw_word384_add_mod_384x384(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
    );
    fn cw_word384_sub_mod_384x384(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
    );
    fn cw_word384_mul_382x(out: *mut u64, left: *const u64, right: *const u64, modulus: *const u64);
    fn cw_word384_sqr_382x(out: *mut u64, input: *const u64, modulus: *const u64);
    fn cw_word384_mul_mont_384x(
        out: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
        n0: u64,
    );
    fn cw_word384_sqr_mont_384x(out: *mut u64, input: *const u64, modulus: *const u64, n0: u64);
}

/// A canonical six-limb Montgomery residue `aR mod p`, where `R = 2^384`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct Word<P: Modulus> {
    limbs: [u64; LIMBS],
    marker: PhantomData<P>,
}

impl Word<crate::Bls12381> {
    /// Montgomery encoding of one for the BLS12-381 coordinate field.
    pub const ONE: Self = Self::from_montgomery([
        0x760900000002fffd,
        0xebf4000bc40c0002,
        0x5f48985753c758ba,
        0x77ce585370525745,
        0x5c071a97a256ec6d,
        0x15f65ec3fa80e493,
    ]);
}

impl<P: Modulus> Word<P> {
    /// The additive identity.
    pub const ZERO: Self = Self::from_montgomery([0; LIMBS]);

    const fn from_montgomery(limbs: [u64; LIMBS]) -> Self {
        Self {
            limbs,
            marker: PhantomData,
        }
    }

    fn from_canonical_unchecked(words: &[u64; LIMBS]) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Transparent output and every input pointer have the exact
        // six-limb ABI shape, output is disjoint, and the routine writes all six
        // output limbs before return. The sealed parameters bind p, n0, and RR.
        unsafe {
            cw_word384_mul_mont_384(
                out.as_mut_ptr().cast(),
                words.as_ptr(),
                P::PARAMETERS.canonical_rr.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
                P::PARAMETERS.canonical_n0,
            );
            out.assume_init()
        }
    }

    /// Returns the multiplicative identity.
    #[inline(always)]
    pub fn one() -> Self {
        Self::from_canonical_unchecked(&[1, 0, 0, 0, 0, 0])
    }

    /// Constructs a field element from an unsigned integer.
    #[inline(always)]
    pub fn from_u64(value: u64) -> Self {
        Self::from_canonical_unchecked(&[value, 0, 0, 0, 0, 0])
    }

    /// Converts a canonical little-endian six-word integer into Montgomery form.
    ///
    /// Returns `None` when the integer is greater than or equal to the modulus.
    pub fn from_canonical(words: [u64; LIMBS]) -> Option<Self> {
        is_below(&words, &P::PARAMETERS.modulus).then(|| Self::from_canonical_unchecked(&words))
    }

    /// Returns the canonical little-endian six-word integer.
    pub fn to_canonical(&self) -> [u64; LIMBS] {
        let mut out = MaybeUninit::<[u64; LIMBS]>::uninit();
        // SAFETY: Input and output are complete, non-overlapping six-limb arrays,
        // this type guarantees a canonical Montgomery residue for sealed p, and
        // the routine writes all six output limbs before return.
        unsafe {
            cw_word384_from_mont_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
                P::PARAMETERS.canonical_n0,
            );
            out.assume_init()
        }
    }

    /// Converts an RNS field element through its canonical integer.
    pub fn from_element(value: Element<P>) -> Self {
        Self::from_canonical_unchecked(&canonical(&Standard::from(value)))
    }

    /// Converts this value into the existing RNS field representation.
    pub fn to_element(&self) -> Element<P> {
        Element::from(from_canonical::<P>(&self.to_canonical()))
    }

    /// Adds two field elements.
    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Inputs have the six-limb ABI and are below p. Output storage is
        // disjoint from both read-only inputs, which may alias. The routine
        // initializes all six output limbs.
        unsafe {
            cw_word384_add_mod_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                rhs.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
            );
            out.assume_init()
        }
    }

    /// Subtracts a field element.
    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Inputs have the six-limb ABI and are below p. Output storage is
        // disjoint from both read-only inputs, which may alias. The routine
        // initializes all six output limbs.
        unsafe {
            cw_word384_sub_mod_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                rhs.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
            );
            out.assume_init()
        }
    }

    /// Returns the additive inverse.
    #[inline(always)]
    pub fn neg(&self) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Transparent output and input have the exact six-limb ABI shape,
        // are disjoint, and input is below p. Flag one requests negation, and the
        // routine writes all output limbs.
        unsafe {
            cw_word384_cneg_mod_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                1,
                P::PARAMETERS.modulus.as_ptr(),
            );
            out.assume_init()
        }
    }

    /// Doubles this field element.
    #[inline(always)]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Multiplies two field elements.
    #[inline(always)]
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Inputs have the six-limb ABI and are canonical Montgomery residues.
        // Output storage is disjoint from both read-only inputs, which may alias.
        // The routine initializes all six output limbs.
        unsafe {
            cw_word384_mul_mont_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                rhs.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
                P::PARAMETERS.canonical_n0,
            );
            out.assume_init()
        }
    }

    /// Squares this field element using the dedicated square schedule.
    #[inline(always)]
    pub fn square(&self) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Transparent output and input have the exact six-limb ABI shape,
        // are disjoint, and input is canonical. The routine writes all output limbs.
        unsafe {
            cw_word384_sqr_mont_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
                P::PARAMETERS.canonical_n0,
            );
            out.assume_init()
        }
    }

    /// Returns the multiplicative inverse, or `None` for zero.
    pub fn invert(&self) -> Option<Self> {
        let canonical = self.to_canonical();
        let nonzero = !canonical.ct_eq(&[0; LIMBS]);
        let inverse = inverse::invert::<P>(&canonical);
        let result = Self::from_canonical_unchecked(&inverse);
        bool::from(nonzero).then_some(result)
    }

    /// Returns the unreduced twelve-limb product below `pR`.
    #[inline(always)]
    pub fn mul_wide(&self, rhs: &Self) -> Wide<P> {
        let mut out = MaybeUninit::<Wide<P>>::uninit();
        // SAFETY: Output and inputs have the exact 12/6/6-limb ABI shapes. Output
        // storage is disjoint from both read-only inputs, which may alias. The
        // routine initializes all twelve output limbs. Inputs below p give a
        // product below pR because p < R.
        unsafe {
            cw_word384_mul_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                rhs.limbs.as_ptr(),
            );
            out.assume_init()
        }
    }

    /// Returns the unreduced twelve-limb square below `pR`.
    #[inline(always)]
    pub fn square_wide(&self) -> Wide<P> {
        let mut out = MaybeUninit::<Wide<P>>::uninit();
        // SAFETY: Transparent output and input have the exact 12/6-limb ABI shapes
        // and are disjoint. The routine writes all output limbs. Since input is
        // below p and p < R, its square is below pR.
        unsafe {
            cw_word384_sqr_384(out.as_mut_ptr().cast(), self.limbs.as_ptr());
            out.assume_init()
        }
    }
}

impl<P: Modulus> ConditionallySelectable for Word<P> {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0; LIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = u64::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        Self::from_montgomery(limbs)
    }
}

impl<P: Modulus> ConstantTimeEq for Word<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.limbs.ct_eq(&other.limbs)
    }
}

impl<P: Modulus> PartialEq for Word<P> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<P: Modulus> Eq for Word<P> {}

impl<P: Modulus> Zeroize for Word<P> {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

/// A twelve-limb integer in `[0, pR)` awaiting one Montgomery reduction.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct Wide<P: Modulus> {
    limbs: [u64; WIDE_LIMBS],
    marker: PhantomData<P>,
}

impl<P: Modulus> Wide<P> {
    #[cfg(test)]
    const fn from_words(limbs: [u64; WIDE_LIMBS]) -> Self {
        Self {
            limbs,
            marker: PhantomData,
        }
    }

    /// Adds two wide values modulo `pR`.
    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Inputs have the twelve-limb ABI and satisfy `[0,pR)`. Output
        // storage is disjoint from both read-only inputs, which may alias. The
        // routine initializes all twelve output limbs.
        unsafe {
            cw_word384_add_mod_384x384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                rhs.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
            );
            out.assume_init()
        }
    }

    /// Subtracts a wide value modulo `pR`.
    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = MaybeUninit::<Self>::uninit();
        // SAFETY: Inputs have the twelve-limb ABI and satisfy `[0,pR)`. Output
        // storage is disjoint from both read-only inputs, which may alias. The
        // routine initializes all twelve output limbs.
        unsafe {
            cw_word384_sub_mod_384x384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                rhs.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
            );
            out.assume_init()
        }
    }

    /// Applies one Montgomery reduction and returns a canonical field element.
    #[inline(always)]
    pub fn reduce(&self) -> Word<P> {
        let mut out = MaybeUninit::<Word<P>>::uninit();
        // SAFETY: Transparent output and input have the exact 6/12-limb ABI shapes
        // and are disjoint. Input is below pR, and the routine writes all output
        // limbs before return.
        unsafe {
            cw_word384_redc_mont_384(
                out.as_mut_ptr().cast(),
                self.limbs.as_ptr(),
                P::PARAMETERS.modulus.as_ptr(),
                P::PARAMETERS.canonical_n0,
            );
            out.assume_init()
        }
    }
}

impl<P: Modulus> Zeroize for Wide<P> {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

/// Adds two quadratic-extension values.
#[inline(always)]
pub fn add_fp2<P: Modulus>(left: &[Word<P>; 2], right: &[Word<P>; 2]) -> [Word<P>; 2] {
    let mut out = MaybeUninit::<[Word<P>; 2]>::uninit();
    // SAFETY: Transparent words make each array a contiguous twelve-limb value.
    // Both inputs are canonical and may alias, while output storage is disjoint.
    // The routine initializes both canonical output coefficients.
    unsafe {
        cw_word384_add_mod_384x(
            out.as_mut_ptr().cast(),
            left.as_ptr().cast(),
            right.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
        );
        out.assume_init()
    }
}

/// Subtracts one quadratic-extension value from another.
#[inline(always)]
pub fn sub_fp2<P: Modulus>(left: &[Word<P>; 2], right: &[Word<P>; 2]) -> [Word<P>; 2] {
    let mut out = MaybeUninit::<[Word<P>; 2]>::uninit();
    // SAFETY: Transparent words make each array a contiguous twelve-limb value.
    // Both inputs are canonical and may alias, while output storage is disjoint.
    // The routine initializes both canonical output coefficients.
    unsafe {
        cw_word384_sub_mod_384x(
            out.as_mut_ptr().cast(),
            left.as_ptr().cast(),
            right.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
        );
        out.assume_init()
    }
}

/// Multiplies both quadratic-extension coefficients by three.
#[inline(always)]
pub fn mul_by_3_fp2<P: Modulus>(input: &[Word<P>; 2]) -> [Word<P>; 2] {
    let mut out = MaybeUninit::<[Word<P>; 2]>::uninit();
    // SAFETY: Transparent words give the input and output the exact twelve-limb
    // ABI shape. Input is canonical, output is disjoint, and the routine
    // initializes both canonical output coefficients.
    unsafe {
        cw_word384_mul_by_3_mod_384x(
            out.as_mut_ptr().cast(),
            input.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
        );
        out.assume_init()
    }
}

/// Multiplies both quadratic-extension coefficients by eight.
#[inline(always)]
pub fn mul_by_8_fp2<P: Modulus>(input: &[Word<P>; 2]) -> [Word<P>; 2] {
    let mut out = MaybeUninit::<[Word<P>; 2]>::uninit();
    // SAFETY: Transparent words give the input and output the exact twelve-limb
    // ABI shape. Input is canonical, output is disjoint, and the routine
    // initializes both canonical output coefficients.
    unsafe {
        cw_word384_mul_by_8_mod_384x(
            out.as_mut_ptr().cast(),
            input.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
        );
        out.assume_init()
    }
}

/// Multiplies a quadratic-extension value by 1 + u.
#[inline(always)]
pub fn mul_by_u_plus_one_fp2<P: Modulus>(input: &[Word<P>; 2]) -> [Word<P>; 2] {
    let mut out = MaybeUninit::<[Word<P>; 2]>::uninit();
    // SAFETY: Transparent words give the input and output the exact twelve-limb
    // ABI shape. Input is canonical, output is disjoint, and the routine
    // initializes both canonical output coefficients.
    unsafe {
        cw_word384_mul_by_1_plus_i_mod_384x(
            out.as_mut_ptr().cast(),
            input.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
        );
        out.assume_init()
    }
}

/// Multiplies two quadratic-extension values into wide real and imaginary parts.
#[inline(always)]
pub fn mul_fp2_wide<P: Modulus>(left: &[Word<P>; 2], right: &[Word<P>; 2]) -> [Wide<P>; 2] {
    let mut out = MaybeUninit::<[Wide<P>; 2]>::uninit();
    // SAFETY: Transparent words/wides make each array contiguous with the exact
    // 12/24-limb ABI shape. Inputs are below p, every sealed p is below 2^381,
    // output storage is disjoint, and the routine writes all 24 output limbs.
    unsafe {
        cw_word384_mul_382x(
            out.as_mut_ptr().cast(),
            left.as_ptr().cast(),
            right.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
        );
        out.assume_init()
    }
}

/// Squares a quadratic-extension value into wide real and imaginary parts.
#[inline(always)]
pub fn square_fp2_wide<P: Modulus>(input: &[Word<P>; 2]) -> [Wide<P>; 2] {
    let mut out = MaybeUninit::<[Wide<P>; 2]>::uninit();
    // SAFETY: Transparent words/wides make the arrays contiguous with the exact
    // 12/24-limb ABI shape. Inputs are below p, every sealed p is below 2^381,
    // output storage is disjoint, and the routine writes all 24 output limbs.
    unsafe {
        cw_word384_sqr_382x(
            out.as_mut_ptr().cast(),
            input.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
        );
        out.assume_init()
    }
}

/// Multiplies two quadratic-extension values and reduces both coefficients.
#[inline(always)]
pub fn mul_fp2<P: Modulus>(left: &[Word<P>; 2], right: &[Word<P>; 2]) -> [Word<P>; 2] {
    let mut out = MaybeUninit::<[Word<P>; 2]>::uninit();
    // SAFETY: Transparent words make each array contiguous with the exact
    // twelve-limb ABI shape. Inputs are canonical, output is disjoint, and the
    // routine writes all twelve output limbs.
    unsafe {
        cw_word384_mul_mont_384x(
            out.as_mut_ptr().cast(),
            left.as_ptr().cast(),
            right.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
            P::PARAMETERS.canonical_n0,
        );
        out.assume_init()
    }
}

/// Squares a quadratic-extension value and reduces both coefficients.
#[inline(always)]
pub fn square_fp2<P: Modulus>(input: &[Word<P>; 2]) -> [Word<P>; 2] {
    let mut out = MaybeUninit::<[Word<P>; 2]>::uninit();
    // SAFETY: Transparent words make each array contiguous with the exact
    // twelve-limb ABI shape. Inputs are canonical, output is disjoint, and the
    // routine writes all twelve output limbs.
    unsafe {
        cw_word384_sqr_mont_384x(
            out.as_mut_ptr().cast(),
            input.as_ptr().cast(),
            P::PARAMETERS.modulus.as_ptr(),
            P::PARAMETERS.canonical_n0,
        );
        out.assume_init()
    }
}

fn is_below(left: &[u64; LIMBS], right: &[u64; LIMBS]) -> bool {
    let mut borrow = false;
    for i in 0..LIMBS {
        let (difference, first) = left[i].overflowing_sub(right[i]);
        let (_, second) = difference.overflowing_sub(u64::from(borrow));
        borrow = first | second;
    }
    borrow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BanderScalar, Bls12381, BlsScalar, Curve25519};
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use subtle::{Choice, ConditionallySelectable};

    #[test]
    fn bls_coordinate_one_is_const() {
        const ONE: Word<Bls12381> = Word::<Bls12381>::ONE;
        assert_eq!(ONE, Word::<Bls12381>::one());
        assert_eq!(ONE.to_element(), Element::<Bls12381>::ONE);
    }

    fn integer(words: &[u64]) -> BigUint {
        BigUint::from_bytes_le(
            &words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
        )
    }

    fn words<const N: usize>(value: &BigUint) -> [u64; N] {
        let digits = value.to_u64_digits();
        assert!(digits.len() <= N);
        let mut out = [0; N];
        out[..digits.len()].copy_from_slice(&digits);
        out
    }

    fn word<P: Modulus>(value: &BigUint) -> Word<P> {
        Word::from_canonical(words(value)).expect("canonical word")
    }

    fn assert_word<P: Modulus>(value: &Word<P>, modulus: &BigUint) {
        assert!(integer(&value.limbs).cmp(modulus).is_lt());
    }

    fn fp2_product(left: &[BigUint; 2], right: &[BigUint; 2], modulus: &BigUint) -> [BigUint; 2] {
        [
            (&left[0] * &right[0] + modulus - (&left[1] * &right[1]) % modulus) % modulus,
            (&left[0] * &right[1] + &left[1] * &right[0]) % modulus,
        ]
    }

    fn check<P: Modulus>() {
        let modulus = integer(&P::PARAMETERS.modulus);
        let maximum = &modulus - 1u32;
        let values = [
            BigUint::zero(),
            BigUint::one(),
            BigUint::from(2u32),
            BigUint::from(u64::MAX),
            (BigUint::one() << 191usize) + BigUint::from(0x0123_4567_89ab_cdefu64),
            &modulus - 2u32,
            maximum.clone(),
        ];

        assert_eq!(core::mem::size_of::<Word<P>>(), 48);
        assert_eq!(core::mem::size_of::<Wide<P>>(), 96);
        assert!(Word::<P>::from_canonical(P::PARAMETERS.modulus).is_none());
        assert!(Word::<P>::from_canonical([u64::MAX; LIMBS]).is_none());
        assert_eq!(Word::<P>::ZERO.to_canonical(), [0; LIMBS]);
        assert_eq!(Word::<P>::one().to_canonical(), [1, 0, 0, 0, 0, 0]);
        assert_eq!(
            Word::<P>::from_u64(u64::MAX).to_canonical(),
            [u64::MAX, 0, 0, 0, 0, 0]
        );

        for left in &values {
            let a = word::<P>(left);
            assert_word(&a, &modulus);
            assert_eq!(integer(&a.to_canonical()), *left);
            assert_eq!(
                integer(&a.double().to_canonical()),
                (left << 1usize) % &modulus
            );
            assert_eq!(
                integer(&a.neg().to_canonical()),
                (&modulus - left) % &modulus
            );
            assert_eq!(a.square(), a.mul(&a));
            assert_eq!(a.square_wide().reduce(), a.square());
            assert_word(&a.double(), &modulus);
            assert_word(&a.neg(), &modulus);
            assert_word(&a.square(), &modulus);

            let element = Element::<P>::from_raw(&words::<LIMBS>(left)).expect("canonical element");
            assert_eq!(Word::from_element(element), a);
            assert_eq!(a.to_element(), element);
            let mut redundant = Standard::from(element);
            for half in 0..2 {
                let moduli = if half == 0 {
                    &P::PARAMETERS.m.moduli
                } else {
                    &P::PARAMETERS.n.moduli
                };
                for (lane, &residue_modulus) in redundant.halves[half].iter_mut().zip(moduli) {
                    *lane = *lane % residue_modulus + residue_modulus;
                }
            }
            assert_eq!(Word::from_element(Element::from(redundant)), a);

            if left.is_zero() {
                assert!(a.invert().is_none());
            } else {
                let inverse = a.invert().expect("nonzero inverse");
                assert_word(&inverse, &modulus);
                assert_eq!(a.mul(&inverse), Word::one());
                assert_eq!(
                    integer(&inverse.to_canonical()),
                    left.modpow(&(&modulus - 2u32), &modulus)
                );
            }

            for right in &values {
                let b = word::<P>(right);
                assert_word(&b, &modulus);
                assert_eq!(
                    Word::conditional_select(&a, &b, Choice::from(0)).limbs,
                    a.limbs
                );
                assert_eq!(
                    Word::conditional_select(&a, &b, Choice::from(1)).limbs,
                    b.limbs
                );
                assert_eq!(
                    integer(&a.add(&b).to_canonical()),
                    (left + right) % &modulus
                );
                assert_eq!(
                    integer(&a.sub(&b).to_canonical()),
                    (left + &modulus - right) % &modulus
                );
                assert_eq!(
                    integer(&a.mul(&b).to_canonical()),
                    (left * right) % &modulus
                );
                assert_eq!(a.mul_wide(&b).reduce(), a.mul(&b));

                assert_word(&a.add(&b), &modulus);
                assert_word(&a.sub(&b), &modulus);
                assert_word(&a.mul(&b), &modulus);

                let sum = a.square_wide().add(&b.square_wide());
                let difference = a.square_wide().sub(&b.square_wide());
                assert_eq!(sum.reduce(), a.square().add(&b.square()));
                assert_eq!(difference.reduce(), a.square().sub(&b.square()));
            }
        }

        let wide_modulus = &modulus << 384usize;
        let wide_maximum = Wide::<P>::from_words(words::<WIDE_LIMBS>(&(&wide_modulus - 1u32)));
        let wide_one = Wide::<P>::from_words(words::<WIDE_LIMBS>(&BigUint::one()));
        let wide_zero = Wide::<P>::from_words([0; WIDE_LIMBS]);
        assert_eq!(wide_maximum.add(&wide_one).limbs, [0; WIDE_LIMBS]);
        assert_eq!(wide_zero.sub(&wide_one).limbs, wide_maximum.limbs);
        let r = (BigUint::one() << 384usize) % &modulus;
        let r_inverse = r.modpow(&(&modulus - 2u32), &modulus);
        let expected_maximum = (&modulus - (&r_inverse * &r_inverse) % &modulus) % &modulus;
        let reduced_maximum = wide_maximum.reduce();
        assert_word(&reduced_maximum, &modulus);
        assert_eq!(integer(&reduced_maximum.to_canonical()), expected_maximum);

        let fp2_cases = [
            (
                [BigUint::zero(), BigUint::zero()],
                [BigUint::zero(), BigUint::zero()],
            ),
            (
                [BigUint::one(), BigUint::zero()],
                [BigUint::zero(), BigUint::one()],
            ),
            (
                [maximum.clone(), maximum.clone()],
                [maximum.clone(), maximum.clone()],
            ),
            (
                [values[4].clone(), values[6].clone()],
                [values[5].clone(), values[3].clone()],
            ),
        ];
        for (left_values, right_values) in fp2_cases {
            let left = [word::<P>(&left_values[0]), word::<P>(&left_values[1])];
            let right = [word::<P>(&right_values[0]), word::<P>(&right_values[1])];
            let expected_product = fp2_product(&left_values, &right_values, &modulus);
            let expected_square = fp2_product(&left_values, &left_values, &modulus);

            let product = mul_fp2(&left, &right);
            let wide_product = mul_fp2_wide(&left, &right);
            let square = square_fp2(&left);
            let wide_square = square_fp2_wide(&left);
            for i in 0..2 {
                assert_word(&product[i], &modulus);
                assert_eq!(integer(&product[i].to_canonical()), expected_product[i]);
                assert_eq!(wide_product[i].reduce(), product[i]);
                assert!(integer(&wide_product[i].limbs) < wide_modulus);
                assert_word(&square[i], &modulus);
                assert_eq!(integer(&square[i].to_canonical()), expected_square[i]);
                assert_eq!(wide_square[i].reduce(), square[i]);
                assert!(integer(&wide_square[i].limbs) < wide_modulus);
            }
        }

        // The specialized loose routines admit any canonical Montgomery limbs below
        // p, including values near p that do not arise by encoding canonical p-1.
        let raw_near_modulus = [
            Word::<P>::from_montgomery(words::<LIMBS>(&maximum)),
            Word::<P>::from_montgomery(words::<LIMBS>(&(&modulus - 2u32))),
        ];
        let raw_values = raw_near_modulus
            .each_ref()
            .map(|value| integer(&value.to_canonical()));
        let raw_expected = fp2_product(&raw_values, &raw_values, &modulus);
        let raw_product = mul_fp2(&raw_near_modulus, &raw_near_modulus);
        let raw_wide_product = mul_fp2_wide(&raw_near_modulus, &raw_near_modulus);
        let raw_square = square_fp2(&raw_near_modulus);
        let raw_wide_square = square_fp2_wide(&raw_near_modulus);
        for i in 0..2 {
            assert_eq!(integer(&raw_product[i].to_canonical()), raw_expected[i]);
            assert_eq!(raw_wide_product[i].reduce(), raw_product[i]);
            assert!(integer(&raw_wide_product[i].limbs) < wide_modulus);
            assert_eq!(integer(&raw_square[i].to_canonical()), raw_expected[i]);
            assert_eq!(raw_wide_square[i].reduce(), raw_square[i]);
            assert!(integer(&raw_wide_square[i].limbs) < wide_modulus);
        }

        let mut erased_word = word::<P>(&maximum);
        erased_word.zeroize();
        assert_eq!(erased_word, Word::ZERO);
        let mut erased_wide = wide_maximum;
        erased_wide.zeroize();
        assert_eq!(erased_wide.limbs, [0; WIDE_LIMBS]);
    }

    #[test]
    fn sealed_moduli_match_integer_oracle() {
        check::<Bls12381>();
        check::<BlsScalar>();
        check::<BanderScalar>();
        check::<Curve25519>();
    }

    fn check_bulk_fp2<P: Modulus>() {
        let modulus = integer(&P::PARAMETERS.modulus);
        let maximum = &modulus - 1u32;
        let raw_maximum = Word::<P>::from_montgomery(words::<LIMBS>(&maximum));
        let raw_minus_two = Word::<P>::from_montgomery(words::<LIMBS>(&(&modulus - 2u32)));
        let mixed =
            word::<P>(&((BigUint::one() << 191usize) + BigUint::from(0x0123_4567_89ab_cdefu64)));
        let cases = [
            [Word::ZERO, Word::ZERO],
            [Word::one(), Word::ZERO],
            [Word::ZERO, raw_maximum],
            [raw_minus_two, Word::one()],
            [mixed, raw_maximum],
            [raw_maximum, raw_minus_two],
        ];

        for value in &cases {
            let expected_three = [
                value[0].double().add(&value[0]),
                value[1].double().add(&value[1]),
            ];
            let expected_eight = [
                value[0].double().double().double(),
                value[1].double().double().double(),
            ];
            let expected_nonresidue = [value[0].sub(&value[1]), value[0].add(&value[1])];
            assert_eq!(mul_by_3_fp2(value), expected_three);
            assert_eq!(mul_by_8_fp2(value), expected_eight);
            assert_eq!(mul_by_u_plus_one_fp2(value), expected_nonresidue);
            assert_eq!(
                add_fp2(value, value),
                [value[0].add(&value[0]), value[1].add(&value[1])]
            );
            assert_eq!(sub_fp2(value, value), [Word::ZERO; 2]);

            for output in [
                mul_by_3_fp2(value),
                mul_by_8_fp2(value),
                mul_by_u_plus_one_fp2(value),
            ] {
                assert_word(&output[0], &modulus);
                assert_word(&output[1], &modulus);
            }

            for right in &cases {
                let sum = add_fp2(value, right);
                let difference = sub_fp2(value, right);
                assert_eq!(sum, [value[0].add(&right[0]), value[1].add(&right[1])]);
                assert_eq!(
                    difference,
                    [value[0].sub(&right[0]), value[1].sub(&right[1])]
                );
                assert_word(&sum[0], &modulus);
                assert_word(&sum[1], &modulus);
                assert_word(&difference[0], &modulus);
                assert_word(&difference[1], &modulus);
            }
        }
    }

    #[test]
    fn bulk_fp2_linear_operations_match_scalar_words() {
        check_bulk_fp2::<Bls12381>();
        check_bulk_fp2::<BlsScalar>();
        check_bulk_fp2::<BanderScalar>();
        check_bulk_fp2::<Curve25519>();
    }

    fn blst_words(value: &blst::blst_fp) -> [u64; LIMBS] {
        let mut out = [0; LIMBS];
        // SAFETY: Both pointers address the complete blst field/word arrays.
        unsafe { blst::blst_uint64_from_fp(out.as_mut_ptr(), value) };
        out
    }

    fn blst_fp(words: &[u64; LIMBS]) -> blst::blst_fp {
        let mut out = blst::blst_fp::default();
        // SAFETY: Both pointers address complete six-limb arrays and the test inputs
        // are canonical BLS12-381 field integers.
        unsafe { blst::blst_fp_from_uint64(&mut out, words.as_ptr()) };
        out
    }

    #[test]
    fn bls12381_matches_blst_oracle() {
        let modulus = integer(&Bls12381::PARAMETERS.modulus);
        let left_words = words::<LIMBS>(&(&modulus - 2u32));
        let right_words = words::<LIMBS>(
            &((BigUint::one() << 255usize) + BigUint::from(0xdead_beef_cafe_babeu64)),
        );
        let left = Word::<Bls12381>::from_canonical(left_words).expect("canonical left");
        let right = Word::<Bls12381>::from_canonical(right_words).expect("canonical right");
        let blst_left = blst_fp(&left_words);
        let blst_right = blst_fp(&right_words);

        let mut blst_product = blst::blst_fp::default();
        let mut blst_square = blst::blst_fp::default();
        // SAFETY: Inputs and outputs are distinct, initialized blst field values.
        unsafe {
            blst::blst_fp_mul(&mut blst_product, &blst_left, &blst_right);
            blst::blst_fp_sqr(&mut blst_square, &blst_left);
        }
        assert_eq!(left.mul(&right).to_canonical(), blst_words(&blst_product));
        assert_eq!(left.square().to_canonical(), blst_words(&blst_square));

        let left_fp2 = blst::blst_fp2 {
            fp: [blst_left, blst_right],
        };
        let right_fp2 = blst::blst_fp2 {
            fp: [blst_right, blst_left],
        };
        let mut blst_product_fp2 = blst::blst_fp2::default();
        let mut blst_square_fp2 = blst::blst_fp2::default();
        // SAFETY: Inputs and outputs are distinct, initialized blst Fp2 values.
        unsafe {
            blst::blst_fp2_mul(&mut blst_product_fp2, &left_fp2, &right_fp2);
            blst::blst_fp2_sqr(&mut blst_square_fp2, &left_fp2);
        }

        let word_left = [left, right];
        let word_right = [right, left];
        let product_fp2 = mul_fp2(&word_left, &word_right);
        let square_fp2 = square_fp2(&word_left);
        for i in 0..2 {
            assert_eq!(
                product_fp2[i].to_canonical(),
                blst_words(&blst_product_fp2.fp[i])
            );
            assert_eq!(
                square_fp2[i].to_canonical(),
                blst_words(&blst_square_fp2.fp[i])
            );
        }
    }
}
