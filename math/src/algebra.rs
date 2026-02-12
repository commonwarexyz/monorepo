//! Provides traits for algebraic operations.
//!
//! These traits are designed to lean on the existing Rust operations in [`std::ops`],
//! so that the familiar `+`, `+=`, etc. operators can be used. The traits are also
//! designed with performant implementations in mind, so implementations try to
//! use methods which don't require copying unnecessarily.
use commonware_parallel::Strategy as ParStrategy;
use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRngCore;

/// Yield all the bits in a u64, from lowest to highest.
fn yield_bits_le(x: u64) -> impl Iterator<Item = bool> {
    (0..64).map(move |i| (x >> i) & 1 != 0)
}

/// Yield the bits in a u64, until they all become 0.
fn yield_bits_le_until_zeroes(x: u64) -> impl Iterator<Item = bool> {
    (0..64 - x.leading_zeros()).map(move |i| (x >> i) & 1 != 0)
}

/// Yield all of the bits in an array of u64s, in little endian order.
fn yield_bits_le_arr(xs: &[u64]) -> impl Iterator<Item = bool> + use<'_> {
    let (&last, start) = xs.split_last().unwrap_or((&0, &[]));
    start
        .iter()
        .copied()
        .flat_map(yield_bits_le)
        .chain(yield_bits_le_until_zeroes(last))
}

/// Inner utility for [`Additive::scale`] and [`Ring::exp`].
///
/// The "double-and-add" / "square-and-multiply" algorithms work over an arbitrary
/// monoid, i.e. something supporting:
///
/// 1. 1 : T
/// 2. (<>) : T -> T -> T
///
/// We take these two operations, along with a helper for applying the operation
/// to oneself, in order to make the algorithm generic.
fn monoid_exp<T: Clone>(
    zero: T,
    op: impl Fn(&mut T, &T),
    self_op: impl Fn(&mut T),
    x: &T,
    bits_le: &[u64],
) -> T {
    let mut acc = zero;
    let mut w = x.clone();
    for b in yield_bits_le_arr(bits_le) {
        if b {
            op(&mut acc, &w);
        }
        self_op(&mut w)
    }
    acc
}

/// Return `[1, base, base^2, ..., base^(len - 1)]`.
pub fn powers<R: Ring>(base: &R, len: usize) -> impl Iterator<Item = R> + '_ {
    (0..len).scan(R::one(), move |state, _| {
        let out = state.clone();
        *state *= base;
        Some(out)
    })
}

/// A basic trait we expect algebraic data structures to implement.
///
/// Types implementing this trait need to support:
///
/// 1. `T.clone()`,
/// 2. `format!("{:?}", &T)`
/// 2. `&T == &T`,
/// 3. `&T != &T`.
///
/// In other words, being clonable, and comparable for equality.
pub trait Object: Clone + Debug + PartialEq + Eq + Send + Sync {}

/// A type that supports addition, subtraction, and negation.
///
/// For some type `T` implementing this trait, the following operations must be
/// supported:
///
/// 1. `&mut T += &T`,
/// 2. `T + &T`,
/// 3. `&mut T -= &T`,
/// 4. `T - &T`,
/// 5. `-T`.
///
/// There are other combinations of borrowing that could be chosen, but these
/// should be efficiently implementable, even for a "heavier" struct, e.g.
/// a vector of values.
///
/// # Usage
///
///
/// ```
/// # use commonware_math::algebra::Additive;
///
/// // We use .clone() whenever ownership is needed.
/// fn example<T: Additive>(mut x: T, y: T) {
///     x += &y;
///     x.clone() + &y;
///     x -= &y;
///     x.clone() - &y;
///     -x.clone();
///     T::zero();
/// }
/// ```
pub trait Additive:
    Object
    + for<'a> AddAssign<&'a Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Neg<Output = Self>
{
    /// The neutral element for addition.
    fn zero() -> Self;

    /// Add an element to itself.
    ///
    /// This has a default implementation involving a clone.
    ///
    /// This can be overriden if a more efficient implementation is available.
    fn double(&mut self) {
        *self += &self.clone();
    }

    /// Scale this number by a positive integer.
    ///
    /// To support arbitrary positive integers, we expect to see 64 bit limbs
    /// in little endian order.
    ///
    /// For example, for a 256 bit integer, we expect a slice of 4 elements,
    /// starting with the lowest 64 bits.
    fn scale(&self, bits_le: &[u64]) -> Self {
        monoid_exp(Self::zero(), |a, b| *a += b, |a| a.double(), self, bits_le)
    }
}

/// A type that supports multiplication.
///
/// For some type `T` implementing this trait, the following operations must be
/// supported:
///
/// 1. `&mut T *= &T`,
/// 2. `T * &T`.
///
/// As with [`Additive`], the borrowing scheme is chosen to keep implementations
/// efficient even for heavier structures.
///
/// # Usage
///
/// ```
/// # use commonware_math::algebra::Multiplicative;
///
/// // We use .clone() whenever ownership is needed.
/// fn example<T: Multiplicative>(mut x: T, y: T) {
///     x *= &y;
///     x.clone() * &y;
/// }
/// ```
pub trait Multiplicative:
    Object + for<'a> MulAssign<&'a Self> + for<'a> Mul<&'a Self, Output = Self>
{
    /// Multiply an element with itself.
    ///
    /// This has a default implementation involving a clone.
    ///
    /// This can be overriden for a specific type that's better.
    fn square(&mut self) {
        *self *= &self.clone();
    }
}

/// A type which implements [`Additive`], and supports scaling by some other type.
///
/// Mathematically, this is a (right) `R`-module.
///
/// The following operations must be supported (in addition to [`Additive`]):
/// 1. `T *= &R`,
/// 2. `T * &R`
///
///
/// # Usage
///
/// ```
/// # use commonware_math::algebra::Space;
///
/// // We use .clone() whenever ownership is needed.
/// fn example<R, T: Space<R>>(mut x: T, y: R) {
///     x *= &y;
///     x.clone() * &y;
/// }
/// ```
pub trait Space<R>:
    Additive + for<'a> MulAssign<&'a R> + for<'a> Mul<&'a R, Output = Self>
{
    /// Calculate `sum_i points[i] * scalars[i]`.
    ///
    /// There's a default implementation, but for many types, a more efficient
    /// algorithm is possible.
    ///
    /// Both slices should be considered as padded with [`Additive::zero`] so
    /// that they have the same length.
    ///
    /// For empty slices, the result should be [`Additive::zero`];
    fn msm(points: &[Self], scalars: &[R], _strategy: &impl ParStrategy) -> Self {
        msm_naive(points, scalars)
    }
}

/// A naive implementation of [`Space::msm`].
///
/// This is what the trait does by default.
///
/// This is useful when implementing the trait, because for small inputs it
/// might be worth just using the naive implementation, because faster
/// algorithms have some overhead in terms of allocating space.
pub fn msm_naive<R, K: Space<R>>(points: &[K], scalars: &[R]) -> K {
    let mut out = K::zero();
    for (s, p) in scalars.iter().zip(points.iter()) {
        out += &(p.clone() * s);
    }
    out
}

impl<R: Additive + Multiplicative> Space<R> for R {}

/// An instance of a mathematical Ring.
///
/// This combines [`Additive`] and [`Multiplicative`], and introduces a
/// neutral element for multiplication, [`Ring::one`].
pub trait Ring: Additive + Multiplicative {
    /// The neutral element for multiplication.
    ///
    /// Multiplying by this element does nothing.
    fn one() -> Self;

    /// Exponentiate this number by a positive integer.
    ///
    /// To support arbitrary positive integers, we expect to see 64 bit limbs
    /// in little endian order.
    ///
    /// For example, for a 256 bit integer, we expect a slice of 4 elements,
    /// starting with the lowest 64 bits.
    fn exp(&self, bits_le: &[u64]) -> Self {
        monoid_exp(Self::one(), |a, b| *a *= b, |a| a.square(), self, bits_le)
    }
}

/// An instance of a mathematical Field.
///
/// This inherits from [`Ring`], and requires the existence of multiplicative
/// inverses as well.
pub trait Field: Ring {
    /// The multiplicative inverse of an element.
    ///
    /// For [`Additive::zero`], this should return [`Additive::zero`].
    ///
    /// For any other element `x`, this should return an element `y` such that
    /// `x * y` is equal to [`Ring::one`].
    fn inv(&self) -> Self;
}

/// A [`Field`] which supports operations allowing for efficient NTTs.
///
/// Fields implementing this trait must have characteristic not equal to 2
/// (so that 2 is invertible), and must have a multiplicative group with
/// sufficiently large 2-adic order.
pub trait FieldNTT: Field {
    /// The maximum (lg) of the power of two root of unity this fields supports.
    const MAX_LG_ROOT_ORDER: u8;

    /// A root of unity of order `2^lg`.
    ///
    /// In other words, for `r = root_of_unity(lg)`, `k = 2^lg` should be the
    /// smallest power such that `r^k = 1`.
    ///
    /// This function should return `None` only for `lg > MAX_LG_ROOT_ORDER`.
    fn root_of_unity(lg: u8) -> Option<Self>;

    /// An element which is not a power of a root of unity.
    ///
    /// In other words, for any `lg`, `k`, this element should not equal
    /// `Self::root_of_unity(lg)^k`.
    fn coset_shift() -> Self;

    fn coset_shift_inv() -> Self {
        Self::coset_shift().inv()
    }

    /// Return the result of dividing this element by `2`.
    ///
    /// This is equivalent to `self * (1 + 1)^-1`, but is usually implementable
    /// in a more efficient way.
    fn div_2(&self) -> Self {
        (Self::one() + &Self::one()).inv() * self
    }
}

/// A group suitable for use in cryptography.
///
/// This is a cyclic group, with a specified generator.
///
/// The group is of prime order, and thus has an associated field of scalars.
///
/// This trait requires that this type implements [`Space`] over that field.
pub trait CryptoGroup: Space<Self::Scalar> {
    type Scalar: Field;

    /// Return the generator point of this group.
    fn generator() -> Self;
}

/// A [`CryptoGroup`] which supports obliviously sampling elements.
///
/// This capability is also often referred to as "hash to curve", in the
/// context of Elliptic Curve Cryptography, but we use the term "group"
/// to match the naming conventions for other traits.
///
/// Advanced protocols use this capability to create new generator elements
/// whose discrete logarithm relative to other points is unknown.
pub trait HashToGroup: CryptoGroup {
    /// Hash a domain separator, and a message, returning a group element.
    ///
    /// This should return an element without knowing its discrete logarithm.
    ///
    /// In particular, hashing into a [`CryptoGroup::Scalar`], and then multiplying
    /// that by [`CryptoGroup::generator`] DOES NOT work.
    fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Self;

    /// Convert randomness to a group element, without learning its discrete logarithm.
    ///
    /// This has a default implementation assuming 128 bits of collision security.
    /// This works by generating 256 bits of randomness, and then passing that
    /// to [`HashToGroup::hash_to_group`].
    ///
    /// If you have a more efficient implementation, or want more collision security,
    /// override this method.
    fn rand_to_group(mut rng: impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::hash_to_group(&[], &bytes)
    }
}

/// A trait for objects that can be randomly sampled.
///
/// The only stipulation about this sampling process is that the result
/// should be indistinguishable from one sampled uniformly at random.
///
/// Beyond that, we don't assume that we don't learn other things about the
/// object as the sampler.
pub trait Random {
    /// Sample an object uniformly at random.
    fn random(rng: impl CryptoRngCore) -> Self;
}

#[cfg(any(test, feature = "arbitrary"))]
pub mod test_suites {
    //! A collection of property tests for algebraic types.
    //!
    //! Provides pre-canned test suites that verify algebraic laws hold for a given type.
    //! For example, [`fuzz_additive`] checks:
    //!
    //! - `+=` is consistent with `+`
    //! - Addition is commutative
    //! - Addition is associative
    //! - Zero is the neutral element
    //! - Negation is the additive inverse
    //!
    //! These functions take `&mut Unstructured` so users can run the harness themselves.
    //!
    //! # Example
    //!
    //! ```
    //! # use commonware_math::algebra::test_suites::*;
    //! # use commonware_math::fields::goldilocks::F;
    //! commonware_invariants::minifuzz::test(|u| fuzz_field::<F>(u));
    //! ```
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    fn check_add_assign<T: Additive>(a: T, b: T) {
        let mut acc = a.clone();
        acc += &b;
        assert_eq!(acc, a + &b, "+= does not match +");
    }

    fn check_add_commutes<T: Additive>(a: T, b: T) {
        assert_eq!(a.clone() + &b, b + &a, "+ not commutative");
    }

    fn check_add_associates<T: Additive>(a: T, b: T, c: T) {
        assert_eq!((a.clone() + &b) + &c, a + &(b + &c), "+ not associative");
    }

    fn check_add_zero<T: Additive>(a: T) {
        assert_eq!(T::zero() + &a, a, "a + 0 != a");
    }

    fn check_add_neg_self<T: Additive>(a: T) {
        let neg_a = -a.clone();
        assert_eq!(T::zero(), a + &neg_a, "a - a != 0");
    }

    fn check_sub_vs_add_neg<T: Additive>(a: T, b: T) {
        assert_eq!(a.clone() - &b, a + &-b, "a - b != a + (-b)");
    }

    fn check_sub_assign<T: Additive>(a: T, b: T) {
        let mut acc = a.clone();
        acc -= &b;
        assert_eq!(acc, a - &b, "-= different from -");
    }

    /// Fuzz the [`Additive`] trait properties.
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    pub fn fuzz_additive<T: Additive + for<'a> Arbitrary<'a>>(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let a: T = u.arbitrary()?;
        let b: T = u.arbitrary()?;
        let c: T = u.arbitrary()?;
        check_add_assign(a.clone(), b.clone());
        check_add_commutes(a.clone(), b.clone());
        check_add_associates(a.clone(), b.clone(), c);
        check_add_zero(a.clone());
        check_add_neg_self(a.clone());
        check_sub_vs_add_neg(a.clone(), b.clone());
        check_sub_assign(a, b);
        Ok(())
    }

    fn check_mul_assign<T: Multiplicative>(a: T, b: T) {
        let mut acc = a.clone();
        acc *= &b;
        assert_eq!(acc, a * &b, "*= different from *");
    }

    fn check_mul_commutes<T: Multiplicative>(a: T, b: T) {
        assert_eq!(a.clone() * &b, b * &a, "* not commutative");
    }

    fn check_mul_associative<T: Multiplicative>(a: T, b: T, c: T) {
        assert_eq!((a.clone() * &b) * &c, a * &(b * &c), "* not associative");
    }

    /// Fuzz the [`Multiplicative`] trait properties.
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    pub fn fuzz_multiplicative<T: Multiplicative + for<'a> Arbitrary<'a>>(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let a: T = u.arbitrary()?;
        let b: T = u.arbitrary()?;
        let c: T = u.arbitrary()?;
        check_mul_assign(a.clone(), b.clone());
        check_mul_commutes(a.clone(), b.clone());
        check_mul_associative(a, b, c);
        Ok(())
    }

    fn check_mul_one<T: Ring>(a: T) {
        assert_eq!(T::one() * &a, a, "a * 1 != a");
    }

    fn check_mul_distributes<T: Ring>(a: T, b: T, c: T) {
        assert_eq!(
            (a.clone() + &b) * &c,
            a * &c + &(b * &c),
            "(a + b) * c != a * c + b * c"
        );
    }

    /// Fuzz the [`Ring`] trait properties.
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    /// This also checks [`Additive`] and [`Multiplicative`] properties.
    pub fn fuzz_ring<T: Ring + for<'a> Arbitrary<'a>>(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        fuzz_additive::<T>(u)?;
        fuzz_multiplicative::<T>(u)?;
        let a: T = u.arbitrary()?;
        let b: T = u.arbitrary()?;
        let c: T = u.arbitrary()?;
        check_mul_one(a.clone());
        check_mul_distributes(a, b, c);
        Ok(())
    }

    fn check_inv<T: Field>(a: T) {
        if a == T::zero() {
            assert_eq!(T::zero(), a.inv(), "0.inv() != 0");
        } else {
            assert_eq!(a.inv() * &a, T::one(), "a * a.inv() != 1");
        }
    }

    /// Fuzz the [`Field`] trait properties.
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    /// This also checks [`Ring`] properties.
    pub fn fuzz_field<T: Field + for<'a> Arbitrary<'a>>(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        fuzz_ring::<T>(u)?;
        let a: T = u.arbitrary()?;
        check_inv(a);
        Ok(())
    }

    fn check_scale_distributes<R, K: Space<R>>(a: K, b: K, x: R) {
        assert_eq!((a.clone() + &b) * &x, a * &x + &(b * &x));
    }

    fn check_scale_assign<R, K: Space<R>>(a: K, b: R) {
        let mut acc = a.clone();
        acc *= &b;
        assert_eq!(acc, a * &b);
    }

    fn check_msm_eq_naive<R, K: Space<R>>(points: &[K], scalars: &[R]) {
        use commonware_parallel::Sequential;
        assert_eq!(
            msm_naive(points, scalars),
            K::msm(points, scalars, &Sequential)
        );
    }

    /// Fuzz the [`Space`] trait properties, assuming nothing about the scalar `R`.
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    pub fn fuzz_space<R: Debug + for<'a> Arbitrary<'a>, K: Space<R> + for<'a> Arbitrary<'a>>(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let a: K = u.arbitrary()?;
        let b: K = u.arbitrary()?;
        let x: R = u.arbitrary()?;
        check_scale_distributes(a.clone(), b, x);
        let c: R = u.arbitrary()?;
        check_scale_assign(a, c);
        let len: usize = u.int_in_range(0..=16)?;
        let points: Vec<K> = (0..len)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;
        let scalars: Vec<R> = (0..len)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;
        check_msm_eq_naive(&points, &scalars);
        Ok(())
    }

    fn check_scale_compat<R: Multiplicative, K: Space<R>>(a: K, b: R, c: R) {
        assert_eq!((a.clone() * &b) * &c, a * &(b * &c));
    }

    /// Fuzz the [`Space`] trait properties, assuming `R` is [`Multiplicative`].
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    /// This also checks base [`Space`] properties plus compatibility with multiplication.
    pub fn fuzz_space_multiplicative<
        R: Multiplicative + for<'a> Arbitrary<'a>,
        K: Space<R> + for<'a> Arbitrary<'a>,
    >(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        fuzz_space::<R, K>(u)?;
        let a: K = u.arbitrary()?;
        let b: R = u.arbitrary()?;
        let c: R = u.arbitrary()?;
        check_scale_compat(a, b, c);
        Ok(())
    }

    fn check_scale_one<R: Ring, K: Space<R>>(a: K) {
        assert_eq!(a.clone(), a * &R::one());
    }

    fn check_scale_zero<R: Ring, K: Space<R>>(a: K) {
        assert_eq!(K::zero(), a * &R::zero());
    }

    /// Fuzz the [`Space`] trait properties, assuming `R` is a [`Ring`].
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    /// This also checks [`fuzz_space_multiplicative`] properties plus compatibility
    /// with [`Ring::one()`] and [`Additive::zero()`].
    pub fn fuzz_space_ring<R: Ring + for<'a> Arbitrary<'a>, K: Space<R> + for<'a> Arbitrary<'a>>(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        fuzz_space_multiplicative::<R, K>(u)?;
        let a: K = u.arbitrary()?;
        check_scale_one::<R, K>(a.clone());
        check_scale_zero::<R, K>(a);
        Ok(())
    }

    fn check_hash_to_group<G: HashToGroup>(data: [[u8; 4]; 4]) {
        let (dst0, m0, dst1, m1) = (&data[0], &data[1], &data[2], &data[3]);
        assert_eq!(
            (dst0, m0) == (dst1, m1),
            G::hash_to_group(dst0, m0) == G::hash_to_group(dst1, m1)
        );
    }

    /// Fuzz the [`HashToGroup`] trait properties.
    ///
    /// Takes arbitrary data and checks that the hash function is deterministic.
    /// This doesn't check any properties related to [`CryptoGroup`].
    pub fn fuzz_hash_to_group<G: HashToGroup>(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let data: [[u8; 4]; 4] = u.arbitrary()?;
        check_hash_to_group::<G>(data);
        Ok(())
    }

    fn check_root_of_unity_order<T: FieldNTT>(lg: u8) {
        if lg > T::MAX_LG_ROOT_ORDER {
            assert!(
                T::root_of_unity(lg).is_none(),
                "root_of_unity should be None for lg > MAX"
            );
            return;
        }
        let root = T::root_of_unity(lg).expect("root_of_unity should be Some for lg <= MAX");

        let mut order = Vec::new();
        let mut remaining = lg;
        while remaining >= 64 {
            order.push(0u64);
            remaining -= 64;
        }
        order.push(1u64 << remaining);

        assert_eq!(root.exp(&order), T::one(), "root^(2^lg) should equal 1");
        if lg > 0 {
            let last = order.len() - 1;
            order[0] = order[0].wrapping_sub(1);
            for i in 0..last {
                if order[i] == u64::MAX {
                    order[i + 1] = order[i + 1].wrapping_sub(1);
                }
            }
            assert_ne!(
                root.exp(&order),
                T::one(),
                "root^(2^lg - 1) should not equal 1"
            );
        }
    }

    fn check_div_2<T: FieldNTT>(a: T) {
        let two = T::one() + &T::one();
        assert_eq!(a.div_2() * &two, a, "div_2(a) * 2 should equal a");
    }

    fn check_coset_shift_inv<T: FieldNTT>() {
        assert_eq!(
            T::coset_shift() * &T::coset_shift_inv(),
            T::one(),
            "coset_shift * coset_shift_inv should equal 1"
        );
    }

    /// Run the test suite for the [`FieldNTT`] trait.
    ///
    /// This will also run [`fuzz_field`].
    pub fn fuzz_field_ntt<T: FieldNTT + for<'a> Arbitrary<'a>>(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        fuzz_field::<T>(u)?;

        // Biased choice towards div_2 checks
        match u.int_in_range(0u8..=9)? {
            0 => {
                check_coset_shift_inv::<T>();
            }
            1 => {
                let lg = u.int_in_range(0..=T::MAX_LG_ROOT_ORDER + 1)?;
                check_root_of_unity_order::<T>(lg);
            }
            _ => {
                check_div_2(T::arbitrary(u)?);
            }
        }
        Ok(())
    }
}

commonware_macros::stability_scope!(ALPHA {
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz {
        use super::*;
        use crate::fields::goldilocks::F;
        use arbitrary::{Arbitrary, Unstructured};
        use commonware_parallel::Sequential;

        #[derive(Debug, Arbitrary)]
        pub enum Plan {
            ExpOne(F),
            ExpZero(F),
            Exp(F, u32, u32),
            PowersMatchesExp(F, u16),
            ScaleOne(F),
            ScaleZero(F),
            Scale(F, u32, u32),
            Msm2([F; 2], [F; 2]),
        }

        impl Plan {
            pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
                match self {
                    Self::ExpOne(x) => {
                        assert_eq!(x.exp(&[1]), x);
                    }
                    Self::ExpZero(x) => {
                        assert_eq!(x.exp(&[]), F::one());
                    }
                    Self::Exp(x, a, b) => {
                        let a = u64::from(a);
                        let b = u64::from(b);
                        assert_eq!(x.exp(&[a + b]), x.exp(&[a]) * x.exp(&[b]));
                    }
                    Self::PowersMatchesExp(base, index) => {
                        let pow_i = powers(&base, usize::from(index) + 1)
                            .last()
                            .expect("len=index+1 guarantees at least one item");
                        assert_eq!(pow_i, base.exp(&[u64::from(index)]));
                    }
                    Self::ScaleOne(x) => {
                        assert_eq!(x.scale(&[1]), x);
                    }
                    Self::ScaleZero(x) => {
                        assert_eq!(x.scale(&[]), F::zero());
                    }
                    Self::Scale(x, a, b) => {
                        let a = u64::from(a);
                        let b = u64::from(b);
                        assert_eq!(x.scale(&[a + b]), x.scale(&[a]) + x.scale(&[b]));
                    }
                    Self::Msm2(a, b) => {
                        assert_eq!(F::msm(&a, &b, &Sequential), a[0] * b[0] + a[1] * b[1]);
                    }
                }
                Ok(())
            }
        }

        #[test]
        fn test_fuzz() {
            commonware_invariants::minifuzz::test(|u| u.arbitrary::<Plan>()?.run(u));
        }
    }
});
