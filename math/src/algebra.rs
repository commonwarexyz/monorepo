//! Provides traits for algebraic operations.
//!
//! These traits are designed to lean on the existing Rust operations in [`std::ops`],
//! so that the familiar `+`, `+=`, etc. operators can be used. The traits are also
//! designed with performant implementations in mind, so implementations try to
//! use methods which don't require copying unnecessarily.
#[cfg(not(feature = "std"))]
use alloc::vec;
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, Write};
use commonware_parallel::Strategy;
use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRng;

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

/// Return `shift, shift * base, shift * base^2, ...`.
///
/// Use `powers(R::one(), base)` if you just want the standard powers.
pub fn powers<R: Ring>(shift: R, base: &R) -> impl Iterator<Item = R> + '_ {
    iter::successors(Some(shift), move |state: &R| Some(state.clone() * base))
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
pub trait Object: Clone + Debug + Eq + Send + Sync {}

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
/// # Properties
///
/// Implementations are expected to form a commutative group under addition:
///
/// - `+=` and `-=` agree with `+` and `-`,
/// - addition satisfies `a + b = b + a` and `(a + b) + c = a + (b + c)`,
/// - [`Additive::zero`] satisfies `0 + a = a`,
/// - negation satisfies `a + (-a) = 0` and `a - b = a + (-b)`,
/// - [`Additive::scale`] satisfies `a.scale(&[]) = 0`,
///   `a.scale(&[1]) = a`, and `a.scale(m + n) = a.scale(m) + a.scale(n)`.
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
/// # Properties
///
/// Implementations are expected to have a commutative, associative
/// multiplication:
///
/// - `*=` agrees with `*`,
/// - multiplication satisfies `a * b = b * a` and `(a * b) * c = a * (b * c)`.
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
/// # Properties
///
/// Implementations are expected to behave like a right `R`-module action:
///
/// - `*=` agrees with `*`,
/// - scalar multiplication satisfies `(a + b) * x = a * x + b * x`,
/// - [`Space::msm`] satisfies `msm(points, scalars) = sum_i points[i] * scalars[i]`,
/// - [`Space::mul_each`] multiplies each `elements[i]` by `scalars[i]`,
/// - when `R: Multiplicative`, `((a * x) * y) = a * (x * y)`,
/// - when `R: Ring`, `a * 1 = a` and `a * 0 = 0`.
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
    fn msm(points: &[Self], scalars: &[R], _strategy: &impl Strategy) -> Self {
        msm_naive(points, scalars)
    }

    /// Multiplies `elements[i]` by `scalars[i]` in place, for each index `i`.
    ///
    /// # Panics
    ///
    /// Panics if `elements` and `scalars` differ in length.
    //
    // The default runs the multiplications on `strategy`. An override can use
    // batch instructions or share work across elements.
    fn mul_each(elements: &mut [Self], scalars: &[R], strategy: &impl Strategy)
    where
        R: Sync,
    {
        assert_eq!(
            elements.len(),
            scalars.len(),
            "elements and scalars must have the same length"
        );
        // `Strategy` has no for-each operation, so this `fold` carries a `()`
        // accumulator and only multiplies elements in place.
        strategy.fold(
            elements.iter_mut().zip(scalars),
            || (),
            |(), (element, scalar)| *element *= scalar,
            |(), ()| (),
        );
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
///
/// # Properties
///
/// Implementations are expected to be commutative rings:
///
/// - [`Additive`] and [`Multiplicative`] laws both hold,
/// - [`Ring::one`] satisfies `1 * a = a`,
/// - multiplication satisfies `(a + b) * c = a * c + b * c`,
/// - [`Ring::exp`] satisfies `a.exp(&[]) = 1`,
///   `a.exp(&[1]) = a`, and `a.exp(m + n) = a.exp(m) * a.exp(n)`.
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
///
/// # Properties
///
/// Implementations are expected to satisfy the usual field inverse laws:
///
/// - all [`Ring`] laws hold,
/// - `0.inv() = 0`,
/// - for any nonzero `a`, `a * a.inv() = 1`.
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
///
/// # Properties
///
/// Implementations are expected to satisfy the NTT-specific laws checked by
/// the property tests:
///
/// - `root_of_unity(lg)` returns `None` only when `lg > MAX_LG_ROOT_ORDER`,
/// - otherwise, `root_of_unity(lg)^(2^lg) = 1` and, for `lg > 0`, `root_of_unity(lg)^(2^lg - 1) != 1`,
/// - `coset_shift()` and `coset_shift_inv()` satisfy `coset_shift() * coset_shift_inv() = 1`,
/// - `div_2(a)` satisfies `div_2(a) * (1 + 1) = a`.
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

/// A [`Field`] which messages can be hashed into.
///
/// Protocols use this capability to derive challenges and other elements that
/// must look uniformly random, but be reproducible from public data.
///
/// # Properties
///
/// - equal `(domain_separator, message)` pairs satisfy
///   `hash_to_field(dst0, m0) = hash_to_field(dst1, m1)` whenever
///   `(dst0, m0) = (dst1, m1)`.
pub trait HashToField: Field {
    /// Hash a domain separator, and a message, returning a field element.
    ///
    /// The result should be indistinguishable from a uniformly random element.
    fn hash_to_field(domain_separator: &[u8], message: &[u8]) -> Self;
}

/// A [`CryptoGroup`] which supports obliviously sampling elements.
///
/// This capability is also often referred to as "hash to curve", in the
/// context of Elliptic Curve Cryptography, but we use the term "group"
/// to match the naming conventions for other traits.
///
/// Advanced protocols use this capability to create new generator elements
/// whose discrete logarithm relative to other points is unknown.
///
/// # Properties
///
/// - equal `(domain_separator, message)` pairs satisfy
///   `hash_to_group(dst0, m0) = hash_to_group(dst1, m1)` whenever
///   `(dst0, m0) = (dst1, m1)`.
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
    fn rand_to_group(mut rng: impl CryptoRng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::hash_to_group(&[], &bytes)
    }
}

/// A [`CryptoGroup`] with a pairing.
///
/// A pairing `o : (G1, G2) -> GT` takes an element of `G1` and an element of
/// `G2`, and returns an element of `GT`. This trait writes `GT` additively, so a
/// pairing is written `A o X` rather than the more familiar `e(A, X)`.
/// The implementor is `G1`, [`Self::Twin`] is `G2`, and [`Self::Target`] is
/// `GT`.
/// To run code generic over a [`PairingGroup`] `G` with the two groups swapped,
/// pass [`Twin<G>`] in place of `G`, as BLS signatures do when they choose which
/// group holds the public keys.
///
/// The pairing is bilinear:
///
///   - `0 o X = 0 = A o 0`,
///   - `(A + B) o X = A o X + B o X`,
///   - `A o (X + Y) = A o X + A o Y`.
///
/// Scaling either side gives the same pairing. For each type `R` that both
/// `Self` and [`Self::Twin`] are a [`Space`] over, and that is used with this
/// pairing, `(A * r) o X = A o (X * r)` for every `r` of type `R`.
///
/// [`Self::pairing`] computes one pairing. [`Self::pairings`] computes several,
/// and [`Self::multi_pairing`] computes their sum. Both have default
/// implementations, which an implementation can override to share work across
/// pairs, such as the single final exponentiation that a sum of Tate pairings
/// needs.
///
/// [`Self::scaled_multi_pairing`] computes a sum of pairings, each with one side
/// multiplied by its own scalar. It runs faster when this trait is implemented on
/// the group whose scalar multiplication is cheaper.
pub trait PairingGroup: CryptoGroup {
    /// The group that this group pairs with.
    type Twin: CryptoGroup<Scalar = Self::Scalar>;

    /// The target group `GT` of the pairing.
    type Target: Additive;

    /// Returns `self o other`.
    fn pairing(&self, other: &Self::Twin) -> Self::Target;

    /// Writes `lefts[i] o rights[i]` to `outputs[i]` for each index `i`.
    ///
    /// The default computes each pairing with [`Self::pairing`] on `strategy`. An
    /// override can use batch instructions, which raise throughput even on one
    /// thread.
    ///
    /// # Panics
    ///
    /// Panics if `lefts`, `rights`, and `outputs` differ in length.
    //
    // The batch methods take the left and right elements as separate slices
    // rather than one slice of pairs. Callers often hold them apart already, as
    // batch verification holds public keys and hashed messages, and code that
    // swaps the two groups passes the same slices in the other order instead of
    // copying every pair.
    fn pairings(
        lefts: &[Self],
        rights: &[Self::Twin],
        outputs: &mut [Self::Target],
        strategy: &impl Strategy,
    ) {
        assert_eq!(
            lefts.len(),
            rights.len(),
            "lefts and rights must have the same length"
        );
        assert_eq!(
            lefts.len(),
            outputs.len(),
            "lefts and outputs must have the same length"
        );
        // `Strategy` has no for-each operation, so this `fold` carries a `()`
        // accumulator and only writes outputs. The zip gives each pair its own
        // output slot: a task writes its pairing in place, however the strategy
        // splits the items.
        strategy.fold(
            lefts.iter().zip(rights).zip(outputs),
            || (),
            |(), ((p, q), out)| *out = p.pairing(q),
            |(), ()| (),
        );
    }

    /// Returns the sum of `lefts[i] o rights[i]` over each index `i`, or zero if
    /// both slices are empty.
    ///
    /// The default sums the outputs of [`Self::pairings`], so an override of that
    /// method also speeds up this one.
    ///
    /// # Panics
    ///
    /// Panics if `lefts` and `rights` differ in length.
    fn multi_pairing(
        lefts: &[Self],
        rights: &[Self::Twin],
        strategy: &impl Strategy,
    ) -> Self::Target {
        let mut outputs = vec![Self::Target::zero(); lefts.len()];
        Self::pairings(lefts, rights, &mut outputs, strategy);
        strategy.fold(
            &outputs,
            Self::Target::zero,
            |mut acc, out| {
                acc += out;
                acc
            },
            |mut a, b| {
                a += &b;
                a
            },
        )
    }

    /// Returns the sum of `(lefts[i] * scalars[i]) o rights[i]` over each index
    /// `i` that has a scalar, plus `lefts[i] o rights[i]` over each index that
    /// does not, or zero if the slices are empty.
    ///
    /// With a random scalar for each pairing equation, the sum checks all the
    /// equations at once, as batch verification does. Callers must not pass
    /// secret scalars, because an implementation may run in time that depends
    /// on them.
    ///
    /// # Panics
    ///
    /// Panics if `lefts` and `rights` differ in length, or if `scalars` is longer
    /// than `lefts`.
    //
    // The default multiplies `lefts` by the scalars with `Space::mul_each`, then
    // calls `multi_pairing`. The scaling law in the trait docs lets the scalars
    // multiply either side of each pairing, and `lefts` is the cheaper side when
    // the trait is implemented on the group whose scalar multiplication is cheaper.
    //
    // Pairs without a scalar are not multiplied, so a caller can append a pair
    // that it has already weighted without paying for a multiplication by one.
    //
    // Implementations should not need to override this method. Its cost lies in
    // the scalar multiplications and the multi-pairing, which implementations
    // speed up by overriding `Space::mul_each` and `multi_pairing`. A kernel
    // that fused the two steps would save only one pass over the scaled copies.
    //
    // The bound on `Self::Twin` lets an implementation multiply `rights` instead,
    // when the twin is the cheaper side.
    fn scaled_multi_pairing<R: Sync>(
        lefts: &[Self],
        rights: &[Self::Twin],
        scalars: &[R],
        strategy: &impl Strategy,
    ) -> Self::Target
    where
        Self: Space<R>,
        Self::Twin: Space<R>,
    {
        assert_eq!(
            lefts.len(),
            rights.len(),
            "lefts and rights must have the same length"
        );
        assert!(
            scalars.len() <= lefts.len(),
            "scalars must not be longer than lefts"
        );
        let mut scaled = lefts.to_vec();
        Self::mul_each(&mut scaled[..scalars.len()], scalars, strategy);
        Self::multi_pairing(&scaled, rights, strategy)
    }
}

/// An element of the group that `G` pairs with, as a [`PairingGroup`] whose
/// twin is `G`.
///
/// [`Twin::new`] wraps an element `X` of `G::Twin`, and [`Twin::into_inner`]
/// and [`AsRef`] return it. `Twin::new(X).pairing(&A)` returns
/// `A.pairing(&X)`. `Twin<Twin<G>>` wraps `G` rather than being `G`.
///
/// A `Twin<G>` has the same encoding, hash, hash to the group, and formatting
/// as the element it wraps.
#[derive(Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Twin<G: PairingGroup>(G::Twin);

// Generic `From` impls cannot replace these methods. `From<G::Twin> for Twin<G>`
// conflicts with core's `From<T> for T`, because `G::Twin` may be `Twin<G>`, and
// `From<Twin<G>> for G::Twin` breaks the orphan rule.
impl<G: PairingGroup> Twin<G> {
    /// Wraps `x`.
    pub const fn new(x: G::Twin) -> Self {
        Self(x)
    }

    /// Returns the wrapped element.
    pub fn into_inner(self) -> G::Twin {
        self.0
    }

    /// Returns `twins` as a slice of the elements they wrap, without copying.
    const fn as_inner_slice(twins: &[Self]) -> &[G::Twin] {
        // SAFETY: `Twin<G>` is `#[repr(transparent)]` over its only field, of type
        // `G::Twin`, so both types have the same size, alignment, and valid values.
        // The pointer and length therefore describe `twins.len()` initialized
        // `G::Twin` values, borrowed for the lifetime of `twins`.
        unsafe { core::slice::from_raw_parts(twins.as_ptr().cast(), twins.len()) }
    }

    /// Returns `twins` as a mutable slice of the elements they wrap, without
    /// copying.
    const fn as_inner_slice_mut(twins: &mut [Self]) -> &mut [G::Twin] {
        // SAFETY: `Twin<G>` is `#[repr(transparent)]` over its only field, of type
        // `G::Twin`, so both types have the same size, alignment, and valid values.
        // The pointer and length therefore describe `twins.len()` initialized
        // `G::Twin` values. The result reborrows `twins` exclusively for its
        // lifetime, and every `G::Twin` written through it is a valid `Twin<G>`.
        unsafe { core::slice::from_raw_parts_mut(twins.as_mut_ptr().cast(), twins.len()) }
    }
}

impl<G: PairingGroup> AsRef<G::Twin> for Twin<G> {
    fn as_ref(&self) -> &G::Twin {
        &self.0
    }
}

impl<G: PairingGroup> Object for Twin<G> {}

impl<'a, G: PairingGroup> Add<&'a Self> for Twin<G> {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl<'a, G: PairingGroup> AddAssign<&'a Self> for Twin<G> {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.0 += &rhs.0;
    }
}

impl<'a, G: PairingGroup> Sub<&'a Self> for Twin<G> {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        Self(self.0 - &rhs.0)
    }
}

impl<'a, G: PairingGroup> SubAssign<&'a Self> for Twin<G> {
    fn sub_assign(&mut self, rhs: &'a Self) {
        self.0 -= &rhs.0;
    }
}

impl<G: PairingGroup> Neg for Twin<G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<G: PairingGroup> Additive for Twin<G> {
    fn zero() -> Self {
        Self(G::Twin::zero())
    }

    fn double(&mut self) {
        self.0.double();
    }
}

impl<'a, G: PairingGroup, R> Mul<&'a R> for Twin<G>
where
    G::Twin: Space<R>,
{
    type Output = Self;

    fn mul(self, rhs: &'a R) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl<'a, G: PairingGroup, R> MulAssign<&'a R> for Twin<G>
where
    G::Twin: Space<R>,
{
    fn mul_assign(&mut self, rhs: &'a R) {
        self.0 *= rhs;
    }
}

impl<G: PairingGroup, R> Space<R> for Twin<G>
where
    G::Twin: Space<R>,
{
    fn msm(points: &[Self], scalars: &[R], strategy: &impl Strategy) -> Self {
        Self(G::Twin::msm(
            Self::as_inner_slice(points),
            scalars,
            strategy,
        ))
    }

    fn mul_each(elements: &mut [Self], scalars: &[R], strategy: &impl Strategy)
    where
        R: Sync,
    {
        G::Twin::mul_each(Self::as_inner_slice_mut(elements), scalars, strategy);
    }
}

impl<G: PairingGroup> CryptoGroup for Twin<G> {
    type Scalar = G::Scalar;

    fn generator() -> Self {
        Self(G::Twin::generator())
    }
}

impl<G: PairingGroup> HashToGroup for Twin<G>
where
    G::Twin: HashToGroup,
{
    fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Self {
        Self(G::Twin::hash_to_group(domain_separator, message))
    }

    fn rand_to_group(rng: impl CryptoRng) -> Self {
        Self(G::Twin::rand_to_group(rng))
    }
}

// The batch methods pass their slices to `G`'s in the other order, so they use
// any faster versions that `G` overrides them with, without copying elements.
impl<G: PairingGroup> PairingGroup for Twin<G> {
    type Twin = G;
    type Target = G::Target;

    fn pairing(&self, other: &G) -> G::Target {
        other.pairing(&self.0)
    }

    fn pairings(lefts: &[Self], rights: &[G], outputs: &mut [G::Target], strategy: &impl Strategy) {
        G::pairings(rights, Self::as_inner_slice(lefts), outputs, strategy);
    }

    fn multi_pairing(lefts: &[Self], rights: &[G], strategy: &impl Strategy) -> G::Target {
        G::multi_pairing(rights, Self::as_inner_slice(lefts), strategy)
    }

    // `G` is the cheaper side by convention, so this override multiplies `rights`
    // and passes both slices to `G` in the other order. It cannot delegate to
    // `G::scaled_multi_pairing`, because that call needs `G::Twin: Space<R>`,
    // which the compiler does not infer from `Twin<G>: Space<R>`.
    fn scaled_multi_pairing<R: Sync>(
        lefts: &[Self],
        rights: &[G],
        scalars: &[R],
        strategy: &impl Strategy,
    ) -> G::Target
    where
        Self: Space<R>,
        G: Space<R>,
    {
        assert_eq!(
            lefts.len(),
            rights.len(),
            "lefts and rights must have the same length"
        );
        assert!(
            scalars.len() <= lefts.len(),
            "scalars must not be longer than lefts"
        );
        let mut scaled = rights.to_vec();
        G::mul_each(&mut scaled[..scalars.len()], scalars, strategy);
        G::multi_pairing(&scaled, Self::as_inner_slice(lefts), strategy)
    }
}

// `derive` would bound `G` by `Copy` and `Hash`, which the wrapped element
// does not need, so these impls bound `G::Twin` instead.
impl<G: PairingGroup> Copy for Twin<G> where G::Twin: Copy {}

impl<G: PairingGroup> Hash for Twin<G>
where
    G::Twin: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// `Debug` and `Display` print the wrapped element alone, so a `Twin<G>` prints
// like the element it wraps rather than as `Twin(..)`.
impl<G: PairingGroup> Debug for Twin<G> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<G: PairingGroup> Display for Twin<G>
where
    G::Twin: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<G: PairingGroup> Write for Twin<G>
where
    G::Twin: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<G: PairingGroup> Read for Twin<G>
where
    G::Twin: Read,
{
    type Cfg = <G::Twin as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        G::Twin::read_cfg(buf, cfg).map(Self)
    }
}

impl<G: PairingGroup> FixedSize for Twin<G>
where
    G::Twin: FixedSize,
{
    const SIZE: usize = G::Twin::SIZE;
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, G: PairingGroup> arbitrary::Arbitrary<'a> for Twin<G>
where
    G::Twin: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
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
    fn random(rng: impl CryptoRng) -> Self;
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

    fn check_mul_each_eq_naive<R: Sync, K: Space<R>>(points: &[K], scalars: &[R]) {
        use commonware_parallel::Sequential;
        let expected: Vec<K> = points
            .iter()
            .zip(scalars)
            .map(|(p, s)| p.clone() * s)
            .collect();
        let mut products = points.to_vec();
        K::mul_each(&mut products, scalars, &Sequential);
        assert_eq!(
            products, expected,
            "mul_each does not match multiplying each point"
        );
    }

    /// Fuzz the [`Space`] trait properties, assuming nothing about the scalar `R`.
    ///
    /// Takes arbitrary data and checks that algebraic laws hold.
    pub fn fuzz_space<
        R: Debug + Sync + for<'a> Arbitrary<'a>,
        K: Space<R> + for<'a> Arbitrary<'a>,
    >(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let a: K = u.arbitrary()?;
        let b: K = u.arbitrary()?;
        let x: R = u.arbitrary()?;
        check_scale_distributes(a.clone(), b, x);
        let c: R = u.arbitrary()?;
        check_scale_assign(a, c);
        let (points, scalars): (Vec<K>, Vec<R>) = u.arbitrary::<Vec<(K, R)>>()?.into_iter().unzip();
        check_msm_eq_naive(&points, &scalars);
        let (points, scalars): (Vec<K>, Vec<R>) = u.arbitrary::<Vec<(K, R)>>()?.into_iter().unzip();
        check_mul_each_eq_naive(&points, &scalars);
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

    fn check_hash_to_field<F: HashToField>(data: [[u8; 4]; 4]) {
        let (dst0, m0, dst1, m1) = (&data[0], &data[1], &data[2], &data[3]);
        assert_eq!(
            (dst0, m0) == (dst1, m1),
            F::hash_to_field(dst0, m0) == F::hash_to_field(dst1, m1)
        );
    }

    /// Fuzz the [`HashToField`] trait properties.
    ///
    /// Takes arbitrary data and checks that the hash function is deterministic.
    /// This doesn't check any properties related to [`Field`].
    pub fn fuzz_hash_to_field<F: HashToField>(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let data: [[u8; 4]; 4] = u.arbitrary()?;
        check_hash_to_field::<F>(data);
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

    fn check_pairing_zero<G: PairingGroup>(a: G, x: G::Twin) {
        assert_eq!(G::zero().pairing(&x), G::Target::zero(), "0 o X != 0");
        assert_eq!(a.pairing(&G::Twin::zero()), G::Target::zero(), "A o 0 != 0");
    }

    fn check_pairing_linear_left<G: PairingGroup>(a: G, b: G, x: G::Twin) {
        assert_eq!(
            (a.clone() + &b).pairing(&x),
            a.pairing(&x) + &b.pairing(&x),
            "(A + B) o X != A o X + B o X"
        );
    }

    fn check_pairing_linear_right<G: PairingGroup>(a: G, x: G::Twin, y: G::Twin) {
        assert_eq!(
            a.pairing(&(x.clone() + &y)),
            a.pairing(&x) + &a.pairing(&y),
            "A o (X + Y) != A o X + A o Y"
        );
    }

    fn check_pairing_scalar<G: PairingGroup>(a: G, x: G::Twin, s: G::Scalar) {
        assert_eq!(
            (a.clone() * &s).pairing(&x),
            a.pairing(&(x * &s)),
            "(A * s) o X != A o (X * s)"
        );
    }

    fn check_pairings_eq_naive<G: PairingGroup>(lefts: &[G], rights: &[G::Twin]) {
        use commonware_parallel::Sequential;
        // Start each output one pairing of the generators away from its expected
        // value, so the check below catches any output that `pairings` leaves
        // unwritten. A degenerate pairing makes that offset zero, but then every
        // expected value is zero too.
        let offset = G::generator().pairing(&G::Twin::generator());
        let mut outputs: Vec<G::Target> = lefts
            .iter()
            .zip(rights)
            .map(|(a, x)| a.pairing(x) + &offset)
            .collect();
        G::pairings(lefts, rights, &mut outputs, &Sequential);
        for ((a, x), out) in lefts.iter().zip(rights).zip(&outputs) {
            assert_eq!(*out, a.pairing(x), "pairings does not match pairing");
        }
    }

    fn check_multi_pairing_eq_naive<G: PairingGroup>(lefts: &[G], rights: &[G::Twin]) {
        use commonware_parallel::Sequential;
        let mut expected = G::Target::zero();
        for (a, x) in lefts.iter().zip(rights) {
            expected += &a.pairing(x);
        }
        assert_eq!(
            G::multi_pairing(lefts, rights, &Sequential),
            expected,
            "multi_pairing does not match the sum of pairings"
        );
    }

    fn check_scaled_multi_pairing_eq_naive<G: PairingGroup>(
        lefts: &[G],
        rights: &[G::Twin],
        scalars: &[G::Scalar],
    ) {
        use commonware_parallel::Sequential;
        // Scaling either side gives the same pairing, so the expected sum
        // multiplies the left elements. Pairs without a scalar add unscaled.
        let mut expected = G::Target::zero();
        for (i, (a, x)) in lefts.iter().zip(rights).enumerate() {
            let a = scalars.get(i).map_or_else(|| a.clone(), |s| a.clone() * s);
            expected += &a.pairing(x);
        }
        assert_eq!(
            G::scaled_multi_pairing(lefts, rights, scalars, &Sequential),
            expected,
            "scaled_multi_pairing does not match the sum of scaled pairings"
        );
    }

    /// Checks the [`PairingGroup`] laws on arbitrary inputs.
    ///
    /// Each call runs one check, since pairings are expensive: that the pairing is
    /// bilinear, that scaling either side by a [`CryptoGroup::Scalar`] gives the
    /// same pairing, or that [`PairingGroup::pairings`],
    /// [`PairingGroup::multi_pairing`], or [`PairingGroup::scaled_multi_pairing`]
    /// agrees with [`PairingGroup::pairing`].
    ///
    /// It does not check that the pairing is non-degenerate. The [`Space`] suites
    /// cover [`PairingGroup::Twin`] as a group, and [`fuzz_additive`] covers
    /// [`PairingGroup::Target`].
    pub fn fuzz_pairing_group<G>(u: &mut Unstructured<'_>) -> arbitrary::Result<()>
    where
        G: PairingGroup + for<'a> Arbitrary<'a>,
        G::Twin: for<'a> Arbitrary<'a>,
        G::Scalar: for<'a> Arbitrary<'a>,
    {
        match u.int_in_range(0u8..=6)? {
            0 => check_pairing_zero::<G>(u.arbitrary()?, u.arbitrary()?),
            1 => check_pairing_linear_left::<G>(u.arbitrary()?, u.arbitrary()?, u.arbitrary()?),
            2 => check_pairing_linear_right::<G>(u.arbitrary()?, u.arbitrary()?, u.arbitrary()?),
            3 => check_pairing_scalar::<G>(u.arbitrary()?, u.arbitrary()?, u.arbitrary()?),
            4 => {
                let (lefts, rights): (Vec<G>, Vec<G::Twin>) =
                    u.arbitrary::<Vec<_>>()?.into_iter().unzip();
                check_pairings_eq_naive(&lefts, &rights);
            }
            5 => {
                let (lefts, rights): (Vec<G>, Vec<G::Twin>) =
                    u.arbitrary::<Vec<_>>()?.into_iter().unzip();
                check_multi_pairing_eq_naive(&lefts, &rights);
            }
            _ => {
                let len = u.arbitrary_len::<(G, G::Twin, G::Scalar)>()?;
                let lefts = (0..len)
                    .map(|_| u.arbitrary())
                    .collect::<arbitrary::Result<Vec<G>>>()?;
                let rights = (0..len)
                    .map(|_| u.arbitrary())
                    .collect::<arbitrary::Result<Vec<G::Twin>>>()?;
                // Scale a prefix of the pairs, from none of them to all of them.
                let scaled = u.int_in_range(0..=len)?;
                let scalars = (0..scaled)
                    .map(|_| u.arbitrary())
                    .collect::<arbitrary::Result<Vec<G::Scalar>>>()?;
                check_scaled_multi_pairing_eq_naive(&lefts, &rights, &scalars);
            }
        }
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
            PowersMatchesExp(F, F, u16),
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
                    Self::PowersMatchesExp(shift, base, index) => {
                        let pow_i = powers(shift, &base)
                            .take(usize::from(index) + 1)
                            .last()
                            .expect("len=index+1 guarantees at least one item");
                        assert_eq!(pow_i, shift * base.exp(&[u64::from(index)]));
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
