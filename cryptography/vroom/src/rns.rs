//! Bounded residue arithmetic with delayed Montgomery reduction and expansion.
//!
//! Lane intervals are measured in each residue modulus; integer intervals are
//! measured in `40p`, or `1600p^2` for wide products. Preparation changes only
//! the lanes. Reduction and expansion own the integer-representation bounds.
//! A standard value encodes `u = a*M (mod p)`, where `M` is the first basis
//! product. Fixed rotations in each basis let multiplication remove one factor
//! of `M` while retaining bounded, redundant representatives.
//!
//! For optional SIMD backends, keep [`WithBackend::call`] implementations and
//! their arithmetic helpers in the selected target-feature context with
//! `#[inline(always)]`, or use a separately gated bulk entry. Outlined helpers
//! can otherwise incur per-instruction wrapper calls. Backend tokens and
//! intrinsic gates enforce CPU feature safety independently of inlining.

#[cfg(all(target_arch = "x86_64", any(feature = "std", test), not(miri)))]
mod avx512;
pub mod bounds;
pub(crate) mod kernel;
pub(crate) mod parameters;
#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
pub mod test;

use crate::{Element, Modulus, SignedTerm};
use bounds::{
    Bound, Difference, ExpandRange, LaneNegated, LaneProduct, LiftedLane, Montgomery, Negated,
    Offset, Prepared, Product, Range, Reduced, Scale, Sum,
};
use core::{
    array,
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};
use kernel::{Kernel, Lanes, RawWide};
#[doc(hidden)]
pub use parameters::Parameters;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

pub(crate) const LANES: usize = 8;
pub(crate) const BITS: u32 = 50;
pub(crate) const WORD: u32 = 52;
pub(crate) const MASK: u64 = (1 << WORD) - 1;
pub(crate) const MULT_OK: i64 = 1 << (WORD - BITS);
/// The preparation limit shared by the reference formula schedules.
pub const PREP_BOUND: i64 = 4;

/// A sealed arithmetic backend obtained through [`with_backend`].
#[allow(private_bounds)]
pub trait Backend: Kernel {}
impl<T: Kernel> Backend for T {}

/// A complete computation parameterized by its arithmetic backend.
pub trait WithBackend {
    /// The computation's result.
    type Output;
    /// Runs with a backend validated for the current CPU.
    fn call<B: Backend>(self, backend: B) -> Self::Output;
}

/// Runs a computation with the best available backend.
pub fn with_backend<F: WithBackend>(f: F) -> F::Output {
    #[cfg(all(target_arch = "x86_64", any(feature = "std", test), not(miri)))]
    if let Some(backend) = avx512::Backend::new() {
        // SAFETY: the private token is constructed only after both feature checks.
        return unsafe { backend.call(f) };
    }
    f.call(kernel::Portable)
}

/// The context for a sequence of bounded field operations.
#[derive(Clone, Copy, Debug)]
pub struct Ring<P: Modulus, B: Backend> {
    backend: B,
    marker: PhantomData<P>,
}

/// An expanded value carrying independent lane and integer intervals.
#[derive(Clone, Copy, Debug)]
pub struct Expanded<P: Modulus, L: Bound, R: Bound> {
    pub(crate) halves: [Lanes; 2],
    marker: PhantomData<(P, L, R)>,
}

/// An expanded field value with lanes in `[0,2q]` and integer in `[0,40p]`.
pub type Standard<P> = Expanded<P, Range<0, 2>, Range<0, 1>>;

/// Carry-free products carrying squared-modulus and integer intervals.
///
/// Each lane represents `high*2^WORD + low`, interpreting both halves as signed
/// during linear operations. The low half has the same interval in word units.
/// Reduction requires a nonnegative combined value and low half; the high half
/// can remain negative until carry transfer.
#[derive(Clone, Copy, Debug)]
pub struct Wide<P: Modulus, L: Bound, R: Bound> {
    halves: [RawWide; 2],
    marker: PhantomData<(P, L, R)>,
}

/// A reduced value retained only in the second residue basis.
#[derive(Clone, Copy, Debug)]
pub struct Small<P: Modulus, L: Bound, R: Bound> {
    n: Lanes,
    marker: PhantomData<(P, L, R)>,
}

/// A prepared operand bound to the backend that will multiply it.
#[derive(Clone, Copy, Debug)]
pub struct Left<P: Modulus, B: Backend, L: Bound, R: Bound> {
    value: Expanded<P, L, R>,
    backend: B,
}

/// A product that can accumulate directly into a reusable wide value.
#[derive(Clone, Copy, Debug)]
pub struct DelayedProduct<P: Modulus, B: Backend, L1: Bound, R1: Bound, L2: Bound, R2: Bound> {
    left: Expanded<P, L1, R1>,
    right: Expanded<P, L2, R2>,
    backend: B,
}

/// A validated input to a Montgomery reduction batch.
#[derive(Clone, Copy, Debug)]
pub struct Ready<P: Modulus, const A: i64 = 800> {
    m: Lanes,
    n: RawWide,
    marker: PhantomData<P>,
}

const fn normal_capacity<L: Bound>() {
    let interval = L::INTERVAL;
    let magnitude = if -(interval.lower as i128) > interval.upper as i128 {
        -(interval.lower as i128)
    } else {
        interval.upper as i128
    };
    assert!(magnitude * (1i128 << BITS) < (1i128 << 63));
}

const fn wide_capacity<L: Bound>() {
    let interval = L::INTERVAL;
    let magnitude = if -(interval.lower as i128) > interval.upper as i128 {
        -(interval.lower as i128)
    } else {
        interval.upper as i128
    };
    assert!(magnitude * (1i128 << WORD) < (1i128 << 63));
    assert!(magnitude * ((1i128 << (2 * BITS - WORD)) + 1) < (1i128 << 63));
}

const fn multiply_capacity<A: Bound, B: Bound>() {
    assert!(A::INTERVAL.lower >= 0 && B::INTERVAL.lower >= 0);
    assert!(A::INTERVAL.upper <= MULT_OK && B::INTERVAL.upper <= MULT_OK);
    wide_capacity::<LaneProduct<A, B>>();
}

const fn prepare_capacity<P: Modulus, L: Bound, const TO: i64>() {
    normal_capacity::<L>();
    assert!(TO >= 1 && TO <= MULT_OK);
    let mut upper = L::INTERVAL.upper as i128;
    if L::INTERVAL.lower < 0 {
        upper += bounds::negate_offset(-L::INTERVAL.lower) as i128;
    }
    if (TO == 1 && upper > 4) || (TO > 1 && upper > 2 * TO as i128) {
        let mut i = 0;
        while i < LANES {
            assert!(
                (1i128 << BITS) - 1 + upper * P::PARAMETERS.m.complement[i] as i128
                    <= 2 * P::PARAMETERS.m.moduli[i] as i128
            );
            assert!(
                (1i128 << BITS) - 1 + upper * P::PARAMETERS.n.complement[i] as i128
                    <= 2 * P::PARAMETERS.n.moduli[i] as i128
            );
            i += 1;
        }
    }
}

impl<P: Modulus, L: Bound, R: Bound> Expanded<P, L, R> {
    pub(crate) const fn from_halves(halves: [Lanes; 2]) -> Self {
        normal_capacity::<L>();
        Self {
            halves,
            marker: PhantomData,
        }
    }

    /// Widens the integer interval without changing the value.
    #[inline(always)]
    pub const fn recast_rns<N: Bound>(self) -> Expanded<P, L, N> {
        const {
            assert!(N::INTERVAL.contains(R::INTERVAL));
        }
        Expanded::from_halves(self.halves)
    }

    /// Multiplies a bounded value by a public integer constant.
    #[inline(always)]
    pub fn scale<const C: i64>(self) -> Expanded<P, Scale<L, C>, Scale<R, C>> {
        const {
            normal_capacity::<Scale<L, C>>();
            let _ = Scale::<R, C>::INTERVAL;
        }
        let mut halves = self.halves;
        for half in &mut halves {
            for value in half {
                *value = value.wrapping_mul(C as u64);
            }
        }
        Expanded::from_halves(halves)
    }
}

impl<P: Modulus> Standard<P> {
    /// The additive identity.
    pub const ZERO: Self = Self::from_halves([[0; LANES]; 2]);
    /// The multiplicative identity.
    pub const ONE: Self = Self::from_halves(P::PARAMETERS.one);
}

impl<P: Modulus, L: Bound, R: Bound> ConditionallySelectable for Expanded<P, L, R> {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::from_halves(array::from_fn(|half| {
            array::from_fn(|i| {
                u64::conditional_select(&a.halves[half][i], &b.halves[half][i], choice)
            })
        }))
    }
}

impl<P: Modulus> Zeroize for Standard<P> {
    fn zeroize(&mut self) {
        self.halves.zeroize();
    }
}

macro_rules! linear_expanded {
    ($trait:ident, $method:ident, $bound:ident, $operation:ident) => {
        impl<P: Modulus, L: Bound, R: Bound, L2: Bound, R2: Bound> $trait<Expanded<P, L2, R2>>
            for Expanded<P, L, R>
        {
            type Output = Expanded<P, $bound<L, L2>, $bound<R, R2>>;
            #[inline(always)]
            fn $method(self, other: Expanded<P, L2, R2>) -> Self::Output {
                const {
                    normal_capacity::<$bound<L, L2>>();
                    let _ = $bound::<R, R2>::INTERVAL;
                }
                Expanded::from_halves(array::from_fn(|half| {
                    array::from_fn(|i| self.halves[half][i].$operation(other.halves[half][i]))
                }))
            }
        }
        impl<P: Modulus, L: Bound, R: Bound, L2: Bound, R2: Bound> $trait<Small<P, L2, R2>>
            for Small<P, L, R>
        {
            type Output = Small<P, $bound<L, L2>, $bound<R, R2>>;
            #[inline(always)]
            fn $method(self, other: Small<P, L2, R2>) -> Self::Output {
                const {
                    normal_capacity::<$bound<L, L2>>();
                    let _ = $bound::<R, R2>::INTERVAL;
                }
                Small {
                    n: array::from_fn(|i| self.n[i].$operation(other.n[i])),
                    marker: PhantomData,
                }
            }
        }
        impl<P: Modulus, L: Bound, R: Bound, L2: Bound, R2: Bound> $trait<Wide<P, L2, R2>>
            for Wide<P, L, R>
        {
            type Output = Wide<P, $bound<L, L2>, $bound<R, R2>>;
            #[inline(always)]
            fn $method(self, other: Wide<P, L2, R2>) -> Self::Output {
                const {
                    wide_capacity::<$bound<L, L2>>();
                    let _ = $bound::<R, R2>::INTERVAL;
                }
                let mut halves = self.halves;
                let mut half = 0;
                while half < 2 {
                    let mut i = 0;
                    while i < LANES {
                        halves[half].high[i] =
                            halves[half].high[i].$operation(other.halves[half].high[i]);
                        halves[half].low[i] =
                            halves[half].low[i].$operation(other.halves[half].low[i]);
                        i += 1;
                    }
                    half += 1;
                }
                Wide {
                    halves,
                    marker: PhantomData,
                }
            }
        }
    };
}
linear_expanded!(Add, add, Sum, wrapping_add);
linear_expanded!(Sub, sub, Difference, wrapping_sub);

impl<P: Modulus, L: Bound, R: Bound> Small<P, L, R> {
    /// Widens the integer interval.
    #[inline(always)]
    pub const fn recast_rns<N: Bound>(self) -> Small<P, L, N> {
        const {
            assert!(N::INTERVAL.contains(R::INTERVAL));
        }
        Small {
            n: self.n,
            marker: PhantomData,
        }
    }
    /// Multiplies by a public integer constant before expansion.
    #[inline(always)]
    pub fn scale<const C: i64>(self) -> Small<P, Scale<L, C>, Scale<R, C>> {
        const {
            normal_capacity::<Scale<L, C>>();
            let _ = Scale::<R, C>::INTERVAL;
        }
        Small {
            n: self.n.map(|x| x.wrapping_mul(C as u64)),
            marker: PhantomData,
        }
    }
}

impl<P: Modulus, L: Bound, R: Bound> Wide<P, L, R> {
    /// Multiplies a wide value by a public integer constant.
    #[inline(always)]
    pub fn scale<const C: i64>(self) -> Wide<P, Scale<L, C>, Scale<R, C>> {
        const {
            wide_capacity::<Scale<L, C>>();
            let _ = Scale::<R, C>::INTERVAL;
        }
        let mut halves = self.halves;
        for half in &mut halves {
            for value in &mut half.high {
                *value = value.wrapping_mul(C as u64);
            }
            for value in &mut half.low {
                *value = value.wrapping_mul(C as u64);
            }
        }
        Wide {
            halves,
            marker: PhantomData,
        }
    }
    /// Returns this already materialized product.
    #[inline(always)]
    pub const fn complete(self) -> Self {
        self
    }
}

impl<P: Modulus, B: Backend, L: Bound, R: Bound> Left<P, B, L, R> {
    /// Recovers the prepared operand for reuse as a right operand.
    #[inline(always)]
    pub const fn into_expanded(self) -> Expanded<P, L, R> {
        self.value
    }
}

impl<P: Modulus, B: Backend, L: Bound, R: Bound, L2: Bound, R2: Bound> Mul<Expanded<P, L2, R2>>
    for Left<P, B, L, R>
{
    type Output = DelayedProduct<P, B, L, R, L2, R2>;
    #[inline(always)]
    fn mul(self, right: Expanded<P, L2, R2>) -> Self::Output {
        const {
            multiply_capacity::<L, L2>();
            let _ = Product::<R, R2>::INTERVAL;
        }
        DelayedProduct {
            left: self.value,
            right,
            backend: self.backend,
        }
    }
}

impl<P: Modulus, B: Backend, L1: Bound, R1: Bound, L2: Bound, R2: Bound>
    DelayedProduct<P, B, L1, R1, L2, R2>
{
    /// Materializes the low and high product halves.
    #[inline(always)]
    pub fn complete(self) -> Wide<P, LaneProduct<L1, L2>, Product<R1, R2>> {
        const {
            multiply_capacity::<L1, L2>();
        }
        Wide {
            halves: [
                self.backend
                    .madd(RawWide::ZERO, &self.left.halves[0], &self.right.halves[0]),
                self.backend
                    .madd(RawWide::ZERO, &self.left.halves[1], &self.right.halves[1]),
            ],
            marker: PhantomData,
        }
    }
}

impl<P: Modulus, B: Backend, L: Bound, R: Bound, L1: Bound, R1: Bound, L2: Bound, R2: Bound>
    Add<DelayedProduct<P, B, L1, R1, L2, R2>> for Wide<P, L, R>
{
    type Output = Wide<P, Sum<L, LaneProduct<L1, L2>>, Sum<R, Product<R1, R2>>>;
    #[inline(always)]
    fn add(self, other: DelayedProduct<P, B, L1, R1, L2, R2>) -> Self::Output {
        const {
            multiply_capacity::<L1, L2>();
            wide_capacity::<Sum<L, LaneProduct<L1, L2>>>();
            let _ = Sum::<R, Product<R1, R2>>::INTERVAL;
        }
        Wide {
            halves: [
                other.backend.madd(
                    self.halves[0],
                    &other.left.halves[0],
                    &other.right.halves[0],
                ),
                other.backend.madd(
                    self.halves[1],
                    &other.left.halves[1],
                    &other.right.halves[1],
                ),
            ],
            marker: PhantomData,
        }
    }
}

impl<
    P: Modulus,
    B: Backend,
    L1: Bound,
    R1: Bound,
    L2: Bound,
    R2: Bound,
    L3: Bound,
    R3: Bound,
    L4: Bound,
    R4: Bound,
> Add<DelayedProduct<P, B, L3, R3, L4, R4>> for DelayedProduct<P, B, L1, R1, L2, R2>
{
    type Output = Wide<
        P,
        Sum<LaneProduct<L1, L2>, LaneProduct<L3, L4>>,
        Sum<Product<R1, R2>, Product<R3, R4>>,
    >;
    #[inline(always)]
    fn add(self, other: DelayedProduct<P, B, L3, R3, L4, R4>) -> Self::Output {
        self.complete() + other
    }
}

mod sealed {
    pub trait Input {}
    pub trait Batch {}
}

/// A sealed product representation accepted at a reduction boundary.
#[allow(private_bounds)]
pub trait ReductionInput<P: Modulus, B: Backend>: sealed::Input {
    /// The wide lane interval.
    type Lane: Bound;
    /// The represented integer interval.
    type Integer: Bound;
    #[doc(hidden)]
    fn into_wide(self) -> Wide<P, Self::Lane, Self::Integer>;
}
impl<P: Modulus, L: Bound, R: Bound> sealed::Input for Wide<P, L, R> {}
impl<P: Modulus, B: Backend, L: Bound, R: Bound> ReductionInput<P, B> for Wide<P, L, R> {
    type Lane = L;
    type Integer = R;
    #[inline(always)]
    fn into_wide(self) -> Self {
        self
    }
}
impl<P: Modulus, B: Backend, L1: Bound, R1: Bound, L2: Bound, R2: Bound> sealed::Input
    for DelayedProduct<P, B, L1, R1, L2, R2>
{
}
impl<P: Modulus, B: Backend, L1: Bound, R1: Bound, L2: Bound, R2: Bound> ReductionInput<P, B>
    for DelayedProduct<P, B, L1, R1, L2, R2>
{
    type Lane = LaneProduct<L1, L2>;
    type Integer = Product<R1, R2>;
    #[inline(always)]
    fn into_wide(self) -> Wide<P, Self::Lane, Self::Integer> {
        self.complete()
    }
}

impl<P: Modulus, B: Backend> Ring<P, B> {
    /// Creates a ring context from a validated backend token.
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            marker: PhantomData,
        }
    }

    /// Reduces lane magnitudes while retaining the integer interval.
    #[inline(always)]
    pub fn prep<L: Bound, R: Bound>(
        &self,
        value: Expanded<P, L, R>,
    ) -> Expanded<P, Prepared<L, 4>, R> {
        const {
            prepare_capacity::<P, L, 4>();
        }
        Expanded::from_halves([
            self.backend
                .prepare::<L, 4>(&value.halves[0], &P::PARAMETERS.m),
            self.backend
                .prepare::<L, 4>(&value.halves[1], &P::PARAMETERS.n),
        ])
    }

    /// Prepares an operand and binds its multiplication to this backend.
    #[inline(always)]
    pub fn prep_left<L: Bound, R: Bound>(
        &self,
        value: Expanded<P, L, R>,
    ) -> Left<P, B, Prepared<L, 4>, R> {
        Left {
            value: self.prep(value),
            backend: self.backend,
        }
    }

    /// Prepares standard lanes while retaining the integer interval.
    #[inline(always)]
    pub fn prep_standard<L: Bound, R: Bound>(
        &self,
        value: Expanded<P, L, R>,
    ) -> Expanded<P, Range<0, 2>, R> {
        const {
            prepare_capacity::<P, L, 2>();
        }
        Expanded::from_halves([
            self.backend
                .prepare::<L, 2>(&value.halves[0], &P::PARAMETERS.m),
            self.backend
                .prepare::<L, 2>(&value.halves[1], &P::PARAMETERS.n),
        ])
    }

    /// Negates the integer using an exact lane-modulus offset.
    #[inline(always)]
    pub const fn negate<L: Bound, R: Bound>(
        &self,
        value: Expanded<P, L, R>,
    ) -> Expanded<P, LaneNegated<L>, Negated<R>> {
        const {
            normal_capacity::<LaneNegated<L>>();
            let _ = Negated::<R>::INTERVAL;
        }
        let offset = const { bounds::negate_offset(L::INTERVAL.upper) as u64 };
        let mut halves = value.halves;
        let mut i = 0;
        while i < LANES {
            halves[0][i] = offset
                .wrapping_mul(P::PARAMETERS.m.moduli[i])
                .wrapping_sub(halves[0][i]);
            halves[1][i] = offset
                .wrapping_mul(P::PARAMETERS.n.moduli[i])
                .wrapping_sub(halves[1][i]);
            i += 1;
        }
        Expanded::from_halves(halves)
    }

    /// Negates an integer in `[0,U*40p]`, retaining that interval.
    #[inline(always)]
    pub fn standard_negate<L: Bound, R: Bound>(
        &self,
        value: Expanded<P, L, R>,
    ) -> Expanded<P, Range<0, 2>, R> {
        const {
            assert!(R::INTERVAL.lower == 0);
        }
        type LanesAfter<L> = Sum<LaneNegated<L>, Range<0, 1>>;
        let negated = self.negate(value);
        let offset = const { ordinary_offset::<P>(R::INTERVAL.upper) };
        let halves: [Lanes; 2] = array::from_fn(|half| {
            array::from_fn(|i| negated.halves[half][i].wrapping_add(offset[half][i]))
        });
        const {
            prepare_capacity::<P, LanesAfter<L>, 2>();
        }
        Expanded::from_halves([
            self.backend
                .prepare::<LanesAfter<L>, 2>(&halves[0], &P::PARAMETERS.m),
            self.backend
                .prepare::<LanesAfter<L>, 2>(&halves[1], &P::PARAMETERS.n),
        ])
    }

    /// Constructs the reference's exact carry-free squared-modulus offset.
    ///
    /// The lane extent `E` must be in `0..=800`.
    #[inline(always)]
    pub const fn wide_offset<const E: i64, const R: i64>(&self) -> Wide<P, Offset<E>, Range<R, R>> {
        wide_capacity::<Offset<E>>();
        assert!(E >= 0);
        Wide {
            halves: const { wide_offset::<P>(E, R) },
            marker: PhantomData,
        }
    }

    /// Completes a product and validates its reduction bounds.
    ///
    /// The public batch bound `A` must be in `0..=800`, and it must contain the
    /// product's lane interval after adding any required integer offset.
    ///
    /// ```compile_fail
    /// use commonware_cryptography_vroom::{Backend, Bls12381, WithBackend, with_backend};
    /// use commonware_cryptography_vroom::rns::{Ring, Standard};
    ///
    /// struct TooWide;
    /// impl WithBackend for TooWide {
    ///     type Output = ();
    ///     fn call<B: Backend>(self, backend: B) {
    ///         let ring = Ring::<Bls12381, B>::new(backend);
    ///         let one = Standard::<Bls12381>::ONE;
    ///         let _ = ring.ready::<801>(ring.prep_left(one) * one);
    ///     }
    /// }
    /// with_backend(TooWide);
    /// ```
    #[inline(always)]
    pub fn ready<const A: i64>(&self, input: impl ReductionInput<P, B>) -> Ready<P, A> {
        self.ready_wide::<A, _, _>(input.into_wide())
    }

    #[inline(always)]
    fn ready_wide<const A: i64, L: Bound, R: Bound>(
        &self,
        mut value: Wide<P, L, R>,
    ) -> Ready<P, A> {
        const {
            assert!(A >= 0 && A <= 800);
            wide_capacity::<Range<0, A>>();
            assert!(L::INTERVAL.lower >= 0);
            assert!(LiftedLane::<L, R>::INTERVAL.upper <= A);
            let offset = if R::INTERVAL.lower < 0 { 1932 } else { 0 };
            assert!(R::INTERVAL.lower as i128 + offset >= 0);
            assert!(R::INTERVAL.upper as i128 + offset <= 4309);
        }
        if const { R::INTERVAL.lower < 0 } {
            let offset = const { wide_offset::<P>(0, 1932) };
            for (value, offset) in value.halves.iter_mut().zip(offset) {
                for i in 0..LANES {
                    value.high[i] = value.high[i].wrapping_add(offset.high[i]);
                    value.low[i] = value.low[i].wrapping_add(offset.low[i]);
                }
            }
        }
        let m = self.backend.reduce(&value.halves[0], &P::PARAMETERS.m);
        type M<L, R> = Montgomery<LiftedLane<L, R>>;
        let m = if P::PARAMETERS.no_k {
            const {
                prepare_capacity::<P, M<L, R>, 2>();
            }
            self.backend.prepare::<M<L, R>, 2>(&m, &P::PARAMETERS.m)
        } else {
            const {
                prepare_capacity::<P, M<L, R>, MULT_OK>();
            }
            self.backend
                .prepare::<M<L, R>, MULT_OK>(&m, &P::PARAMETERS.m)
        };
        Ready {
            m,
            n: value.halves[1],
            marker: PhantomData,
        }
    }

    /// Reduces a batch while retaining only the second residue basis.
    #[inline(always)]
    pub fn batch_reduce<const N: usize, const A: i64>(
        &self,
        input: &[Ready<P, A>; N],
    ) -> [Small<P, Reduced<P, A>, Range<0, 1>>; N] {
        const {
            normal_capacity::<Reduced<P, A>>();
        }
        let m: [Lanes; N] = array::from_fn(|i| input[i].m);
        let n: [RawWide; N] = array::from_fn(|i| input[i].n);
        let n = self
            .backend
            .change_base(&m, &n, &P::PARAMETERS.reduce, P::PARAMETERS.no_k);
        let mut output = [Small {
            n: [0; LANES],
            marker: PhantomData,
        }; N];
        for (output, n) in output.iter_mut().zip(&n) {
            output.n = self.backend.reduce(n, &P::PARAMETERS.n);
        }
        output
    }

    /// Makes a reduced integer nonnegative and prepares its expansion lanes.
    #[inline(always)]
    pub fn prep_expand<L: Bound, R: Bound>(
        &self,
        value: Small<P, L, R>,
    ) -> Small<P, Range<0, 2>, ExpandRange<R>> {
        type InputLane<L> = Sum<L, Range<0, 1>>;
        const {
            prepare_capacity::<P, InputLane<L>, 2>();
        }
        let offset = const { ordinary_offset::<P>(bounds::expand_offset(R::INTERVAL.lower)) };
        let n = array::from_fn(|i| value.n[i].wrapping_add(offset[1][i]));
        Small {
            n: self
                .backend
                .prepare::<InputLane<L>, 2>(&n, &P::PARAMETERS.n),
            marker: PhantomData,
        }
    }

    /// Expands a batch, preserving each input's integer interval.
    #[inline(always)]
    pub fn batch_expand<T: ExpansionBatch<P>>(&self, input: &T) -> T::Output {
        input.expand(self)
    }

    #[inline(always)]
    fn expand_raw<const N: usize>(&self, n: &[Lanes; N]) -> [Lanes; N] {
        type ExpandedWide = Range<0, { 4 * LANES as i64 }>;
        type ExpandedMont = Montgomery<ExpandedWide>;
        const {
            prepare_capacity::<P, ExpandedMont, 2>();
        }
        let m = self
            .backend
            .change_base(n, &[RawWide::ZERO; N], &P::PARAMETERS.expand, false);
        let mut output = [[0; LANES]; N];
        for (output, m) in output.iter_mut().zip(&m) {
            *output = self.backend.prepare::<ExpandedMont, 2>(
                &self.backend.reduce(m, &P::PARAMETERS.m),
                &P::PARAMETERS.m,
            );
        }
        output
    }

    /// Reduces and expands a batch into standard field values.
    #[inline(always)]
    pub fn batch_reduce_expand<const N: usize, const A: i64>(
        &self,
        input: &[Ready<P, A>; N],
    ) -> [Standard<P>; N] {
        let reduced = self.batch_reduce(input);
        let mut n = [[0; LANES]; N];
        for (n, reduced) in n.iter_mut().zip(&reduced) {
            *n = self.prep_expand(*reduced).n;
        }
        let m = self.expand_raw(&n);
        let mut output = [Standard::<P>::ZERO; N];
        for (i, output) in output.iter_mut().enumerate() {
            *output = Expanded::from_halves([m[i], n[i]]);
        }
        output
    }

    /// Multiplies two standard values.
    #[inline(always)]
    pub fn mul(&self, a: Standard<P>, b: Standard<P>) -> Standard<P> {
        self.batch_reduce_expand(&[self.ready::<800>(self.prep_left(a) * b)])[0]
    }

    /// Adds two values and closes their integer bound.
    #[inline(always)]
    pub fn add(&self, a: Standard<P>, b: Standard<P>) -> Standard<P> {
        self.batch_reduce_expand(&[self.ready::<800>(self.prep_left(a + b) * Standard::ONE)])[0]
    }

    /// Subtracts two values and closes their integer bound.
    #[inline(always)]
    pub fn sub(&self, a: Standard<P>, b: Standard<P>) -> Standard<P> {
        self.add(a, self.standard_negate(b))
    }

    /// Returns whether the represented field value is zero.
    #[inline(always)]
    pub fn is_zero(&self, value: Standard<P>) -> Choice {
        crate::field::canonical(&value).ct_eq(&[0; 6])
    }

    /// Inverts a standard value through the fixed-schedule canonical boundary.
    pub fn invert(&self, value: Standard<P>) -> Option<Standard<P>> {
        crate::field::invert_standard(value)
    }

    /// Computes an inner product using bounded groups of sixteen products.
    #[inline(always)]
    pub fn sum_of_products<const N: usize>(
        &self,
        a: &[Element<P>; N],
        b: &[Element<P>; N],
    ) -> Standard<P> {
        let mut result = Standard::ZERO;
        let mut start = 0;
        while start < N {
            let mut wide = Wide::<P, Range<0, 64>, Range<0, 16>> {
                halves: [RawWide::ZERO; 2],
                marker: PhantomData,
            };
            for i in start..N.min(start + 16) {
                let a = Standard::from(a[i]);
                let b = Standard::from(b[i]);
                for half in 0..2 {
                    wide.halves[half] =
                        self.backend
                            .madd(wide.halves[half], &a.halves[half], &b.halves[half]);
                }
            }
            let next = self.batch_reduce_expand(&[self.ready::<800>(wide)])[0];
            result = if start == 0 {
                next
            } else {
                self.add(result, next)
            };
            start += 16;
        }
        result
    }

    /// Computes signed inner products without branching on their signs.
    #[inline(always)]
    pub fn signed_sum<const N: usize, const T: usize>(
        &self,
        terms: &[[SignedTerm<'_, P>; T]; N],
    ) -> [Standard<P>; N] {
        let mut result = [Standard::ZERO; N];
        let mut start = 0;
        while start < T {
            let mut ready = [Ready {
                m: [0; LANES],
                n: RawWide::ZERO,
                marker: PhantomData,
            }; N];
            for (row, ready) in ready.iter_mut().enumerate() {
                let mut wide = Wide::<P, Range<0, 257>, Range<0, 64>> {
                    halves: const { wide_offset::<P>(128, 32) },
                    marker: PhantomData,
                };
                for &(a, b, negative) in &terms[row][start..T.min(start + 32)] {
                    let a = Standard::from(*a);
                    let b = Standard::from(*b);
                    for half in 0..2 {
                        let product =
                            self.backend
                                .madd(RawWide::ZERO, &a.halves[half], &b.halves[half]);
                        for i in 0..LANES {
                            wide.halves[half].high[i] =
                                wide.halves[half].high[i].wrapping_add(u64::conditional_select(
                                    &product.high[i],
                                    &product.high[i].wrapping_neg(),
                                    negative,
                                ));
                            wide.halves[half].low[i] =
                                wide.halves[half].low[i].wrapping_add(u64::conditional_select(
                                    &product.low[i],
                                    &product.low[i].wrapping_neg(),
                                    negative,
                                ));
                        }
                    }
                }
                *ready = self.ready::<800>(wide);
            }
            let next = self.batch_reduce_expand(&ready);
            if start == 0 {
                result = next;
            } else {
                for (result, next) in result.iter_mut().zip(&next) {
                    *result = self.add(*result, *next);
                }
            }
            start += 32;
        }
        result
    }
}

const fn ordinary_offset<P: Modulus>(k: i64) -> [Lanes; 2] {
    let mut out = [[0; LANES]; 2];
    let mut half = 0;
    while half < 2 {
        let moduli = if half == 0 {
            &P::PARAMETERS.m.moduli
        } else {
            &P::PARAMETERS.n.moduli
        };
        let mut i = 0;
        while i < LANES {
            out[half][i] = (P::PARAMETERS.encoded_p[half][i] as i128 * k as i128 * 40)
                .rem_euclid(moduli[i] as i128) as u64;
            i += 1;
        }
        half += 1;
    }
    out
}

const fn wide_offset<P: Modulus>(e: i64, k: i64) -> [RawWide; 2] {
    assert!(e >= 0 && e <= 800);
    let mut out = [RawWide::ZERO; 2];
    let mut half = 0;
    while half < 2 {
        let moduli = if half == 0 {
            &P::PARAMETERS.m.moduli
        } else {
            &P::PARAMETERS.n.moduli
        };
        let mut i = 0;
        while i < LANES {
            let q = moduli[i] as u128;
            let value = e as u128 * q * q;
            let desired = (P::PARAMETERS.wide_encoded_p2[half][i] as i128 * k as i128 * 1600)
                .rem_euclid(q as i128) as u128;
            let mut low = (value & MASK as u128) + desired + e as u128 * q;
            let minimum = (e as u128) << WORD;
            if low < minimum {
                low += (minimum - low).div_ceil(q) * q;
            }
            out[half].high[i] = (value >> WORD) as u64;
            out[half].low[i] = low as u64;
            i += 1;
        }
        half += 1;
    }
    out
}

/// A sealed homogeneous or heterogeneous batch of prepared small values.
#[allow(private_bounds)]
pub trait ExpansionBatch<P: Modulus>: sealed::Batch {
    /// Expanded values retaining their individual integer intervals.
    type Output;
    #[doc(hidden)]
    fn expand<B: Backend>(&self, ring: &Ring<P, B>) -> Self::Output;
}

const fn expansion_capacity<P: Modulus, R: Bound>() {
    assert!(R::INTERVAL.lower >= 0);
    assert!(R::INTERVAL.upper <= P::PARAMETERS.max_expand);
}

impl<P: Modulus, R: Bound, const N: usize> sealed::Batch for [Small<P, Range<0, 2>, R>; N] {}
impl<P: Modulus, R: Bound, const N: usize> ExpansionBatch<P> for [Small<P, Range<0, 2>, R>; N] {
    type Output = [Expanded<P, Range<0, 2>, R>; N];
    #[inline(always)]
    fn expand<B: Backend>(&self, ring: &Ring<P, B>) -> Self::Output {
        const {
            expansion_capacity::<P, R>();
        }
        let mut n = [[0; LANES]; N];
        let mut i = 0;
        while i < N {
            n[i] = self[i].n;
            i += 1;
        }
        let m = ring.expand_raw(&n);
        let mut output = [Expanded::from_halves([[0; LANES]; 2]); N];
        i = 0;
        while i < N {
            output[i] = Expanded::from_halves([m[i], n[i]]);
            i += 1;
        }
        output
    }
}

macro_rules! tuple_expansion {
    ($n:expr; $( $r:ident:$i:tt ),+) => {
        impl<P:Modulus,$($r:Bound),+> sealed::Batch for ($(Small<P,Range<0,2>,$r>,)+) {}
        impl<P:Modulus,$($r:Bound),+> ExpansionBatch<P> for ($(Small<P,Range<0,2>,$r>,)+) {
            type Output=($(Expanded<P,Range<0,2>,$r>,)+);
            #[inline(always)]
            fn expand<B:Backend>(&self,ring:&Ring<P,B>)->Self::Output {
                const { $(expansion_capacity::<P,$r>();)+ }
                let n=[ $(self.$i.n,)+ ];let m=ring.expand_raw(&n);
                ($(Expanded::from_halves([m[$i],n[$i]]),)+)
            }
        }
    };
}
tuple_expansion!(1; R0:0);
tuple_expansion!(2; R0:0,R1:1);
tuple_expansion!(3; R0:0,R1:1,R2:2);
tuple_expansion!(4; R0:0,R1:1,R2:2,R3:3);
tuple_expansion!(5; R0:0,R1:1,R2:2,R3:3,R4:4);
tuple_expansion!(6; R0:0,R1:1,R2:2,R3:3,R4:4,R5:5);
tuple_expansion!(7; R0:0,R1:1,R2:2,R3:3,R4:4,R5:5,R6:6);
tuple_expansion!(8; R0:0,R1:1,R2:2,R3:3,R4:4,R5:5,R6:6,R7:7);
tuple_expansion!(9; R0:0,R1:1,R2:2,R3:3,R4:4,R5:5,R6:6,R7:7,R8:8);
tuple_expansion!(10; R0:0,R1:1,R2:2,R3:3,R4:4,R5:5,R6:6,R7:7,R8:8,R9:9);
tuple_expansion!(11; R0:0,R1:1,R2:2,R3:3,R4:4,R5:5,R6:6,R7:7,R8:8,R9:9,R10:10);
tuple_expansion!(12; R0:0,R1:1,R2:2,R3:3,R4:4,R5:5,R6:6,R7:7,R8:8,R9:9,R10:10,R11:11);
