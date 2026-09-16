// Adapted from VROOM/src/fp2.hpp.
// Copyright 2026 Simon Langowski, licensed under MIT.
// See LICENSE-VROOM for the permission notice.

//! Bounded quadratic-extension arithmetic for the shared residue backend.

use commonware_cryptography_vroom::{
    Backend, Bls12381,
    rns::{
        DelayedProduct, Expanded, Left, Ready, ReductionInput, Ring, Standard, Wide,
        bounds::{
            Bound, LaneNegated, LaneProduct, Negated, Prepared, Product as BoundProduct, Range,
            Scale as BoundScale,
        },
    },
};
use core::ops::{Add, Mul, Sub};
use subtle::{Choice, ConditionallySelectable};

type Sum<A, B> = <A as Add<B>>::Output;
type Product<A, B> = <A as Mul<B>>::Output;
type Scaled<A, const C: i64> = <A as Scale<C>>::Output;
type Field<L, R> = Expanded<Bls12381, L, R>;
type Negation<L, R> = Field<LaneNegated<L>, Negated<R>>;
type PreparedField<L, R> = Field<Prepared<L, 4>, R>;
type PreparedLeft<B, L, R> = Left<Bls12381, B, Prepared<L, 4>, R>;

type Accumulated<X, Y, LX, LY, LN, RX, RY> = Fp2<
    Sum<Sum<X, Product<LX, RX>>, Product<LN, RY>>,
    Sum<Sum<Y, Product<LX, RY>>, Product<LY, RX>>,
>;
type Squared<B, LX, RX, LY, RY, LN, RN> = Fp2<
    Sum<
        Product<Left<Bls12381, B, LX, RX>, Field<LX, RX>>,
        Product<Left<Bls12381, B, LN, RN>, Field<LY, RY>>,
    >,
    Scaled<Product<Left<Bls12381, B, LX, RX>, Field<LY, RY>>, 2>,
>;
type PreparedFp2Left<B, LX, RX, LY, RY> = Fp2Left<
    PreparedLeft<B, LX, RX>,
    PreparedLeft<B, LY, RY>,
    PreparedLeft<B, LaneNegated<Prepared<LY, 4>>, Negated<RY>>,
>;
type BoundedLeft<B, LX, RX, LY, RY, LN, RN> =
    Fp2Left<Left<Bls12381, B, LX, RX>, Left<Bls12381, B, LY, RY>, Left<Bls12381, B, LN, RN>>;
type NegatedLeft<B, LX, RX, LY, RY, LN, RN> = Fp2Left<
    PreparedLeft<B, LaneNegated<LX>, Negated<RX>>,
    Left<Bls12381, B, LN, RN>,
    Left<Bls12381, B, LY, RY>,
>;
type ThreeB<LX, RX, LY, RY> = Fp2<
    Scaled<Sum<Field<LX, RX>, Negation<LY, RY>>, 12>,
    Scaled<Sum<Field<LX, RX>, Field<LY, RY>>, 12>,
>;
type ScalarProduct<B, LX, RX, LY, RY, L, R> = Fp2<
    Product<PreparedLeft<B, LX, RX>, Field<L, R>>,
    Product<PreparedLeft<B, LY, RY>, Field<L, R>>,
>;

pub(crate) type Fp2Standard = Fp2<Standard<Bls12381>>;
pub(crate) type Fp2Ready<const A: i64 = 800> = [Ready<Bls12381, A>; 2];
pub(crate) type Fp2LeftStandard<B> = Fp2Left<
    PreparedLeft<B, Range<0, 2>, Range<0, 1>>,
    PreparedLeft<B, Range<0, 2>, Range<0, 1>>,
    PreparedLeft<B, Range<0, 2>, Range<0, 1>>,
>;

pub(crate) trait Batch<const N: usize, const A: i64> {
    fn reduce_expand<B: Backend>(&self, ring: &Ring<Bls12381, B>) -> [Fp2Standard; N];
}

macro_rules! batch {
    ($n:literal; $($i:literal),+) => {
        impl<const A: i64> Batch<$n, A> for [Fp2Ready<A>; $n] {
            #[inline(always)]
            fn reduce_expand<B: Backend>(&self, ring: &Ring<Bls12381, B>) -> [Fp2Standard; $n] {
                let coefficients = ring.batch_reduce_expand(&[
                    $(self[$i][0],)+
                    $(self[$i][1],)+
                ]);
                [$(Fp2 { c0: coefficients[$i], c1: coefficients[$n + $i] },)+]
            }
        }
    };
}

batch!(1; 0);
batch!(2; 0, 1);
batch!(3; 0, 1, 2);
batch!(4; 0, 1, 2, 3);
batch!(5; 0, 1, 2, 3, 4);
batch!(6; 0, 1, 2, 3, 4, 5);

pub(crate) trait Scale<const C: i64> {
    type Output;
    fn scaled(self) -> Self::Output;
}

macro_rules! scale_component {
    ($name:ident) => {
        impl<L: Bound, R: Bound, const C: i64> Scale<C> for $name<Bls12381, L, R> {
            type Output = $name<Bls12381, BoundScale<L, C>, BoundScale<R, C>>;

            #[inline]
            fn scaled(self) -> Self::Output {
                self.scale::<C>()
            }
        }
    };
}

scale_component!(Expanded);
scale_component!(Wide);

impl<B: Backend, L1: Bound, R1: Bound, L2: Bound, R2: Bound, const C: i64> Scale<C>
    for DelayedProduct<Bls12381, B, L1, R1, L2, R2>
{
    type Output =
        Wide<Bls12381, BoundScale<LaneProduct<L1, L2>, C>, BoundScale<BoundProduct<R1, R2>, C>>;

    #[inline]
    fn scaled(self) -> Self::Output {
        self.complete().scale::<C>()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fp2<X, Y = X> {
    pub(crate) c0: X,
    pub(crate) c1: Y,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fp2Left<X, Y, N> {
    c0: X,
    c1: Y,
    minus_c1: N,
}

impl<X: ConditionallySelectable, Y: ConditionallySelectable> ConditionallySelectable for Fp2<X, Y> {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c0: X::conditional_select(&a.c0, &b.c0, choice),
            c1: Y::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

macro_rules! component_operation {
    ($trait:ident, $method:ident, $operation:tt) => {
        impl<X, Y, A, B> $trait<Fp2<A, B>> for Fp2<X, Y>
        where
            X: $trait<A>,
            Y: $trait<B>,
        {
            type Output = Fp2<X::Output, Y::Output>;

            #[inline]
            fn $method(self, rhs: Fp2<A, B>) -> Self::Output {
                Fp2 {
                    c0: self.c0 $operation rhs.c0,
                    c1: self.c1 $operation rhs.c1,
                }
            }
        }
    };
}

component_operation!(Add, add, +);
component_operation!(Sub, sub, -);

impl<X, Y, S: Copy> Mul<S> for Fp2<X, Y>
where
    X: Mul<S>,
    Y: Mul<S>,
{
    type Output = Fp2<X::Output, Y::Output>;

    #[inline]
    fn mul(self, rhs: S) -> Self::Output {
        Fp2 {
            c0: self.c0 * rhs,
            c1: self.c1 * rhs,
        }
    }
}

impl<X, Y, N, A, B> Mul<Fp2<A, B>> for Fp2Left<X, Y, N>
where
    X: Copy + Mul<A> + Mul<B>,
    Y: Mul<A>,
    N: Mul<B>,
    A: Copy,
    B: Copy,
    Product<X, A>: Add<Product<N, B>>,
    Product<X, B>: Add<Product<Y, A>>,
{
    type Output = Fp2<Sum<Product<X, A>, Product<N, B>>, Sum<Product<X, B>, Product<Y, A>>>;

    #[inline(always)]
    fn mul(self, rhs: Fp2<A, B>) -> Self::Output {
        Fp2 {
            c0: self.c0 * rhs.c0 + self.minus_c1 * rhs.c1,
            c1: self.c0 * rhs.c1 + self.c1 * rhs.c0,
        }
    }
}

impl<X, Y> Fp2<X, Y> {
    #[inline]
    pub(crate) fn scale<const C: i64>(self) -> Fp2<Scaled<X, C>, Scaled<Y, C>>
    where
        X: Scale<C>,
        Y: Scale<C>,
    {
        Fp2 {
            c0: self.c0.scaled(),
            c1: self.c1.scaled(),
        }
    }

    #[inline(always)]
    pub(crate) fn mul_accumulate<LX, LY, LN, RX, RY>(
        self,
        left: Fp2Left<LX, LY, LN>,
        right: Fp2<RX, RY>,
    ) -> Accumulated<X, Y, LX, LY, LN, RX, RY>
    where
        LX: Copy + Mul<RX> + Mul<RY>,
        LY: Mul<RX>,
        LN: Mul<RY>,
        RX: Copy,
        RY: Copy,
        X: Add<Product<LX, RX>>,
        Sum<X, Product<LX, RX>>: Add<Product<LN, RY>>,
        Y: Add<Product<LX, RY>>,
        Sum<Y, Product<LX, RY>>: Add<Product<LY, RX>>,
    {
        Fp2 {
            c0: self.c0 + left.c0 * right.c0 + left.minus_c1 * right.c1,
            c1: self.c1 + left.c0 * right.c1 + left.c1 * right.c0,
        }
    }
}

impl From<super::Fp2> for Fp2Standard {
    #[inline]
    fn from(value: super::Fp2) -> Self {
        Self {
            c0: value.c0.into(),
            c1: value.c1.into(),
        }
    }
}

impl From<Fp2Standard> for super::Fp2 {
    #[inline]
    fn from(value: Fp2Standard) -> Self {
        Self {
            c0: value.c0.into(),
            c1: value.c1.into(),
        }
    }
}

impl<B: Backend, LX: Bound, RX: Bound, LY: Bound, RY: Bound, LN: Bound, RN: Bound>
    Fp2Left<Left<Bls12381, B, LX, RX>, Left<Bls12381, B, LY, RY>, Left<Bls12381, B, LN, RN>>
{
    #[inline]
    pub(crate) const fn to_fp2(self) -> Fp2<Field<LX, RX>, Field<LY, RY>> {
        Fp2 {
            c0: self.c0.into_expanded(),
            c1: self.c1.into_expanded(),
        }
    }

    #[inline(always)]
    pub(crate) fn square(self) -> Squared<B, LX, RX, LY, RY, LN, RN> {
        Fp2 {
            c0: self.c0 * self.c0.into_expanded() + self.minus_c1 * self.c1.into_expanded(),
            c1: (self.c0 * self.c1.into_expanded()).complete().scale::<2>(),
        }
    }
}

pub(crate) struct Fp2Ring<'a, B: Backend> {
    ring: &'a Ring<Bls12381, B>,
}

impl<'a, B: Backend> Fp2Ring<'a, B> {
    #[inline]
    pub(crate) const fn new(ring: &'a Ring<Bls12381, B>) -> Self {
        Self { ring }
    }

    #[inline(always)]
    pub(crate) fn ready<const A: i64>(
        &self,
        value: Fp2<impl ReductionInput<Bls12381, B>, impl ReductionInput<Bls12381, B>>,
    ) -> Fp2Ready<A> {
        [
            self.ring.ready::<A>(value.c0),
            self.ring.ready::<A>(value.c1),
        ]
    }

    #[inline(always)]
    pub(crate) fn batch_reduce_expand<const N: usize, const A: i64>(
        &self,
        values: &[Fp2Ready<A>; N],
    ) -> [Fp2Standard; N]
    where
        [Fp2Ready<A>; N]: Batch<N, A>,
    {
        values.reduce_expand(self.ring)
    }

    #[inline(always)]
    pub(crate) fn mul(&self, left: Fp2Standard, right: Fp2Standard) -> Fp2Standard {
        let [result] = self.batch_reduce_expand(&[self.ready::<800>(self.prep_left(left) * right)]);
        result
    }

    #[inline(always)]
    pub(crate) fn square(&self, value: Fp2Standard) -> Fp2Standard {
        let [result] =
            self.batch_reduce_expand(&[self.ready::<800>(self.prep_left(value).square())]);
        result
    }

    #[inline(always)]
    pub(crate) fn prep<LX: Bound, RX: Bound, LY: Bound, RY: Bound>(
        &self,
        value: Fp2<Field<LX, RX>, Field<LY, RY>>,
    ) -> Fp2<PreparedField<LX, RX>, PreparedField<LY, RY>> {
        Fp2 {
            c0: self.ring.prep(value.c0),
            c1: self.ring.prep(value.c1),
        }
    }

    #[inline(always)]
    pub(crate) fn prep_left<LX: Bound, RX: Bound, LY: Bound, RY: Bound>(
        &self,
        value: Fp2<Field<LX, RX>, Field<LY, RY>>,
    ) -> PreparedFp2Left<B, LX, RX, LY, RY> {
        let c0 = self.ring.prep_left(value.c0);
        let c1 = self.ring.prep_left(value.c1);
        let minus_c1 = self.ring.prep_left(self.ring.negate(c1.into_expanded()));
        Fp2Left { c0, c1, minus_c1 }
    }

    #[inline(always)]
    pub(crate) fn prep_left_standard(&self, value: Fp2Standard) -> Fp2LeftStandard<B> {
        Fp2Left {
            c0: self.ring.prep_left(value.c0),
            c1: self.ring.prep_left(value.c1),
            minus_c1: self.ring.prep_left(self.ring.standard_negate(value.c1)),
        }
    }

    #[inline]
    pub(crate) fn negate_left<LX: Bound, RX: Bound, LY: Bound, RY: Bound, LN: Bound, RN: Bound>(
        &self,
        value: BoundedLeft<B, LX, RX, LY, RY, LN, RN>,
    ) -> NegatedLeft<B, LX, RX, LY, RY, LN, RN> {
        Fp2Left {
            c0: self
                .ring
                .prep_left(self.ring.negate(value.c0.into_expanded())),
            c1: value.minus_c1,
            minus_c1: value.c1,
        }
    }

    #[inline]
    pub(crate) const fn negate<LX: Bound, RX: Bound, LY: Bound, RY: Bound>(
        &self,
        value: Fp2<Field<LX, RX>, Field<LY, RY>>,
    ) -> Fp2<Negation<LX, RX>, Negation<LY, RY>> {
        Fp2 {
            c0: self.ring.negate(value.c0),
            c1: self.ring.negate(value.c1),
        }
    }

    #[inline]
    pub(crate) fn standard_negate(&self, value: Fp2Standard) -> Fp2Standard {
        Fp2 {
            c0: self.ring.standard_negate(value.c0),
            c1: self.ring.standard_negate(value.c1),
        }
    }

    #[inline]
    pub(crate) fn conjugate(&self, value: Fp2Standard) -> Fp2Standard {
        Fp2 {
            c0: value.c0,
            c1: self.ring.standard_negate(value.c1),
        }
    }

    #[inline]
    pub(crate) fn is_zero(&self, value: Fp2Standard) -> Choice {
        self.ring.is_zero(value.c0) & self.ring.is_zero(value.c1)
    }

    #[inline]
    pub(crate) fn mul_3b<LX: Bound, RX: Bound, LY: Bound, RY: Bound>(
        &self,
        value: Fp2<Field<LX, RX>, Field<LY, RY>>,
    ) -> ThreeB<LX, RX, LY, RY> {
        Fp2 {
            c0: value.c0 + self.ring.negate(value.c1),
            c1: value.c0 + value.c1,
        }
        .scale::<12>()
    }

    #[inline]
    pub(crate) fn mul_by_fp<LX: Bound, RX: Bound, LY: Bound, RY: Bound, L: Bound, R: Bound>(
        &self,
        value: Fp2<Field<LX, RX>, Field<LY, RY>>,
        scalar: Field<L, R>,
    ) -> ScalarProduct<B, LX, RX, LY, RY, L, R> {
        Fp2 {
            c0: self.ring.prep_left(value.c0) * scalar,
            c1: self.ring.prep_left(value.c1) * scalar,
        }
    }
}
