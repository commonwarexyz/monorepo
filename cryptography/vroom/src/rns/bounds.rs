//! Inclusive intervals carried in types throughout the residue computation.

use core::marker::PhantomData;

pub(super) mod sealed {
    pub trait Sealed {}
}

/// An inclusive interval of integer multiples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interval {
    /// The smallest permitted multiple.
    pub lower: i64,
    /// The largest permitted multiple.
    pub upper: i64,
}

impl Interval {
    /// Creates an ordered interval whose endpoints fit signed 64-bit storage.
    pub const fn new(lower: i128, upper: i128) -> Self {
        assert!(lower <= upper);
        assert!(lower >= i64::MIN as i128);
        assert!(upper <= i64::MAX as i128);
        Self {
            lower: lower as i64,
            upper: upper as i64,
        }
    }

    pub(crate) const fn add(self, other: Self) -> Self {
        Self::new(
            self.lower as i128 + other.lower as i128,
            self.upper as i128 + other.upper as i128,
        )
    }

    pub(crate) const fn sub(self, other: Self) -> Self {
        Self::new(
            self.lower as i128 - other.upper as i128,
            self.upper as i128 - other.lower as i128,
        )
    }

    pub(crate) const fn mul(self, other: Self) -> Self {
        let products = [
            self.lower as i128 * other.lower as i128,
            self.lower as i128 * other.upper as i128,
            self.upper as i128 * other.lower as i128,
            self.upper as i128 * other.upper as i128,
        ];
        let mut lower = products[0];
        let mut upper = lower;
        let mut i = 1;
        while i < 4 {
            lower = if lower < products[i] {
                lower
            } else {
                products[i]
            };
            upper = if upper > products[i] {
                upper
            } else {
                products[i]
            };
            i += 1;
        }
        Self::new(lower, upper)
    }

    /// Returns whether this interval contains every value in another interval.
    pub const fn contains(self, other: Self) -> bool {
        self.lower <= other.lower && self.upper >= other.upper
    }
}

/// A sealed interval computed entirely from type parameters.
pub trait Bound: sealed::Sealed + Copy + core::fmt::Debug {
    /// The inclusive endpoints.
    const INTERVAL: Interval;
}

/// An explicit inclusive interval.
#[derive(Clone, Copy, Debug)]
pub struct Range<const LOWER: i64, const UPPER: i64>;

impl<const L: i64, const U: i64> sealed::Sealed for Range<L, U> {}
impl<const L: i64, const U: i64> Bound for Range<L, U> {
    const INTERVAL: Interval = Interval::new(L as i128, U as i128);
}

macro_rules! binary_bound {
    ($name:ident, $operation:ident) => {
        #[doc = concat!("The interval resulting from `", stringify!($operation), "` on two intervals.")]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<A: Bound, B: Bound>(PhantomData<(A, B)>);
        impl<A: Bound, B: Bound> sealed::Sealed for $name<A, B> {}
        impl<A: Bound, B: Bound> Bound for $name<A, B> {
            const INTERVAL: Interval = A::INTERVAL.$operation(B::INTERVAL);
        }
    };
}

binary_bound!(Sum, add);
binary_bound!(Difference, sub);
binary_bound!(Product, mul);
/// An interval scaled by a public constant.
pub type Scale<A, const C: i64> = Product<A, Range<C, C>>;

/// Product bounds that also cover the independent low product half.
#[derive(Clone, Copy, Debug)]
pub struct LaneProduct<A: Bound, B: Bound>(PhantomData<(A, B)>);
impl<A: Bound, B: Bound> sealed::Sealed for LaneProduct<A, B> {}
impl<A: Bound, B: Bound> Bound for LaneProduct<A, B> {
    const INTERVAL: Interval = {
        assert!(A::INTERVAL.lower >= 0 && B::INTERVAL.lower >= 0);
        Interval::new(0, A::INTERVAL.upper as i128 * B::INTERVAL.upper as i128)
    };
}

/// The interval `[E,E+1]` used by an exact wide offset.
#[derive(Clone, Copy, Debug)]
pub struct Offset<const E: i64>;
impl<const E: i64> sealed::Sealed for Offset<E> {}
impl<const E: i64> Bound for Offset<E> {
    const INTERVAL: Interval = Interval::new(E as i128, E as i128 + 1);
}

/// An interval with its sign reversed.
#[derive(Clone, Copy, Debug)]
pub struct Negated<A: Bound>(PhantomData<A>);
impl<A: Bound> sealed::Sealed for Negated<A> {}
impl<A: Bound> Bound for Negated<A> {
    const INTERVAL: Interval =
        Interval::new(-(A::INTERVAL.upper as i128), -(A::INTERVAL.lower as i128));
}

/// Lane bounds after subtracting from a power-of-two modulus multiple.
#[derive(Clone, Copy, Debug)]
pub struct LaneNegated<A: Bound>(PhantomData<A>);
impl<A: Bound> sealed::Sealed for LaneNegated<A> {}
impl<A: Bound> Bound for LaneNegated<A> {
    const INTERVAL: Interval = {
        let offset = negate_offset(A::INTERVAL.upper);
        Interval::new(
            offset as i128 - A::INTERVAL.upper as i128,
            offset as i128 - A::INTERVAL.lower as i128,
        )
    };
}

pub(crate) const fn negate_offset(upper: i64) -> i64 {
    if upper <= 0 {
        return 0;
    }
    let offset = (upper as u64).next_power_of_two();
    assert!(offset <= i64::MAX as u64);
    offset as i64
}

/// Integer bounds after the small-value expansion offset.
#[derive(Clone, Copy, Debug)]
pub struct ExpandRange<R: Bound>(PhantomData<R>);
impl<R: Bound> sealed::Sealed for ExpandRange<R> {}
impl<R: Bound> Bound for ExpandRange<R> {
    const INTERVAL: Interval = {
        let offset = expand_offset(R::INTERVAL.lower);
        R::INTERVAL.add(Interval::new(offset as i128, offset as i128))
    };
}

pub(crate) const fn expand_offset(lower: i64) -> i64 {
    assert!(lower >= -24);
    if lower < -4 {
        24
    } else if lower < 0 {
        4
    } else {
        0
    }
}

/// Lane bounds after preparation to a specified limit.
#[derive(Clone, Copy, Debug)]
pub struct Prepared<A: Bound, const STOP: i64>(PhantomData<A>);
impl<A: Bound, const STOP: i64> sealed::Sealed for Prepared<A, STOP> {}
impl<A: Bound, const STOP: i64> Bound for Prepared<A, STOP> {
    const INTERVAL: Interval = {
        assert!(STOP >= 1);
        let mut lower = A::INTERVAL.lower;
        let mut upper = A::INTERVAL.upper;
        if lower < 0 {
            let mut offset = 1i64;
            while offset < -lower {
                offset = offset.checked_mul(2).unwrap();
            }
            lower += offset;
            upper = upper.checked_add(offset).unwrap();
        }
        assert!(lower >= 0);
        let result = if upper <= STOP {
            upper
        } else if STOP == 1 || upper <= 2 * STOP {
            STOP
        } else {
            2
        };
        Interval::new(0, result as i128)
    };
}

/// Lane bounds after one word Montgomery reduction.
#[derive(Clone, Copy, Debug)]
pub struct Montgomery<A: Bound>(PhantomData<A>);
impl<A: Bound> sealed::Sealed for Montgomery<A> {}
impl<A: Bound> Bound for Montgomery<A> {
    const INTERVAL: Interval = {
        assert!(A::INTERVAL.lower >= 0);
        Interval::new(
            0,
            (A::INTERVAL.upper as i128 + super::MULT_OK as i128 - 1) / super::MULT_OK as i128 + 1,
        )
    };
}

/// Wide lane bounds including a required negative-integer offset.
#[derive(Clone, Copy, Debug)]
pub struct LiftedLane<L: Bound, R: Bound>(PhantomData<(L, R)>);
impl<L: Bound, R: Bound> sealed::Sealed for LiftedLane<L, R> {}
impl<L: Bound, R: Bound> Bound for LiftedLane<L, R> {
    const INTERVAL: Interval =
        L::INTERVAL.add(Interval::new(0, if R::INTERVAL.lower < 0 { 1 } else { 0 }));
}

/// The second-basis lane bound after a reduction batch.
#[derive(Clone, Copy, Debug)]
pub struct Reduced<P: crate::Modulus, const A: i64>(PhantomData<P>);
impl<P: crate::Modulus, const A: i64> sealed::Sealed for Reduced<P, A> {}
impl<P: crate::Modulus, const A: i64> Bound for Reduced<P, A> {
    const INTERVAL: Interval = {
        let contribution = if P::PARAMETERS.no_k {
            2 * super::LANES as i128
        } else {
            2 * super::LANES as i128 * super::MULT_OK as i128
        };
        Interval::new(
            0,
            (A as i128 + contribution + super::MULT_OK as i128 - 1) / super::MULT_OK as i128 + 1,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_arithmetic_matches_extrema() {
        for a in -8..=8 {
            for b in a..=8 {
                for c in -8..=8 {
                    for d in c..=8 {
                        let first = Interval::new(a, b);
                        let second = Interval::new(c, d);
                        let result = first.mul(second);
                        for x in a..=b {
                            for y in c..=d {
                                assert!(
                                    (result.lower as i128..=result.upper as i128)
                                        .contains(&(x * y))
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn reference_ranges_are_compile_time_and_empty() {
        type Negated = Difference<Range<0, 0>, Range<0, 6>>;
        type Wide = Product<Range<0, 6>, Negated>;
        type Lifted = Sum<Wide, Range<1932, 1932>>;
        const EXPECTED: Interval = Lifted::INTERVAL;
        assert_eq!(
            EXPECTED,
            Interval {
                lower: 1896,
                upper: 1932
            }
        );
        assert_eq!(core::mem::size_of::<Lifted>(), 0);
        const {
            assert!(Range::<0, 4309>::INTERVAL.contains(EXPECTED));
        }
        assert_eq!(Prepared::<Range<0, 2>, 4>::INTERVAL.upper, 2);
        assert_eq!(Prepared::<Range<-24, 2>, 4>::INTERVAL.upper, 2);
        assert_eq!(Prepared::<Range<0, 8>, 4>::INTERVAL.upper, 4);
    }
}
