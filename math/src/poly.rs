use crate::algebra::{Additive, Object, Space};
use std::{
    cmp::Ordering,
    fmt::Debug,
    num::NonZeroU32,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// A polynomial, with coefficients in `K`.
#[derive(Clone)]
pub struct Poly<K> {
    // Invariant: (1..=u32::MAX).contains(coeffs.len())
    coeffs: Vec<K>,
}

/// An equality test taking into account high 0 coefficients.
///
/// Without this behavior, the additive test suite does not past, because
/// `x - x` may result in a polynomial with extra 0 coefficients.
impl<K: Additive> PartialEq for Poly<K> {
    fn eq(&self, other: &Self) -> bool {
        match self.len().cmp(&other.len()) {
            Ordering::Equal => self.coeffs == other.coeffs,
            Ordering::Less => {
                let zero = K::zero();
                other
                    .coeffs
                    .iter()
                    .skip(self.len_usize())
                    .all(|x| *x == zero)
            }
            Ordering::Greater => {
                let zero = K::zero();
                self.coeffs
                    .iter()
                    .skip(other.len_usize())
                    .all(|x| *x == zero)
            }
        }
    }
}

impl<K: Additive> Eq for Poly<K> {}

impl<K> Poly<K> {
    fn len(&self) -> NonZeroU32 {
        self.coeffs
            .len()
            .try_into()
            .and_then(|x: u32| x.try_into())
            .expect("Impossible: polynomial length not in 1..=u32::MAX")
    }

    fn len_usize(&self) -> usize {
        self.len().get() as usize
    }

    /// The degree of this polynomial.
    ///
    /// Technically, this is only an *upper bound* on the degree, because
    /// this method does not inspect the coefficients of a polynomial to check
    /// if they're non-zero.
    ///
    /// Because of this, it's possible that two polynomials
    /// considered equal have different degrees.
    ///
    /// For that behavior, see [`Self::degree_exact`].
    pub fn degree(&self) -> u32 {
        self.len().get() - 1
    }

    /// Return the constant value of this polynomial.
    ///
    /// I.e. the first coefficient.
    pub fn constant(&self) -> &K {
        &self.coeffs[0]
    }

    /// Evaluate a polynomial at a particular point.
    ///
    /// For
    ///
    ///   `p(X) := a_0 + a_1 X + a_2 X^2 + ...`
    ///
    /// this returns:
    ///
    ///   `a_0 + a_1 r + a_2 r^2 + ...`
    ///
    /// This can work for any type which can multiply the coefficients of
    /// this polynomial.
    ///
    /// For example, if you have a polynomial consistent of elements of a group,
    /// you can evaluate it using a scalar over that group.
    pub fn eval<R>(&self, r: &R) -> K
    where
        K: Space<R>,
    {
        let mut iter = self.coeffs.iter().rev();
        // Evaluation using Horner's method.
        //
        // p(r)
        // = a_0 + a_1 r + ... + a_n r^N =
        // = a_n r^n + ...
        // = ((a_n) r + a_(n - 1))r + ...)
        let mut acc = iter
            .next()
            .expect("Impossible: Polynomial has no coefficients")
            .clone();
        for coeff in iter {
            acc *= r;
            acc += coeff;
        }
        acc
    }
}

impl<K: Additive> Poly<K> {
    fn merge_with(&mut self, rhs: &Self, f: impl Fn(&mut K, &K)) {
        self.coeffs
            .resize(self.len_usize().max(rhs.len_usize()), K::zero());
        self.coeffs
            .iter_mut()
            .zip(&rhs.coeffs)
            .for_each(|(a, b)| f(a, b));
    }

    /// Like [`Self::degree`], but checking for zero coefficients.
    ///
    /// This method is slower, but reports exact results in case there are zeros.
    ///
    /// This will return 0 for a polynomial with no coefficients.
    pub fn degree_exact(&self) -> u32 {
        let zero = K::zero();
        let leading_zeroes = self.coeffs.iter().rev().take_while(|&x| x == &zero).count();
        let lz_u32 =
            u32::try_from(leading_zeroes).expect("Impossible: Polynomial has >= 2^32 coefficients");
        // The saturation is critical, otherwise you get a negative number for
        // the zero polynomial.
        self.degree().saturating_sub(lz_u32)
    }
}

impl<K: Debug> Debug for Poly<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Poly(")?;
        for (i, c) in self.coeffs.iter().enumerate() {
            if i > 0 {
                write!(f, " + {c:?} X^{i}")?;
            } else {
                write!(f, "{c:?}")?;
            }
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl<K: Additive> Object for Poly<K> {}

// SECTION: implementing Additive

impl<'a, K: Additive> AddAssign<&'a Poly<K>> for Poly<K> {
    fn add_assign(&mut self, rhs: &'a Poly<K>) {
        self.merge_with(rhs, |a, b| *a += b);
    }
}

impl<'a, K: Additive> Add<&'a Poly<K>> for Poly<K> {
    type Output = Self;

    fn add(mut self, rhs: &'a Poly<K>) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a, K: Additive> SubAssign<&'a Poly<K>> for Poly<K> {
    fn sub_assign(&mut self, rhs: &'a Poly<K>) {
        self.merge_with(rhs, |a, b| *a -= b);
    }
}

impl<'a, K: Additive> Sub<&'a Poly<K>> for Poly<K> {
    type Output = Self;

    fn sub(mut self, rhs: &'a Poly<K>) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<K: Additive> Neg for Poly<K> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            coeffs: self.coeffs.into_iter().map(Neg::neg).collect::<Vec<_>>(),
        }
    }
}

impl<K: Additive> Additive for Poly<K> {
    fn zero() -> Self {
        Self {
            coeffs: vec![K::zero()],
        }
    }
}

// SECTION: implementing Space<K>.

impl<'a, R, K: Space<R>> MulAssign<&'a R> for Poly<K> {
    fn mul_assign(&mut self, rhs: &'a R) {
        self.coeffs.iter_mut().for_each(|c| *c *= rhs);
    }
}

impl<'a, R, K: Space<R>> Mul<&'a R> for Poly<K> {
    type Output = Self;

    fn mul(mut self, rhs: &'a R) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<R, K: Space<R>> Space<R> for Poly<K> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fields::goldilocks::F;
    use proptest::{
        prelude::{Arbitrary, BoxedStrategy, Strategy},
        proptest,
        sample::SizeRange,
    };

    impl Arbitrary for Poly<F> {
        type Parameters = SizeRange;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(size: Self::Parameters) -> Self::Strategy {
            let nonempty_size = if size.start() == 0 { size + 1 } else { size };
            proptest::collection::vec(F::arbitrary(), nonempty_size)
                .prop_map(|coeffs| Poly { coeffs })
                .boxed()
        }
    }

    #[test]
    fn test_additive() {
        crate::algebra::test_suites::test_additive(file!(), &Poly::<F>::arbitrary());
    }

    #[test]
    fn test_space() {
        crate::algebra::test_suites::test_space_ring(
            file!(),
            &F::arbitrary(),
            &Poly::<F>::arbitrary(),
        );
    }

    proptest! {
        #[test]
        fn test_eval_add(f: Poly<F>, g: Poly<F>, x: F) {
            assert_eq!(f.eval(&x) + g.eval(&x), (f + &g).eval(&x));
        }

        #[test]
        fn test_eval_scale(f: Poly<F>, x: F, w: F) {
            assert_eq!(f.eval(&x) * &w, (f * &w).eval(&x));
        }

        #[test]
        fn test_eval_zero(f: Poly<F>) {
            assert_eq!(&f.eval(&F::zero()), f.constant());
        }
    }
}
