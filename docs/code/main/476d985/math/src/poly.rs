use crate::algebra::{msm_naive, Additive, CryptoGroup, Field, Object, Random, Ring, Space};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_utils::{non_empty_vec, ordered::Map, vec::NonEmptyVec, TryCollect};
use core::{
    fmt::Debug,
    iter,
    num::NonZeroU32,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use rayon::{prelude::*, ThreadPoolBuilder};

// SECTION: Performance knobs.
const MIN_POINTS_FOR_MSM: usize = 2;

/// A polynomial, with coefficients in `K`.
#[derive(Clone)]
pub struct Poly<K> {
    // Invariant: (1..=u32::MAX).contains(coeffs.len())
    coeffs: NonEmptyVec<K>,
}

impl<K> Poly<K> {
    fn len(&self) -> NonZeroU32 {
        self.coeffs
            .len()
            .try_into()
            .expect("Impossible: polynomial length not in 1..=u32::MAX")
    }

    fn len_usize(&self) -> usize {
        self.coeffs.len().get()
    }

    /// Internal method to construct a polynomial from an iterator.
    ///
    /// This will panic if the iterator does not return any coefficients,
    /// so make sure that the iterator you pass to this function does that.
    fn from_iter_unchecked(iter: impl IntoIterator<Item = K>) -> Self {
        let coeffs = iter
            .into_iter()
            .try_collect::<NonEmptyVec<_>>()
            .expect("polynomial must have a least 1 coefficient");
        Self { coeffs }
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

    /// Return the number of evaluation points required to recover this polynomial.
    ///
    /// In other words, [`Self::degree`] + 1.
    pub fn required(&self) -> NonZeroU32 {
        self.len()
    }

    /// Return the constant value of this polynomial.
    ///
    /// I.e. the first coefficient.
    pub fn constant(&self) -> &K {
        &self.coeffs[0]
    }

    /// Translate the coefficients of this polynomial.
    ///
    /// This applies some kind of map to each coefficient, creating a new
    /// polynomial.
    pub fn translate<L>(&self, f: impl Fn(&K) -> L) -> Poly<L> {
        Poly {
            coeffs: self.coeffs.map(f),
        }
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

    /// Like [`Self::eval`], but using [`Space::msm`].
    ///
    /// This method uses more scratch space, and requires cloning values of
    /// type `R` more, but should be better if [`Space::msm`] has a better algorithm
    /// for `K`.
    pub fn eval_msm<R: Ring>(&self, r: &R) -> K
    where
        K: Space<R>,
    {
        // Contains 1, r, r^2, ...
        let weights = {
            let len = self.len_usize();
            let mut out = Vec::with_capacity(len);
            out.push(R::one());
            let mut acc = R::one();
            for _ in 1..len {
                acc *= r;
                out.push(acc.clone());
            }
            out
        };
        K::msm(&self.coeffs, &weights, 1)
    }
}

impl<K: Debug> Debug for Poly<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl<K: EncodeSize> EncodeSize for Poly<K> {
    fn encode_size(&self) -> usize {
        self.coeffs.encode_size()
    }
}

impl<K: Write> Write for Poly<K> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.coeffs.write(buf);
    }
}

impl<K: Read> Read for Poly<K> {
    type Cfg = (RangeCfg<NonZeroU32>, <K as Read>::Cfg);

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            coeffs: NonEmptyVec::<K>::read_cfg(buf, &(cfg.0.into(), cfg.1.clone()))?,
        })
    }
}

impl<K: Random> Poly<K> {
    // Returns a new polynomial of the given degree where each coefficient is
    // sampled at random from the provided RNG.
    pub fn new(mut rng: impl CryptoRngCore, degree: u32) -> Self {
        Self::from_iter_unchecked((0..=degree).map(|_| K::random(&mut rng)))
    }

    /// Returns a new scalar polynomial with a particular value for the constant coefficient.
    ///
    /// This does the same thing as [`Poly::new`] otherwise.
    pub fn new_with_constant(mut rng: impl CryptoRngCore, degree: u32, constant: K) -> Self {
        Self::from_iter_unchecked(
            iter::once(constant).chain((0..=degree).skip(1).map(|_| K::random(&mut rng))),
        )
    }
}

/// An equality test taking into account high 0 coefficients.
///
/// Without this behavior, the additive test suite does not past, because
/// `x - x` may result in a polynomial with extra 0 coefficients.
impl<K: Additive> PartialEq for Poly<K> {
    fn eq(&self, other: &Self) -> bool {
        let zero = K::zero();
        let max_len = self.len().max(other.len());
        let self_then_zeros = self.coeffs.iter().chain(iter::repeat(&zero));
        let other_then_zeros = other.coeffs.iter().chain(iter::repeat(&zero));
        self_then_zeros
            .zip(other_then_zeros)
            .take(max_len.get() as usize)
            .all(|(a, b)| a == b)
    }
}

impl<K: Additive> Eq for Poly<K> {}

impl<K: Additive> Poly<K> {
    fn merge_with(&mut self, rhs: &Self, f: impl Fn(&mut K, &K)) {
        self.coeffs
            .resize(self.coeffs.len().max(rhs.coeffs.len()), K::zero());
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
            coeffs: self.coeffs.map_into(Neg::neg),
        }
    }
}

impl<K: Additive> Additive for Poly<K> {
    fn zero() -> Self {
        Self {
            coeffs: non_empty_vec![K::zero()],
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

#[cfg(feature = "std")]
impl<R: Sync, K: Space<R>> Space<R> for Poly<K> {
    fn msm(polys: &[Self], scalars: &[R], concurrency: usize) -> Self {
        if polys.len() < MIN_POINTS_FOR_MSM {
            return msm_naive(polys, scalars);
        }

        let cols = polys.len().min(scalars.len());
        let polys = &polys[..cols];
        let scalars = &scalars[..cols];

        let rows = polys
            .iter()
            .map(|x| x.len_usize())
            .max()
            .expect("at least 1 point");

        if concurrency > 1 {
            let pool = ThreadPoolBuilder::new()
                .num_threads(concurrency)
                .build()
                .expect("Unable to build thread pool");

            let coeffs = pool.install(|| {
                (0..rows)
                    .into_par_iter()
                    .map(|i| {
                        let row: Vec<_> = polys
                            .iter()
                            .map(|p| p.coeffs.get(i).cloned().unwrap_or_else(K::zero))
                            .collect();
                        K::msm(&row, scalars, 1)
                    })
                    .collect::<Vec<_>>()
            });
            return Poly::from_iter_unchecked(coeffs);
        }

        let mut row = Vec::with_capacity(cols);
        let coeffs = (0..rows).map(|i| {
            row.clear();
            for p in polys {
                row.push(p.coeffs.get(i).cloned().unwrap_or_else(K::zero));
            }
            K::msm(&row, scalars, concurrency)
        });

        Poly::from_iter_unchecked(coeffs)
    }
}

#[cfg(not(feature = "std"))]
impl<R, K: Space<R>> Space<R> for Poly<K> {
    fn msm(polys: &[Self], scalars: &[R], concurrency: usize) -> Self {
        if polys.len() < MIN_POINTS_FOR_MSM {
            return msm_naive(polys, scalars);
        }

        let cols = polys.len().min(scalars.len());
        let polys = &polys[..cols];
        let scalars = &scalars[..cols];

        let rows = polys
            .iter()
            .map(|x| x.len_usize())
            .max()
            .expect("at least 1 point");

        let mut row = Vec::with_capacity(cols);
        let coeffs = (0..rows).map(|i| {
            row.clear();
            for p in polys {
                row.push(p.coeffs.get(i).cloned().unwrap_or_else(K::zero));
            }
            K::msm(&row, scalars, concurrency)
        });
        Poly::from_iter_unchecked(coeffs)
    }
}

impl<G: CryptoGroup> Poly<G> {
    /// Commit to a polynomial of scalars, producing a polynomial of group elements.
    pub fn commit(p: Poly<G::Scalar>) -> Self {
        p.translate(|c| G::generator() * c)
    }
}

/// An interpolator allows recovering a polynomial's constant from values.
///
/// This is useful for polynomial secret sharing. There, a secret is stored
/// in the constant of a polynomial. Shares of the secret are created by
/// evaluating the polynomial at various points. Given enough values for
/// these points, the secret can be recovered.
///
/// Using an [`Interpolator`] can be more efficient, because work can be
/// done in advance based only on the points that will be used for recovery,
/// before the value of the polynomial at these points is known. The interpolator
/// can use these values to recover the secret at a later time.
///
/// ### Usage
///
/// ```
/// # use commonware_math::{fields::goldilocks::F, poly::{Poly, Interpolator}};
/// # use commonware_utils::TryCollect;
/// # fn example(f: Poly<F>, g: Poly<F>, p0: F, p1: F) {
///     let interpolator = Interpolator::new([(0, p0), (1, p1)]);
///     assert_eq!(
///         Some(*f.constant()),
///         interpolator.interpolate(&[(0, f.eval(&p0)), (1, f.eval(&p1))].into_iter().try_collect().unwrap(), 1)
///     );
///     assert_eq!(
///         Some(*g.constant()),
///         interpolator.interpolate(&[(1, g.eval(&p1)), (0, g.eval(&p0))].into_iter().try_collect().unwrap(), 1)
///     );
/// # }
/// ```
pub struct Interpolator<I, F> {
    weights: Map<I, F>,
}

impl<I: PartialEq, F: Ring> Interpolator<I, F> {
    /// Interpolate a polynomial's evaluations to recover its constant.
    ///
    /// The indices provided here MUST match those provided to [`Self::new`] exactly,
    /// otherwise `None` will be returned.
    pub fn interpolate<K: Space<F>>(&self, evals: &Map<I, K>, concurrency: usize) -> Option<K> {
        if evals.keys() != self.weights.keys() {
            return None;
        }
        Some(K::msm(evals.values(), self.weights.values(), concurrency))
    }
}

impl<I: Clone + Ord, F: Field> Interpolator<I, F> {
    /// Create a new interpolator, given an association from indices to evaluation points.
    ///
    /// If an index appears multiple times, the implementation is free to use
    /// any one of the evaluation points associated with that index. In other words,
    /// don't do that, or ensure that if, for some reason, an index appears more
    /// than once, then it has the same evaluation point.
    pub fn new(points: impl IntoIterator<Item = (I, F)>) -> Self {
        let points = Map::from_iter_dedup(points);
        let weights = points
            .iter_pairs()
            .map(|(i, w_i)| {
                let mut top_i = F::one();
                let mut bot_i = F::one();
                for (j, w_j) in points.iter_pairs() {
                    if i == j {
                        continue;
                    }
                    top_i *= w_j;
                    bot_i *= &(w_j.clone() - w_i);
                }
                top_i * &bot_i.inv()
            })
            .collect::<Vec<_>>();
        // Avoid re-sorting by using the memory of points.
        let mut out = points;
        for (out_i, weight_i) in out.values_mut().iter_mut().zip(weights.into_iter()) {
            *out_i = weight_i;
        }
        Self { weights: out }
    }
}

#[cfg(feature = "arbitrary")]
mod fuzz {
    use super::*;
    use arbitrary::Arbitrary;

    impl<'a, F: Arbitrary<'a>> Arbitrary<'a> for Poly<F> {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                coeffs: u.arbitrary()?,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::{F, G};
    use commonware_codec::Encode;
    use proptest::{
        prelude::{Arbitrary, BoxedStrategy, Strategy},
        prop_assume, proptest,
        sample::SizeRange,
    };

    impl Arbitrary for Poly<F> {
        type Parameters = SizeRange;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(size: Self::Parameters) -> Self::Strategy {
            let nonempty_size = if size.start() == 0 { size + 1 } else { size };
            proptest::collection::vec(F::arbitrary(), nonempty_size)
                .prop_map(Poly::from_iter_unchecked)
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

    #[test]
    fn test_eq() {
        fn eq(a: &[u8], b: &[u8]) -> bool {
            Poly {
                coeffs: a.iter().copied().map(F::from).try_collect().unwrap(),
            } == Poly {
                coeffs: b.iter().copied().map(F::from).try_collect().unwrap(),
            }
        }
        assert!(eq(&[1, 2], &[1, 2]));
        assert!(!eq(&[1, 2], &[2, 3]));
        assert!(!eq(&[1, 2], &[1, 2, 3]));
        assert!(!eq(&[1, 2, 3], &[1, 2]));
        assert!(eq(&[1, 2], &[1, 2, 0, 0]));
        assert!(eq(&[1, 2, 0, 0], &[1, 2]));
        assert!(!eq(&[1, 2, 0], &[2, 3]));
        assert!(!eq(&[2, 3], &[1, 2, 0]));
    }

    proptest! {
        #[test]
        fn test_codec(f: Poly<F>) {
            assert_eq!(&f, &Poly::<F>::read_cfg(&mut f.encode(), &(RangeCfg::exact(f.required()), ())).unwrap())
        }

        #[test]
        fn test_eval_add(f: Poly<F>, g: Poly<F>, x: F) {
            assert_eq!(f.eval(&x) + &g.eval(&x), (f + &g).eval(&x));
        }

        #[test]
        fn test_eval_scale(f: Poly<F>, x: F, w: F) {
            assert_eq!(f.eval(&x) * &w, (f * &w).eval(&x));
        }

        #[test]
        fn test_eval_zero(f: Poly<F>) {
            assert_eq!(&f.eval(&F::zero()), f.constant());
        }

        #[test]
        fn test_eval_msm(f: Poly<F>, x: F) {
            assert_eq!(f.eval(&x), f.eval_msm(&x));
        }

        #[test]
        fn test_interpolate(f: Poly<F>) {
            // Make sure this isn't the zero polynomial.
            prop_assume!(f != Poly::zero());
            prop_assume!(f.required().get() < F::MAX as u32);
            let mut points = (0..f.required().get()).map(|i| F::from((i + 1) as u8)).collect::<Vec<_>>();
            let interpolator = Interpolator::new(points.iter().copied().enumerate());
            let evals = Map::from_iter_dedup(points.iter().map(|p| f.eval(p)).enumerate());
            let recovered = interpolator.interpolate(&evals, 1);
            assert_eq!(recovered.as_ref(), Some(f.constant()));
            points.pop();
            assert!(interpolator.interpolate(&Map::from_iter_dedup(points.iter().map(|p| f.eval(p)).enumerate()), 1).is_none());
        }

        #[test]
        fn test_translate_scale(f: Poly<F>, x: F) {
            assert_eq!(f.translate(|c| x * c), f * &x);
        }

        #[test]
        fn test_commit_eval(f: Poly<F>, x: F) {
            assert_eq!(G::generator() * &f.eval(&x), Poly::<G>::commit(f).eval(&x));
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Poly<F>>
        }
    }
}
