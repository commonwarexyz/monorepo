use crate::algebra::{
    msm_naive, Additive, CryptoGroup, Field, FieldNTT, Object, Random, Ring, Space,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_parallel::Strategy;
use commonware_utils::{non_empty_vec, ordered::Map, vec::NonEmptyVec, TryCollect};
use core::{
    fmt::Debug,
    iter,
    num::NonZeroU32,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRngCore;

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

    const fn len_usize(&self) -> usize {
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
    pub fn eval_msm<R: Ring>(&self, r: &R, strategy: &impl Strategy) -> K
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
        K::msm(&self.coeffs, &weights, strategy)
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

impl<'a, K: Additive> AddAssign<&'a Self> for Poly<K> {
    fn add_assign(&mut self, rhs: &'a Self) {
        self.merge_with(rhs, |a, b| *a += b);
    }
}

impl<'a, K: Additive> Add<&'a Self> for Poly<K> {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a, K: Additive> SubAssign<&'a Self> for Poly<K> {
    fn sub_assign(&mut self, rhs: &'a Self) {
        self.merge_with(rhs, |a, b| *a -= b);
    }
}

impl<'a, K: Additive> Sub<&'a Self> for Poly<K> {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
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

impl<R: Sync, K: Space<R> + Send> Space<R> for Poly<K> {
    fn msm(polys: &[Self], scalars: &[R], strategy: &impl Strategy) -> Self {
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

        let coeffs = strategy.map_init_collect_vec(
            0..rows,
            || Vec::with_capacity(cols),
            |row, i| {
                row.clear();
                for p in polys {
                    row.push(p.coeffs.get(i).cloned().unwrap_or_else(K::zero));
                }
                K::msm(row, scalars, strategy)
            },
        );
        Self::from_iter_unchecked(coeffs)
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
/// # use commonware_parallel::Sequential;
/// # use commonware_utils::TryCollect;
/// # fn example(f: Poly<F>, g: Poly<F>, p0: F, p1: F) {
///     let interpolator = Interpolator::new([(0, p0), (1, p1)]);
///     assert_eq!(
///         Some(*f.constant()),
///         interpolator.interpolate(&[(0, f.eval(&p0)), (1, f.eval(&p1))].into_iter().try_collect().unwrap(), &Sequential)
///     );
///     assert_eq!(
///         Some(*g.constant()),
///         interpolator.interpolate(&[(1, g.eval(&p1)), (0, g.eval(&p0))].into_iter().try_collect().unwrap(), &Sequential)
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
    pub fn interpolate<K: Space<F>>(
        &self,
        evals: &Map<I, K>,
        strategy: &impl Strategy,
    ) -> Option<K> {
        if evals.keys() != self.weights.keys() {
            return None;
        }
        Some(K::msm(evals.values(), self.weights.values(), strategy))
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
        let n = points.len();
        if n == 0 {
            return Self { weights: points };
        }

        // Compute W = product of all w_i
        // Compute c_i = w_i * product((w_j - w_i) for j != i)
        let values = points.values();
        let zero = F::zero();
        let mut total_product = F::one();
        let mut c = Vec::with_capacity(n);
        for (i, w_i) in values.iter().enumerate() {
            // If evaluation point is zero, L_i(0) = 1 for this point and 0 for all others.
            if w_i == &zero {
                let mut out = points;
                for (j, w) in out.values_mut().iter_mut().enumerate() {
                    *w = if j == i { F::one() } else { F::zero() };
                }
                return Self { weights: out };
            }

            // Accumulate c_i = w_i * product((w_j - w_i) for j != i) for batch inversion.
            total_product *= w_i;
            let mut c_i = w_i.clone();
            for w_j in values
                .iter()
                .enumerate()
                .filter_map(|(j, v)| (j != i).then_some(v))
            {
                c_i *= &(w_j.clone() - w_i);
            }
            c.push(c_i);
        }

        // Batch inversion using Montgomery's trick to compute W/c_i for all i
        // Step 1: Compute prefix products (prefix[i] = c[0] * ... * c[i-1])
        let mut prefix = Vec::with_capacity(n + 1);
        prefix.push(F::one());
        let mut acc = F::one();
        for c_i in &c {
            acc *= c_i;
            prefix.push(acc.clone());
        }

        // Step 2: Single inversion, multiplied by W
        let mut inv_acc = total_product * &prefix[n].inv();

        // Step 3: Compute weights directly into output
        let mut out = points;
        let out_vals = out.values_mut();
        for i in (0..n).rev() {
            out_vals[i] = inv_acc.clone() * &prefix[i];
            inv_acc *= &c[i];
        }
        Self { weights: out }
    }
}

impl<I: Clone + Ord, F: FieldNTT> Interpolator<I, F> {
    /// Create an interpolator for evaluation points at roots of unity.
    ///
    /// This uses the fast O(n log n) algorithm from [`crate::ntt::lagrange_coefficients`].
    ///
    /// Each `(I, u32)` pair maps an index `I` to an evaluation point `w^k` where `w` is
    /// a primitive root of unity of order `next_power_of_two(total)`.
    ///
    /// Indices `k >= total` are ignored.
    #[commonware_macros::stability(ALPHA)]
    pub fn roots_of_unity(
        total: NonZeroU32,
        points: commonware_utils::ordered::BiMap<I, u32>,
    ) -> Self {
        let weights = <Map<I, F> as commonware_utils::TryFromIterator<(I, F)>>::try_from_iter(
            crate::ntt::lagrange_coefficients(total, points.values().iter().copied())
                .into_iter()
                .filter_map(|(k, coeff)| Some((points.get_key(&k)?.clone(), coeff))),
        )
        .expect("points has already been deduped");
        Self { weights }
    }

    /// Create an interpolator for evaluation points at roots of unity using naive O(n^2) algorithm.
    ///
    /// This computes the actual root of unity values and delegates to [`Interpolator::new`].
    /// Useful for testing against [`Self::roots_of_unity`].
    ///
    /// Indices `k >= total` are ignored.
    #[commonware_macros::stability(ALPHA)]
    pub fn roots_of_unity_naive(
        total: NonZeroU32,
        points: commonware_utils::ordered::BiMap<I, u32>,
    ) -> Self {
        use crate::algebra::powers;

        let total_u32 = total.get();
        let size = (total_u32 as u64).next_power_of_two();
        let lg_size = size.ilog2() as u8;
        let w = F::root_of_unity(lg_size).expect("domain too large for NTT");

        let points: Vec<(I, u32)> = points.into_iter().filter(|(_, k)| *k < total_u32).collect();
        let max_k = points.iter().map(|(_, k)| *k).max().unwrap_or(0) as usize;
        let powers: Vec<_> = powers(&w, max_k + 1).collect();

        let eval_points = points
            .into_iter()
            .map(|(i, k)| (i, powers[k as usize].clone()));
        Self::new(eval_points)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod impl_arbitrary {
    use super::*;
    use arbitrary::Arbitrary;

    impl<'a, F: Arbitrary<'a>> Arbitrary<'a> for Poly<F> {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let first = u.arbitrary()?;
            let rest: Vec<F> = u.arbitrary()?;
            let mut coeffs = NonEmptyVec::new(first);
            coeffs.extend(rest);
            Ok(Self { coeffs })
        }
    }
}

#[commonware_macros::stability(ALPHA)]
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::{
        algebra::test_suites,
        test::{F, G},
    };
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_codec::Encode as _;
    use commonware_parallel::Sequential;
    use commonware_utils::{
        ordered::{BiMap, Map},
        TryFromIterator,
    };

    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        Codec(Poly<F>),
        EvalAdd(Poly<F>, Poly<F>, F),
        EvalScale(Poly<F>, F, F),
        EvalZero(Poly<F>),
        EvalMsm(Poly<F>, F),
        Interpolate(Poly<F>),
        InterpolateWithZeroPoint(Poly<F>),
        InterpolateWithZeroPointMiddle(Poly<F>),
        TranslateScale(Poly<F>, F),
        CommitEval(Poly<F>, F),
        RootsOfUnityEqNaive(u16),
        FuzzAdditive,
        FuzzSpaceRing,
    }

    impl Plan {
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Codec(f) => {
                    assert_eq!(
                        &f,
                        &Poly::<F>::read_cfg(&mut f.encode(), &(RangeCfg::exact(f.required()), ()))
                            .unwrap()
                    );
                }
                Self::EvalAdd(f, g, x) => {
                    assert_eq!(f.eval(&x) + &g.eval(&x), (f + &g).eval(&x));
                }
                Self::EvalScale(f, x, w) => {
                    assert_eq!(f.eval(&x) * &w, (f * &w).eval(&x));
                }
                Self::EvalZero(f) => {
                    assert_eq!(&f.eval(&F::zero()), f.constant());
                }
                Self::EvalMsm(f, x) => {
                    assert_eq!(f.eval(&x), f.eval_msm(&x, &Sequential));
                }
                Self::Interpolate(f) => {
                    if f == Poly::zero() || f.required().get() >= F::MAX as u32 {
                        return Ok(());
                    }
                    let mut points = (0..f.required().get())
                        .map(|i| F::from((i + 1) as u8))
                        .collect::<Vec<_>>();
                    let interpolator = Interpolator::new(points.iter().copied().enumerate());
                    let evals = Map::from_iter_dedup(points.iter().map(|p| f.eval(p)).enumerate());
                    let recovered = interpolator.interpolate(&evals, &Sequential);
                    assert_eq!(recovered.as_ref(), Some(f.constant()));
                    points.pop();
                    assert_eq!(
                        interpolator.interpolate(
                            &Map::from_iter_dedup(points.iter().map(|p| f.eval(p)).enumerate()),
                            &Sequential
                        ),
                        None
                    );
                }
                Self::InterpolateWithZeroPoint(f) => {
                    if f == Poly::zero() || f.required().get() >= F::MAX as u32 {
                        return Ok(());
                    }
                    let points: Vec<_> =
                        (0..f.required().get()).map(|i| F::from(i as u8)).collect();
                    let interpolator = Interpolator::new(points.iter().copied().enumerate());
                    let evals = Map::from_iter_dedup(points.iter().map(|p| f.eval(p)).enumerate());
                    let recovered = interpolator.interpolate(&evals, &Sequential);
                    assert_eq!(recovered.as_ref(), Some(f.constant()));
                }
                Self::InterpolateWithZeroPointMiddle(f) => {
                    if f == Poly::zero()
                        || f.required().get() < 2
                        || f.required().get() >= F::MAX as u32
                    {
                        return Ok(());
                    }
                    let n = f.required().get();
                    let points: Vec<_> = (1..n)
                        .map(|i| F::from(i as u8))
                        .chain(core::iter::once(F::zero()))
                        .collect();
                    let interpolator = Interpolator::new(points.iter().copied().enumerate());
                    let evals = Map::from_iter_dedup(points.iter().map(|p| f.eval(p)).enumerate());
                    let recovered = interpolator.interpolate(&evals, &Sequential);
                    assert_eq!(recovered.as_ref(), Some(f.constant()));
                }
                Self::TranslateScale(f, x) => {
                    assert_eq!(f.translate(|c| x * c), f * &x);
                }
                Self::CommitEval(f, x) => {
                    assert_eq!(G::generator() * &f.eval(&x), Poly::<G>::commit(f).eval(&x));
                }
                Self::RootsOfUnityEqNaive(n) => {
                    let n = (u32::from(n) % 256) + 1;
                    let total = NonZeroU32::new(n).expect("n is in 1..=256");
                    let points = BiMap::try_from_iter((0..n as usize).map(|i| (i, i as u32)))
                        .expect("interpolation points should be bijective");
                    let fast = Interpolator::<usize, crate::fields::goldilocks::F>::roots_of_unity(
                        total,
                        points.clone(),
                    );
                    let naive =
                        Interpolator::<usize, crate::fields::goldilocks::F>::roots_of_unity_naive(
                            total, points,
                        );
                    assert_eq!(fast.weights, naive.weights);
                }
                Self::FuzzAdditive => {
                    test_suites::fuzz_additive::<Poly<F>>(u)?;
                }
                Self::FuzzSpaceRing => {
                    test_suites::fuzz_space_ring::<F, Poly<F>>(u)?;
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
#[cfg(test)]
mod test {
    use super::*;
    use crate::test::F;

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

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Poly<F>>
        }
    }
}
