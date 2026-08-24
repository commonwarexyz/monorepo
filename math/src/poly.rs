use crate::{
    algebra::{Additive, CryptoGroup, Field, FieldNTT, Object, Random, Ring, Space, msm_naive, powers},
    ntt::{Domain, Error},
};
#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, vec, vec::Vec};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_parallel::Strategy;
use commonware_utils::{TryCollect, non_empty_vec, ordered::Map, vec::NonEmptyVec};
use core::{
    fmt::Debug,
    iter,
    num::NonZeroU32,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::borrow::Cow;

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

    /// Construct a polynomial from coefficients in ascending degree order.
    ///
    /// Returns `None` if the iterator is empty: a polynomial always has at
    /// least its constant coefficient. Trailing zero coefficients are kept;
    /// see [`Self::trim`].
    pub fn from_coefficients(coeffs: impl IntoIterator<Item = K>) -> Option<Self> {
        Some(Self {
            coeffs: coeffs.into_iter().try_collect::<NonEmptyVec<_>>().ok()?,
        })
    }

    /// Construct a polynomial from a vector known to be non-empty.
    ///
    /// Panics if `coeffs` is empty, so only pass vectors whose length the
    /// caller has already established.
    fn from_vec_unchecked(coeffs: Vec<K>) -> Self {
        Self::from_coefficients(coeffs).expect("polynomial must have at least 1 coefficient")
    }

    /// Return the coefficients in ascending degree order.
    pub fn coefficients(&self) -> &[K] {
        &self.coeffs
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
        let weights = powers(R::one(), r)
            .take(self.len_usize())
            .collect::<Vec<_>>();
        K::msm(&self.coeffs, &weights, strategy)
    }

    /// Compute `sum_i a_i * self(b_i)`.
    ///
    /// This is more efficient than several calls to `eval_msm`, but produces the
    /// same result.
    ///
    /// This returns `0` if the iterator is empty.
    pub fn lin_comb_eval<'a, R: Ring + 'a>(
        &self,
        into_iter: impl IntoIterator<Item = (R, Cow<'a, R>)>,
        strategy: &impl Strategy,
    ) -> K
    where
        K: Space<R>,
    {
        // Contains a0 + a1 + ..., a0 b0 + a1 b1 + ..., a0 b0^2 + a1 b1^2 + ...
        let weights = {
            let mut iter = into_iter.into_iter();
            let Some((a0, b0)) = iter.next() else {
                return K::zero();
            };

            let len = self.len_usize();
            let mut out: Vec<_> = powers(a0, b0.as_ref()).take(len).collect();
            for (ai, bi) in iter {
                powers(ai, bi.as_ref())
                    .take(len)
                    .zip(out.iter_mut())
                    .for_each(|(c_j, o_j)| *o_j += &c_j);
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
    pub fn new(mut rng: impl CryptoRng, degree: u32) -> Self {
        Self::from_iter_unchecked((0..=degree).map(|_| K::random(&mut rng)))
    }

    /// Returns a new scalar polynomial with a particular value for the constant coefficient.
    ///
    /// This does the same thing as [`Poly::new`] otherwise.
    pub fn new_with_constant(mut rng: impl CryptoRng, degree: u32, constant: K) -> Self {
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

// SECTION: dense polynomial arithmetic.

/// Multiplying two polynomials whose product has at most this many
/// coefficients is cheaper naively than through an NTT.
const NAIVE_MUL_MAX_OUTPUT: usize = 32;

#[commonware_macros::stability(ALPHA)]
impl<K: Additive> Poly<K> {
    /// Drop trailing zero coefficients, leaving at least the constant.
    ///
    /// [`Poly`] does not maintain a canonical representation, so a polynomial
    /// produced by arithmetic may carry high zero coefficients. Equality and
    /// [`Self::degree_exact`] already ignore them; trim when the coefficient
    /// slice itself is consumed, for example as the scalars of a
    /// multi-scalar multiplication.
    pub fn trim(&mut self) {
        let zero = K::zero();
        while self.coeffs.len().get() > 1 && self.coeffs.last() == &zero {
            self.coeffs.pop();
        }
    }

    /// Divide by the vanishing polynomial `X^m - 1` of a domain of size `m`.
    ///
    /// Returns `(quotient, remainder)`, where the remainder has `m`
    /// coefficients.
    pub fn divide_by_vanishing(&self, m: usize) -> Result<(Self, Self), Error> {
        if m == 0 {
            return Err(Error::EmptyDomain);
        }
        let len = self.len_usize();
        if len <= m {
            return Ok((Self::zero(), self.clone()));
        }

        // Reduce from the top: X^(m + i) = X^i modulo the vanishing polynomial,
        // so each high coefficient folds into the coefficient m places below it
        // and becomes a quotient coefficient.
        let mut work = self.coeffs.to_vec();
        let mut quotient = vec![K::zero(); len - m];
        for high in (m..len).rev() {
            let factor = work[high].clone();
            work[high] = K::zero();
            work[high - m] += &factor;
            quotient[high - m] = factor;
        }
        work.truncate(m);

        Ok((Self::from_vec_unchecked(quotient), Self::from_vec_unchecked(work)))
    }

    /// Multiply by the vanishing polynomial `X^m - 1` of a domain of size `m`.
    pub fn mul_vanishing(&self, m: usize) -> Result<Self, Error> {
        if m == 0 {
            return Err(Error::EmptyDomain);
        }
        let len = self
            .len_usize()
            .checked_add(m)
            .ok_or(Error::PolynomialSizeOverflow)?;
        let mut coefficients = vec![K::zero(); len];
        for (index, coefficient) in self.coeffs.iter().enumerate() {
            coefficients[index] -= coefficient;
            coefficients[index + m] += coefficient;
        }
        Ok(Self::from_vec_unchecked(coefficients))
    }

    /// Add a multiple of the vanishing polynomial `X^m - 1`.
    ///
    /// Returns `self + mask * (X^m - 1)`, which agrees with `self` at every
    /// point of a domain of size `m`.
    pub fn mask_vanishing(&self, mask: &Self, m: usize) -> Result<Self, Error> {
        if m == 0 {
            return Err(Error::EmptyDomain);
        }
        let shifted = mask
            .len_usize()
            .checked_add(m)
            .ok_or(Error::PolynomialSizeOverflow)?;
        let len = self.len_usize().max(shifted);
        let mut coefficients = vec![K::zero(); len];
        for (output, coefficient) in coefficients.iter_mut().zip(&self.coeffs) {
            *output += coefficient;
        }
        for (index, coefficient) in mask.coeffs.iter().enumerate() {
            coefficients[index] -= coefficient;
            coefficients[index + m] += coefficient;
        }
        Ok(Self::from_vec_unchecked(coefficients))
    }
}

#[commonware_macros::stability(ALPHA)]
impl<K: Ring> Poly<K> {
    /// Divide by `X - root` using synthetic division.
    ///
    /// Returns `(quotient, remainder)`, where the remainder equals
    /// `self.eval(&root)`.
    pub fn divide_by_linear(&self, root: &K) -> (Self, K) {
        let len = self.len_usize();
        if len == 1 {
            return (Self::zero(), self.constant().clone());
        }

        let mut quotient = vec![K::zero(); len - 1];
        quotient[len - 2] = self.coeffs[len - 1].clone();
        for index in (1..len - 1).rev() {
            quotient[index - 1] = self.coeffs[index].clone() + &(quotient[index].clone() * root);
        }
        let remainder = self.coeffs[0].clone() + &(quotient[0].clone() * root);
        (Self::from_vec_unchecked(quotient), remainder)
    }
}

#[commonware_macros::stability(ALPHA)]
impl<F: FieldNTT> Poly<F> {
    /// Multiply two polynomials.
    ///
    /// Small products are computed naively; larger ones go through an NTT over
    /// a radix-2 domain, which costs `O(n log n)` instead of `O(n^2)`.
    pub fn multiply(&self, other: &Self) -> Result<Self, Error> {
        let len = self
            .len_usize()
            .checked_add(other.len_usize())
            .and_then(|len| len.checked_sub(1))
            .ok_or(Error::PolynomialSizeOverflow)?;

        if len <= NAIVE_MUL_MAX_OUTPUT {
            let mut coefficients = vec![F::zero(); len];
            for (i, left) in self.coeffs.iter().enumerate() {
                for (j, right) in other.coeffs.iter().enumerate() {
                    coefficients[i + j] += &(left.clone() * right);
                }
            }
            return Ok(Self::from_vec_unchecked(coefficients));
        }

        let domain = Domain::new(len)?;
        let mut evaluations = domain.evaluate(&self.coeffs)?;
        for (product, value) in evaluations.iter_mut().zip(domain.evaluate(&other.coeffs)?) {
            *product *= &value;
        }
        let mut coefficients = domain.interpolate(&evaluations)?;
        coefficients.truncate(len);
        Ok(Self::from_vec_unchecked(coefficients))
    }

    /// Evaluate this polynomial at every point of `domain`.
    ///
    /// The polynomial must fit in the domain; see [`Domain::evaluate`].
    pub fn evaluate_over(&self, domain: &Domain<F>) -> Result<Vec<F>, Error> {
        domain.evaluate(&self.coeffs)
    }

    /// Interpolate the polynomial taking one value at every point of `domain`.
    ///
    /// This is the inverse of [`Self::evaluate_over`].
    pub fn interpolate(domain: &Domain<F>, evaluations: &[F]) -> Result<Self, Error> {
        Ok(Self::from_vec_unchecked(domain.interpolate(evaluations)?))
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

#[commonware_macros::stability(ALPHA)]
impl<I: Clone + Ord, F: crate::algebra::FieldNTT> Interpolator<I, F> {
    /// Create an interpolator for evaluation points at roots of unity.
    ///
    /// This uses the fast O(n log n) algorithm from [`crate::ntt::lagrange_coefficients`].
    ///
    /// Each `(I, u32)` pair maps an index `I` to an evaluation point `w^k` where `w` is
    /// a primitive root of unity of order `next_power_of_two(total)`.
    ///
    /// Indices `k >= total` are ignored.
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
    #[cfg(any(test, feature = "fuzz"))]
    fn roots_of_unity_naive(
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
        let powers: Vec<_> = powers(F::one(), &w).take(max_k + 1).collect();

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
        TryFromIterator,
        ordered::{BiMap, Map},
    };

    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        Codec(Poly<F>),
        EvalAdd(Poly<F>, Poly<F>, F),
        EvalScale(Poly<F>, F, F),
        EvalZero(Poly<F>),
        EvalMsm(Poly<F>, F),
        LinCombEval(Poly<F>, Vec<(F, F)>),
        Interpolate(Poly<F>),
        InterpolateWithZeroPoint(Poly<F>),
        InterpolateWithZeroPointMiddle(Poly<F>),
        TranslateScale(Poly<F>, F),
        CommitEval(Poly<F>, F),
        RootsOfUnityEqNaive(u16),
        MulMatchesNaive(Poly<GF>, Poly<GF>),
        DivideByVanishingRoundTrip(Poly<GF>, u8),
        DivideByLinearRoundTrip(Poly<GF>, GF),
        MaskVanishingPreservesDomain(Poly<GF>, Poly<GF>, u8),
        EvaluateInterpolateRoundTrip(Poly<GF>, u8),
        TrimPreservesPolynomial(Poly<GF>),
        FuzzAdditive,
        FuzzSpaceRing,
    }

    /// The NTT-capable field the polynomial-arithmetic plans run over.
    ///
    /// [`crate::test::F`] does not implement [`crate::algebra::FieldNTT`], so
    /// these plans use the goldilocks field instead.
    type GF = crate::fields::goldilocks::F;

    /// Multiply two polynomials by definition, for comparison against
    /// [`Poly::multiply`].
    fn naive_multiply(left: &[GF], right: &[GF]) -> Vec<GF> {
        let mut out = vec![GF::zero(); left.len() + right.len() - 1];
        for (i, a) in left.iter().enumerate() {
            for (j, b) in right.iter().enumerate() {
                out[i + j] += &(*a * b);
            }
        }
        out
    }

    /// Round `size` up to a radix-2 domain that can hold `minimum` points.
    fn domain_for(minimum: usize, size: u8) -> Domain<GF> {
        Domain::new(minimum.max(1 + usize::from(size % 8))).expect("domain is small")
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
                Self::LinCombEval(f, pairs) => {
                    let naive_eval = pairs.iter().fold(F::zero(), |mut acc, (a, b)| {
                        acc += &(*a * &f.eval(b));
                        acc
                    });
                    let lin_comb = f.lin_comb_eval(
                        pairs.iter().map(|(a, b)| (*a, Cow::Borrowed(b))),
                        &Sequential,
                    );
                    assert_eq!(naive_eval, lin_comb);
                }
                Self::Interpolate(f) => {
                    if f == Poly::zero() || u64::from(f.required().get()) >= F::MAX {
                        return Ok(());
                    }
                    let mut points = (0..f.required().get())
                        .map(|i| F::from(u64::from(i) + 1))
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
                    if f == Poly::zero() || u64::from(f.required().get()) >= F::MAX {
                        return Ok(());
                    }
                    let points: Vec<_> = (0..f.required().get())
                        .map(|i| F::from(u64::from(i)))
                        .collect();
                    let interpolator = Interpolator::new(points.iter().copied().enumerate());
                    let evals = Map::from_iter_dedup(points.iter().map(|p| f.eval(p)).enumerate());
                    let recovered = interpolator.interpolate(&evals, &Sequential);
                    assert_eq!(recovered.as_ref(), Some(f.constant()));
                }
                Self::InterpolateWithZeroPointMiddle(f) => {
                    if f == Poly::zero()
                        || f.required().get() < 2
                        || u64::from(f.required().get()) >= F::MAX
                    {
                        return Ok(());
                    }
                    let n = f.required().get();
                    let points: Vec<_> = (1..n)
                        .map(|i| F::from(u64::from(i)))
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
                Self::MulMatchesNaive(f, g) => {
                    let expected =
                        Poly::from_coefficients(naive_multiply(f.coefficients(), g.coefficients()))
                            .expect("product has at least 1 coefficient");
                    assert_eq!(f.multiply(&g).unwrap(), expected);
                }
                Self::DivideByVanishingRoundTrip(f, size) => {
                    let m = 1 + usize::from(size % 16);
                    let (quotient, remainder) = f.divide_by_vanishing(m).unwrap();
                    assert!(remainder.coefficients().len() <= m);
                    assert_eq!(quotient.mul_vanishing(m).unwrap() + &remainder, f);
                }
                Self::DivideByLinearRoundTrip(f, root) => {
                    let (quotient, remainder) = f.divide_by_linear(&root);
                    assert_eq!(remainder, f.eval(&root));
                    // quotient * (X - root) + remainder == f
                    let shifted = Poly::from_coefficients(
                        core::iter::once(GF::zero()).chain(quotient.coefficients().iter().copied()),
                    )
                    .expect("shift keeps at least 1 coefficient");
                    let scaled = quotient * &-root;
                    let constant =
                        Poly::from_coefficients([remainder]).expect("constant is non-empty");
                    assert_eq!(shifted + &scaled + &constant, f);
                }
                Self::MaskVanishingPreservesDomain(f, mask, size) => {
                    let domain = domain_for(f.coefficients().len(), size);
                    let masked = f.mask_vanishing(&mask, domain.size()).unwrap();
                    for index in 0..domain.size() {
                        let point = domain.element(index).unwrap();
                        assert_eq!(f.eval(&point), masked.eval(&point));
                    }
                }
                Self::EvaluateInterpolateRoundTrip(f, size) => {
                    let domain = domain_for(f.coefficients().len(), size);
                    let evaluations = f.evaluate_over(&domain).unwrap();
                    for (index, evaluation) in evaluations.iter().enumerate() {
                        assert_eq!(*evaluation, f.eval(&domain.element(index).unwrap()));
                    }
                    assert_eq!(Poly::interpolate(&domain, &evaluations).unwrap(), f);
                }
                Self::TrimPreservesPolynomial(f) => {
                    let mut trimmed = f.clone();
                    trimmed.trim();
                    assert_eq!(trimmed, f);
                    assert_eq!(
                        trimmed.coefficients().len(),
                        f.degree_exact() as usize + 1
                    );
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
    use super::{fuzz::Plan, *};
    use crate::test::F;
    use arbitrary::Unstructured;

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

    #[test]
    fn lin_comb_eval_edge_cases() {
        fn poly(coeffs: &[u8]) -> Poly<F> {
            Poly {
                coeffs: coeffs.iter().copied().map(F::from).try_collect().unwrap(),
            }
        }

        fn pairs(values: &[(u8, u8)]) -> Vec<(F, F)> {
            values
                .iter()
                .map(|(a, b)| (F::from(*a), F::from(*b)))
                .collect()
        }

        let cases = [
            Plan::LinCombEval(poly(&[3, 5, 7]), vec![]),
            Plan::LinCombEval(poly(&[11]), pairs(&[(2, 0), (3, 1), (5, 8)])),
            Plan::LinCombEval(poly(&[4, 6, 8]), pairs(&[(2, 5), (7, 5), (3, 5)])),
            Plan::LinCombEval(poly(&[9, 2, 3, 4]), pairs(&[(6, 0), (1, 0), (5, 7)])),
            Plan::LinCombEval(poly(&[1, 2, 4, 8]), pairs(&[(3, 1), (7, 1), (2, 6)])),
        ];
        let mut u = Unstructured::new(&[]);
        for case in cases {
            case.run(&mut u).unwrap();
        }
    }

    #[test]
    fn interpolation_plans_cover_large_test_field() {
        let poly = Poly {
            coeffs: [3u8, 5, 7, 11]
                .into_iter()
                .map(F::from)
                .try_collect()
                .unwrap(),
        };
        let mut u = Unstructured::new(&[]);
        for make_plan in [
            Plan::Interpolate as fn(Poly<F>) -> Plan,
            Plan::InterpolateWithZeroPoint,
            Plan::InterpolateWithZeroPointMiddle,
        ] {
            make_plan(poly.clone()).run(&mut u).unwrap();
        }
    }

    /// Concrete worked examples for the dense-arithmetic operations, over an
    /// NTT-capable field so [`Poly::multiply`] can use both of its paths.
    mod arithmetic {
        use super::*;
        use crate::{fields::goldilocks::F as GF, ntt::Domain};

        fn poly(coeffs: &[u64]) -> Poly<GF> {
            Poly::from_coefficients(coeffs.iter().copied().map(GF::from)).unwrap()
        }

        #[test]
        fn add_sub_multiply_match_worked_examples() {
            let left = poly(&[1, 2, 3]);
            let right = poly(&[4, 5]);

            assert_eq!(left.clone() + &right, poly(&[5, 7, 3]));
            assert_eq!(left.clone() - &right, poly(&[1, 2, 3]) - &poly(&[4, 5]));
            assert_eq!(left.multiply(&right).unwrap(), poly(&[4, 13, 22, 15]));

            let point = GF::from(7u64);
            assert_eq!(
                left.multiply(&right).unwrap().eval(&point),
                left.eval(&point) * &right.eval(&point)
            );
        }

        #[test]
        fn ntt_multiplication_matches_naive_convolution() {
            let left = poly(&(1..=20).collect::<Vec<_>>());
            let right = poly(&(21..=39).collect::<Vec<_>>());
            assert!(
                left.coefficients().len() + right.coefficients().len() - 1 > NAIVE_MUL_MAX_OUTPUT,
                "inputs must be large enough to take the NTT path"
            );

            let mut expected = vec![GF::zero(); 38];
            for (i, a) in left.coefficients().iter().enumerate() {
                for (j, b) in right.coefficients().iter().enumerate() {
                    expected[i + j] += &(*a * b);
                }
            }
            assert_eq!(
                left.multiply(&right).unwrap(),
                Poly::from_coefficients(expected).unwrap()
            );
        }

        #[test]
        fn division_by_vanishing_returns_quotient_and_remainder() {
            let input = poly(&[3, 4, 0, 0, 2, 3]);
            let (quotient, remainder) = input.divide_by_vanishing(4).unwrap();
            assert_eq!(quotient, poly(&[2, 3]));
            assert_eq!(remainder, poly(&[5, 7]));
            assert_eq!(quotient.mul_vanishing(4).unwrap() + &remainder, input);

            // A polynomial below the domain degree passes through unchanged.
            let small = poly(&[1, 2]);
            let (quotient, remainder) = small.divide_by_vanishing(4).unwrap();
            assert_eq!(quotient, Poly::zero());
            assert_eq!(remainder, small);

            assert_eq!(small.divide_by_vanishing(0), Err(Error::EmptyDomain));
            assert_eq!(small.mul_vanishing(0), Err(Error::EmptyDomain));
            assert_eq!(small.mask_vanishing(&small, 0), Err(Error::EmptyDomain));
        }

        #[test]
        fn synthetic_division_returns_evaluation_remainder() {
            let root = GF::from(2u64);
            // 5X^3 - 6X^2 - 5X + 1
            let input = Poly::from_coefficients([
                GF::from(1u64),
                -GF::from(5u64),
                -GF::from(6u64),
                GF::from(5u64),
            ])
            .unwrap();

            let (quotient, remainder) = input.divide_by_linear(&root);
            assert_eq!(quotient, poly(&[3, 4, 5]));
            assert_eq!(remainder, GF::from(7u64));
            assert_eq!(remainder, input.eval(&root));

            // A constant divides to zero with itself as the remainder.
            let constant = poly(&[9]);
            let (quotient, remainder) = constant.divide_by_linear(&root);
            assert_eq!(quotient, Poly::zero());
            assert_eq!(remainder, GF::from(9u64));
        }

        #[test]
        fn vanishing_mask_preserves_domain_evaluations() {
            let domain = Domain::<GF>::new(4).unwrap();
            let input = poly(&[7, 8, 9]);
            let mask = poly(&[2, 3]);
            let masked = input.mask_vanishing(&mask, domain.size()).unwrap();

            assert_eq!(masked, poly(&[5, 5, 9, 0, 2, 3]));
            for index in 0..domain.size() {
                let point = domain.element(index).unwrap();
                assert_eq!(input.eval(&point), masked.eval(&point));
            }
        }

        #[test]
        fn trim_drops_trailing_zeroes_but_keeps_the_constant() {
            let mut padded = poly(&[1, 2, 0, 0]);
            padded.trim();
            assert_eq!(padded.coefficients(), poly(&[1, 2]).coefficients());

            let mut zero = poly(&[0, 0, 0]);
            zero.trim();
            assert_eq!(zero.coefficients(), &[GF::zero()]);
            assert_eq!(zero, Poly::zero());
        }

        #[test]
        fn from_coefficients_rejects_an_empty_iterator() {
            assert!(Poly::<GF>::from_coefficients([]).is_none());
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
