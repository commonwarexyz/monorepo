//! Build and batch multiscalar-multiplication (MSM) checks.
//!
//! A [`Tangle`] stores a linear combination of points where some points are
//! already known and some are referenced by [`TangleIdx`] so they can be
//! supplied later. This is useful when a protocol wants to assemble MSM
//! verification equations first and evaluate them once the full generator set is
//! available.
//!
//! Because tangles can be added and scaled, several MSM checks can be batched
//! into one combined check before evaluation. If `T_i` is the verification
//! equation for check `i`, callers can form `sum_i rho_i * T_i` and evaluate
//! once instead of running one MSM per check. In practice this reduces the
//! number of separate MSM evaluations and lets one larger MSM amortize the
//! scalar-multiplication overhead.
//!
//! # Usage
//!
//! ```rust
//! use commonware_math::{algebra::Space, fields::goldilocks::F, tangle::Tangle};
//! use commonware_parallel::Sequential;
//!
//! let check_a = Tangle::free_row(0, [F::from(2u64), F::from(3u64)])
//!     - &Tangle::tethered([(F::from(7u64), F::from(11u64))]);
//! let check_b = Tangle::free_point((1, 0), F::from(5u64))
//!     + &Tangle::tethered([(F::from(13u64), F::from(17u64))]);
//!
//! // Batch the two checks with a random-looking scalar.
//! let batched = check_a + &(check_b * &F::from(19u64));
//!
//! let value = batched
//!     .eval(
//!         [
//!             ((0, 0), F::from(13u64)),
//!             ((0, 1), F::from(17u64)),
//!             ((1, 0), F::from(19u64)),
//!         ],
//!         &Sequential,
//!     )
//!     .expect("all free points are supplied");
//!
//! let expected = F::msm(
//!     &[
//!         F::from(13u64),
//!         F::from(17u64),
//!         F::from(19u64),
//!         F::from(11u64),
//!         F::from(17u64),
//!     ],
//!     &[
//!         F::from(2u64),
//!         F::from(3u64),
//!         F::from(95u64),
//!         -F::from(7u64),
//!         F::from(247u64),
//!     ],
//!     &Sequential,
//! );
//! assert_eq!(value, expected);
//! ```

use crate::algebra::{Additive, Object, Space};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_parallel::{Sequential, Strategy};
use core::{
    cmp::Ordering,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// A row and column identifying a free point in a [`Tangle`].
pub type TangleIdx = (u32, u32);

/// A partially bound MSM check.
///
/// Free terms are indexed by [`TangleIdx`] and bound later by [`Self::eval`].
/// Tethered terms already carry their point directly.
#[derive(Clone, Debug)]
pub struct Tangle<F, G> {
    free: BTreeMap<TangleIdx, F>,
    tethered: Vec<(F, G)>,
}

impl<F, G> Default for Tangle<F, G> {
    fn default() -> Self {
        Self {
            free: Default::default(),
            tethered: Default::default(),
        }
    }
}

impl<F, G> Tangle<F, G> {
    /// Construct a tangle from points that are already known.
    pub fn tethered(weighted_points: impl IntoIterator<Item = (F, G)>) -> Self {
        Self {
            tethered: weighted_points.into_iter().collect(),
            ..Default::default()
        }
    }

    /// Construct a row of free points with consecutive column indices.
    pub fn free_row(row: u32, weights: impl IntoIterator<Item = F>) -> Self {
        Self {
            free: weights
                .into_iter()
                .enumerate()
                .map(|(col, w)| {
                    (
                        (
                            row,
                            col.try_into()
                                .expect("free_row provided more than 2^32 items"),
                        ),
                        w,
                    )
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Construct a tangle containing a single free point.
    pub fn free_point(idx: TangleIdx, weight: F) -> Self {
        let mut out = Self::default();
        out.free.insert(idx, weight);
        out
    }
}

impl<F: Additive, G: Space<F>> Tangle<F, G> {
    /// Evaluate the tangle once generators for all free points are available.
    ///
    /// Returns [`None`] if any free point is missing from `generators`.
    pub fn eval(
        mut self,
        generators: impl IntoIterator<Item = (TangleIdx, G)>,
        strategy: &impl Strategy,
    ) -> Option<G> {
        let generators = generators.into_iter();
        let size_estimate = generators.size_hint().0 + self.tethered.len();
        let mut points = Vec::with_capacity(size_estimate);
        let mut weights = Vec::with_capacity(size_estimate);
        for (idx, point) in generators {
            points.push(point);
            if let Some(weight) = self.free.remove(&idx) {
                weights.push(weight);
            } else {
                weights.push(F::zero());
            }
        }
        // This means that some weights are missing generators.
        if !self.free.is_empty() {
            return None;
        }
        for (weight, point) in self.tethered {
            points.push(point);
            weights.push(weight);
        }
        Some(G::msm(&points, &weights, strategy))
    }
}

impl<F: Additive, G: Space<F>> PartialEq for Tangle<F, G> {
    fn eq(&self, other: &Self) -> bool {
        let zero = F::zero();
        let mut lhs = self.free.iter().peekable();
        let mut rhs = other.free.iter().peekable();
        let free_equal = core::iter::from_fn(|| {
            let ordering = match (lhs.peek().copied(), rhs.peek().copied()) {
                (Some((lhs_idx, _)), Some((rhs_idx, _))) => lhs_idx.cmp(rhs_idx),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => return None,
            };
            Some(match ordering {
                Ordering::Equal => (
                    lhs.next().map(|(_, weight)| weight),
                    rhs.next().map(|(_, weight)| weight),
                ),
                Ordering::Less => (lhs.next().map(|(_, weight)| weight), None),
                Ordering::Greater => (None, rhs.next().map(|(_, weight)| weight)),
            })
        })
        .all(|(lhs_weight, rhs_weight)| lhs_weight.unwrap_or(&zero) == rhs_weight.unwrap_or(&zero));
        if !free_equal {
            return false;
        }

        // Compare the tethered points semantically rather than by their stored
        // order. This can be inefficient because it clones the tethered data
        // and allocates scratch vectors on every check.
        let size = self.tethered.len() + other.tethered.len();
        let mut points = Vec::with_capacity(size);
        let mut weights = Vec::with_capacity(size);

        for (weight, point) in &self.tethered {
            points.push(point.clone());
            weights.push(weight.clone());
        }
        for (weight, point) in &other.tethered {
            points.push(point.clone());
            weights.push(-weight.clone());
        }

        G::msm(&points, &weights, &Sequential) == G::zero()
    }
}

impl<F: Additive, G: Space<F>> Eq for Tangle<F, G> {}

impl<F: Additive, G: Space<F>> Object for Tangle<F, G> {}

impl<'a, F: Additive, G: Space<F>> AddAssign<&'a Self> for Tangle<F, G> {
    fn add_assign(&mut self, rhs: &'a Self) {
        for (idx, weight) in &rhs.free {
            self.free
                .entry(*idx)
                .and_modify(|existing| *existing += weight)
                .or_insert_with(|| weight.clone());
        }
        self.tethered.extend(rhs.tethered.iter().cloned());
    }
}

impl<'a, F: Additive, G: Space<F>> Add<&'a Self> for Tangle<F, G> {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a, F: Additive, G: Space<F>> SubAssign<&'a Self> for Tangle<F, G> {
    fn sub_assign(&mut self, rhs: &'a Self) {
        for (idx, weight) in &rhs.free {
            self.free
                .entry(*idx)
                .and_modify(|existing| *existing -= weight)
                .or_insert_with(|| -weight.clone());
        }
        self.tethered.extend(
            rhs.tethered
                .iter()
                .cloned()
                .map(|(weight, point)| (-weight, point)),
        );
    }
}

impl<'a, F: Additive, G: Space<F>> Sub<&'a Self> for Tangle<F, G> {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<F: Additive, G: Space<F>> Neg for Tangle<F, G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            free: self
                .free
                .into_iter()
                .map(|(idx, weight)| (idx, -weight))
                .collect(),
            tethered: self
                .tethered
                .into_iter()
                .map(|(weight, point)| (-weight, point))
                .collect(),
        }
    }
}

impl<F: Additive, G: Space<F>> Additive for Tangle<F, G> {
    fn zero() -> Self {
        Self {
            free: BTreeMap::new(),
            tethered: Vec::new(),
        }
    }
}

impl<'a, F: Space<F>, G: Space<F>> MulAssign<&'a F> for Tangle<F, G> {
    fn mul_assign(&mut self, rhs: &'a F) {
        self.free.values_mut().for_each(|weight| *weight *= rhs);
        self.tethered
            .iter_mut()
            .for_each(|(weight, _)| *weight *= rhs);
    }
}

impl<'a, F: Space<F>, G: Space<F>> Mul<&'a F> for Tangle<F, G> {
    type Output = Self;

    fn mul(mut self, rhs: &'a F) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<F: Space<F>, G: Space<F>> Space<F> for Tangle<F, G> {}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, F: arbitrary::Arbitrary<'a>, G: arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a>
    for Tangle<F, G>
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            free: u.arbitrary::<Vec<(TangleIdx, F)>>()?.into_iter().collect(),
            tethered: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        algebra::{Additive, CryptoGroup},
        test::{F, G},
    };
    use commonware_parallel::Sequential;

    #[test]
    fn eval_requires_all_free_generators() {
        let tangle = Tangle::free_row(0, [F::from(2u64), F::from(3u64)])
            + &Tangle::free_point((1, 0), F::from(5u64))
            + &Tangle::tethered([(F::from(7u64), G::generator())]);

        assert_eq!(tangle.eval([((0, 0), G::generator())], &Sequential), None);
    }

    #[test]
    fn eq_is_semantic() {
        let g = G::generator();
        let h = g * &F::from(2u64);
        let lhs = Tangle::free_point((0, 0), F::from(3u64))
            + &Tangle::free_point((0, 1), F::zero())
            + &Tangle::tethered([(F::from(5u64), g), (F::from(7u64), h)]);
        let rhs = Tangle::free_point((0, 0), F::from(3u64))
            + &Tangle::tethered([(F::from(7u64), h), (F::from(5u64), g)]);

        assert_eq!(lhs, rhs);
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
    use commonware_parallel::Sequential;
    use std::collections::BTreeMap;

    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        EvalMatchesMsm(Vec<(F, F)>, (F, F), (F, F)),
        EvalIsLinear(Tangle<F, G>, Tangle<F, G>, Vec<(TangleIdx, G)>),
        FuzzAdditive,
        FuzzSpaceRing,
    }

    fn cover_generators(
        u: &mut Unstructured<'_>,
        tangles: &[&Tangle<F, G>],
        generators: Vec<(TangleIdx, G)>,
    ) -> arbitrary::Result<Vec<(TangleIdx, G)>> {
        let mut covered: BTreeMap<_, _> = generators.into_iter().collect();
        for idx in tangles
            .iter()
            .flat_map(|tangle| tangle.free.keys())
            .copied()
        {
            if let std::collections::btree_map::Entry::Vacant(entry) = covered.entry(idx) {
                entry.insert(u.arbitrary()?);
            }
        }
        Ok(covered.into_iter().collect())
    }

    impl Plan {
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::EvalMatchesMsm(
                    row,
                    (free_weight, free_point),
                    (tethered_weight, tethered_point),
                ) => {
                    let row_weights = row.iter().map(|(weight, _)| *weight);
                    let mut tangle = Tangle::free_row(0, row_weights);
                    tangle += &Tangle::free_point((1, 0), free_weight);
                    tangle += &Tangle::tethered([(tethered_weight, tethered_point)]);

                    let mut generators = Vec::with_capacity(row.len() + 1);
                    let mut points = Vec::with_capacity(row.len() + 2);
                    let mut weights = Vec::with_capacity(row.len() + 2);
                    for (col, (weight, point)) in row.into_iter().enumerate() {
                        let col = col.try_into().expect("row width should fit in u32");
                        generators.push(((0, col), point));
                        points.push(point);
                        weights.push(weight);
                    }
                    generators.push(((1, 0), free_point));
                    points.push(free_point);
                    weights.push(free_weight);
                    points.push(tethered_point);
                    weights.push(tethered_weight);

                    assert_eq!(
                        tangle.eval(generators, &Sequential),
                        Some(F::msm(&points, &weights, &Sequential))
                    );
                }
                Self::EvalIsLinear(lhs, rhs, generators) => {
                    let generators = cover_generators(u, &[&lhs, &rhs], generators)?;
                    let lhs_eval = lhs
                        .clone()
                        .eval(generators.iter().cloned(), &Sequential)
                        .expect("cover_generators should supply all free lhs points");
                    let rhs_eval = rhs
                        .clone()
                        .eval(generators.iter().cloned(), &Sequential)
                        .expect("cover_generators should supply all free rhs points");

                    assert_eq!(
                        (lhs + &rhs).eval(generators, &Sequential),
                        Some(lhs_eval + &rhs_eval)
                    );
                }
                Self::FuzzAdditive => {
                    test_suites::fuzz_additive::<Tangle<F, G>>(u)?;
                }
                Self::FuzzSpaceRing => {
                    test_suites::fuzz_space_ring::<F, Tangle<F, G>>(u)?;
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
