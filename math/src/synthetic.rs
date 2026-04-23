//! Synthetic linear combinations of free generators and concrete points.
//!
//! A [`Synthetic`] stores a linear combination where some terms reference
//! abstract generators (identified by `u32` indices) and others carry
//! concrete points. Generators are supplied later via [`Synthetic::eval`] to
//! produce a concrete group element.
//!
//! Scaling multiplies all weights. Addition merges the free terms (adding
//! weights at matching indices) and concatenates the concrete terms.
//!
//! # Usage
//!
//! ```rust
//! # #[cfg(feature = "arbitrary")]
//! # {
//! # use commonware_math::{algebra::{Additive, CryptoGroup, Ring, Space}, test::{F, G}, synthetic::Synthetic};
//! # use commonware_parallel::Sequential;
//! // Symbolic generators G_0, G_1.
//! let [g0, g1] = Synthetic::<F, G>::generators_array();
//!
//! // Build 2*G_0 + 3*G_1.
//! let expr = (g0 * &F::from(2u64)) + &(g1 * &F::from(3u64));
//!
//! // Evaluate with concrete points.
//! // In practice, use independent generators (e.g. from hash_to_group)
//! // rather than scaling a single one.
//! let a = G::generator();
//! let b = a * &F::from(5u64);
//! let result = expr.eval(&[a, b], &Sequential);
//! assert_eq!(result, (a * &F::from(2u64)) + &(b * &F::from(3u64)));
//! # }
//! ```

use crate::algebra::{Additive, Object, Ring, Space};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_parallel::{Sequential, Strategy};
use core::{
    cmp::Ordering,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// A linear combination of free generators and concrete points.
///
/// Free terms are indexed by `u32` and bound later via [`Self::eval`].
/// Concrete terms carry their point directly.
#[derive(Clone, Debug)]
pub struct Synthetic<F, G> {
    free: BTreeMap<u32, F>,
    concrete: Vec<(F, G)>,
}

impl<F, G> Default for Synthetic<F, G> {
    fn default() -> Self {
        Self {
            free: Default::default(),
            concrete: Default::default(),
        }
    }
}

impl<F, G> Synthetic<F, G> {
    /// Construct from known weighted points.
    pub fn concrete(weighted_points: impl IntoIterator<Item = (F, G)>) -> Self {
        Self {
            concrete: weighted_points.into_iter().collect(),
            ..Default::default()
        }
    }

    /// The maximum free generator index, or `None` if there are no free terms.
    pub fn max_free_index(&self) -> Option<u32> {
        self.free.keys().next_back().copied()
    }

    /// Apply `f` to every weight (free and concrete).
    fn for_each_weight(&mut self, mut f: impl FnMut(&mut F)) {
        self.free.values_mut().for_each(&mut f);
        self.concrete.iter_mut().for_each(|(w, _)| f(w));
    }

    /// Yield symbolic generators `G_0, G_1, G_2, ...` with unit weight.
    pub fn generators() -> impl Iterator<Item = Self>
    where
        F: Ring,
    {
        (0u32..).map(|i| {
            let mut out = Self::default();
            out.free.insert(i, F::one());
            out
        })
    }

    /// Return `[G_0, G_1, ..., G_{N-1}]` as symbolic generators with unit weight.
    pub fn generators_array<const N: usize>() -> [Self; N]
    where
        F: Ring,
    {
        let mut iter = Self::generators();
        core::array::from_fn(|_| iter.next().expect("generators is infinite"))
    }
}

impl<F: Additive, G: Space<F>> Synthetic<F, G> {
    /// Evaluate, substituting concrete generators for the free indices.
    ///
    /// `generators[i]` provides the point for free index `i`.
    ///
    /// # Panics
    ///
    /// Panics if `generators` does not contain an entry for every free index.
    pub fn eval(self, generators: &[G], strategy: &impl Strategy) -> G {
        let total = self.free.len() + self.concrete.len();
        let mut points = Vec::with_capacity(total);
        let mut weights = Vec::with_capacity(total);
        for (idx, weight) in self.free {
            points.push(generators[idx as usize].clone());
            weights.push(weight);
        }
        for (weight, point) in self.concrete {
            points.push(point);
            weights.push(weight);
        }
        G::msm(&points, &weights, strategy)
    }
}

impl<F: Additive, G: Space<F>> PartialEq for Synthetic<F, G> {
    fn eq(&self, other: &Self) -> bool {
        let zero = F::zero();
        let mut lhs = self.free.iter().peekable();
        let mut rhs = other.free.iter().peekable();
        let free_equal = core::iter::from_fn(|| {
            let ordering = match (lhs.peek().copied(), rhs.peek().copied()) {
                (Some((li, _)), Some((ri, _))) => li.cmp(ri),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => return None,
            };
            Some(match ordering {
                Ordering::Equal => (lhs.next().map(|(_, w)| w), rhs.next().map(|(_, w)| w)),
                Ordering::Less => (lhs.next().map(|(_, w)| w), None),
                Ordering::Greater => (None, rhs.next().map(|(_, w)| w)),
            })
        })
        .all(|(lw, rw)| lw.unwrap_or(&zero) == rw.unwrap_or(&zero));
        if !free_equal {
            return false;
        }

        let size = self.concrete.len() + other.concrete.len();
        let mut points = Vec::with_capacity(size);
        let mut weights = Vec::with_capacity(size);
        for (weight, point) in &self.concrete {
            points.push(point.clone());
            weights.push(weight.clone());
        }
        for (weight, point) in &other.concrete {
            points.push(point.clone());
            weights.push(-weight.clone());
        }
        G::msm(&points, &weights, &Sequential) == G::zero()
    }
}

impl<F: Additive, G: Space<F>> Eq for Synthetic<F, G> {}

impl<F: Additive, G: Space<F>> Object for Synthetic<F, G> {}

impl<'a, F: Additive, G: Space<F>> AddAssign<&'a Self> for Synthetic<F, G> {
    fn add_assign(&mut self, rhs: &'a Self) {
        for (idx, weight) in &rhs.free {
            self.free
                .entry(*idx)
                .and_modify(|existing| *existing += weight)
                .or_insert_with(|| weight.clone());
        }
        self.concrete.extend(rhs.concrete.iter().cloned());
    }
}

impl<'a, F: Additive, G: Space<F>> Add<&'a Self> for Synthetic<F, G> {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a, F: Additive, G: Space<F>> SubAssign<&'a Self> for Synthetic<F, G> {
    fn sub_assign(&mut self, rhs: &'a Self) {
        for (idx, weight) in &rhs.free {
            self.free
                .entry(*idx)
                .and_modify(|existing| *existing -= weight)
                .or_insert_with(|| -weight.clone());
        }
        self.concrete.extend(
            rhs.concrete
                .iter()
                .cloned()
                .map(|(weight, point)| (-weight, point)),
        );
    }
}

impl<'a, F: Additive, G: Space<F>> Sub<&'a Self> for Synthetic<F, G> {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<F: Additive, G: Space<F>> Neg for Synthetic<F, G> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.for_each_weight(|w| *w = -core::mem::replace(w, F::zero()));
        self
    }
}

impl<F: Additive, G: Space<F>> Additive for Synthetic<F, G> {
    fn zero() -> Self {
        Self::default()
    }
}

impl<'a, F: Space<F>, G: Space<F>> MulAssign<&'a F> for Synthetic<F, G> {
    fn mul_assign(&mut self, rhs: &'a F) {
        self.for_each_weight(|w| *w *= rhs);
    }
}

impl<'a, F: Space<F>, G: Space<F>> Mul<&'a F> for Synthetic<F, G> {
    type Output = Self;

    fn mul(mut self, rhs: &'a F) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<F: Space<F>, G: Space<F>> Space<F> for Synthetic<F, G> {}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, F: arbitrary::Arbitrary<'a>, G: arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a>
    for Synthetic<F, G>
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(0..=8)?;
        let free: BTreeMap<u32, F> = (0..len)
            .map(|_| Ok((u.int_in_range(0..=32u32)?, u.arbitrary()?)))
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            free,
            concrete: u.arbitrary()?,
        })
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

    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        EvalMatchesMsm(Vec<F>, Vec<(F, G)>),
        EvalIsLinear(Synthetic<F, G>, Synthetic<F, G>, Vec<G>),
        FuzzAdditive,
        FuzzSpaceRing,
    }

    fn cover_generators(
        u: &mut Unstructured<'_>,
        virtuals: &[&Synthetic<F, G>],
        mut gens: Vec<G>,
    ) -> arbitrary::Result<Vec<G>> {
        let needed = virtuals
            .iter()
            .filter_map(|v| v.max_free_index())
            .max()
            .map_or(0, |m| m as usize + 1);
        while gens.len() < needed {
            gens.push(u.arbitrary()?);
        }
        Ok(gens)
    }

    impl Plan {
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::EvalMatchesMsm(free_weights, concrete) => {
                    let mut expr = Synthetic::<F, G>::zero();
                    let mut gen_iter = Synthetic::<F, G>::generators();
                    for w in &free_weights {
                        expr += &(gen_iter.next().unwrap() * w);
                    }
                    expr += &Synthetic::concrete(concrete.iter().cloned());

                    let gens: Vec<G> = (0..free_weights.len())
                        .map(|_| u.arbitrary())
                        .collect::<arbitrary::Result<_>>()?;

                    let mut points = Vec::with_capacity(free_weights.len() + concrete.len());
                    let mut weights = Vec::with_capacity(free_weights.len() + concrete.len());
                    for (i, w) in free_weights.into_iter().enumerate() {
                        points.push(gens[i]);
                        weights.push(w);
                    }
                    for (w, p) in &concrete {
                        points.push(*p);
                        weights.push(*w);
                    }

                    assert_eq!(
                        expr.eval(&gens, &Sequential),
                        G::msm(&points, &weights, &Sequential)
                    );
                }
                Self::EvalIsLinear(lhs, rhs, generators) => {
                    let gens = cover_generators(u, &[&lhs, &rhs], generators)?;
                    let lhs_eval = lhs.clone().eval(&gens, &Sequential);
                    let rhs_eval = rhs.clone().eval(&gens, &Sequential);
                    assert_eq!((lhs + &rhs).eval(&gens, &Sequential), lhs_eval + &rhs_eval);
                }
                Self::FuzzAdditive => {
                    test_suites::fuzz_additive::<Synthetic<F, G>>(u)?;
                }
                Self::FuzzSpaceRing => {
                    test_suites::fuzz_space_ring::<F, Synthetic<F, G>>(u)?;
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
