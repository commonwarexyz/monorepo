use crate::algebra::{Additive, Object};
use std::{
    fmt::Debug,
    num::NonZeroUsize,
    ops::{Add, AddAssign, Neg, Sub, SubAssign},
};

/// A polynomial, with coefficients in `K`.
#[derive(Clone, PartialEq, Eq)]
pub struct Poly<K> {
    // Invariant: never empty
    coeffs: Vec<K>,
}

impl<K> Poly<K> {
    fn len(&self) -> NonZeroUsize {
        self.coeffs
            .len()
            .try_into()
            .expect("Impossible: Poly has no coefficients")
    }

    /// The degree of this polynomial.
    ///
    /// This will return 0 for a polynomial with no coefficients.
    pub fn degree(&self) -> usize {
        self.len().get() - 1
    }
}

impl<K: Additive> Poly<K> {
    fn merge_with(&mut self, rhs: &Self, f: impl Fn(&mut K, &K)) {
        self.coeffs.resize(rhs.len().max(self.len()).get(), K::ZERO);
        self.coeffs
            .iter_mut()
            .zip(&rhs.coeffs)
            .for_each(|(a, b)| f(a, b));
    }
}

impl<K: Debug> Debug for Poly<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Poly(")?;
        for (i, c) in self.coeffs.iter().enumerate() {
            if i > 0 {
                write!(f, "+ {c:?} X^{i}")?;
            } else {
                write!(f, "{c:?}")?;
            }
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl<K: Object> Object for Poly<K> {}

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
    const ZERO: Self = Self { coeffs: Vec::new() };
}
