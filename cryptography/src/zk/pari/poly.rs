//! Dense polynomial operations used by the PARI proof system.
//!
//! The radix-2 transform is local rather than shared with `commonware_math::ntt`
//! because this module also needs polynomial multiplication and division, which
//! the math crate does not provide; unifying them is a possible follow-up.

use crate::bls12381::primitives::group::Scalar;
use commonware_math::algebra::{Additive, Field, FieldNTT, Ring};
use thiserror::Error;

const NAIVE_MUL_MAX_OUTPUT: usize = 32;

/// Errors returned by polynomial and evaluation-domain operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum Error {
    /// A polynomial must contain at least its constant coefficient.
    #[error("polynomial coefficients cannot be empty")]
    EmptyPolynomial,
    /// A radix-2 domain cannot be constructed for an empty input.
    #[error("domain size cannot be zero")]
    EmptyDomain,
    /// Rounding the requested domain size to a power of two overflowed.
    #[error("domain size overflow for requested size {requested}")]
    DomainSizeOverflow { requested: usize },
    /// The scalar field does not support the requested root of unity.
    #[error("domain size {size} exceeds maximum radix-2 log size {max_log_size}")]
    UnsupportedDomainSize { size: usize, max_log_size: u8 },
    /// The provided evaluation vector has the wrong length.
    #[error("expected {expected} evaluations, got {actual}")]
    EvaluationCount { expected: usize, actual: usize },
    /// A polynomial cannot be evaluated on a domain smaller than its coefficient vector.
    #[error("polynomial has {coefficients} coefficients but domain size is {domain_size}")]
    PolynomialTooLarge {
        coefficients: usize,
        domain_size: usize,
    },
    /// The requested domain element does not exist.
    #[error("domain index {index} is out of range for size {size}")]
    DomainIndex { index: usize, size: usize },
    /// Polynomial size arithmetic overflowed.
    #[error("polynomial size arithmetic overflow")]
    PolynomialSizeOverflow,
    /// Memory for an output vector could not be reserved.
    #[error("unable to reserve space for {requested} scalar values")]
    Allocation { requested: usize },
}

/// The result type for polynomial operations.
pub(super) type Result<T> = core::result::Result<T, Error>;

/// A canonical dense polynomial with coefficients in ascending degree order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Polynomial {
    // Invariant: coefficients is non-empty and has no trailing zero unless this is zero.
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Construct a polynomial from coefficients in ascending degree order.
    pub(super) fn from_coefficients(mut coefficients: Vec<Scalar>) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(Error::EmptyPolynomial);
        }
        Self::normalize(&mut coefficients);
        Ok(Self { coefficients })
    }

    /// Return the zero polynomial.
    pub(super) fn zero() -> Self {
        Self {
            coefficients: vec![Scalar::zero()],
        }
    }

    /// Return the canonical coefficients in ascending degree order.
    pub(super) fn coefficients(&self) -> &[Scalar] {
        &self.coefficients
    }

    /// Return whether this polynomial is zero.
    pub(super) fn is_zero(&self) -> bool {
        self.coefficients.len() == 1 && self.coefficients[0] == Scalar::zero()
    }

    /// Return the exact degree, or `None` for the zero polynomial.
    #[cfg(test)]
    pub(super) fn degree(&self) -> Option<usize> {
        (!self.is_zero()).then_some(self.coefficients.len() - 1)
    }

    /// Evaluate this polynomial with Horner's method.
    pub(super) fn evaluate_at(&self, point: &Scalar) -> Scalar {
        let mut result = Scalar::zero();
        for coefficient in self.coefficients.iter().rev() {
            result *= point;
            result += coefficient;
        }
        result
    }

    /// Add two polynomials.
    pub(super) fn add(&self, other: &Self) -> Result<Self> {
        let output_len = self.coefficients.len().max(other.coefficients.len());
        let mut coefficients = zeroes(output_len)?;
        for (output, coefficient) in coefficients.iter_mut().zip(&self.coefficients) {
            *output += coefficient;
        }
        for (output, coefficient) in coefficients.iter_mut().zip(&other.coefficients) {
            *output += coefficient;
        }
        Self::from_nonempty(coefficients)
    }

    /// Subtract `other` from this polynomial.
    pub(super) fn sub(&self, other: &Self) -> Result<Self> {
        let output_len = self.coefficients.len().max(other.coefficients.len());
        let mut coefficients = zeroes(output_len)?;
        for (output, coefficient) in coefficients.iter_mut().zip(&self.coefficients) {
            *output += coefficient;
        }
        for (output, coefficient) in coefficients.iter_mut().zip(&other.coefficients) {
            *output -= coefficient;
        }
        Self::from_nonempty(coefficients)
    }

    /// Multiply two polynomials.
    pub(super) fn mul(&self, other: &Self) -> Result<Self> {
        if self.is_zero() || other.is_zero() {
            return Ok(Self::zero());
        }
        let output_len = self
            .coefficients
            .len()
            .checked_add(other.coefficients.len())
            .and_then(|len| len.checked_sub(1))
            .ok_or(Error::PolynomialSizeOverflow)?;

        if output_len <= NAIVE_MUL_MAX_OUTPUT {
            return self.mul_naive(other, output_len);
        }

        let domain = Domain::new(output_len)?;
        let mut product_evaluations = domain.evaluate(self)?;
        let other_evaluations = domain.evaluate(other)?;
        for (product, value) in product_evaluations.iter_mut().zip(&other_evaluations) {
            *product *= value;
        }
        domain.interpolate(&product_evaluations)
    }

    fn mul_naive(&self, other: &Self, output_len: usize) -> Result<Self> {
        let mut coefficients = zeroes(output_len)?;
        for (left_index, left) in self.coefficients.iter().enumerate() {
            for (right_index, right) in other.coefficients.iter().enumerate() {
                let index = left_index
                    .checked_add(right_index)
                    .ok_or(Error::PolynomialSizeOverflow)?;
                let product = left.clone() * right;
                coefficients[index] += &product;
            }
        }
        Self::from_nonempty(coefficients)
    }

    /// Divide by `X^m - 1`, where `m` is the domain size.
    ///
    /// Returns `(quotient, remainder)`, with the remainder having degree less than `m`.
    pub(super) fn divide_by_vanishing(&self, domain: &Domain) -> Result<(Self, Self)> {
        let m = domain.size;
        let input_len = self.coefficients.len();
        if input_len <= m {
            return Ok((Self::zero(), self.try_clone()?));
        }

        let mut work = copy_scalars(&self.coefficients)?;
        let mut quotient = zeroes(
            input_len
                .checked_sub(m)
                .ok_or(Error::PolynomialSizeOverflow)?,
        )?;
        for high in (m..input_len).rev() {
            let quotient_index = high.checked_sub(m).ok_or(Error::PolynomialSizeOverflow)?;
            let factor = work[high].clone();
            quotient[quotient_index] = factor.clone();
            work[quotient_index] += &factor;
            work[high] = Scalar::zero();
        }
        work.truncate(m);

        Ok((Self::from_nonempty(quotient)?, Self::from_nonempty(work)?))
    }

    /// Divide by `X - root` using synthetic division.
    ///
    /// Returns `(quotient, remainder)` where the remainder equals `self(root)`.
    pub(super) fn divide_by_linear(&self, root: &Scalar) -> Result<(Self, Scalar)> {
        let input_len = self.coefficients.len();
        if input_len == 1 {
            return Ok((Self::zero(), self.coefficients[0].clone()));
        }

        let quotient_len = input_len
            .checked_sub(1)
            .ok_or(Error::PolynomialSizeOverflow)?;
        let mut quotient = zeroes(quotient_len)?;
        quotient[quotient_len - 1] = self.coefficients[input_len - 1].clone();
        for index in (1..quotient_len).rev() {
            let product = quotient[index].clone() * root;
            quotient[index - 1] = self.coefficients[index].clone() + &product;
        }
        let product = quotient[0].clone() * root;
        let remainder = self.coefficients[0].clone() + &product;
        Ok((Self::from_nonempty(quotient)?, remainder))
    }

    /// Multiply by the domain vanishing polynomial `X^m - 1`.
    pub(super) fn mul_vanishing(&self, domain: &Domain) -> Result<Self> {
        if self.is_zero() {
            return Ok(Self::zero());
        }
        let output_len = self
            .coefficients
            .len()
            .checked_add(domain.size)
            .ok_or(Error::PolynomialSizeOverflow)?;
        let mut coefficients = zeroes(output_len)?;
        for (index, coefficient) in self.coefficients.iter().enumerate() {
            coefficients[index] -= coefficient;
            coefficients[index + domain.size] += coefficient;
        }
        Self::from_nonempty(coefficients)
    }

    /// Add a multiple of the domain vanishing polynomial.
    ///
    /// For `m = domain.size()`, this returns `self + mask * (X^m - 1)`. The result
    /// agrees with `self` at every point in the domain.
    pub(super) fn mask_vanishing(&self, mask: &Self, domain: &Domain) -> Result<Self> {
        if mask.is_zero() {
            return self.try_clone();
        }

        let shifted_len = mask
            .coefficients
            .len()
            .checked_add(domain.size)
            .ok_or(Error::PolynomialSizeOverflow)?;
        let output_len = self.coefficients.len().max(shifted_len);
        let mut coefficients = zeroes(output_len)?;
        for (output, coefficient) in coefficients.iter_mut().zip(&self.coefficients) {
            *output += coefficient;
        }
        for (index, coefficient) in mask.coefficients.iter().enumerate() {
            let shifted_index = index
                .checked_add(domain.size)
                .ok_or(Error::PolynomialSizeOverflow)?;
            coefficients[index] -= coefficient;
            coefficients[shifted_index] += coefficient;
        }
        Self::from_nonempty(coefficients)
    }

    fn from_nonempty(mut coefficients: Vec<Scalar>) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(Error::EmptyPolynomial);
        }
        Self::normalize(&mut coefficients);
        Ok(Self { coefficients })
    }

    fn normalize(coefficients: &mut Vec<Scalar>) {
        while coefficients.len() > 1
            && coefficients
                .last()
                .is_some_and(|value| *value == Scalar::zero())
        {
            coefficients.pop();
        }
    }

    fn try_clone(&self) -> Result<Self> {
        Self::from_nonempty(copy_scalars(&self.coefficients)?)
    }
}

/// A multiplicative radix-2 evaluation domain for BLS12-381 scalars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Domain {
    size: usize,
    log_size: u8,
    generator: Scalar,
    generator_inverse: Scalar,
    size_inverse: Scalar,
}

impl Domain {
    /// Construct the smallest radix-2 domain containing `minimum_size` points.
    pub(super) fn new(minimum_size: usize) -> Result<Self> {
        if minimum_size == 0 {
            return Err(Error::EmptyDomain);
        }
        let size = minimum_size
            .checked_next_power_of_two()
            .ok_or(Error::DomainSizeOverflow {
                requested: minimum_size,
            })?;
        let log_size =
            u8::try_from(size.trailing_zeros()).map_err(|_| Error::UnsupportedDomainSize {
                size,
                max_log_size: Scalar::MAX_LG_ROOT_ORDER,
            })?;
        let generator = Scalar::root_of_unity(log_size).ok_or(Error::UnsupportedDomainSize {
            size,
            max_log_size: Scalar::MAX_LG_ROOT_ORDER,
        })?;
        let size_u64 = u64::try_from(size).map_err(|_| Error::UnsupportedDomainSize {
            size,
            max_log_size: Scalar::MAX_LG_ROOT_ORDER,
        })?;
        let size_inverse = Scalar::from(size_u64).inv();
        let generator_inverse = generator.inv();
        Ok(Self {
            size,
            log_size,
            generator,
            generator_inverse,
            size_inverse,
        })
    }

    /// Return the number of points in this domain.
    #[cfg(test)]
    pub(super) const fn size(&self) -> usize {
        self.size
    }

    /// Return the base-2 logarithm of the domain size.
    #[cfg(test)]
    pub(super) const fn log_size(&self) -> u8 {
        self.log_size
    }

    /// Return the domain point `generator^index`.
    #[cfg(test)]
    pub(super) fn element(&self, index: usize) -> Result<Scalar> {
        if index >= self.size {
            return Err(Error::DomainIndex {
                index,
                size: self.size,
            });
        }
        let exponent = u64::try_from(index).map_err(|_| Error::DomainIndex {
            index,
            size: self.size,
        })?;
        Ok(self.generator.exp(&[exponent]))
    }

    /// Evaluate `X^m - 1` at `point`, where `m` is the domain size.
    pub(super) fn evaluate_vanishing(&self, point: &Scalar) -> Scalar {
        point.exp(&[self.size as u64]) - &Scalar::one()
    }

    /// Return whether `point` is in this domain.
    #[cfg(test)]
    pub(super) fn contains(&self, point: &Scalar) -> bool {
        self.evaluate_vanishing(point) == Scalar::zero()
    }

    /// Evaluate a polynomial at every point in the domain using a radix-2 NTT.
    pub(super) fn evaluate(&self, polynomial: &Polynomial) -> Result<Vec<Scalar>> {
        if polynomial.coefficients.len() > self.size {
            return Err(Error::PolynomialTooLarge {
                coefficients: polynomial.coefficients.len(),
                domain_size: self.size,
            });
        }
        let mut evaluations = zeroes(self.size)?;
        for (output, coefficient) in evaluations.iter_mut().zip(&polynomial.coefficients) {
            *output = coefficient.clone();
        }
        self.transform(&mut evaluations, false);
        Ok(evaluations)
    }

    /// Interpolate a polynomial from one value at every point in the domain.
    pub(super) fn interpolate(&self, evaluations: &[Scalar]) -> Result<Polynomial> {
        self.check_evaluation_count(evaluations.len())?;
        let mut coefficients = copy_scalars(evaluations)?;
        self.transform(&mut coefficients, true);
        Polynomial::from_nonempty(coefficients)
    }

    /// Return all Lagrange basis polynomials evaluated at `point`.
    pub(super) fn lagrange_coefficients(&self, point: &Scalar) -> Result<Vec<Scalar>> {
        // The domain contains every m-th root of unity, so a vanishing point
        // is a domain element and its coefficients form an elementary basis.
        let vanishing = self.evaluate_vanishing(point);
        if vanishing == Scalar::zero() {
            let mut coefficients = zeroes(self.size)?;
            let mut root = Scalar::one();
            for coefficient in &mut coefficients {
                if &root == point {
                    *coefficient = Scalar::one();
                    break;
                }
                root *= &self.generator;
            }
            return Ok(coefficients);
        }

        // Store prefix products, then use one inversion to invert every denominator.
        let mut coefficients = zeroes(self.size)?;
        let mut product = Scalar::one();
        let mut root = Scalar::one();
        for coefficient in &mut coefficients {
            *coefficient = product.clone();
            let denominator = point.clone() - &root;
            product *= &denominator;
            root *= &self.generator;
        }

        let mut product_inverse = product.inv();
        root = self.generator_inverse.clone();
        for coefficient in coefficients.iter_mut().rev() {
            let denominator = point.clone() - &root;
            let prefix = coefficient.clone();
            *coefficient = prefix * &product_inverse;
            product_inverse *= &denominator;
            root *= &self.generator_inverse;
        }

        let scale = vanishing * &self.size_inverse;
        root = Scalar::one();
        for coefficient in &mut coefficients {
            let factor = scale.clone() * &root;
            *coefficient *= &factor;
            root *= &self.generator;
        }
        Ok(coefficients)
    }

    /// Return the Lagrange basis polynomials for `indices` evaluated at `point`.
    ///
    /// The output is aligned with `indices`. Uses the closed form
    /// `L_i(X) = Z_H(X) g^i / (m (X - g^i))` with one batched inversion, so the
    /// cost is `O(|indices| log m)` rather than the `O(m)` of
    /// [`Self::lagrange_coefficients`].
    pub(super) fn lagrange_coefficients_at(
        &self,
        point: &Scalar,
        indices: &[u32],
    ) -> Result<Vec<Scalar>> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(indices.len())
            .map_err(|_| Error::Allocation {
                requested: indices.len(),
            })?;
        for &index in indices {
            if (index as usize) >= self.size {
                return Err(Error::DomainIndex {
                    index: index as usize,
                    size: self.size,
                });
            }
            roots.push(self.generator.exp(&[u64::from(index)]));
        }

        let vanishing = self.evaluate_vanishing(point);
        let mut coefficients = zeroes(indices.len())?;
        if vanishing == Scalar::zero() {
            // The point is a domain element: the basis is elementary.
            for (coefficient, root) in coefficients.iter_mut().zip(&roots) {
                if root == point {
                    *coefficient = Scalar::one();
                }
            }
            return Ok(coefficients);
        }

        // Store prefix products, then use one inversion to invert every denominator.
        let scale = vanishing * &self.size_inverse;
        let mut product = Scalar::one();
        for (coefficient, root) in coefficients.iter_mut().zip(&roots) {
            *coefficient = product.clone();
            let denominator = point.clone() - root;
            product *= &denominator;
        }
        let mut product_inverse = product.inv();
        for (coefficient, root) in coefficients.iter_mut().zip(&roots).rev() {
            let prefix = coefficient.clone();
            *coefficient = ((scale.clone() * root) * &prefix) * &product_inverse;
            let denominator = point.clone() - root;
            product_inverse *= &denominator;
        }
        Ok(coefficients)
    }

    /// Evaluate the interpolation of `evaluations` at an arbitrary point.
    #[cfg(test)]
    pub(super) fn lagrange_evaluate(
        &self,
        evaluations: &[Scalar],
        point: &Scalar,
    ) -> Result<Scalar> {
        self.check_evaluation_count(evaluations.len())?;
        let coefficients = self.lagrange_coefficients(point)?;
        let mut result = Scalar::zero();
        for (value, coefficient) in evaluations.iter().zip(&coefficients) {
            let term = value.clone() * coefficient;
            result += &term;
        }
        Ok(result)
    }

    const fn check_evaluation_count(&self, actual: usize) -> Result<()> {
        if actual != self.size {
            return Err(Error::EvaluationCount {
                expected: self.size,
                actual,
            });
        }
        Ok(())
    }

    fn transform(&self, values: &mut [Scalar], inverse: bool) {
        // The public callers ensure this exact length before reaching the transform.
        debug_assert_eq!(values.len(), self.size);

        let mut reversed = 0usize;
        for index in 1..self.size {
            let mut bit = self.size >> 1;
            while reversed & bit != 0 {
                reversed ^= bit;
                bit >>= 1;
            }
            reversed ^= bit;
            if index < reversed {
                values.swap(index, reversed);
            }
        }

        let transform_generator = if inverse {
            &self.generator_inverse
        } else {
            &self.generator
        };
        let mut width = 2usize;
        while width <= self.size {
            let half = width / 2;
            let exponent = (self.size / width) as u64;
            let step = transform_generator.exp(&[exponent]);
            for chunk in values.chunks_exact_mut(width) {
                let (left, right) = chunk.split_at_mut(half);
                let mut twiddle = Scalar::one();
                for (left, right) in left.iter_mut().zip(right) {
                    let product = right.clone() * &twiddle;
                    let original_left = left.clone();
                    *left = original_left.clone() + &product;
                    *right = original_left - &product;
                    twiddle *= &step;
                }
            }
            if width == self.size {
                break;
            }
            // The domain size is a supported power of two, so this cannot overflow.
            width *= 2;
        }

        if inverse {
            for value in values {
                *value *= &self.size_inverse;
            }
        }
    }
}

fn zeroes(len: usize) -> Result<Vec<Scalar>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(len)
        .map_err(|_| Error::Allocation { requested: len })?;
    values.resize_with(len, Scalar::zero);
    Ok(values)
}

fn copy_scalars(values: &[Scalar]) -> Result<Vec<Scalar>> {
    let mut output = zeroes(values.len())?;
    output.clone_from_slice(values);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn polynomial(coefficients: Vec<Scalar>) -> Polynomial {
        Polynomial::from_coefficients(coefficients).unwrap()
    }

    fn naive_evaluate(coefficients: &[Scalar], point: &Scalar) -> Scalar {
        let mut power = Scalar::one();
        let mut result = Scalar::zero();
        for coefficient in coefficients {
            let term = coefficient.clone() * &power;
            result += &term;
            power *= point;
        }
        result
    }

    fn naive_multiply(left: &[Scalar], right: &[Scalar]) -> Vec<Scalar> {
        let mut output = vec![Scalar::zero(); left.len() + right.len() - 1];
        for (left_index, left) in left.iter().enumerate() {
            for (right_index, right) in right.iter().enumerate() {
                let product = left.clone() * right;
                output[left_index + right_index] += &product;
            }
        }
        output
    }

    #[test]
    fn polynomial_add_sub_mul_match_naive_examples() {
        let left = polynomial(vec![scalar(1), scalar(2), scalar(3)]);
        let right = polynomial(vec![scalar(4), scalar(5)]);
        assert_eq!(left.degree(), Some(2));
        assert_eq!(Polynomial::zero().degree(), None);

        assert_eq!(
            left.add(&right).unwrap(),
            polynomial(vec![scalar(5), scalar(7), scalar(3)])
        );
        assert_eq!(
            left.sub(&right).unwrap(),
            polynomial(vec![-scalar(3), -scalar(3), scalar(3)])
        );
        assert_eq!(
            left.mul(&right).unwrap(),
            polynomial(vec![scalar(4), scalar(13), scalar(22), scalar(15)])
        );

        let point = scalar(7);
        let product = left.mul(&right).unwrap();
        assert_eq!(
            product.evaluate_at(&point),
            left.evaluate_at(&point) * &right.evaluate_at(&point)
        );
    }

    #[test]
    fn ntt_multiplication_matches_naive_convolution() {
        let left_coefficients = (1..=20).map(scalar).collect::<Vec<_>>();
        let right_coefficients = (21..=39).map(scalar).collect::<Vec<_>>();
        let expected = polynomial(naive_multiply(&left_coefficients, &right_coefficients));
        let left = polynomial(left_coefficients);
        let right = polynomial(right_coefficients);

        assert!(left.coefficients().len() + right.coefficients().len() - 1 > NAIVE_MUL_MAX_OUTPUT);
        assert_eq!(left.mul(&right).unwrap(), expected);
    }

    #[test]
    fn radix_two_evaluation_and_interpolation_match_naive() {
        let domain = Domain::new(3).unwrap();
        assert_eq!(domain.size(), 4);
        assert_eq!(domain.log_size(), 2);

        let input = polynomial(vec![scalar(3), scalar(1), scalar(4), scalar(1)]);
        let evaluations = domain.evaluate(&input).unwrap();
        for (index, evaluation) in evaluations.iter().enumerate() {
            let point = domain.element(index).unwrap();
            assert!(domain.contains(&point));
            assert_eq!(domain.evaluate_vanishing(&point), Scalar::zero());
            assert_eq!(*evaluation, naive_evaluate(input.coefficients(), &point));
        }
        assert!(!domain.contains(&Scalar::zero()));
        assert_eq!(domain.interpolate(&evaluations).unwrap(), input);
    }

    #[test]
    fn division_by_vanishing_returns_quotient_and_remainder() {
        let domain = Domain::new(4).unwrap();
        let input = polynomial(vec![
            scalar(3),
            scalar(4),
            Scalar::zero(),
            Scalar::zero(),
            scalar(2),
            scalar(3),
        ]);
        let expected_quotient = polynomial(vec![scalar(2), scalar(3)]);
        let expected_remainder = polynomial(vec![scalar(5), scalar(7)]);

        let (quotient, remainder) = input.divide_by_vanishing(&domain).unwrap();
        assert_eq!(quotient, expected_quotient);
        assert_eq!(remainder, expected_remainder);

        let vanishing = polynomial(vec![
            -Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::one(),
        ]);
        assert_eq!(
            quotient.mul(&vanishing).unwrap().add(&remainder).unwrap(),
            input
        );
    }

    #[test]
    fn synthetic_division_returns_evaluation_remainder() {
        let root = scalar(2);
        let input = polynomial(vec![scalar(1), -scalar(5), -scalar(6), scalar(5)]);
        let expected_quotient = polynomial(vec![scalar(3), scalar(4), scalar(5)]);

        let (quotient, remainder) = input.divide_by_linear(&root).unwrap();
        assert_eq!(quotient, expected_quotient);
        assert_eq!(remainder, scalar(7));
        assert_eq!(remainder, input.evaluate_at(&root));
    }

    #[test]
    fn vanishing_mask_preserves_domain_evaluations() {
        let domain = Domain::new(4).unwrap();
        let input = polynomial(vec![scalar(7), scalar(8), scalar(9)]);
        let mask = polynomial(vec![scalar(2), scalar(3)]);
        let masked = input.mask_vanishing(&mask, &domain).unwrap();

        assert_eq!(
            masked,
            polynomial(vec![
                scalar(5),
                scalar(5),
                scalar(9),
                Scalar::zero(),
                scalar(2),
                scalar(3),
            ])
        );
        for index in 0..domain.size() {
            let point = domain.element(index).unwrap();
            assert_eq!(input.evaluate_at(&point), masked.evaluate_at(&point));
        }
    }

    #[test]
    fn lagrange_evaluation_matches_interpolated_polynomial() {
        let domain = Domain::new(4).unwrap();
        let evaluations = vec![scalar(2), scalar(5), scalar(7), scalar(11)];
        let interpolated = domain.interpolate(&evaluations).unwrap();
        let point = scalar(9);

        assert_eq!(
            domain.lagrange_evaluate(&evaluations, &point).unwrap(),
            interpolated.evaluate_at(&point)
        );

        for (index, expected) in evaluations.iter().enumerate() {
            let domain_point = domain.element(index).unwrap();
            assert_eq!(
                domain
                    .lagrange_evaluate(&evaluations, &domain_point)
                    .unwrap(),
                *expected
            );
            let coefficients = domain.lagrange_coefficients(&domain_point).unwrap();
            for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
                let expected_coefficient = if coefficient_index == index {
                    Scalar::one()
                } else {
                    Scalar::zero()
                };
                assert_eq!(*coefficient, expected_coefficient);
            }
        }
    }

    #[test]
    fn targeted_lagrange_coefficients_match_full_basis() {
        let domain = Domain::new(8).unwrap();
        let indices = [0u32, 3, 5, 7];

        let point = scalar(23);
        let full = domain.lagrange_coefficients(&point).unwrap();
        let targeted = domain.lagrange_coefficients_at(&point, &indices).unwrap();
        for (slot, &index) in indices.iter().enumerate() {
            assert_eq!(targeted[slot], full[index as usize]);
        }

        let inside = domain.element(5).unwrap();
        let targeted = domain.lagrange_coefficients_at(&inside, &indices).unwrap();
        for (slot, &index) in indices.iter().enumerate() {
            let expected = if index == 5 {
                Scalar::one()
            } else {
                Scalar::zero()
            };
            assert_eq!(targeted[slot], expected);
        }

        assert!(
            domain
                .lagrange_coefficients_at(&point, &[])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            domain.lagrange_coefficients_at(&point, &[8]),
            Err(Error::DomainIndex { index: 8, size: 8 })
        );
    }

    #[test]
    fn malformed_sizes_return_errors() {
        assert_eq!(
            Polynomial::from_coefficients(Vec::new()),
            Err(Error::EmptyPolynomial)
        );
        assert_eq!(Domain::new(0), Err(Error::EmptyDomain));
        assert_eq!(
            Domain::new(usize::MAX),
            Err(Error::DomainSizeOverflow {
                requested: usize::MAX
            })
        );

        let domain = Domain::new(4).unwrap();
        assert_eq!(
            domain.interpolate(&[scalar(1)]),
            Err(Error::EvaluationCount {
                expected: 4,
                actual: 1
            })
        );
        assert_eq!(
            domain.element(4),
            Err(Error::DomainIndex { index: 4, size: 4 })
        );

        let oversized = polynomial(vec![scalar(1), scalar(2), scalar(3), scalar(4), scalar(5)]);
        assert_eq!(
            domain.evaluate(&oversized),
            Err(Error::PolynomialTooLarge {
                coefficients: 5,
                domain_size: 4
            })
        );
    }
}
