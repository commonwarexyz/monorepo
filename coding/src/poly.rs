use crate::field::F;
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_utils::bitmap::{BitMap, DEFAULT_CHUNK_SIZE};
use rand_core::CryptoRngCore;
use std::ops::{Index, IndexMut};

/// Reverse the first `bit_width` bits of `i`.
///
/// Any bits beyond that width will be erased.
fn reverse_bits(bit_width: u32, i: u64) -> u64 {
    assert!(bit_width <= 64, "bit_width must be <= 64");
    i.wrapping_shl(64 - bit_width).reverse_bits()
}

/// Calculate an NTT, or an inverse NTT (with FORWARD=false), in place.
///
/// We implement this generically over anything we can index into, which allows
/// performing NTTs in place
fn ntt<const FORWARD: bool, M: IndexMut<(usize, usize), Output = F>>(
    rows: usize,
    cols: usize,
    matrix: &mut M,
) {
    let lg_rows = rows.ilog2() as usize;
    assert_eq!(1 << lg_rows, rows, "rows should be a power of 2");
    // A number w such that w^(2^lg_rows) = 1.
    // (Or, in the inverse case, the inverse of that number, to undo the NTT).
    let w = {
        let w = F::root_of_unity(lg_rows as u8).expect("too many rows to perform NTT");
        if FORWARD {
            w
        } else {
            // since w^(2^lg_rows) = 1, w^(2^lg_rows - 1) * w = 1,
            // making that left-hand term the inverse of w.
            w.exp((1 << lg_rows) - 1)
        }
    };
    // The inverse algorithm consists of carefully undoing the work of the
    // standard algorithm, so we describe that in detail.
    //
    // To understand the NTT algorithm, first consider the case of a single
    // column. We have a polynomial f(X), and we want to turn that into:
    //
    // [f(w^0), f(w^1), ..., f(w^(2^lg_rows - 1))]
    //
    // Our polynomial can be written as:
    //
    // f+(X^2) + X f-(X^2)
    //
    // where f+ and f- are polynomials with half the degree.
    // f+ is obtained by taking the coefficients at even indices,
    // f- is obtained by taking the coefficients at odd indices.
    //
    // w^2 is also conveniently a 2^(lg_rows - 1) root of unity. Thus,
    // we can recursively compute an NTT on f+, using w^2 as the root,
    // and an NTT on f-, using w^2 as the root, each of which is a problem
    // of half the size.
    //
    // We can then compute:
    // f+((w^i)^2) + (w^i) f-((w^i)^2)
    // f+((w^i)^2) - (w^i) f-((w^i)^2)
    // for each i.
    // (Note that (-w^i)^2 = ((-w)^2)^i = (w^i)^2))
    //
    // Our coefficients are conveniently laid out as [f+ f-], already
    // in a neat order. When we recurse, the coefficients of f+ are, in
    // turn, already laid out as [f++ f+-], and so on.
    //
    // We just need to transform this recursive algorithm, in top down form,
    // into an iterative one, in bottom up form. For that, note that the NTT
    // for the case of 1 row is trivial: do nothing.

    // Will contain, in bottom up order, the power of w we need at that stage.
    // At the last stage, we need w itself.
    // At the stage before last, we need w^2.
    // And so on.
    // How many stages do we need? If we have 1 row, we need 0 stages.
    // In general, with 2^n rows, we need n stages.
    let stages = {
        let mut out = vec![(0usize, F::zero()); lg_rows];
        let mut w_i = w;
        for i in (0..lg_rows).rev() {
            out[i] = (i, w_i);
            w_i = w_i * w_i;
        }
        // In the case of the reverse algorithm, we undo each stage of the
        // forward algorithm, starting with the last stage.
        if !FORWARD {
            out.reverse();
        }
        out
    };
    for (stage, w) in stages.into_iter() {
        // At stage i, we have polynomials with 2^i coefficients,
        // which have already been evaluated to create 2^i entries.
        // We need to combine these evaluations to create 2^(i + 1) entries,
        // representing the evaluation of a polynomial with 2^(i + 1) coefficients.
        // If we have two of these evaluations, laid out one after the other:
        //
        // [x_0, x_1, ...] [y_0, y_1, ...]
        //
        // Then the number of elements we need to skip to get the corresponding
        // element in the other half is simply the number of elements in each half,
        // i.e. 2^i.
        let skip = 1 << stage;
        let mut i = 0;
        while i < rows {
            // In the case of a backwards NTT, skew should be the inverse of the skew
            // in the forwards direction.
            let mut w_j = F::one();
            for j in 0..skip {
                let index_a = i + j;
                let index_b = index_a + skip;
                for k in 0..cols {
                    let (a, b) = (matrix[(index_a, k)], matrix[(index_b, k)]);
                    if FORWARD {
                        matrix[(index_a, k)] = a + w_j * b;
                        matrix[(index_b, k)] = a - w_j * b;
                    } else {
                        // To check the math, convince yourself that applying the forward
                        // transformation, and then this transformation, with w_j being the
                        // inverse of the value above, that you get (a, b).
                        // (a + w_j * b) + (a - w_j * b) = 2 * a
                        matrix[(index_a, k)] = (a + b).div_2();
                        // (a + w_j * b) - (a - w_j * b) = 2 * w_j * b.
                        // w_j in this branch is the inverse of w_j in the other branch.
                        matrix[(index_b, k)] = ((a - b) * w_j).div_2();
                    }
                }
                w_j = w_j * w;
            }
            i += 2 * skip;
        }
    }
}

/// A single column of some larger data.
///
/// This allows us to easily do NTTs over partial segments of some bigger matrix.
struct Column<'a> {
    data: &'a mut [F],
}

impl<'a> Index<(usize, usize)> for Column<'a> {
    type Output = F;

    fn index(&self, (i, _): (usize, usize)) -> &Self::Output {
        &self.data[i]
    }
}
impl<'a> IndexMut<(usize, usize)> for Column<'a> {
    fn index_mut(&mut self, (i, _): (usize, usize)) -> &mut Self::Output {
        &mut self.data[i]
    }
}

/// Represents a matrix of field elements, of arbitrary dimensions
///
/// This is in row major order, so consider processing elements in the same
/// row first, for locality.
#[derive(Clone, PartialEq)]
pub struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<F>,
}

impl EncodeSize for Matrix {
    fn encode_size(&self) -> usize {
        self.rows.encode_size() + self.cols.encode_size() + self.data.encode_size()
    }
}

impl Write for Matrix {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.rows.write(buf);
        self.cols.write(buf);
        self.data.write(buf);
    }
}

impl Read for Matrix {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_els: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let cfg = RangeCfg::from(..=max_els);
        let rows = usize::read_cfg(buf, &cfg)?;
        let cols = usize::read_cfg(buf, &cfg)?;
        let data = Vec::<F>::read_cfg(buf, &(cfg, ()))?;
        let expected_len = rows
            .checked_mul(cols)
            .ok_or(commonware_codec::Error::Invalid(
                "Matrix",
                "matrix dimensions overflow",
            ))?;
        if data.len() != expected_len {
            return Err(commonware_codec::Error::Invalid(
                "Matrix",
                "matrix element count does not match dimensions",
            ));
        }
        Ok(Self { rows, cols, data })
    }
}

impl std::fmt::Debug for Matrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..self.rows {
            let row_i = &self[i];
            for &row_i_j in row_i {
                write!(f, "{row_i_j:?} ")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl Matrix {
    /// Create a zero matrix, with a certain number of rows and columns
    fn zero(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![F::zero(); rows * cols],
        }
    }

    /// Initialize a matrix, with dimensions, and data to pull from.
    ///
    /// Any extra data is ignored, any data not supplied is treated as 0.
    pub fn init(rows: usize, cols: usize, mut data: impl Iterator<Item = F>) -> Self {
        let mut out = Self::zero(rows, cols);
        'outer: for i in 0..rows {
            for row_i in &mut out[i] {
                let Some(x) = data.next() else {
                    break 'outer;
                };
                *row_i = x;
            }
        }
        out
    }

    /// Interpret the columns of this matrix as polynomials, with at least `min_coefficients`.
    ///
    /// This will, in fact, produce a matrix padded to the next power of 2 of that number.
    ///
    /// This will return `None` if `min_coefficients < self.rows`, which would mean
    /// discarding data, instead of padding it.
    pub fn as_polynomials(&self, min_coefficients: usize) -> Option<PolynomialVector> {
        if min_coefficients < self.rows {
            return None;
        }
        Some(PolynomialVector::new(
            min_coefficients,
            self.cols,
            (0..self.rows).flat_map(|i| self[i].iter().copied()),
        ))
    }

    /// Multiply this matrix by another.
    ///
    /// This assumes that the number of columns in this matrix match the number
    /// of rows in the other matrix.
    pub fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.cols, other.rows);
        let mut out = Self::zero(self.rows, other.cols);
        for i in 0..self.rows {
            for j in 0..self.cols {
                let c = self[(i, j)];
                let other_j = &other[j];
                for k in 0..other.cols {
                    out[(i, k)] = out[(i, k)] + c * other_j[k]
                }
            }
        }
        out
    }

    fn ntt<const FORWARD: bool>(&mut self) {
        ntt::<FORWARD, Self>(self.rows, self.cols, self)
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    // Iterate over the rows of this matrix.
    pub fn iter(&self) -> impl Iterator<Item = &[F]> {
        (0..self.rows).map(|i| &self[i])
    }

    /// Create a random matrix with certain dimensions.
    pub fn rand(mut rng: impl CryptoRngCore, rows: usize, cols: usize) -> Self {
        Self::init(rows, cols, (0..rows * cols).map(|_| F::rand(&mut rng)))
    }
}

impl Index<usize> for Matrix {
    type Output = [F];

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[self.cols * index..self.cols * (index + 1)]
    }
}

impl IndexMut<usize> for Matrix {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[self.cols * index..self.cols * (index + 1)]
    }
}

impl Index<(usize, usize)> for Matrix {
    type Output = F;

    fn index(&self, (i, j): (usize, usize)) -> &Self::Output {
        &self.data[self.cols * i + j]
    }
}

impl IndexMut<(usize, usize)> for Matrix {
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut Self::Output {
        &mut self.data[self.cols * i + j]
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Polynomial {
    coefficients: Vec<F>,
}

impl Polynomial {
    /// Create a polynomial which vanishes (evaluates to 0) except at a few points.
    ///
    /// It's assumed that `except` is a bit vector with length a power of 2.
    ///
    /// For each index i NOT IN `except`, the resulting polynomial will evaluate
    /// to w^i, where w is a `except.len()` root of unity.
    ///
    /// e.g. with `except` = 1001, then the resulting polynomial will
    /// evaluate to 0 at w^1 and w^2, where w is a 4th root of unity.
    fn vanishing(except: &BitMap) -> Self {
        // Algorithm taken from: https://ethresear.ch/t/reed-solomon-erasure-code-recovery-in-n-log-2-n-time-with-ffts/3039.
        // The basic idea of the algorithm is that given a set of indices S,
        // we can split it in two: the even indices (first bit = 0) and the odd indices.
        // We compute two vanishing polynomials over
        //
        //   S_L := {i / 2 | i in S}
        //   S_R := {(i - 1) / 2 | i in S}
        //
        // Using a domain of half the size. i.e. instead of w, they use w^2 as the root.
        //
        // V_L vanishes at (w^2)^(i / 2) for each i in S, i.e. w^i, for each even i in S.
        // Similarly, V_R vanishes at (w^2)^((i - 1) / 2) = w^(i - 1), for each odd i in S.
        //
        // To combine these into one polynomial, we multiply the roots of V_R by w, so that it
        // vanishes at the w^i (for odd i) instead of w^(i - 1).
        //
        // To multiply the roots of a polynomial
        //
        //   P(X) := a0 + a1 X + a2 X^2 + ...
        //
        // by some factor z, it suffices to divide the ith coefficient by z^i:
        //
        //   Q(X) := a0 + (a1 / z) X + (a2 / z^2) X^2 + ...
        //
        // Notice that Q(z X) = P(X), so if P(x) = 0, then Q(z x) = 0, so we've multiplied
        // the roots by a factor of z.
        //
        // After multiplying the roots of V_R by w, we can then multiply the resulting polynomial
        // with V_L, producing a polynomial which vanishes at the right indices.
        //
        // To multiply efficiently, we can do multiplication over the evaluation domain:
        // we perform an NTT over each polynomial, multiplie the evaluations pointwise,
        // and then perform an inverse NTT to get the result. We just need to make sure that
        // when we perform the NTT, we've added enough extra 0 coefficients in each polynomial
        // to accommodate the extra degree. e.g. if we have two polynomials of degree 1, then
        // we need to make sure to pad them to have enough coefficients for a polynomial of degree 2,
        // so that we can correctly interpolate the result back.
        //
        // The tricky part is transforming this algorithm into an iterative one, and respecting
        // the reverse bit order of the coefficients we need
        let rows = except.len() as usize;
        let padded_rows = rows.next_power_of_two();
        let zeroes = except.count_zeros() as usize + padded_rows - rows;
        assert!(zeroes < padded_rows, "too many points to vanish over");
        let lg_rows = padded_rows.ilog2();
        // At each iteration, we split `except` into sections.
        // Each section has a polynomial associated with it, which should
        // be the polynomial that vanishes over all the 0 bits of that section,
        // or the 0 polynomial if that section has no 0 bits.
        //
        // The sections are organized into a tree:
        //
        // 0xx             1xx
        // 00x     01x     10x         11x
        // 000 001 010 011 100 101 110 111
        //
        // The first half of the sections are even, the second half are odd.
        // The first half of the first half have their first two bits set to 00,
        // the second half of the first half have their first two bits set to 01,
        // and so on.
        //
        // In other words, the ith index in except becomes the i.reverse_bits()
        // section.
        //
        // How many polynomials do we have? (Potentially 0 ones).
        let mut polynomial_count = padded_rows;
        // How many coefficients does each polynomial have?
        let mut polynomial_size: usize = 2;
        // For the first iteration, each
        let mut polynomials = vec![F::zero(); 2 * padded_rows];
        let mut active = BitMap::<DEFAULT_CHUNK_SIZE>::with_capacity(polynomial_count as u64);
        for i in 0..polynomial_count {
            let rev_i = reverse_bits(lg_rows, i as u64) as usize;
            if !except.get(rev_i as u64) {
                polynomials[2 * i] = -F::one();
                polynomials[2 * i + 1] = F::one();
                active.push(true);
            } else {
                active.push(false);
            }
        }
        // Rather than store w at each iteration, and divide by it, just store its inverse,
        // allowing us to multiply by it.
        let w_invs = {
            // since w^(2^lg_rows) = 1, w^(2^lg_rows - 1) * w = 1,
            // making that left-hand term the inverse of w.
            let mut w_inv = F::root_of_unity(lg_rows as u8)
                .expect("too many rows to create vanishing polynomial")
                .exp((1 << lg_rows) - 1);
            let lg_rows = lg_rows as usize;
            let mut out = Vec::with_capacity(lg_rows);
            for _ in 0..lg_rows {
                out.push(w_inv);
                w_inv = w_inv * w_inv;
            }
            out.reverse();
            out
        };
        // When we multiply
        let mut scratch: Vec<F> = Vec::with_capacity(padded_rows);
        for w_inv in w_invs.into_iter() {
            // After this iteration, we're going to end up with half the polynomials
            polynomial_count >>= 1;
            // and each of them will be twice as large.
            let new_polynomial_size = polynomial_size << 1;
            // Our goal is to construct the ith polynomial.
            for i in 0..polynomial_count {
                let start = new_polynomial_size * i;
                let has_left = if ((2 * i) as u64) < active.len() {
                    active.get((2 * i) as u64)
                } else {
                    false
                };
                let has_right = if ((2 * i + 1) as u64) < active.len() {
                    active.get((2 * i + 1) as u64)
                } else {
                    false
                };
                match (has_left, has_right) {
                    // No polynomials to combine.
                    (false, false) => {}
                    // We need to multiply the roots of the right side,
                    // but then it can just expand to fill the entire polynomial.
                    (false, true) => {
                        let slice = &mut polynomials[start..start + new_polynomial_size];
                        // Scale the roots of the right side by w.
                        let lg_p_size = polynomial_size.ilog2();
                        let mut w_j = F::one();
                        for j in 0..polynomial_size {
                            let index =
                                polynomial_size + reverse_bits(lg_p_size, j as u64) as usize;
                            slice[index] = slice[index] * w_j;
                            w_j = w_j * w_inv;
                        }
                        // Expand the right side to occupy the entire space.
                        // The left side must be 0s.
                        for j in 0..polynomial_size {
                            slice.swap(polynomial_size + j, 2 * j);
                        }
                    }
                    // No need to multiply roots, but we do need to expand the left side.
                    (true, false) => {
                        let slice = &mut polynomials[start..start + new_polynomial_size];
                        // Expand the left side to occupy the entire space.
                        // The right side must be 0s.
                        for j in (0..polynomial_size).rev() {
                            slice.swap(j, 2 * j);
                        }
                    }
                    // We need to combine the two doing an actual multiplication.
                    (true, true) => {
                        debug_assert_eq!(scratch.len(), 0);
                        scratch.resize(new_polynomial_size, F::zero());
                        let slice = &mut polynomials[start..start + new_polynomial_size];

                        let lg_p_size = polynomial_size.ilog2();
                        let mut w_j = F::one();
                        for j in 0..polynomial_size {
                            let index =
                                polynomial_size + reverse_bits(lg_p_size, j as u64) as usize;
                            slice[index] = slice[index] * w_j;
                            w_j = w_j * w_inv;
                        }

                        // Expand the right side to occupy all of scratch.
                        // Clear the right side.
                        for j in 0..polynomial_size {
                            scratch[2 * j] = slice[polynomial_size + j];
                            slice[polynomial_size + j] = F::zero();
                        }

                        // Expand the left side to occupy the entire space.
                        // The right side has been cleared above.
                        for j in (0..polynomial_size).rev() {
                            slice.swap(j, 2 * j);
                        }

                        // Multiply the polynomials together, by first evaluating each of them,
                        // then multiplying their evaluations, producing (f * g) evaluated over
                        // the domain, which we can then interpolate back.
                        ntt::<true, _>(new_polynomial_size, 1, &mut Column { data: &mut scratch });
                        ntt::<true, _>(new_polynomial_size, 1, &mut Column { data: slice });
                        for (s_i, p_i) in scratch.drain(..).zip(slice.iter_mut()) {
                            *p_i = *p_i * s_i
                        }
                        ntt::<false, _>(new_polynomial_size, 1, &mut Column { data: slice })
                    }
                }
                // If there was a polynomial on the left or the right, then on the next iteration
                // the combined section will have data to process, so we need to set it to true
                // Resize active if needed and set the bit
                active.set(i as u64, has_left | has_right);
            }
            polynomial_size = new_polynomial_size;
        }
        // If the final polynomial is inactive, there are no points to vanish over,
        // so we want to return the polynomial f(X) = 1.
        if !active.get(0) {
            let mut coefficients = vec![F::zero(); padded_rows];
            coefficients[0] = F::one();
            return Self { coefficients };
        }
        // We have a polynomial that's twice the size we need, so we need to truncate it.
        // This is the opposite of the sub-routine we had for expanding the left side to fit
        // the entire polynomial.
        for i in 0..padded_rows {
            polynomials.swap(i, 2 * i);
        }
        polynomials.truncate(padded_rows);
        Self {
            coefficients: polynomials,
        }
    }

    #[cfg(test)]
    fn evaluate(&self, point: F) -> F {
        let mut out = F::zero();
        let rows = self.coefficients.len();
        let lg_rows = rows.ilog2();
        for i in (0..rows).rev() {
            out = out * point + self.coefficients[reverse_bits(lg_rows, i as u64) as usize];
        }
        out
    }

    #[cfg(test)]
    fn degree(&self) -> usize {
        let rows = self.coefficients.len();
        let lg_rows = rows.ilog2();
        for i in (0..rows).rev() {
            if self.coefficients[reverse_bits(lg_rows, i as u64) as usize] != F::zero() {
                return i;
            }
        }
        0
    }

    /// Divide the roots of each polynomial by some factor.
    ///
    /// If f(x) = 0, then after this transformation, f(x / z) = 0 instead.
    ///
    /// The number of roots does not change.
    ///
    /// c.f. [Polynomial::vanishing] for an explanation of how this works.
    fn divide_roots(&mut self, factor: F) {
        let mut factor_i = F::one();
        let lg_rows = self.coefficients.len().ilog2();
        for i in 0..self.coefficients.len() {
            let index = reverse_bits(lg_rows, i as u64) as usize;
            self.coefficients[index] = self.coefficients[index] * factor_i;
            factor_i = factor_i * factor;
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialVector {
    // Each column of this matrix contains the coefficients of a polynomial,
    // in reverse bit order. So, the ith coefficient appears at index i.reverse_bits().
    //
    // For example, a polynomial a0 + a1 X + a2 X^2 + a3 X^3 is stored as:
    //
    // a0 a2 a1 a3
    //
    // This is convenient because the even coefficients and the odd coefficients
    // split nicely into halves. The first half of the rows have the property
    // that the first bit of their coefficient index is 0, then in that subset
    // the first half has the second bit set to 0, and the second half set to 1,
    // and so on, recursively.
    data: Matrix,
}

impl PolynomialVector {
    /// Construct a new vector of polynomials, from dimensions, and coefficients.
    ///
    /// The coefficients should be supplied in order of increasing index,
    /// and then for each polynomial.
    ///
    /// In other words, if you have 3 polynomials:
    ///
    /// a0 + a1 X + ...
    /// b0 + b1 X + ...
    /// c0 + c1 X + ...
    ///
    /// The iterator should yield:
    ///
    /// a0 b0 c0
    /// a1 b1 c1
    /// ...
    ///
    /// Any coefficients not supplied are treated as being equal to 0.
    fn new(rows: usize, cols: usize, mut coefficients: impl Iterator<Item = F>) -> Self {
        assert!(rows > 0);
        let rows = rows.next_power_of_two();
        let lg_rows = rows.ilog2();
        let mut data = Matrix::zero(rows, cols);
        'outer: for i in 0..rows {
            let row_i = &mut data[reverse_bits(lg_rows, i as u64) as usize];
            for row_i_j in row_i {
                let Some(c) = coefficients.next() else {
                    break 'outer;
                };
                *row_i_j = c;
            }
        }
        Self { data }
    }

    /// Evaluate each polynomial in this vector over all points in an interpolation domain.
    pub fn evaluate(mut self) -> EvaluationVector {
        self.data.ntt::<true>();
        let active_rows = BitMap::ones(self.data.rows as u64);
        EvaluationVector {
            data: self.data,
            active_rows,
        }
    }

    /// Like [Self::evaluate], but with a simpler algorithm that's much less efficient.
    ///
    /// Exists as a useful tool for testing
    #[cfg(test)]
    fn evaluate_naive(self) -> EvaluationVector {
        let rows = self.data.rows;
        let lg_rows = rows.ilog2();
        let w = F::root_of_unity(lg_rows as u8).expect("too much data to calculate NTT");
        // entry (i, j) of this matrix will contain w^ij. Thus, multiplying it
        // with the coefficients of a polynomial, in column order, will evaluate it.
        // We also need to re-arrange the columns of the matrix to match the same
        // order we have for polynomial coefficients.
        let mut vandermonde_matrix = Matrix::zero(rows, rows);
        let mut w_i = F::one();
        for i in 0..rows {
            let row_i = &mut vandermonde_matrix[i];
            let mut w_ij = F::one();
            for j in 0..rows {
                // Remember, the coeffients of the polynomial are in reverse bit order!
                row_i[reverse_bits(lg_rows, j as u64) as usize] = w_ij;
                w_ij = w_ij * w_i;
            }
            w_i = w_i * w;
        }

        EvaluationVector {
            data: vandermonde_matrix.mul(&self.data),
            active_rows: BitMap::ones(rows as u64),
        }
    }

    /// Divide the roots of each polynomial by some factor.
    ///
    /// c.f. [Polynomial::divide_roots]. This performs the same operation on
    /// each polynomial in this vector.
    fn divide_roots(&mut self, factor: F) {
        let mut factor_i = F::one();
        let lg_rows = self.data.rows.ilog2();
        for i in 0..self.data.rows {
            for p_i in &mut self.data[reverse_bits(lg_rows, i as u64) as usize] {
                *p_i = *p_i * factor_i;
            }
            factor_i = factor_i * factor;
        }
    }

    /// For each polynomial P_i in this vector compute the evaluation of P_i / Q.
    ///
    /// Naturally, you can call [EvaluationVector::interpolate]. The reason we don't
    /// do this is that the algorithm naturally yields an [EvaluationVector], and
    /// some use-cases may want access to that data as well.
    ///
    /// This assumes that the number of coefficients in the polynomials of this vector
    /// matches that of `q` (the coefficients can be 0, but need to be padded to the right size).
    ///
    /// This assumes that `q` has no zeroes over [F::NOT_ROOT_OF_UNITY] * [F::ROOT_OF_UNITY]^i,
    /// for any i. This will be the case for [Polynomial::vanishing].
    /// If this isn't the case, the result may be junk.
    ///
    /// If `q` doesn't divide a partiular polynomial in this vector, the result
    /// for that polynomial is not guaranteed to be anything meaningful.
    fn divide(&mut self, mut q: Polynomial) {
        // The algorithm operates column wise.
        //
        // You can compute P(X) / Q(X) by evaluating each polynomial, then computing
        //
        //   P(w^i) / Q(w^i)
        //
        // for each evaluation point. Then, you can interpolate back.
        //
        // But wait! What if Q(w^i) = 0? In particular, for the case of recovering
        // a polynomial from data with missing rows, we *expect* P(w^i) = 0 = Q(w^i)
        // for the indicies we're missing, so this doesn't work.
        //
        // What we can do is to instead multiply each of the roots by some factor z,
        // such that z w^i != w^j, for any i, j. In other words, we change the roots
        // such that they're not in the evaluation domain anymore, allowing us to
        // divide. We can then interpolate the result back into a polynomial,
        // and divide back the roots to where they should be.
        //
        // c.f. [PolynomialVector::divide_roots]
        assert_eq!(
            self.data.rows,
            q.coefficients.len(),
            "cannot divide by polynomial of the wrong size"
        );
        let skew = F::NOT_ROOT_OF_UNITY;
        let skew_inv = F::NOT_ROOT_OF_UNITY_INV;
        self.divide_roots(skew);
        q.divide_roots(skew);
        ntt::<true, _>(self.data.rows, self.data.cols, &mut self.data);
        ntt::<true, _>(
            q.coefficients.len(),
            1,
            &mut Column {
                data: &mut q.coefficients,
            },
        );
        // Do a point wise division.
        for i in 0..self.data.rows {
            let q_i = q.coefficients[i];
            // If `q_i = 0`, then we will get 0 in the output.
            // We don't expect any of the q_i to be 0, but being 0 is only one
            // of the many possibilities for the coefficient to be incorrect,
            // so doing a runtime assertion here doesn't make sense.
            let q_i_inv = q_i.inv();
            for d_i_j in &mut self.data[i] {
                *d_i_j = *d_i_j * q_i_inv;
            }
        }
        // Interpolate back, using the inverse skew
        ntt::<false, _>(self.data.rows, self.data.cols, &mut self.data);
        self.divide_roots(skew_inv);
    }

    /// Iterate over up to n rows of this vector.
    ///
    /// For example, given polynomials:
    ///
    ///   a0 + a1 X + a2 X^2 + ...
    ///   b0 + b1 X + b2 X^2 + ...
    ///
    /// This will return:
    ///
    ///   a0 b0
    ///   a1 b1
    ///   ...
    ///
    /// up to n times.
    pub fn coefficients_up_to(&self, n: usize) -> impl Iterator<Item = &[F]> {
        let n = n.min(self.data.rows);
        let lg_rows = self.data.rows().ilog2();
        (0..n).map(move |i| &self.data[reverse_bits(lg_rows, i as u64) as usize])
    }
}

/// The result of evaluating a vector of polynomials over all points in an interpolation domain.
///
/// This struct also remembers which rows have ever been filled with [Self::fill_row].
/// This is used in [Self::recover], which can use the rows that are present to fill in the missing
/// rows.
#[derive(Debug, PartialEq)]
pub struct EvaluationVector {
    data: Matrix,
    active_rows: BitMap,
}

impl EvaluationVector {
    /// Figure out the polynomial which evaluates to this vector.
    ///
    /// i.e. the inverse of [PolynomialVector::evaluate].
    ///
    /// (This makes all the rows count as filled).
    fn interpolate(mut self) -> PolynomialVector {
        self.data.ntt::<false>();
        PolynomialVector { data: self.data }
    }

    /// Create an empty element of this struct, with no filled rows.
    pub fn empty(lg_rows: usize, cols: usize) -> Self {
        let data = Matrix::zero(1 << lg_rows, cols);
        let active = BitMap::zeroes(data.rows as u64);
        Self {
            data,
            active_rows: active,
        }
    }

    /// Fill a specific row.
    pub fn fill_row(&mut self, row: usize, data: &[F]) {
        assert!(data.len() <= self.data.cols);
        self.data[row][..data.len()].copy_from_slice(data);
        self.active_rows.set(row as u64, true);
    }

    /// Erase a particular row.
    ///
    /// Useful for testing the recovery procedure.
    #[cfg(test)]
    fn remove_row(&mut self, row: usize) {
        self.data[row].fill(F::zero());
        self.active_rows.set(row as u64, false);
    }

    fn multiply(&mut self, polynomial: Polynomial) {
        let Polynomial { mut coefficients } = polynomial;
        ntt::<true, _>(
            coefficients.len(),
            1,
            &mut Column {
                data: &mut coefficients,
            },
        );
        for (i, &c_i) in coefficients.iter().enumerate() {
            for self_j in &mut self.data[i] {
                *self_j = *self_j * c_i;
            }
        }
    }

    /// Attempt to recover the missing rows in this data.
    pub fn recover(mut self) -> PolynomialVector {
        // If we had all of the rows, we could simply call [Self::interpolate],
        // in order to recover the original polynomial. If we do this while missing some
        // rows, what we get is D(X) * V(X) where D is the original polynomial,
        // and V(X) is a polynomial which vanishes at all the rows we're missing.
        //
        // As long as the degree of D is low enough, compared to the number of evaluations
        // we *do* have, then we can recover it by performing:
        //
        //   (D(X) * V(X)) / V(X)
        //
        // If we have multiple columns, then this procedure can be done column by column,
        // with the same vanishing polynomial.
        let vanishing = Polynomial::vanishing(&self.active_rows);
        self.multiply(vanishing.clone());
        let mut out = self.interpolate();
        out.divide(vanishing);
        out
    }

    /// Get the underlying data, as a Matrix.
    pub fn data(self) -> Matrix {
        self.data
    }

    /// Return how many distinct rows have been filled.
    pub fn filled_rows(&self) -> usize {
        self.active_rows.count_ones() as usize
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    fn any_f() -> impl Strategy<Value = F> {
        any::<u64>().prop_map(F::from)
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(4, 0b1000), 0b0001);
        assert_eq!(reverse_bits(4, 0b0100), 0b0010);
        assert_eq!(reverse_bits(4, 0b0010), 0b0100);
        assert_eq!(reverse_bits(4, 0b0001), 0b1000);
    }

    #[test]
    fn matrix_read_rejects_length_mismatch() {
        use bytes::BytesMut;
        use commonware_codec::{Read as _, Write as _};

        let mut buf = BytesMut::new();
        (2usize).write(&mut buf);
        (2usize).write(&mut buf);
        vec![F::one(); 3].write(&mut buf);

        let mut bytes = buf.freeze();
        let result = Matrix::read_cfg(&mut bytes, &8);
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid(
                "Matrix",
                "matrix element count does not match dimensions"
            ))
        ));
    }

    fn any_polynomial_vector(
        max_log_rows: usize,
        max_cols: usize,
    ) -> impl Strategy<Value = PolynomialVector> {
        (0..=max_log_rows).prop_flat_map(move |lg_rows| {
            (1..=max_cols).prop_flat_map(move |cols| {
                let rows = 1 << lg_rows;
                proptest::collection::vec(any_f(), rows * cols).prop_map(move |coefficients| {
                    PolynomialVector::new(rows, cols, coefficients.into_iter())
                })
            })
        })
    }

    fn any_bit_vec_not_all_0(max_log_rows: usize) -> impl Strategy<Value = BitMap> {
        (0..=max_log_rows).prop_flat_map(move |lg_rows| {
            let rows = (1 << lg_rows) as usize;
            (0..rows).prop_flat_map(move |set_row| {
                proptest::collection::vec(any::<bool>(), 1 << lg_rows).prop_map(move |mut bools| {
                    bools[set_row] = true;
                    BitMap::from(bools.as_slice())
                })
            })
        })
    }

    #[derive(Debug)]
    struct RecoverySetup {
        n: usize,
        k: usize,
        cols: usize,
        data: Vec<F>,
        present: BitMap,
    }

    impl RecoverySetup {
        fn any(max_n: usize, max_k: usize, max_cols: usize) -> impl Strategy<Value = Self> {
            (1..=max_n).prop_flat_map(move |n| {
                (0..=max_k).prop_flat_map(move |k| {
                    (1..=max_cols).prop_flat_map(move |cols| {
                        proptest::collection::vec(any_f(), n * cols).prop_flat_map(move |data| {
                            let padded_rows = (n + k).next_power_of_two();
                            proptest::sample::subsequence(
                                (0..padded_rows).collect::<Vec<_>>(),
                                n..=padded_rows,
                            )
                            .prop_map(move |indices| {
                                let mut present = BitMap::zeroes(padded_rows as u64);
                                for i in indices {
                                    present.set(i as u64, true);
                                }
                                Self {
                                    n,
                                    k,
                                    cols,
                                    // idk why this is necessary, but who cares
                                    data: data.clone(),
                                    present,
                                }
                            })
                        })
                    })
                })
            })
        }

        fn test(self) {
            let data = PolynomialVector::new(self.n + self.k, self.cols, self.data.into_iter());
            let mut encoded = data.clone().evaluate();
            for (i, b_i) in self.present.iter().enumerate() {
                if !b_i {
                    encoded.remove_row(i);
                }
            }
            let recovered_data = encoded.recover();
            assert_eq!(data, recovered_data);
        }
    }

    #[test]
    fn test_recovery_000() {
        RecoverySetup {
            n: 1,
            k: 1,
            cols: 1,
            data: vec![F::one()],
            present: vec![false, true].into(),
        }
        .test()
    }

    proptest! {
        #[test]
        fn test_ntt_eq_naive(p in any_polynomial_vector(6, 4)) {
            let ntt = p.clone().evaluate();
            let ntt_naive = p.evaluate_naive();
            assert_eq!(ntt, ntt_naive);
        }

        #[test]
        fn test_evaluation_then_inverse(p in any_polynomial_vector(6, 4)) {
            assert_eq!(p.clone(), p.evaluate().interpolate());
        }

        #[test]
        fn test_vanishing_polynomial(bv in any_bit_vec_not_all_0(8)) {
            let v = Polynomial::vanishing(&bv);
            let expected_degree = bv.count_zeros();
            assert_eq!(v.degree(), expected_degree as usize, "expected v to have degree {expected_degree}");
            let w = F::root_of_unity(bv.len().ilog2() as u8).unwrap();
            let mut w_i = F::one();
            for b_i in bv.iter() {
                let v_at_w_i = v.evaluate(w_i);
                if !b_i {
                    assert_eq!(v_at_w_i, F::zero(), "v should evaluate to 0 at {w_i:?}");
                } else {
                    assert_ne!(v_at_w_i, F::zero());
                }
                w_i = w_i * w;
            }
        }

        #[test]
        fn test_recovery(setup in RecoverySetup::any(128, 128, 4)) {
            setup.test();
        }
    }
}
