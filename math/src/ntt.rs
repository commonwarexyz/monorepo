use crate::algebra::{Additive, FieldNTT, Ring};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_utils::bitmap::BitMap;
use core::{
    num::NonZeroU32,
    ops::{Index, IndexMut},
};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Determines the size of polynomials we compute naively in [`EvaluationColumn::vanishing`].
///
/// Benchmarked to be optimal, based on BLS12381 threshold recovery time.
const LG_VANISHING_BASE: u32 = 8;

/// Reverse the first `bit_width` bits of `i`.
///
/// Any bits beyond that width will be erased.
fn reverse_bits(bit_width: u32, i: u64) -> u64 {
    assert!(bit_width <= 64, "bit_width must be <= 64");
    i.wrapping_shl(64 - bit_width).reverse_bits()
}

/// Turn a slice into reversed bit order in place.
///
/// `out` MUST have length `2^bit_width`.
fn reverse_slice<T>(bit_width: u32, out: &mut [T]) {
    assert_eq!(out.len(), 1 << bit_width);
    for i in 0..out.len() {
        let j = reverse_bits(bit_width, i as u64) as usize;
        // Only swap once, and don't swap if the location is the same.
        if i < j {
            out.swap(i, j);
        }
    }
}

/// Calculate an NTT, or an inverse NTT (with FORWARD=false), in place.
///
/// We implement this generically over anything we can index into, which allows
/// performing NTTs in place.
fn ntt<const FORWARD: bool, F: FieldNTT, M: IndexMut<(usize, usize), Output = F>>(
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
            w.exp(&[(1 << lg_rows) - 1])
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
            out[i] = (i, w_i.clone());
            w_i = w_i.clone() * &w_i;
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
                    let (a, b) = (matrix[(index_a, k)].clone(), matrix[(index_b, k)].clone());
                    if FORWARD {
                        let w_j_b = w_j.clone() * &b;
                        matrix[(index_a, k)] = a.clone() + &w_j_b;
                        matrix[(index_b, k)] = a - &w_j_b;
                    } else {
                        // To check the math, convince yourself that applying the forward
                        // transformation, and then this transformation, with w_j being the
                        // inverse of the value above, that you get (a, b).
                        // (a + w_j * b) + (a - w_j * b) = 2 * a
                        matrix[(index_a, k)] = (a.clone() + &b).div_2();
                        // (a + w_j * b) - (a - w_j * b) = 2 * w_j * b.
                        // w_j in this branch is the inverse of w_j in the other branch.
                        matrix[(index_b, k)] = ((a - &b) * &w_j).div_2();
                    }
                }
                w_j *= &w;
            }
            i += 2 * skip;
        }
    }
}

/// Columns of some larger piece of data.
///
/// This allows us to easily do NTTs over partial segments of some bigger matrix.
struct Columns<'a, const N: usize, F> {
    data: [&'a mut [F]; N],
}

impl<'a, const N: usize, F> Index<(usize, usize)> for Columns<'a, N, F> {
    type Output = F;

    fn index(&self, (i, j): (usize, usize)) -> &Self::Output {
        &self.data[j][i]
    }
}

impl<'a, const N: usize, F> IndexMut<(usize, usize)> for Columns<'a, N, F> {
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut Self::Output {
        &mut self.data[j][i]
    }
}

/// Used to keep track of the points at which a polynomial needs to vanish.
///
/// This takes care of subtle details like padding and bit ordering.
///
/// This struct is associated with a particular size, which is a power of two,
/// and thus a particular root of unity.
#[derive(Debug, PartialEq)]
pub struct VanishingPoints {
    lg_size: u32,
    bits: BitMap,
}

impl VanishingPoints {
    /// This will have size `2^lg_size`, and vanish everywhere.
    ///
    /// Be aware that this means all points are initially marked as vanishing.
    pub fn new(lg_size: u32) -> Self {
        Self {
            lg_size,
            bits: BitMap::zeroes(1 << lg_size),
        }
    }

    /// This will have size `2^lg_size`, and vanish nowhere.
    pub fn all_non_vanishing(lg_size: u32) -> Self {
        Self {
            lg_size,
            bits: BitMap::ones(1 << lg_size),
        }
    }

    pub const fn lg_size(&self) -> u32 {
        self.lg_size
    }

    /// Set the root `w^index` to vanish, `value = false`, or not, `value = true`.
    fn set(&mut self, index: u64, value: bool) {
        self.bits.set(reverse_bits(self.lg_size, index), value);
    }

    /// Set the root `w^index` to not vanish.
    ///
    /// cf. `set`;
    pub fn set_non_vanishing(&mut self, index: u64) {
        self.set(index, true);
    }

    pub fn get(&self, index: u64) -> bool {
        self.bits.get(reverse_bits(self.lg_size, index))
    }

    pub fn count_non_vanishing(&self) -> u64 {
        self.bits.count_ones()
    }

    /// Check that a particular chunk of this set vanishes.
    ///
    /// `lg_chunk_size` determines the size of the chunk, which must be a power of two.
    ///
    /// `index` determines which chunk to use. After chunk 0, you have chunk 1, and so on.
    ///
    /// The chunk is taken from the set in reverse bit order. This is what methods
    /// that create a vanishing polynomial recursively want. Take care when using
    /// this naively.
    fn chunk_vanishes_everywhere(&self, lg_chunk_size: u32, index: u64) -> bool {
        assert!(lg_chunk_size <= self.lg_size);
        let start = index << lg_chunk_size;
        self.bits.is_unset(start..start + (1 << lg_chunk_size))
    }

    /// Yield the bits of a chunk, in reverse bit order.
    ///
    /// cf. `chunk_vanishes_everywhere`, which uses the same chunk indexing scheme.
    fn get_chunk(&self, lg_chunk_size: u32, index: u64) -> impl Iterator<Item = bool> + '_ {
        (index << lg_chunk_size..(index + 1) << lg_chunk_size).map(|i| self.bits.get(i))
    }

    #[cfg(any(test, feature = "fuzz"))]
    fn iter_bits_in_order(&self) -> impl Iterator<Item = bool> + '_ {
        (0..(1u64 << self.lg_size)).map(|i| self.get(i))
    }
}

/// Represents the evaluation of a single polynomial over a full domain.
#[derive(Debug)]
struct EvaluationColumn<F> {
    evaluations: Vec<F>,
}

impl<F: FieldNTT> EvaluationColumn<F> {
    /// Evaluate the vanishing polynomial over `points` on the domain.
    ///
    /// This returns the evaluation of the polynomial at `0`, and then the evaluation
    /// of the polynomial over the whole domain.
    ///
    /// This assumes that `points` has at least one non-vanishing point.
    pub fn vanishing(points: &VanishingPoints) -> (F, Self) {
        // The goal of this function is to produce a polynomial v such that
        // v(w^j) = 0 for each index j where points.get(j) = false.
        //
        // The core idea is to split this up recursively. We split the possible
        // roots into two groups, and figure out the vanishing polynomials
        // v_L and v_R for the first and second groups, respectively. Then,
        // multiplying v_L and v_R yields a polynomial with the appropriate roots.
        //
        // We can multiply the polynomials in O(N lg N) time, by performing an
        // NTT on both of them, multiplying the evaluations point wise, and then
        // using a reverse NTT to get a polynomial back.
        //
        // Naturally, we can extend this to construct each sub-polynomial recursively
        // as well, giving an O(N lg^2 N) algorithm in total.
        //
        // This function doesn't return the polynomial directly, but rather an
        // evaluation of the polynomial. This is because many consumers often
        // need this anyways, and by providing them with this result, we avoid
        // performing a reverse NTT that they then proceed to undo. However,
        // they can also need the evaluation at 0, so we provide and calculate that
        // as well. That can also be calculated recursively, and merged with the
        // above calculation.
        //
        // One point we haven't clarified yet is how to split up the roots.
        // Let's use an example. With size 8, the roots are:
        //
        // w^0 w^1 w^2 w^3 w^4 w^5 w^6 w^7
        //
        // or, writing down just the exponent
        //
        // 0 1 2 3 4 5 6 7
        //
        // We could build up our final polynomial by merging polynomials of size
        // two, with roots chosen among the following possibilities:
        //
        // 0 1    2 3    4 5    6 7
        //
        // However, this requires using different roots for each polynomial.
        //
        // If we instead use reverse bit order, we can have things be:
        //
        // 0 4    2 6    1 5    3 7
        //
        // which is equal to:
        //
        // 0 4    2 + (0 4)    1 + (0 4    2 + (0 4))
        //
        // So, we can start by having polynomials with the same possible roots
        // at the lowest level, and then merge by multiplying the roots by
        // the right power, for the polynomial on the right.
        //
        // The roots of a polynomial can easily be multiplied by some factor
        // by dividing its coefficients by powers of a factor.
        // cf [`PolynomialColumn::divide_roots`].
        //
        // Another optimization we can do for the merges is to keep track
        // of polynomials that vanish everywhere and nowhere. A polynomial
        // vanishing nowhere has no effect when merging, so we can skip a multiplication.
        // Similarly, a polynomial vanishing everywhere is of the form X^N - 1,
        // with which multiplication is simple.

        /// Used to keep track of special polynomial values.
        #[derive(Clone, Copy)]
        enum Where {
            /// Vanishes at none of the roots; i.e. is f(X) = 1.
            Nowhere,
            /// Vanishes at at least one of the roots.
            Somewhere,
            /// Vanishes at every single one of the roots.
            Everywhere,
        }

        use Where::*;

        let lg_len = points.lg_size();
        let len = 1usize << lg_len;
        // This will store our in progress polynomials, and eventually,
        // the final evaluations.
        let mut out = vec![F::zero(); len];
        // For small inputs, one chunk might more than cover it all, so we
        // need to make the chunk size be too big.
        let lg_chunk_size = LG_VANISHING_BASE.min(lg_len);
        // We use this to keep track of the polynomial evaluated at 0.
        let mut at_zero = F::one();

        // Populate out with polynomials up to a low degree.
        // We also get a vector with the status of each polymomial, letting
        // us accelerate the merging step.
        let mut vanishes = {
            let chunk_size = 1usize << lg_chunk_size;
            // The negation of each possible root vanishing polynomials can have.
            // We have the roots in reverse bit order.
            let minus_roots = {
                // We can panic without worry here, because we require a smaller
                // root of unity to exist elsewhere.
                let w = u8::try_from(lg_chunk_size)
                    .ok()
                    .and_then(|s| F::root_of_unity(s))
                    .expect("sub-root of unity should exist");
                // The powers of w we'll use as roots, pre-negated.
                let mut out: Vec<_> = (0..)
                    .scan(F::one(), |state, _| {
                        let out = -state.clone();
                        *state *= &w;
                        Some(out)
                    })
                    .take(chunk_size)
                    .collect();
                // Make sure the order is what the rest of this routine expects.
                reverse_slice(lg_chunk_size, out.as_mut_slice());
                out
            };
            // Instead of actually negating `at_zero` inside of the loop below,
            // we instead keep track of whether or not it needs to be negated
            // after the loop, to just perform that operation once.
            let mut negate_at_zero = false;
            // Populate each chunk with the initial polynomial,
            let vanishing = out
                .chunks_exact_mut(chunk_size)
                .enumerate()
                .map(|(i, poly)| {
                    let i_u64 = i as u64;
                    if points.chunk_vanishes_everywhere(lg_chunk_size, i_u64) {
                        // Implicitly, there's a 1 past the end of the polynomial,
                        // which we handle when merging.
                        poly[0] = -F::one();
                        negate_at_zero ^= true;
                        return Where::Everywhere;
                    }
                    poly[0] = F::one();
                    let mut coeffs = 1;
                    for (b_j, minus_root) in points
                        .get_chunk(lg_chunk_size, i_u64)
                        .zip(minus_roots.iter())
                    {
                        if b_j {
                            continue;
                        }
                        // Multiply the polynomial by (X - w^j).
                        poly[coeffs] = F::one();
                        for k in (1..coeffs).rev() {
                            let (chunk_head, chunk_tail) = poly.split_at_mut(k);
                            chunk_tail[0] *= minus_root;
                            chunk_tail[0] += &chunk_head[k - 1];
                        }
                        poly[0] *= minus_root;
                        coeffs += 1;
                    }
                    if coeffs > 1 {
                        reverse_slice(lg_chunk_size, poly);
                        at_zero *= &poly[0];
                        Where::Somewhere
                    } else {
                        Where::Nowhere
                    }
                })
                .collect::<Vec<_>>();
            if negate_at_zero {
                at_zero = -at_zero.clone();
            }
            vanishing
        };
        // Avoid doing any of the subsequent work if we've already covered this case.
        if lg_chunk_size >= lg_len {
            // We do, however, need to turn the coefficients into evaluations.
            return (at_zero, PolynomialColumn { coefficients: out }.evaluate());
        }
        let w_invs = {
            // since w^(2^lg_rows) = 1, w^(2^lg_rows - 1) * w = 1,
            // making that left-hand term the inverse of w.
            let mut w_inv = F::root_of_unity(lg_len as u8)
                .expect("too many rows to create vanishing polynomial")
                .exp(&[(1 << lg_len) - 1]);
            let mut out = Vec::with_capacity((lg_len - lg_chunk_size) as usize);
            for _ in lg_chunk_size..lg_len {
                out.push(w_inv.clone());
                w_inv = w_inv.clone() * &w_inv;
            }
            out.reverse();
            out
        };
        let mut lg_chunk_size = lg_chunk_size;
        let mut scratch = Vec::<F>::with_capacity(len);
        let mut coeff_shifts = Vec::with_capacity(1 << lg_chunk_size);
        for w_inv in w_invs.into_iter() {
            let chunk_size = 1 << lg_chunk_size;
            // Closure to shift coefficients by the current power.
            // This lets us reuse the computation of the powers.
            let mut shift_coeffs = |coeffs: &mut [F]| {
                if coeff_shifts.len() != chunk_size {
                    coeff_shifts.clear();
                    let mut acc = F::one();
                    for _ in 0..chunk_size {
                        coeff_shifts.push(acc.clone());
                        acc *= &w_inv;
                    }
                }
                for (i, coeff_i) in coeffs.iter_mut().enumerate() {
                    *coeff_i *= &coeff_shifts[reverse_bits(lg_chunk_size, i as u64) as usize];
                }
            };
            let next_lg_chunk_size = lg_chunk_size + 1;
            let next_chunk_size = 1 << next_lg_chunk_size;
            for (i, chunk) in out.chunks_exact_mut(1 << next_lg_chunk_size).enumerate() {
                let (left, right) = chunk.split_at_mut(1 << lg_chunk_size);
                let (vanishes_l, vanishes_r) = (vanishes[2 * i], vanishes[2 * i + 1]);
                // We keep track of whether or not the polynomial resulting from
                // the merge is evaluated or not.
                let mut evaluated = false;
                vanishes[i] = match (vanishes_l, vanishes_r) {
                    (Nowhere, Nowhere) => {
                        // Both polynomials consist of 1 0 0 0 ..., and we
                        // want the final result to be that, just with more zeroes,
                        // so we need to clear the 1 value on the right side.
                        right[0] = F::zero();
                        Nowhere
                    }
                    (Nowhere, Somewhere) => {
                        // Clear the one value on the left.
                        left[0] = F::zero();
                        // Adjust the roots on the right.
                        shift_coeffs(right);
                        // Make it take all of the left space.
                        for i in 0..chunk_size {
                            chunk.swap(chunk_size + i, 2 * i);
                        }
                        Somewhere
                    }
                    (Nowhere, Everywhere) => {
                        // (X^(N/2) - 1) is on the right.
                        // First, we multiply its roots by w_N, yielding:
                        //
                        // -X^(N/2) - 1
                        //
                        // in reverse bit order we get the following:
                        left[0] = -F::one();
                        left[1] = -F::one();
                        // And we remove the -1 on the right side.
                        right[0] = F::zero();
                        Somewhere
                    }
                    // These two cases mirror the two above.
                    (Somewhere, Nowhere) => {
                        // Clear the one on the right side.
                        right[0] = F::zero();
                        // Make it take all of the right space.
                        // We can skip moving index 0.
                        for i in (1..chunk_size).rev() {
                            chunk.swap(i, 2 * i);
                        }
                        Somewhere
                    }
                    (Everywhere, Nowhere) => {
                        // Like above, but with the polynomial on the left,
                        // there's no need to adjust the roots.
                        left[0] = -F::one();
                        left[1] = F::one();
                        right[0] = F::zero();
                        Somewhere
                    }
                    (Somewhere, Everywhere) => {
                        // We need to make the left side occupy the whole space.
                        // Shifting by one index has the effect of multiplying
                        // the polynomial by X^(chunk_size), which is what we want.
                        for i in (0..chunk_size).rev() {
                            chunk.swap(i, 2 * i + 1);
                            // We copy the value in i, negate it, and make it occupy
                            // both 2 * i + 1 and 2 * i, thus multiplying by -(X^chunk_size + 1).
                            chunk[2 * i + 1] = -chunk[2 * i + 1].clone();
                            chunk[2 * i] = chunk[2 * i + 1].clone();
                        }
                        Somewhere
                    }
                    (Everywhere, Somewhere) => {
                        // Adjust the roots on the right.
                        shift_coeffs(right);
                        // Like above, but moving the right side, and multiplying by
                        // (X^chunk_size - 1).
                        for i in 0..chunk_size {
                            chunk.swap(chunk_size + i, 2 * i + 1);
                            chunk[2 * i] = -chunk[2 * i + 1].clone();
                        }
                        Somewhere
                    }
                    (Everywhere, Everywhere) => {
                        // Make sure to clear the -1 on the right side.
                        right[0] = F::zero();
                        // By choosing to do things this way, we effectively
                        // negate the final polynomial, so we need to correct
                        // for this with the zero value.
                        at_zero = -at_zero.clone();
                        Everywhere
                    }
                    // In this case, we can assume nothing, and have to do
                    // the full logic for actually multiplying the polynomials.
                    (Somewhere, Somewhere) => {
                        // Adjust the roots on the right.
                        shift_coeffs(right);
                        // Populate the scratch buffer with the right side.
                        scratch.clear();
                        scratch.resize(next_chunk_size, F::zero());
                        for i in 0..chunk_size {
                            core::mem::swap(&mut right[i], &mut scratch[2 * i]);
                        }
                        // We can skip moving index 0.
                        for i in (1..chunk_size).rev() {
                            chunk.swap(i, 2 * i);
                        }
                        // Turn the polynomials into evaluations.
                        ntt::<true, _, _>(
                            next_chunk_size,
                            2,
                            &mut Columns {
                                data: [chunk, scratch.as_mut_slice()],
                            },
                        );
                        // Multiply them, into the chunk.
                        for (l, r) in chunk.iter_mut().zip(scratch.iter_mut()) {
                            *l *= r;
                        }
                        evaluated = true;
                        Somewhere
                    }
                };
                // If this isn't the last iteration, make sure to turn back into coefficients.
                let should_be_evaluated = next_chunk_size >= len;
                if should_be_evaluated != evaluated {
                    if evaluated {
                        ntt::<false, _, _>(next_chunk_size, 1, &mut Columns { data: [chunk] });
                    } else {
                        ntt::<true, _, _>(next_chunk_size, 1, &mut Columns { data: [chunk] });
                    }
                }
            }
            lg_chunk_size = next_lg_chunk_size;
        }
        // We do, however, need to turn the coefficients into evaluations.
        (at_zero, Self { evaluations: out })
    }

    pub fn interpolate(self) -> PolynomialColumn<F> {
        let mut data = self.evaluations;
        ntt::<false, _, _>(
            data.len(),
            1,
            &mut Columns {
                data: [data.as_mut_slice()],
            },
        );
        PolynomialColumn { coefficients: data }
    }
}

/// A column containing a single polynomial.
#[derive(Debug)]
struct PolynomialColumn<F> {
    coefficients: Vec<F>,
}

impl<F: FieldNTT> PolynomialColumn<F> {
    /// Evaluate this polynomial over the domain, returning
    pub fn evaluate(self) -> EvaluationColumn<F> {
        let mut data = self.coefficients;
        ntt::<true, _, _>(
            data.len(),
            1,
            &mut Columns {
                data: [data.as_mut_slice()],
            },
        );
        EvaluationColumn { evaluations: data }
    }

    #[cfg(any(test, feature = "fuzz"))]
    fn evaluate_one(&self, point: F) -> F {
        let mut out = F::zero();
        let rows = self.coefficients.len();
        let lg_rows = rows.ilog2();
        for i in (0..rows).rev() {
            out = out * &point + &self.coefficients[reverse_bits(lg_rows, i as u64) as usize];
        }
        out
    }

    #[cfg(any(test, feature = "fuzz"))]
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
    /// c.f. [`EvaluationColumn::vanishing`] for how this is used.
    fn divide_roots(&mut self, factor: F) {
        let mut factor_i = F::one();
        let lg_rows = self.coefficients.len().ilog2();
        for i in 0..self.coefficients.len() {
            let index = reverse_bits(lg_rows, i as u64) as usize;
            self.coefficients[index] *= &factor_i;
            factor_i *= &factor;
        }
    }
}

/// Represents a matrix of field elements, of arbitrary dimensions
///
/// This is in row major order, so consider processing elements in the same
/// row first, for locality.
#[derive(Clone, PartialEq)]
pub struct Matrix<F> {
    rows: usize,
    cols: usize,
    data: Vec<F>,
}

impl<F: EncodeSize> EncodeSize for Matrix<F> {
    fn encode_size(&self) -> usize {
        self.rows.encode_size() + self.cols.encode_size() + self.data.encode_size()
    }
}

impl<F: Write> Write for Matrix<F> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.rows.write(buf);
        self.cols.write(buf);
        self.data.write(buf);
    }
}

impl<F: Read> Read for Matrix<F> {
    type Cfg = (usize, <F as Read>::Cfg);

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        (max_els, f_cfg): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let cfg = RangeCfg::from(..=*max_els);
        let rows = usize::read_cfg(buf, &cfg)?;
        let cols = usize::read_cfg(buf, &cfg)?;
        let data = Vec::<F>::read_cfg(buf, &(cfg, f_cfg.clone()))?;
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

impl<F: core::fmt::Debug> core::fmt::Debug for Matrix<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for i in 0..self.rows {
            let row_i = &self[i];
            for row_i_j in row_i {
                write!(f, "{row_i_j:?} ")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl<F: Additive> Matrix<F> {
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
    pub fn as_polynomials(&self, min_coefficients: usize) -> Option<PolynomialVector<F>>
    where
        F: Clone,
    {
        if min_coefficients < self.rows {
            return None;
        }
        Some(PolynomialVector::new(
            min_coefficients,
            self.cols,
            (0..self.rows).flat_map(|i| self[i].iter().cloned()),
        ))
    }

    /// Multiply this matrix by another.
    ///
    /// This assumes that the number of columns in this matrix match the number
    /// of rows in the other matrix.
    pub fn mul(&self, other: &Self) -> Self
    where
        F: Clone + Ring,
    {
        assert_eq!(self.cols, other.rows);
        let mut out = Self::zero(self.rows, other.cols);
        for i in 0..self.rows {
            for j in 0..self.cols {
                let c = self[(i, j)].clone();
                let other_j = &other[j];
                for k in 0..other.cols {
                    out[(i, k)] += &(c.clone() * &other_j[k])
                }
            }
        }
        out
    }
}

impl<F: FieldNTT> Matrix<F> {
    fn ntt<const FORWARD: bool>(&mut self) {
        ntt::<FORWARD, F, Self>(self.rows, self.cols, self)
    }
}

impl<F> Matrix<F> {
    pub const fn rows(&self) -> usize {
        self.rows
    }

    pub const fn cols(&self) -> usize {
        self.cols
    }

    /// Iterate over the rows of this matrix.
    pub fn iter(&self) -> impl Iterator<Item = &[F]> {
        (0..self.rows).map(|i| &self[i])
    }
}

impl<F: crate::algebra::Random> Matrix<F> {
    /// Create a random matrix with certain dimensions.
    pub fn rand(mut rng: impl CryptoRngCore, rows: usize, cols: usize) -> Self
    where
        F: Additive,
    {
        Self::init(rows, cols, (0..rows * cols).map(|_| F::random(&mut rng)))
    }
}

impl<F> Index<usize> for Matrix<F> {
    type Output = [F];

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[self.cols * index..self.cols * (index + 1)]
    }
}

impl<F> IndexMut<usize> for Matrix<F> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[self.cols * index..self.cols * (index + 1)]
    }
}

impl<F> Index<(usize, usize)> for Matrix<F> {
    type Output = F;

    fn index(&self, (i, j): (usize, usize)) -> &Self::Output {
        &self.data[self.cols * i + j]
    }
}

impl<F> IndexMut<(usize, usize)> for Matrix<F> {
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut Self::Output {
        &mut self.data[self.cols * i + j]
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, F: arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a> for Matrix<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let rows = u.int_in_range(1..=16)?;
        let cols = u.int_in_range(1..=16)?;
        let data = (0..rows * cols)
            .map(|_| F::arbitrary(u))
            .collect::<arbitrary::Result<Vec<F>>>()?;
        Ok(Self { rows, cols, data })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialVector<F> {
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
    data: Matrix<F>,
}

impl<F: Additive> PolynomialVector<F> {
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
}

impl<F: FieldNTT> PolynomialVector<F> {
    /// Evaluate each polynomial in this vector over all points in an interpolation domain.
    pub fn evaluate(mut self) -> EvaluationVector<F> {
        self.data.ntt::<true>();
        let active_rows = VanishingPoints::all_non_vanishing(self.data.rows().ilog2());
        EvaluationVector {
            data: self.data,
            active_rows,
        }
    }

    /// Like [Self::evaluate], but with a simpler algorithm that's much less efficient.
    ///
    /// Exists as a useful tool for testing
    #[cfg(any(test, feature = "fuzz"))]
    fn evaluate_naive(self) -> EvaluationVector<F> {
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
                row_i[reverse_bits(lg_rows, j as u64) as usize] = w_ij.clone();
                w_ij *= &w_i;
            }
            w_i *= &w;
        }

        EvaluationVector {
            data: vandermonde_matrix.mul(&self.data),
            active_rows: VanishingPoints::all_non_vanishing(lg_rows),
        }
    }

    /// Divide the roots of each polynomial by some factor.
    ///
    /// c.f. [`PolynomialColumn::divide_roots`]. This performs the same operation on
    /// each polynomial in this vector.
    fn divide_roots(&mut self, factor: F) {
        let mut factor_i = F::one();
        let lg_rows = self.data.rows.ilog2();
        for i in 0..self.data.rows {
            for p_i in &mut self.data[reverse_bits(lg_rows, i as u64) as usize] {
                *p_i *= &factor_i;
            }
            factor_i *= &factor;
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
    /// This assumes that `q` has no zeroes over `coset_shift() * root_of_unity()^i`,
    /// for any i. This will be the case for a vanishing polynomial produced by
    /// [EvaluationColumn::vanishing] and then interpolated.
    /// If this isn't the case, the result may be junk.
    ///
    /// If `q` doesn't divide a partiular polynomial in this vector, the result
    /// for that polynomial is not guaranteed to be anything meaningful.
    fn divide(&mut self, mut q: PolynomialColumn<F>) {
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
        let skew = F::coset_shift();
        let skew_inv = F::coset_shift_inv();
        self.divide_roots(skew.clone());
        q.divide_roots(skew);
        ntt::<true, F, _>(self.data.rows, self.data.cols, &mut self.data);
        ntt::<true, F, _>(
            q.coefficients.len(),
            1,
            &mut Columns {
                data: [&mut q.coefficients],
            },
        );
        // Do a point wise division.
        for i in 0..self.data.rows {
            let q_i = q.coefficients[i].clone();
            // If `q_i = 0`, then we will get 0 in the output.
            // We don't expect any of the q_i to be 0, but being 0 is only one
            // of the many possibilities for the coefficient to be incorrect,
            // so doing a runtime assertion here doesn't make sense.
            let q_i_inv = q_i.inv();
            for d_i_j in &mut self.data[i] {
                *d_i_j *= &q_i_inv;
            }
        }
        // Interpolate back, using the inverse skew
        ntt::<false, F, _>(self.data.rows, self.data.cols, &mut self.data);
        self.divide_roots(skew_inv);
    }
}

impl<F> PolynomialVector<F> {
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
pub struct EvaluationVector<F> {
    data: Matrix<F>,
    active_rows: VanishingPoints,
}

impl<F: FieldNTT> EvaluationVector<F> {
    /// Figure out the polynomial which evaluates to this vector.
    ///
    /// i.e. the inverse of [PolynomialVector::evaluate].
    ///
    /// (This makes all the rows count as filled).
    fn interpolate(mut self) -> PolynomialVector<F> {
        self.data.ntt::<false>();
        PolynomialVector { data: self.data }
    }

    /// Erase a particular row.
    ///
    /// Useful for testing the recovery procedure.
    #[cfg(any(test, feature = "fuzz"))]
    fn remove_row(&mut self, row: usize) {
        self.data[row].fill(F::zero());
        self.active_rows.set(row as u64, false);
    }

    fn multiply(&mut self, evaluation: &EvaluationColumn<F>) {
        for (i, e_i) in evaluation.evaluations.iter().enumerate() {
            for self_j in &mut self.data[i] {
                *self_j = self_j.clone() * e_i;
            }
        }
    }

    /// Attempt to recover the missing rows in this data.
    pub fn recover(mut self) -> PolynomialVector<F> {
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
        let (_, vanishing) = EvaluationColumn::vanishing(&self.active_rows);
        self.multiply(&vanishing);
        let mut out = self.interpolate();
        out.divide(vanishing.interpolate());
        out
    }
}

impl<F: Additive> EvaluationVector<F> {
    /// Create an empty element of this struct, with no filled rows.
    ///
    /// `2^lg_rows` must be a valid `usize`.
    pub fn empty(lg_rows: usize, cols: usize) -> Self {
        assert!(
            lg_rows < usize::BITS as usize,
            "2^lg_rows must be a valid usize"
        );
        let data = Matrix::zero(1 << lg_rows, cols);
        let active = VanishingPoints::new(lg_rows as u32);
        Self {
            data,
            active_rows: active,
        }
    }

    /// Fill a specific row.
    pub fn fill_row(&mut self, row: usize, data: &[F])
    where
        F: Clone,
    {
        assert!(data.len() <= self.data.cols);
        self.data[row][..data.len()].clone_from_slice(data);
        self.active_rows.set(row as u64, true);
    }
}

impl<F> EvaluationVector<F> {
    /// Get the underlying data, as a Matrix.
    pub fn data(self) -> Matrix<F> {
        self.data
    }

    /// Return how many distinct rows have been filled.
    pub fn filled_rows(&self) -> usize {
        self.active_rows.count_non_vanishing() as usize
    }
}

/// Compute Lagrange coefficients for interpolating a polynomial at 0 from evaluations
/// at roots of unity.
///
/// Given a subset S of indices where we have evaluations, this computes the Lagrange
/// coefficients needed to interpolate to 0. For each index `j` in S, the coefficient
/// is `L_j(0)` where `L_j` is the Lagrange basis polynomial.
///
/// The key formula is: `L_j(0) = P_Sbar(w^j) / (N * P_Sbar(0))`
///
/// where `P_Sbar` is the (possibly scaled) vanishing polynomial over the complement
/// (missing points), and N is the domain size. This follows from
/// `V_S(X) * V_Sbar(X) = X^N - 1`, which gives `V_S(0) = -1/V_Sbar(0)`.
/// The scaling factor of `P_Sbar` cancels in the ratio.
///
/// Building `P_Sbar` as the vanishing polynomial over missing points is cheaper than building `V_S`
/// when most points are present (the typical erasure-coding case), since `|Sbar| << |S|`.
///
/// # Arguments
/// * `total` - The total number of points in the domain (rounded up to power of 2)
/// * `iter` - Iterator of indices where we have evaluations (duplicates ignored, indices >= total ignored)
///
/// # Returns
/// A vector of `(index, coefficient)` pairs for each unique index in the input set.
pub fn lagrange_coefficients<F: FieldNTT>(
    total: NonZeroU32,
    iter: impl IntoIterator<Item = u32>,
) -> Vec<(u32, F)> {
    let total_u64 = u64::from(total.get());
    let size = total_u64.next_power_of_two();
    let lg_size = size.ilog2();

    let mut present = VanishingPoints::new(lg_size);
    for i in iter {
        let i_u64 = u64::from(i);
        if i_u64 < total_u64 {
            present.set_non_vanishing(i_u64);
        }
    }

    let num_present = present.count_non_vanishing();

    if num_present == 0 {
        return Vec::new();
    }

    let n_f = F::one().scale(&[size]);
    if num_present == size {
        let n_inv = n_f.inv();
        return (0..size).map(|i| (i as u32, n_inv.clone())).collect();
    }

    // Build P_Sbar (vanishes at indices NOT in present) and evaluate at all
    // roots of unity via NTT. Note: vanishing() may produce a scaled polynomial
    // P_Sbar = c * V_Sbar, but the scaling cancels in the ratio below.
    let (p_sbar_at_zero, complement_evals) = EvaluationColumn::vanishing(&present);

    // From V_S(0) * V_Sbar(0) = -1 (since V_S * V_Sbar = X^N - 1), we get:
    //   L_j(0) = -V_S(0) * V_Sbar(w^j) / N = V_Sbar(w^j) / (N * V_Sbar(0))
    // Since P_Sbar = c * V_Sbar, the scaling c cancels:
    //   L_j(0) = P_Sbar(w^j) / (N * P_Sbar(0))
    let factor = (n_f * &p_sbar_at_zero).inv();

    let mut out = Vec::with_capacity(num_present as usize);
    for j in 0..size {
        if present.get(j) {
            let coeff = factor.clone() * &complement_evals.evaluations[j as usize];
            out.push((j as u32, coeff));
        }
    }
    out
}

#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::{algebra::Ring, fields::goldilocks::F};
    use arbitrary::{Arbitrary, Unstructured};

    fn arb_polynomial_vector(
        u: &mut Unstructured<'_>,
        max_log_rows: u32,
        max_cols: usize,
    ) -> arbitrary::Result<PolynomialVector<F>> {
        let lg_rows = u.int_in_range(0..=max_log_rows)?;
        let cols = u.int_in_range(1..=max_cols)?;
        let rows = 1usize << lg_rows;
        let coefficients: Vec<F> = (0..rows * cols)
            .map(|_| Ok(F::from(u.arbitrary::<u64>()?)))
            .collect::<arbitrary::Result<_>>()?;
        Ok(PolynomialVector::new(rows, cols, coefficients.into_iter()))
    }

    fn arb_bit_vec_not_all_0(
        u: &mut Unstructured<'_>,
        max_log_rows: u32,
    ) -> arbitrary::Result<VanishingPoints> {
        let lg_rows = u.int_in_range(0..=max_log_rows)?;
        let rows = 1usize << lg_rows;
        let set_row = u.int_in_range(0..=rows - 1)?;
        let mut bools: Vec<bool> = (0..rows)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;
        bools[set_row] = true;
        let mut out = VanishingPoints::new(lg_rows);
        for (i, b) in bools.into_iter().enumerate() {
            out.set(i as u64, b);
        }
        Ok(out)
    }

    fn arb_recovery_setup(
        u: &mut Unstructured<'_>,
        max_n: usize,
        max_k: usize,
        max_cols: usize,
    ) -> arbitrary::Result<RecoverySetup> {
        let n = u.int_in_range(1..=max_n)?;
        let k = u.int_in_range(0..=max_k)?;
        let cols = u.int_in_range(1..=max_cols)?;
        let data: Vec<F> = (0..n * cols)
            .map(|_| Ok(F::from(u.arbitrary::<u64>()?)))
            .collect::<arbitrary::Result<_>>()?;
        let padded_rows = (n + k).next_power_of_two();
        let num_present = u.int_in_range(n..=padded_rows)?;
        let mut indices: Vec<usize> = (0..padded_rows).collect();
        for i in 0..num_present {
            let j = u.int_in_range(i..=padded_rows - 1)?;
            indices.swap(i, j);
        }
        let mut present = VanishingPoints::new(padded_rows.ilog2());
        for &i in &indices[..num_present] {
            present.set(i as u64, true);
        }
        Ok(RecoverySetup {
            n,
            k,
            cols,
            data,
            present,
        })
    }

    #[derive(Debug)]
    pub struct RecoverySetup {
        n: usize,
        k: usize,
        cols: usize,
        data: Vec<F>,
        present: VanishingPoints,
    }

    impl RecoverySetup {
        #[cfg(test)]
        pub(crate) const fn new(
            n: usize,
            k: usize,
            cols: usize,
            data: Vec<F>,
            present: VanishingPoints,
        ) -> Self {
            Self {
                n,
                k,
                cols,
                data,
                present,
            }
        }

        pub fn test(self) {
            let data = PolynomialVector::new(self.n + self.k, self.cols, self.data.into_iter());
            let mut encoded = data.clone().evaluate();
            for (i, b_i) in self.present.iter_bits_in_order().enumerate() {
                if !b_i {
                    encoded.remove_row(i);
                }
            }
            let recovered_data = encoded.recover();
            assert_eq!(data, recovered_data);
        }
    }

    #[derive(Debug)]
    pub enum Plan {
        NttEqNaive(PolynomialVector<F>),
        EvaluationThenInverse(PolynomialVector<F>),
        VanishingPolynomial(VanishingPoints),
        Recovery(RecoverySetup),
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            match u.int_in_range(0..=3)? {
                0 => Ok(Self::NttEqNaive(arb_polynomial_vector(u, 6, 4)?)),
                1 => Ok(Self::EvaluationThenInverse(arb_polynomial_vector(u, 6, 4)?)),
                2 => Ok(Self::VanishingPolynomial(arb_bit_vec_not_all_0(u, 8)?)),
                _ => Ok(Self::Recovery(arb_recovery_setup(u, 128, 128, 4)?)),
            }
        }
    }

    impl Plan {
        pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::NttEqNaive(p) => {
                    let ntt = p.clone().evaluate();
                    let ntt_naive = p.evaluate_naive();
                    assert_eq!(ntt, ntt_naive);
                }
                Self::EvaluationThenInverse(p) => {
                    assert_eq!(p.clone(), p.evaluate().interpolate());
                }
                Self::VanishingPolynomial(bv) => {
                    let total = 1u64 << bv.lg_size();
                    let expected_degree = total - bv.count_non_vanishing();
                    let (at_zero, evals) = EvaluationColumn::<F>::vanishing(&bv);
                    let v = evals.interpolate();
                    assert_eq!(
                        v.degree(),
                        expected_degree as usize,
                        "expected v to have degree {}",
                        expected_degree
                    );
                    assert_eq!(
                        at_zero, v.coefficients[0],
                        "at_zero should be the 0th coefficient"
                    );
                    let w = F::root_of_unity(bv.lg_size() as u8).unwrap();
                    let mut w_i = F::one();
                    for b_i in bv.iter_bits_in_order() {
                        let v_at_w_i = v.evaluate_one(w_i);
                        if !b_i {
                            assert_eq!(v_at_w_i, F::zero(), "v should evaluate to 0 at {:?}", w_i);
                        } else {
                            assert_ne!(v_at_w_i, F::zero());
                        }
                        w_i = w_i * w;
                    }
                }
                Self::Recovery(setup) => {
                    setup.test();
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_fuzz() {
        use commonware_invariants::minifuzz;
        minifuzz::test(|u| u.arbitrary::<Plan>()?.run(u));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{algebra::Ring, fields::goldilocks::F};

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
        let result = Matrix::<F>::read_cfg(&mut bytes, &(8, ()));
        assert!(matches!(
            result,
            Err(commonware_codec::Error::Invalid(
                "Matrix",
                "matrix element count does not match dimensions"
            ))
        ));
    }

    fn assert_vanishing_points_correct(points: &VanishingPoints) {
        let expected_degree = (1 << points.lg_size()) - points.count_non_vanishing();
        let (at_zero, evaluations) = EvaluationColumn::<F>::vanishing(points);
        if points.count_non_vanishing() == 0 {
            // EvaluationColumn::vanishing assumes at least one non-vanishing point.
            // We still invoke it so callers can exercise internal branch coverage.
            return;
        }
        let polynomial = evaluations.interpolate();
        assert_eq!(
            polynomial.degree(),
            expected_degree as usize,
            "expected v to have degree {expected_degree}"
        );
        assert_eq!(
            at_zero, polynomial.coefficients[0],
            "at_zero should be the 0th coefficient"
        );
        let w = F::root_of_unity(points.lg_size() as u8).unwrap();
        let mut w_i = F::one();
        for (i, point_is_non_vanishing) in points.iter_bits_in_order().enumerate() {
            let value = polynomial.evaluate_one(w_i);
            if point_is_non_vanishing {
                assert_ne!(value, F::zero(), "expected non-zero at i={i}");
            } else {
                assert_eq!(value, F::zero(), "expected zero at i={i}");
            }
            w_i = w_i * w;
        }
    }

    #[test]
    fn test_recovery_000() {
        let present = {
            let mut out = VanishingPoints::new(1);
            out.set_non_vanishing(1);
            out
        };
        fuzz::RecoverySetup::new(1, 1, 1, vec![F::one()], present).test()
    }

    #[test]
    fn test_vanishing_polynomial_all_two_chunk_combinations() {
        fn fill_half(points: &mut VanishingPoints, half: usize, values: [bool; 2]) {
            let chunk_size = 1usize << LG_VANISHING_BASE;
            let start = half * chunk_size;
            let lg_size = points.lg_size();
            for i in 0..chunk_size {
                let value = values[i % 2];
                let raw_index = (start + i) as u64;
                points.set(reverse_bits(lg_size, raw_index), value);
            }
        }

        let lg_size = LG_VANISHING_BASE + 1;
        // (0,0) => Everywhere, (0,1) => Somewhere, (1,1) => Nowhere.
        let states = [[false, false], [false, true], [true, true]];
        for left in states {
            for right in states {
                let mut points = VanishingPoints::new(lg_size);
                // VanishingPoints stores roots in reverse bit order. Writing raw halves
                // directly makes chunk 0/1 align exactly with the implementation's chunks.
                fill_half(&mut points, 0, left);
                fill_half(&mut points, 1, right);
                assert_vanishing_points_correct(&points);
            }
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Matrix<F>>,
        }
    }
}
