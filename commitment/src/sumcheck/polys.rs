//! Polynomial induction for the sumcheck protocol.
//!
//! Computes batched basis polynomials for verifier consistency checks,
//! following the Ligerito paper section 6.2.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;

/// Tensorized dot product exploiting Kronecker structure.
///
/// Reduces O(2^k) to O(k * 2^(k-1)) by folding dimensions.
/// Iterates challenges in reverse since Lagrange basis maps r0 to LSB.
fn tensorized_dot_product<T, U>(row: &[T], challenges: &[U]) -> U
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    let k = challenges.len();
    if k == 0 {
        return if row.len() == 1 {
            U::from(row[0])
        } else {
            U::zero()
        };
    }

    assert_eq!(row.len(), 1 << k, "Row length must be 2^k");

    let mut current: Vec<U> = row.iter().map(|&x| U::from(x)).collect();

    // Fold from last to first challenge
    for &r in challenges.iter().rev() {
        let half = current.len() / 2;
        let one_minus_r = U::one().add(&r); // in GF(2^n): 1-r = 1+r

        for i in 0..half {
            // Lagrange contraction: (1-r)*left + r*right
            current[i] = current[2 * i]
                .mul(&one_minus_r)
                .add(&current[2 * i + 1].mul(&r));
        }
        current.truncate(half);
    }

    current[0]
}

/// Precompute powers of alpha to avoid repeated multiplications.
pub fn precompute_alpha_powers<F: BinaryFieldElement>(alpha: F, n: usize) -> Vec<F> {
    let mut alpha_pows = vec![F::zero(); n];
    if n > 0 {
        alpha_pows[0] = F::one();
        for i in 1..n {
            alpha_pows[i] = alpha_pows[i - 1].mul(&alpha);
        }
    }
    alpha_pows
}

/// Full Ligerito sumcheck polynomial induction per paper section 6.2.
///
/// Computes batched basis polynomial w_l for verifier consistency check.
pub fn induce_sumcheck_poly<T, U>(
    n: usize,
    _sks_vks: &[T],
    opened_rows: &[Vec<T>],
    v_challenges: &[U],
    sorted_queries: &[usize],
    alpha: U,
) -> (Vec<U>, U)
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    let mut basis_poly = vec![U::zero(); 1 << n];
    let mut enforced_sum = U::zero();
    let alpha_pows = precompute_alpha_powers(alpha, opened_rows.len());

    for (i, (row, &query)) in opened_rows.iter().zip(sorted_queries.iter()).enumerate() {
        let dot = tensorized_dot_product(row, v_challenges);
        let contribution = dot.mul(&alpha_pows[i]);
        enforced_sum = enforced_sum.add(&contribution);

        // evaluate_scaled_basis_inplace produces a delta function: only
        // basis_poly[query_mod] is non-zero. Skip the O(2^n) scan and
        // set it directly.
        let query_mod = query % (1 << n);
        basis_poly[query_mod] = basis_poly[query_mod].add(&contribution);
    }

    debug_assert_eq!(
        basis_poly.iter().fold(U::zero(), |acc, &x| acc.add(&x)),
        enforced_sum,
        "sumcheck consistency check failed"
    );

    (basis_poly, enforced_sum)
}

/// Parallel version using thread-local accumulators.
///
/// Divides work into contiguous chunks, one per thread, to avoid locking
/// overhead (chunked parallelism).
#[cfg(feature = "parallel")]
pub fn induce_sumcheck_poly_parallel<T, U>(
    n: usize,
    _sks_vks: &[T],
    opened_rows: &[Vec<T>],
    v_challenges: &[U],
    sorted_queries: &[usize],
    alpha: U,
) -> (Vec<U>, U)
where
    T: BinaryFieldElement + Send + Sync,
    U: BinaryFieldElement + Send + Sync + From<T>,
{
    use rayon::prelude::*;

    assert_eq!(opened_rows.len(), sorted_queries.len());

    let alpha_pows = precompute_alpha_powers(alpha, opened_rows.len());
    let basis_size = 1 << n;
    let n_rows = opened_rows.len();
    let n_threads = rayon::current_num_threads();

    // Compute chunk size, capping to actual rows
    let actual_threads = n_threads.min(n_rows);
    let chunk_size = n_rows.div_ceil(actual_threads);

    // Each thread accumulates into its own basis using the delta-function
    // shortcut: only basis_poly[query_mod] gets a non-zero contribution.
    let results: Vec<(Vec<U>, U)> = (0..actual_threads)
        .into_par_iter()
        .map(|thread_id| {
            let start_idx = thread_id * chunk_size;
            let end_idx = (start_idx + chunk_size).min(n_rows);

            let mut thread_basis = vec![U::zero(); basis_size];
            let mut thread_sum = U::zero();

            for i in start_idx..end_idx {
                let row = &opened_rows[i];
                let query = sorted_queries[i];
                let alpha_pow = alpha_pows[i];

                let dot = tensorized_dot_product(row, v_challenges);
                let contribution = dot.mul(&alpha_pow);
                thread_sum = thread_sum.add(&contribution);

                let query_mod = query % (1 << n);
                thread_basis[query_mod] = thread_basis[query_mod].add(&contribution);
            }

            (thread_basis, thread_sum)
        })
        .collect();

    // Combine results from all threads
    let mut basis_poly = vec![U::zero(); basis_size];
    let mut enforced_sum = U::zero();

    for (thread_basis, thread_sum) in results {
        for (j, val) in thread_basis.into_iter().enumerate() {
            basis_poly[j] = basis_poly[j].add(&val);
        }
        enforced_sum = enforced_sum.add(&thread_sum);
    }

    debug_assert_eq!(
        basis_poly.iter().fold(U::zero(), |acc, &x| acc.add(&x)),
        enforced_sum,
        "parallel sumcheck consistency failed"
    );

    (basis_poly, enforced_sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{BinaryElem128, BinaryElem32};
    use crate::utils::eval_sk_at_vks;

    #[test]
    fn test_alpha_powers() {
        let alpha = BinaryElem128::from_value(5);
        let powers = precompute_alpha_powers(alpha, 4);

        assert_eq!(powers[0], BinaryElem128::one());
        assert_eq!(powers[1], alpha);
        assert_eq!(powers[2], alpha.mul(&alpha));
        assert_eq!(powers[3], alpha.mul(&alpha).mul(&alpha));
    }

    #[test]
    fn test_sumcheck_consistency() {
        let n = 3; // 2^3 = 8 elements
        let sks_vks: Vec<BinaryElem32> = eval_sk_at_vks(1 << n);

        let v_challenges = vec![
            BinaryElem128::from_value(0x1234),
            BinaryElem128::from_value(0x5678),
        ];

        let queries = vec![0, 2, 5];
        let opened_rows = vec![
            vec![BinaryElem32::from_value(1); 4],
            vec![BinaryElem32::from_value(2); 4],
            vec![BinaryElem32::from_value(3); 4],
        ];

        let alpha = BinaryElem128::from_value(0x9ABC);

        let (basis_poly, enforced_sum) =
            induce_sumcheck_poly(n, &sks_vks, &opened_rows, &v_challenges, &queries, alpha);

        // Check sum consistency
        let computed_sum = basis_poly
            .iter()
            .fold(BinaryElem128::zero(), |acc, &x| acc.add(&x));
        assert_eq!(computed_sum, enforced_sum, "Sum consistency check failed");

        // The basis polynomial should not be all zeros (unless all inputs are zero)
        let all_zero = basis_poly.iter().all(|&x| x == BinaryElem128::zero());
        assert!(
            !all_zero || alpha == BinaryElem128::zero(),
            "Basis polynomial should not be all zeros"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_vs_sequential() {
        let n = 12; // 2^12 = 4096 elements
        let sks_vks: Vec<BinaryElem32> = eval_sk_at_vks(1 << n);

        let num_queries = 148;
        let v_challenges = vec![
            BinaryElem128::from_value(0x1234567890abcdef),
            BinaryElem128::from_value(0xfedcba0987654321),
        ];

        let queries: Vec<usize> = (0..num_queries).map(|i| (i * 113) % (1 << n)).collect();
        let opened_rows: Vec<Vec<BinaryElem32>> = (0..num_queries)
            .map(|i| {
                (0..4)
                    .map(|j| BinaryElem32::from_value((i * j + 1) as u32))
                    .collect()
            })
            .collect();

        let alpha = BinaryElem128::from_value(0x9ABC);

        // Run sequential version
        let (seq_basis, seq_sum) =
            induce_sumcheck_poly(n, &sks_vks, &opened_rows, &v_challenges, &queries, alpha);

        // Run parallel version
        let (par_basis, par_sum) = induce_sumcheck_poly_parallel(
            n,
            &sks_vks,
            &opened_rows,
            &v_challenges,
            &queries,
            alpha,
        );

        assert_eq!(
            par_sum, seq_sum,
            "Parallel and sequential enforced sums differ"
        );

        assert_eq!(
            par_basis, seq_basis,
            "Parallel and sequential basis polynomials differ"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_sumcheck_parallel_consistency() {
        let n = 2; // 2^2 = 4 elements
        let sks_vks: Vec<BinaryElem32> = eval_sk_at_vks(1 << n);

        // 1 challenge -> Lagrange basis length = 2^1 = 2
        let v_challenges = vec![BinaryElem128::from_value(0xABCD)];

        let queries = vec![0, 1, 3];
        // Each row must have length 2 to match Lagrange basis
        let opened_rows = vec![
            vec![BinaryElem32::from_value(7), BinaryElem32::from_value(9)],
            vec![BinaryElem32::from_value(11), BinaryElem32::from_value(13)],
            vec![BinaryElem32::from_value(15), BinaryElem32::from_value(17)],
        ];

        let alpha = BinaryElem128::from_value(0x1337);

        // Sequential version
        let (basis_seq, sum_seq) =
            induce_sumcheck_poly(n, &sks_vks, &opened_rows, &v_challenges, &queries, alpha);

        // Parallel version
        let (basis_par, sum_par) = induce_sumcheck_poly_parallel(
            n,
            &sks_vks,
            &opened_rows,
            &v_challenges,
            &queries,
            alpha,
        );

        assert_eq!(
            sum_seq, sum_par,
            "Sequential and parallel sums should match"
        );
        assert_eq!(
            basis_seq, basis_par,
            "Sequential and parallel basis polynomials should match"
        );
    }

    #[test]
    fn test_empty_inputs() {
        let n = 2;
        let sks_vks: Vec<BinaryElem32> = eval_sk_at_vks(1 << n);
        let v_challenges = vec![BinaryElem128::from_value(1)];
        let queries: Vec<usize> = vec![];
        let opened_rows: Vec<Vec<BinaryElem32>> = vec![];
        let alpha = BinaryElem128::from_value(42);

        let (basis_poly, enforced_sum) =
            induce_sumcheck_poly(n, &sks_vks, &opened_rows, &v_challenges, &queries, alpha);

        // With no inputs, everything should be zero
        assert_eq!(enforced_sum, BinaryElem128::zero());
        assert!(basis_poly.iter().all(|&x| x == BinaryElem128::zero()));
    }

    #[test]
    fn test_single_query() {
        let n = 2; // 2^2 = 4 elements
        let sks_vks: Vec<BinaryElem32> = eval_sk_at_vks(1 << n);

        let v_challenges = vec![BinaryElem128::from_value(5)];
        let queries = vec![2]; // Single query at index 2
        // Row must have length 2^k where k = number of challenges
        let opened_rows = vec![vec![BinaryElem32::from_value(7), BinaryElem32::from_value(11)]];
        let alpha = BinaryElem128::from_value(3);

        let (basis_poly, enforced_sum) =
            induce_sumcheck_poly(n, &sks_vks, &opened_rows, &v_challenges, &queries, alpha);

        // Check that basis polynomial has the expected structure
        let basis_sum = basis_poly
            .iter()
            .fold(BinaryElem128::zero(), |acc, &x| acc.add(&x));
        assert_eq!(basis_sum, enforced_sum);

        // Basis polynomial sum should equal enforced sum
        assert!(
            basis_sum == enforced_sum,
            "Basis sum should match enforced sum"
        );
    }
}
