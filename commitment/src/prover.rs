//! Prover: composes encoding, commitment, transcript, and sumcheck.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::encode::{commitment_from_witness, ligero_commit};
use crate::field::BinaryFieldElement;
use crate::proof::{
    Commitment, FinalOpening, Opening, Proof, ProofBuilder, SumcheckRounds, Witness,
};
use crate::utils::{eval_sk_at_vks, partial_eval_multilinear};

/// Dispatch to parallel sumcheck induction when available.
#[cfg(feature = "parallel")]
#[inline(always)]
fn induce_sumcheck<T, U>(
    n: usize,
    sks_vks: &[T],
    opened_rows: &[Vec<T>],
    v_challenges: &[U],
    sorted_queries: &[usize],
    alpha: U,
) -> (Vec<U>, U)
where
    T: BinaryFieldElement + Send + Sync,
    U: BinaryFieldElement + Send + Sync + From<T>,
{
    crate::sumcheck::polys::induce_sumcheck_poly_parallel(
        n,
        sks_vks,
        opened_rows,
        v_challenges,
        sorted_queries,
        alpha,
    )
}

#[cfg(not(feature = "parallel"))]
#[inline(always)]
fn induce_sumcheck<T, U>(
    n: usize,
    sks_vks: &[T],
    opened_rows: &[Vec<T>],
    v_challenges: &[U],
    sorted_queries: &[usize],
    alpha: U,
) -> (Vec<U>, U)
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    crate::sumcheck::polys::induce_sumcheck(
        n,
        sks_vks,
        opened_rows,
        v_challenges,
        sorted_queries,
        alpha,
    )
}

/// Compute sumcheck round coefficients (s0, s1, s2) from the current polynomial.
///
/// s0 = sum of even-indexed terms, s2 = sum of odd-indexed terms, s1 = s0 + s2.
fn compute_sumcheck_coefficients<F: BinaryFieldElement>(poly: &[F]) -> (F, F, F) {
    let n = poly.len() / 2;

    let mut s0 = F::zero();
    let mut s1 = F::zero();
    let mut s2 = F::zero();

    for i in 0..n {
        let p0 = poly[2 * i];
        let p1 = poly[2 * i + 1];

        s0 = s0.add(&p0);
        s1 = s1.add(&p0.add(&p1));
        s2 = s2.add(&p1);
    }

    (s0, s1, s2)
}

/// Fold polynomial in-place: poly[i] = poly[2i] + r * (poly[2i+1] + poly[2i]).
///
/// Safe because write index `i` is always behind read indices `2i` and `2i+1`.
/// Truncates the vector to half its length.
fn fold_polynomial_in_place<F: BinaryFieldElement>(poly: &mut Vec<F>, r: F) {
    let n = poly.len() / 2;

    for i in 0..n {
        let p0 = poly[2 * i];
        let p1 = poly[2 * i + 1];
        poly[i] = p0.add(&r.mul(&p1.add(&p0)));
    }

    poly.truncate(n);
}

/// Evaluate the univariate sumcheck polynomial at x.
///
/// In binary fields: f(x) = s0 + s1 * x, where f(0) = s0, f(1) = s2.
fn evaluate_quadratic<F: BinaryFieldElement>(coeffs: (F, F, F), x: F) -> F {
    let (s0, s1, _s2) = coeffs;
    s0.add(&s1.mul(&x))
}

/// Combine two polynomials: result[i] = f[i] + beta * g[i].
fn glue_polynomials<F: BinaryFieldElement>(f: &[F], g: &[F], beta: F) -> Vec<F> {
    assert_eq!(f.len(), g.len());
    f.iter()
        .zip(g.iter())
        .map(|(&fi, &gi)| fi.add(&beta.mul(&gi)))
        .collect()
}

/// Combine two sums: sum_f + beta * sum_g.
fn glue_sums<F: BinaryFieldElement>(sum_f: F, sum_g: F, beta: F) -> F {
    sum_f.add(&beta.mul(&sum_g))
}

/// Core proving logic after initial commitment and root absorption.
fn prove_core<T, U>(
    config: &crate::ProverConfig<T, U>,
    poly: &[T],
    wtns_0: Witness<T>,
    cm_0: Commitment,
    transcript: &mut impl crate::Transcript,
) -> crate::Result<Proof<T, U>>
where
    T: BinaryFieldElement + Send + Sync + bytemuck::Pod + 'static,
    U: BinaryFieldElement + Send + Sync + From<T> + bytemuck::Pod + 'static,
{
    let mut builder = ProofBuilder::<T, U>::new();
    builder.initial_commitment = Some(cm_0);

    // Get initial challenges in the base field
    let partial_evals_0: Vec<T> = (0..config.initial_k)
        .map(|_| transcript.challenge())
        .collect();

    // Partial evaluation of multilinear polynomial
    let mut f_evals = poly.to_vec();
    partial_eval_multilinear(&mut f_evals, &partial_evals_0);

    // Convert to extension field
    let partial_evals_0_u: Vec<U> = partial_evals_0.iter().map(|&x| U::from(x)).collect();
    let f_evals_u: Vec<U> = f_evals.iter().map(|&x| U::from(x)).collect();

    // First recursive step: commit the folded polynomial in the extension field
    let wtns_1 = ligero_commit(
        &f_evals_u,
        config.dims[0].0,
        config.dims[0].1,
        &config.reed_solomon_codes[0],
    );
    let cm_1 = commitment_from_witness(&wtns_1);
    builder.recursive_commitments.push(cm_1.clone());

    let root_bytes = cm_1.root.root.as_ref().map_or(&[] as &[u8], |h| h.as_slice());
    transcript.absorb_root(root_bytes);

    // Query selection on initial witness
    let rows = wtns_0.num_rows();
    let queries = transcript.distinct_queries(rows, config.num_queries);
    let alpha: U = transcript.challenge();

    // Prepare for sumcheck
    let n = f_evals.len().trailing_zeros() as usize;
    let sks_vks: Vec<T> = eval_sk_at_vks(1 << n);

    let opened_rows: Vec<Vec<T>> = queries.iter().map(|&q| wtns_0.gather_row(q)).collect();
    let mtree_proof = wtns_0.tree.prove(&queries);

    builder.initial_opening = Some(Opening {
        opened_rows: opened_rows.clone(),
        merkle_proof: mtree_proof,
    });

    // Induce the sumcheck polynomial
    let (basis_poly, enforced_sum) = induce_sumcheck(
        n,
        &sks_vks,
        &opened_rows,
        &partial_evals_0_u,
        &queries,
        alpha,
    );

    let mut sumcheck_transcript = vec![];
    let mut current_poly = basis_poly;
    let mut current_sum = enforced_sum;

    // First sumcheck round absorb
    transcript.absorb_elem(current_sum);

    // Recursive rounds
    let mut wtns_prev = wtns_1;

    for i in 0..config.recursive_steps {
        let mut rs = Vec::new();

        // Sumcheck rounds for this recursive step
        for _ in 0..config.ks[i] {
            let coeffs = compute_sumcheck_coefficients(&current_poly);
            sumcheck_transcript.push(coeffs);

            let ri: U = transcript.challenge();
            rs.push(ri);

            fold_polynomial_in_place(&mut current_poly, ri);
            current_sum = evaluate_quadratic(coeffs, ri);
            transcript.absorb_elem(current_sum);
        }

        // Final round
        if i == config.recursive_steps - 1 {
            transcript.absorb_elems(&current_poly);

            let rows = wtns_prev.num_rows();
            let queries = transcript.distinct_queries(rows, config.num_queries);

            let opened_rows: Vec<Vec<U>> =
                queries.iter().map(|&q| wtns_prev.gather_row(q)).collect();
            let mtree_proof = wtns_prev.tree.prove(&queries);

            builder.final_opening = Some(FinalOpening {
                yr: current_poly,
                opened_rows,
                merkle_proof: mtree_proof,
            });

            builder.sumcheck_rounds = Some(SumcheckRounds {
                transcript: sumcheck_transcript,
            });

            return builder.build();
        }

        // Continue recursion: commit the next polynomial
        let wtns_next = ligero_commit(
            &current_poly,
            config.dims[i + 1].0,
            config.dims[i + 1].1,
            &config.reed_solomon_codes[i + 1],
        );

        let cm_next = commitment_from_witness(&wtns_next);
        builder.recursive_commitments.push(cm_next.clone());

        let root_bytes = cm_next
            .root
            .root
            .as_ref()
            .map_or(&[] as &[u8], |h| h.as_slice());
        transcript.absorb_root(root_bytes);

        let rows = wtns_prev.num_rows();
        let queries = transcript.distinct_queries(rows, config.num_queries);
        let alpha: U = transcript.challenge();

        let opened_rows: Vec<Vec<U>> =
            queries.iter().map(|&q| wtns_prev.gather_row(q)).collect();
        let mtree_proof = wtns_prev.tree.prove(&queries);

        builder.recursive_openings.push(Opening {
            opened_rows: opened_rows.clone(),
            merkle_proof: mtree_proof,
        });

        // Induce sumcheck for this round
        let n = current_poly.len().trailing_zeros() as usize;
        let sks_vks: Vec<U> = eval_sk_at_vks(1 << n);

        let (basis_poly, enforced_sum) =
            induce_sumcheck(n, &sks_vks, &opened_rows, &rs, &queries, alpha);

        // Glue sumcheck
        let glue_sum = current_sum.add(&enforced_sum);
        transcript.absorb_elem(glue_sum);

        let beta: U = transcript.challenge();
        current_poly = glue_polynomials(&current_poly, &basis_poly, beta);
        current_sum = glue_sums(current_sum, enforced_sum, beta);

        wtns_prev = wtns_next;
    }

    unreachable!("Should have returned in final round");
}

/// Generate a Ligerito proof for a polynomial.
///
/// Performs the full Ligerito commitment scheme: initial Ligero commit,
/// partial evaluation, recursive sumcheck rounds with Reed-Solomon
/// proximity testing, and final opening.
pub fn prove<T, U>(
    config: &crate::ProverConfig<T, U>,
    poly: &[T],
    transcript: &mut impl crate::Transcript,
) -> crate::Result<Proof<T, U>>
where
    T: BinaryFieldElement + Send + Sync + bytemuck::Pod + 'static,
    U: BinaryFieldElement + Send + Sync + From<T> + bytemuck::Pod + 'static,
{
    config.validate()?;

    // Initial Ligero commitment over the base field
    let wtns_0 = ligero_commit(
        poly,
        config.initial_dims.0,
        config.initial_dims.1,
        &config.initial_reed_solomon,
    );
    let cm_0 = commitment_from_witness(&wtns_0);

    let root_bytes = cm_0
        .root
        .root
        .as_ref()
        .map_or(&[] as &[u8], |h| h.as_slice());
    transcript.absorb_root(root_bytes);

    prove_core(config, poly, wtns_0, cm_0, transcript)
}
