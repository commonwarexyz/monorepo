//! Verifier: composes commitment, transcript, and sumcheck verification.
//!
//! The verifier is the symmetric counterpart to the prover. It replays
//! the same transcript operations using proof data instead of witness
//! data, verifying consistency at each stage.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;
use crate::merkle::Hash;
use crate::utils::{eval_sk_at_vks, verify_ligero};

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

/// Log2 of the inverse code rate (inv_rate = 4).
const LOG_INV_RATE: usize = 2;

/// Verify a Ligerito proof against a Fiat-Shamir transcript.
///
/// Absorbs the initial commitment root, then delegates to [`verify_core`]
/// for the remainder of the protocol.
pub fn verify<T, U>(
    config: &crate::VerifierConfig,
    proof: &crate::proof::Proof<T, U>,
    transcript: &mut impl crate::Transcript,
) -> crate::Result<bool>
where
    T: BinaryFieldElement + Send + Sync,
    U: BinaryFieldElement + Send + Sync + From<T>,
{
    let root_bytes = proof
        .initial_commitment
        .root
        .root
        .as_ref()
        .map_or(&[] as &[u8], |h| h.as_slice());
    transcript.absorb_root(root_bytes);
    verify_core(config, proof, transcript)
}

/// Core verification logic after the initial commitment root has been
/// absorbed into the transcript.
fn verify_core<T, U>(
    config: &crate::VerifierConfig,
    proof: &crate::proof::Proof<T, U>,
    fs: &mut impl crate::Transcript,
) -> crate::Result<bool>
where
    T: BinaryFieldElement + Send + Sync,
    U: BinaryFieldElement + Send + Sync + From<T>,
{
    // Precompute basis evaluations once.
    let cached_initial_sks: Vec<T> = eval_sk_at_vks(1 << config.initial_dim);
    let cached_recursive_sks: Vec<Vec<U>> = config
        .log_dims
        .iter()
        .map(|&dim| eval_sk_at_vks(1 << dim))
        .collect();

    // Get initial challenges in base field.
    let partial_evals_0_t: Vec<T> = (0..config.initial_k)
        .map(|_| fs.challenge())
        .collect();

    let partial_evals_0: Vec<U> = partial_evals_0_t.iter().map(|&x| U::from(x)).collect();

    // Absorb first recursive commitment.
    let rec_root_bytes = proof.recursive_commitments[0]
        .root
        .root
        .as_ref()
        .map_or(&[] as &[u8], |h| h.as_slice());
    fs.absorb_root(rec_root_bytes);

    // Verify initial Merkle proof.
    let depth = config.initial_dim + LOG_INV_RATE;
    let queries = fs.distinct_queries(1 << depth, config.num_queries);

    let hashed_leaves: Vec<Hash> = proof
        .initial_opening
        .opened_rows
        .iter()
        .map(|row| crate::utils::hash_row(row))
        .collect();

    if !crate::merkle::verify_hashed(
        &proof.initial_commitment.root,
        &proof.initial_opening.merkle_proof,
        depth,
        &hashed_leaves,
        &queries,
    ) {
        return Ok(false);
    }

    let alpha = fs.challenge::<U>();

    // Induce initial sumcheck polynomial.
    let sks_vks = &cached_initial_sks;
    let (_, enforced_sum) = induce_sumcheck(
        config.initial_dim,
        sks_vks,
        &proof.initial_opening.opened_rows,
        &partial_evals_0,
        &queries,
        alpha,
    );

    let mut current_sum = enforced_sum;
    fs.absorb_elem(current_sum);

    let mut transcript_idx = 0;

    for i in 0..config.recursive_steps {
        let mut rs = Vec::with_capacity(config.ks[i]);

        // Sumcheck rounds.
        for _ in 0..config.ks[i] {
            if transcript_idx >= proof.sumcheck_rounds.transcript.len() {
                return Ok(false);
            }

            let coeffs = proof.sumcheck_rounds.transcript[transcript_idx];
            let claimed_sum =
                evaluate_quadratic(coeffs, U::zero()).add(&evaluate_quadratic(coeffs, U::one()));

            if claimed_sum != current_sum {
                return Ok(false);
            }

            let ri = fs.challenge::<U>();
            rs.push(ri);
            current_sum = evaluate_quadratic(coeffs, ri);
            fs.absorb_elem(current_sum);

            transcript_idx += 1;
        }

        if i >= proof.recursive_commitments.len() {
            return Ok(false);
        }

        let root = &proof.recursive_commitments[i].root;

        // Final round.
        if i == config.recursive_steps - 1 {
            fs.absorb_elems(&proof.final_opening.yr);

            let depth = config.log_dims[i] + LOG_INV_RATE;
            let queries = fs.distinct_queries(1 << depth, config.num_queries);

            let hashed_final: Vec<Hash> = proof
                .final_opening
                .opened_rows
                .iter()
                .map(|row| crate::utils::hash_row(row))
                .collect();

            if !crate::merkle::verify_hashed(
                root,
                &proof.final_opening.merkle_proof,
                depth,
                &hashed_final,
                &queries,
            ) {
                return Ok(false);
            }

            // Ligero consistency check.
            verify_ligero(
                &queries,
                &proof.final_opening.opened_rows,
                &proof.final_opening.yr,
                &rs,
            );

            return Ok(true);
        }

        // Continue recursion for non-final rounds.
        if i + 1 >= proof.recursive_commitments.len() || i >= proof.recursive_openings.len() {
            return Ok(false);
        }

        let next_root_bytes = proof.recursive_commitments[i + 1]
            .root
            .root
            .as_ref()
            .map_or(&[] as &[u8], |h| h.as_slice());
        fs.absorb_root(next_root_bytes);

        let depth = config.log_dims[i] + LOG_INV_RATE;
        let ligero_opening = &proof.recursive_openings[i];
        let queries = fs.distinct_queries(1 << depth, config.num_queries);

        let hashed_rec: Vec<Hash> = ligero_opening
            .opened_rows
            .iter()
            .map(|row| crate::utils::hash_row(row))
            .collect();

        if !crate::merkle::verify_hashed(
            root,
            &ligero_opening.merkle_proof,
            depth,
            &hashed_rec,
            &queries,
        ) {
            return Ok(false);
        }

        let alpha = fs.challenge::<U>();

        if i >= config.log_dims.len() {
            return Ok(false);
        }

        let sks_vks = &cached_recursive_sks[i];
        let (_, enforced_sum_next) = induce_sumcheck(
            config.log_dims[i],
            sks_vks,
            &ligero_opening.opened_rows,
            &rs,
            &queries,
            alpha,
        );

        let enforced_sum = enforced_sum_next;

        let glue_sum = current_sum.add(&enforced_sum);
        fs.absorb_elem(glue_sum);

        let beta = fs.challenge::<U>();
        current_sum = glue_sums(current_sum, enforced_sum, beta);
    }

    Ok(true)
}

/// Evaluate the degree-1 sumcheck polynomial at point `x`.
///
/// In binary fields the polynomial through (0, s0) and (1, s2) is
/// f(x) = s0 + s1*x, where s1 = s0 + s2.
#[inline(always)]
fn evaluate_quadratic<F: BinaryFieldElement>(coeffs: (F, F, F), x: F) -> F {
    let (s0, s1, _s2) = coeffs;
    s0.add(&s1.mul(&x))
}

/// Combine two partial sums with a random linear combination.
#[inline(always)]
fn glue_sums<F: BinaryFieldElement>(sum_f: F, sum_g: F, beta: F) -> F {
    sum_f.add(&beta.mul(&sum_g))
}
