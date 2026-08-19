use super::{
    Claim, Proof, VerifyingKey, poly::Domain, transcript_challenge, transcript_challenge_prebound,
};
use crate::{
    bls12381::primitives::group::{G1, G2, Scalar, SmallScalar},
    transcript::Transcript,
};
use commonware_codec::Encode;
use commonware_math::algebra::{Additive, CryptoGroup, Multiplicative, Ring, Space};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// One additive term of a block commitment in a batch entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitmentTerm {
    /// The point contributes with weight one.
    Point(G1),
    /// The point contributes scaled by the weight.
    Weighted(G1, Scalar),
}

/// One claim of a prebound batch, with each block commitment expressed as a
/// weighted sum of caller points.
///
/// Expressing a derived commitment through its terms (instead of
/// materializing the sum) lets batch verification fold the derivation into
/// its multi-scalar multiplications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchEntry {
    /// Public inputs in the relation's declared order.
    pub public_inputs: Vec<Scalar>,
    /// Per-block commitment terms, in declared block order.
    pub commitments: Vec<Vec<CommitmentTerm>>,
    /// The proof for this claim.
    pub proof: Proof,
}

/// Verify one Pari proof against its public inputs and expected commitments.
#[must_use]
pub fn verify(
    transcript: &mut Transcript,
    verifying_key: &VerifyingKey,
    claim: &Claim,
    proof: &Proof,
) -> bool {
    verify_inner(transcript, verifying_key, claim, proof, true)
}

/// Verify a proof whose statement the caller has already bound to the
/// transcript.
///
/// # Security
///
/// The Fiat-Shamir challenge only covers what the transcript contains. Before
/// calling, the caller MUST have committed the claim's public inputs and every
/// block commitment (or data that uniquely determines them) to `transcript`,
/// exactly as the prover did via [`super::prove_prebound`]. Use [`verify`]
/// unless the statement needs a custom transcript encoding.
#[must_use]
pub fn verify_prebound(
    transcript: &mut Transcript,
    verifying_key: &VerifyingKey,
    claim: &Claim,
    proof: &Proof,
) -> bool {
    verify_inner(transcript, verifying_key, claim, proof, false)
}

fn verify_inner(
    transcript: &mut Transcript,
    verifying_key: &VerifyingKey,
    claim: &Claim,
    proof: &Proof,
    bind_claim: bool,
) -> bool {
    // Block commitments may legitimately be the identity (e.g. commitments to
    // zero maintained homomorphically), so only the proof points are gated.
    if proof.t == G1::zero() || proof.u == G1::zero() {
        return false;
    }
    let Ok(domain) = verification_domain(verifying_key) else {
        return false;
    };
    if claim.public_inputs.len() != verifying_key.public_inputs as usize
        || claim.commitments.len() != verifying_key.blocks.len()
    {
        return false;
    }
    let challenge = if bind_claim {
        transcript_challenge(transcript, &domain, verifying_key, claim, &proof.t)
    } else {
        transcript_challenge_prebound(transcript, &domain, verifying_key, &proof.t)
    };
    let Some(v_r) = public_evaluation(
        verifying_key,
        &claim.public_inputs,
        &domain,
        &challenge,
        &proof.v_a,
    ) else {
        return false;
    };
    pairing_check(verifying_key, &claim.commitments, proof, &challenge, &v_r)
}

/// Batch verify proofs using verifier-owned unpredictable coefficients.
///
/// Each transcript must contain the same prehistory used to create the proof at
/// the corresponding position. The transcripts are advanced independently.
#[must_use]
pub fn batch_verify(
    rng: &mut impl CryptoRng,
    transcripts: &mut [Transcript],
    verifying_key: &VerifyingKey,
    claims_and_proofs: &[(Claim, Proof)],
    strategy: &impl Strategy,
) -> bool {
    if transcripts.len() != claims_and_proofs.len() {
        return false;
    }
    let entries = claims_and_proofs
        .iter()
        .zip(transcripts.iter_mut())
        .map(|((claim, proof), transcript)| {
            transcript.commit(claim.encode());
            BatchEntry {
                public_inputs: claim.public_inputs.clone(),
                commitments: claim
                    .commitments
                    .iter()
                    .map(|commitment| vec![CommitmentTerm::Point(*commitment)])
                    .collect(),
                proof: proof.clone(),
            }
        })
        .collect::<Vec<_>>();
    batch_verify_prebound(rng, transcripts, verifying_key, &entries, strategy)
}

/// Batch verify proofs whose statements the callers have already bound to the
/// transcripts, with block commitments given as weighted point terms.
///
/// # Security
///
/// The Fiat-Shamir challenges only cover what each transcript contains. Before
/// calling, every transcript MUST bind its entry's public inputs and block
/// commitments (or data that uniquely determines them, e.g. the points and
/// weights of its terms), exactly as the prover did via
/// [`super::prove_prebound`]. Use [`batch_verify`] unless the statements need
/// a custom transcript encoding.
#[must_use]
pub fn batch_verify_prebound(
    rng: &mut impl CryptoRng,
    transcripts: &mut [Transcript],
    verifying_key: &VerifyingKey,
    entries: &[BatchEntry],
    strategy: &impl Strategy,
) -> bool {
    if transcripts.len() != entries.len() {
        return false;
    }
    if entries.is_empty() {
        return true;
    }
    let Ok(domain) = verification_domain(verifying_key) else {
        return false;
    };

    let blocks = verifying_key.blocks.len();
    let mut challenges = Vec::with_capacity(entries.len());
    let mut v_rs = Vec::with_capacity(entries.len());
    for (transcript, entry) in transcripts.iter_mut().zip(entries) {
        if entry.proof.t == G1::zero() || entry.proof.u == G1::zero() {
            return false;
        }
        if entry.public_inputs.len() != verifying_key.public_inputs as usize
            || entry.commitments.len() != blocks
        {
            return false;
        }
        let challenge =
            transcript_challenge_prebound(transcript, &domain, verifying_key, &entry.proof.t);
        let Some(v_r) = public_evaluation(
            verifying_key,
            &entry.public_inputs,
            &domain,
            &challenge,
            &entry.proof.v_a,
        ) else {
            return false;
        };
        challenges.push(challenge);
        v_rs.push(v_r);
    }

    // 128-bit coefficients keep the random linear combination sound at 2^-128
    // while halving the cost of the point aggregations below. Terms that
    // multiply a full-width value stay in the full scalar field.
    let coefficients = (0..entries.len())
        .map(|_| SmallScalar::random(&mut *rng))
        .collect::<Vec<_>>();
    let full_coefficients = coefficients
        .iter()
        .map(|coefficient| Scalar::from(coefficient.clone()))
        .collect::<Vec<_>>();

    // Fold every block commitment, partitioning weight-one terms (which keep
    // the 128-bit coefficient path) from weighted terms.
    let mut folded_commitments = Vec::with_capacity(blocks);
    for block in 0..blocks {
        let mut unit_points = Vec::new();
        let mut unit_scalars = Vec::new();
        let mut weighted_points = Vec::new();
        let mut weighted_scalars = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            for term in &entry.commitments[block] {
                match term {
                    CommitmentTerm::Point(point) => {
                        unit_points.push(*point);
                        unit_scalars.push(coefficients[index].clone());
                    }
                    CommitmentTerm::Weighted(point, weight) => {
                        weighted_points.push(*point);
                        weighted_scalars.push(full_coefficients[index].clone() * weight);
                    }
                }
            }
        }
        folded_commitments.push(
            G1::msm(&unit_points, &unit_scalars, strategy)
                + &G1::msm(&weighted_points, &weighted_scalars, strategy),
        );
    }

    let ts = entries
        .iter()
        .map(|entry| entry.proof.t)
        .collect::<Vec<_>>();
    let us = entries
        .iter()
        .map(|entry| entry.proof.u)
        .collect::<Vec<_>>();
    let t = G1::msm(&ts, &coefficients, strategy);
    let u = G1::msm(&us, &coefficients, strategy);
    let weighted_challenges = full_coefficients
        .iter()
        .zip(&challenges)
        .map(|(coefficient, challenge)| coefficient.clone() * challenge)
        .collect::<Vec<_>>();
    let evaluated_u = G1::msm(&us, &weighted_challenges, strategy);
    let v_a = full_coefficients
        .iter()
        .zip(entries)
        .fold(Scalar::zero(), |sum, (coefficient, entry)| {
            sum + &(coefficient.clone() * &entry.proof.v_a)
        });
    let v_r = full_coefficients
        .iter()
        .zip(v_rs)
        .fold(Scalar::zero(), |sum, (coefficient, value)| {
            sum + &(coefficient.clone() * &value)
        });

    let final_term = evaluated_u - &(verifying_key.alpha_g * &v_a) - &(verifying_key.beta_g * &v_r);
    let mut points = Vec::with_capacity(blocks + 2);
    points.extend_from_slice(&folded_commitments);
    points.push(t);
    points.push(-u);
    let mut generators = Vec::with_capacity(blocks + 2);
    generators.extend_from_slice(&verifying_key.delta_committed_h);
    generators.push(verifying_key.delta_witness_h);
    generators.push(verifying_key.tau_h);
    G1::multi_pairing_check(&points, &generators, &final_term, &G2::generator())
}

fn verification_domain(verifying_key: &VerifyingKey) -> Result<Domain, ()> {
    // Domain::new rounds up to a power of two, so reject sizes it would
    // silently alter.
    if !verifying_key.domain_size.is_power_of_two() {
        return Err(());
    }
    Domain::new(verifying_key.domain_size as usize).map_err(|_| ())
}

/// Evaluate the interpolated public columns dotted with `(1, public inputs)`
/// at an arbitrary point, using one set of targeted Lagrange coefficients.
pub(super) fn evaluate_public_columns(
    verifying_key: &VerifyingKey,
    public_inputs: &[Scalar],
    domain: &Domain,
    point: &Scalar,
) -> Option<(Scalar, Scalar)> {
    let mut values = Vec::with_capacity(1 + public_inputs.len());
    values.push(Scalar::one());
    values.extend_from_slice(public_inputs);
    if verifying_key.public_columns.len() != values.len() {
        return None;
    }

    // Evaluate the Lagrange basis only at the rows the public columns touch,
    // keeping verification independent of the domain size.
    let mut rows = verifying_key
        .public_columns
        .iter()
        .flat_map(|column| column.a.keys().chain(column.b.keys()).copied())
        .collect::<Vec<_>>();
    rows.sort_unstable();
    rows.dedup();
    let lagrange = domain.lagrange_coefficients_at(point, &rows).ok()?;
    let coefficient_at = |row: u32| rows.binary_search(&row).ok().map(|slot| &lagrange[slot]);

    let mut x_a = Scalar::zero();
    let mut x_b = Scalar::zero();
    for (column, value) in verifying_key.public_columns.iter().zip(&values) {
        for (&row, coefficient) in &column.a {
            x_a += &((coefficient.clone() * value) * coefficient_at(row)?);
        }
        for (&row, coefficient) in &column.b {
            x_b += &((coefficient.clone() * value) * coefficient_at(row)?);
        }
    }
    Some((x_a, x_b))
}

/// Evaluate the public side of the verification equation at the challenge.
fn public_evaluation(
    verifying_key: &VerifyingKey,
    public_inputs: &[Scalar],
    domain: &Domain,
    challenge: &Scalar,
    v_a: &Scalar,
) -> Option<Scalar> {
    let (x_a, x_b) = evaluate_public_columns(verifying_key, public_inputs, domain, challenge)?;
    let mut z = v_a.clone() + &x_a;
    z.square();
    Some(z - &x_b)
}

fn pairing_check(
    verifying_key: &VerifyingKey,
    commitments: &[G1],
    proof: &Proof,
    challenge: &Scalar,
    v_r: &Scalar,
) -> bool {
    let final_term =
        proof.u * challenge - &(verifying_key.alpha_g * &proof.v_a) - &(verifying_key.beta_g * v_r);
    let mut points = Vec::with_capacity(commitments.len() + 2);
    points.extend_from_slice(commitments);
    points.push(proof.t);
    points.push(-proof.u);
    let mut generators = Vec::with_capacity(commitments.len() + 2);
    generators.extend_from_slice(&verifying_key.delta_committed_h);
    generators.push(verifying_key.delta_witness_h);
    generators.push(verifying_key.tau_h);
    G1::multi_pairing_check(&points, &generators, &final_term, &G2::generator())
}
