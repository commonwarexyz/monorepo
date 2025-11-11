//! Batched Threshold Diffie–Hellman (TDH) decryption for BLS12-381.
//!
//! This module instantiates the Shoup–Gennaro TDH2 construction over the
//! library’s BLS12-381 primitives and adds the “batch DLEQ” technique from
//! Aditya et al. to prove many partial decryptions at once. Each
//! ciphertext is first validated with a Chaum–Pedersen proof, then all valid
//! headers are folded into a single aggregated proof so a server only sends one
//! transcript regardless of batch size. Clients verify a single proof per
//! responder, skip any malformed ciphertexts, and Lagrange-combine the resulting
//! partial decryptions at `x = 0` to recover the messages.
//!
//! # Design
//!
//! *Ciphertexts.* Encryption matches TDH2: sample `r`, compute the header in
//! G1 (and a secondary header for the Chaum–Pedersen relation), mask the payload
//! with a KDF over `h^r`, and attach the Chaum–Pedersen proof linking both
//! headers to the same exponent.
//!
//! *Server responses.* A server with share `x_i` exponentiates every valid
//! header `u_j` to obtain `u_j^{x_i}` and proves that all outputs share the same
//! discrete log with respect to its public share `h_i`. The proof uses the
//! standard random-linear-combination trick (`ρ_j ← H(...)`, `U = Π u_j^{ρ_j}`,
//! `Û_i = Π u_{i,j}^{ρ_j}`) so the Chaum–Pedersen check is constant size
//! regardless of batch length. Each `ρ_j` is derived from a transcript that
//! commits to the batch context, responder index, ciphertext position, header,
//! and claimed partial, ensuring the aggregated bases correspond to the single
//! DLEQ proof `log_g U = log_{h_i} Û_i`
//! (the Chaum–Pedersen equality-of-discrete-log argument) and therefore cover
//! exactly the ciphertexts this responder processed.
//!
//! *Combination.* Once `t` distinct responses pass verification, the client
//! scales each partial vector by the Lagrange coefficient for that responder and
//! sums the contributions in the same order as the filtered ciphertext set.
//! The resulting `h^r` values are re-used in the TDH KDF to unmask the original
//! plaintexts. Malformed ciphertexts simply appear as missing indices in the
//! canonical batch, so a byzantine sender cannot block honest decryptions.
//!
//! # Acknowledgements
//!
//! The following resources were used as references when implementing this crate:
//!
//! * <https://link.springer.com/chapter/10.1007/3-540-48071-4_7>: Wallet Databases with Observers
//! * <https://link.springer.com/chapter/10.1007/BFb0054113>: Securing threshold cryptosystems against chosen ciphertext attack
//! * <https://link.springer.com/chapter/10.1007/978-3-540-24852-1_36>: Batch Verification for Equality of Discrete Logarithms and Threshold Decryptions

use crate::{
    bls12381::primitives::{
        group::{Element, Point, Scalar, Share},
        poly::{self, Eval},
        variant::Variant,
        Error as PrimitivesError,
    },
    sha256::Sha256,
    transcript::Transcript,
    Hasher,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_codec::{FixedSize, Write};
use core::cmp::min;
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use rayon::{prelude::*, ThreadPoolBuilder};
use thiserror::Error;

/// Transcript namespace for ciphertext Chaum–Pedersen proofs.
const CT_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.ct";
/// Transcript label for ciphertext proof challenges.
const CT_NOISE: &[u8] = b"ct-chal";
/// Transcript namespace for aggregated DLEQ proofs.
const DLEQ_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.dleq";
/// Transcript label for aggregated proof challenges.
const DLEQ_NOISE: &[u8] = b"dleq-chal";
/// Transcript namespace for cross-responder batch scalars.
const RESPONDER_MIX_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.msm";
/// Transcript label for responder mixing scalars.
const RESPONDER_MIX_NOISE: &[u8] = b"msm-mix";
/// Transcript namespace for deriving batch coefficients.
const RHO_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.rho";
/// Transcript label for rho scalars.
const RHO_NOISE: &[u8] = b"rho";
/// Domain label for the TDH KDF.
const KDF_LABEL: &[u8] = b"commonware.bls12381.bte.kdf";
/// Fixed string mapped into a secondary generator for Chaum–Pedersen proofs.
const PROOF_GENERATOR_MSG: &[u8] = b"commonware.bls12381.bte.proof-generator";

/// Public key for TDH encryption (the commitment's constant term).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey<V: Variant> {
    point: V::Public,
}

impl<V: Variant> PublicKey<V> {
    /// Create a public key from a commitment constant (e.g., `poly::Public::constant()`).
    pub fn new(point: V::Public) -> Self {
        Self { point }
    }

    /// Returns the underlying point.
    pub fn as_point(&self) -> &V::Public {
        &self.point
    }
}

/// Chaum–Pedersen proof ensuring `(u, ū)` share the same exponent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaumPedersenProof<V: Variant> {
    pub commitment_generator: V::Public,
    pub commitment_aux: V::Public,
    pub challenge: Scalar,
    pub response: Scalar,
}

/// Ciphertext produced by TDH2 encryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext<V: Variant> {
    pub label: Vec<u8>,
    pub body: Vec<u8>,
    pub header: V::Public,
    pub header_aux: V::Public,
    pub proof: ChaumPedersenProof<V>,
}

/// Batch of ciphertexts plus a caller-chosen context (e.g., request id).
///
/// Ciphertexts whose Chaum–Pedersen proofs fail validation are removed at construction time so
/// downstream decryptions only cover the valid subset. Every participant builds the same
/// [`BatchRequest`] locally from the shared log, avoiding repeated proof verification whenever a
/// server responds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchRequest<V: Variant> {
    pub ciphertexts: Vec<Ciphertext<V>>,
    pub context: Vec<u8>,
    pub threshold: u32,
    pub valid_indices: Vec<u32>,
    pub valid_headers: Vec<V::Public>,
}

impl<V: Variant> BatchRequest<V> {
    /// Build a new batch request by verifying every ciphertext once.
    ///
    /// `concurrency` controls optional Rayon-based parallelism during ciphertext verification (set
    /// to `1` to keep the sequential behavior). On `no_std` builds the parameter is ignored and
    /// verification stays single-threaded.
    pub fn new(
        public: &PublicKey<V>,
        ciphertexts: Vec<Ciphertext<V>>,
        context: Vec<u8>,
        threshold: u32,
        concurrency: usize,
    ) -> Self {
        let mut valid_indices = Vec::new();
        let mut valid_headers = Vec::new();

        #[cfg(feature = "std")]
        let evaluations: Vec<Option<(u32, V::Public)>> = if concurrency > 1 {
            let pool = ThreadPoolBuilder::new()
                .num_threads(concurrency)
                .build()
                .expect("thread pool");
            pool.install(|| {
                ciphertexts
                    .par_iter()
                    .enumerate()
                    .map(|(idx, ct)| {
                        if verify_ciphertext(public, ct) {
                            Some((idx as u32, ct.header))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
        } else {
            ciphertexts
                .iter()
                .enumerate()
                .map(|(idx, ct)| {
                    if verify_ciphertext(public, ct) {
                        Some((idx as u32, ct.header))
                    } else {
                        None
                    }
                })
                .collect()
        };

        #[cfg(not(feature = "std"))]
        let evaluations: Vec<Option<(u32, V::Public)>> = {
            let _ = concurrency;
            ciphertexts
                .iter()
                .enumerate()
                .map(|(idx, ct)| {
                    if verify_ciphertext(public, ct) {
                        Some((idx as u32, ct.header))
                    } else {
                        None
                    }
                })
                .collect()
        };

        for (idx, header) in evaluations.into_iter().flatten() {
            valid_indices.push(idx);
            valid_headers.push(header);
        }

        Self {
            ciphertexts,
            context,
            threshold,
            valid_indices,
            valid_headers,
        }
    }

    pub fn valid_len(&self) -> usize {
        self.valid_indices.len()
    }

    pub fn has_valid_ciphertexts(&self) -> bool {
        !self.valid_indices.is_empty()
    }
}

/// Aggregated Chaum–Pedersen proof over all ciphertexts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatedProof<V: Variant> {
    pub commitment_generator: V::Public,
    pub commitment_aggregate: V::Public,
    pub challenge: Scalar,
    pub response: Scalar,
}

/// Server response containing partial decryptions and a single proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchResponse<V: Variant> {
    pub index: u32,
    /// Positions of ciphertexts (0-indexed) that the server included in this proof.
    pub valid_indices: Vec<u32>,
    pub partials: Vec<V::Public>,
    pub proof: AggregatedProof<V>,
}

/// Errors that can surface while verifying or combining batches.
#[derive(Error, Debug)]
pub enum BatchError {
    #[error("response index {provided} does not match public share {expected}")]
    IndexMismatch { expected: u32, provided: u32 },
    #[error("partials length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("aggregated proof failed for index {0}")]
    InvalidAggregatedProof(u32),
    #[error("duplicate response index {0}")]
    DuplicateIndex(u32),
    #[error("missing lagrange weight for index {0}")]
    MissingWeight(u32),
    #[error("insufficient responses: need {expected}, have {actual}")]
    InsufficientResponses { expected: usize, actual: usize },
    #[error("no valid ciphertexts in batch")]
    NoValidCiphertexts,
    #[error("server reported invalid ciphertext set")]
    InvalidCiphertextSet,
    #[error("weight computation failed: {0}")]
    WeightComputation(#[from] PrimitivesError),
}

/// Encrypt a message with TDH2 using the provided public key.
pub fn encrypt<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    public: &PublicKey<V>,
    label: &[u8],
    message: &[u8],
) -> Ciphertext<V> {
    let r = random_scalar(rng);
    let s = random_scalar(rng);

    let mut header = V::Public::one();
    header.mul(&r);

    let proof_generator = proof_generator::<V>();
    let mut header_aux = proof_generator;
    header_aux.mul(&r);

    let mut hr = public.point;
    hr.mul(&r);

    let mut commitment_generator = V::Public::one();
    commitment_generator.mul(&s);

    let mut commitment_aux = proof_generator;
    commitment_aux.mul(&s);

    let mask = keystream::<V>(&hr, label, message.len());
    let body = xor(message, &mask);

    let challenge = ciphertext_challenge::<V>(
        public,
        label,
        &body,
        &header,
        &header_aux,
        &commitment_generator,
        &commitment_aux,
    );

    let mut response = s;
    let mut tmp = r;
    tmp.mul(&challenge);
    response.add(&tmp);

    let proof = ChaumPedersenProof {
        commitment_generator,
        commitment_aux,
        challenge,
        response,
    };

    Ciphertext {
        label: label.to_vec(),
        body,
        header,
        header_aux,
        proof,
    }
}

/// Verify a TDH2 ciphertext's Chaum–Pedersen proof.
pub fn verify_ciphertext<V: Variant>(public: &PublicKey<V>, ciphertext: &Ciphertext<V>) -> bool {
    let challenge = ciphertext_challenge::<V>(
        public,
        &ciphertext.label,
        &ciphertext.body,
        &ciphertext.header,
        &ciphertext.header_aux,
        &ciphertext.proof.commitment_generator,
        &ciphertext.proof.commitment_aux,
    );

    if challenge != ciphertext.proof.challenge {
        return false;
    }

    let mut lhs = V::Public::one();
    lhs.mul(&ciphertext.proof.response);
    let mut rhs = ciphertext.proof.commitment_generator;
    let mut header_term = ciphertext.header;
    header_term.mul(&ciphertext.proof.challenge);
    rhs.add(&header_term);
    if lhs != rhs {
        return false;
    }

    let proof_generator = proof_generator::<V>();
    let mut lhs_aux = proof_generator;
    lhs_aux.mul(&ciphertext.proof.response);
    let mut rhs_aux = ciphertext.proof.commitment_aux;
    let mut aux_term = ciphertext.header_aux;
    aux_term.mul(&ciphertext.proof.challenge);
    rhs_aux.add(&aux_term);

    lhs_aux == rhs_aux
}

/// Produce a batched response for all valid ciphertexts using a private share.
pub fn respond_to_batch<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    share: &Share,
    request: &BatchRequest<V>,
) -> BatchResponse<V> {
    let index = share.index;
    let headers = &request.valid_headers;
    let partials: Vec<V::Public> = request
        .valid_indices
        .iter()
        .map(|idx| {
            let mut partial = request.ciphertexts[*idx as usize].header;
            partial.mul(&share.private);
            partial
        })
        .collect();

    if headers.is_empty() {
        return BatchResponse {
            index,
            valid_indices: Vec::new(),
            partials,
            proof: AggregatedProof {
                commitment_generator: V::Public::zero(),
                commitment_aggregate: V::Public::zero(),
                challenge: Scalar::zero(),
                response: Scalar::zero(),
            },
        };
    }

    let rhos = derive_rhos::<V>(&request.context, index, headers, &partials);
    let aggregate_base = V::Public::msm(headers, &rhos);
    let aggregate_share = V::Public::msm(&partials, &rhos);

    let s = random_scalar(rng);

    let mut commitment_generator = V::Public::one();
    commitment_generator.mul(&s);

    let mut commitment_aggregate = aggregate_base;
    commitment_aggregate.mul(&s);

    let public_share = share.public::<V>();
    let challenge = aggregated_challenge::<V>(
        &request.context,
        index,
        &public_share,
        &aggregate_base,
        &aggregate_share,
        &commitment_generator,
        &commitment_aggregate,
    );

    let mut response = s;
    let mut tmp = share.private.clone();
    tmp.mul(&challenge);
    response.add(&tmp);

    BatchResponse {
        index,
        valid_indices: request.valid_indices.clone(),
        partials,
        proof: AggregatedProof {
            commitment_generator,
            commitment_aggregate,
            challenge,
            response,
        },
    }
}

/// Verify a server response and return its partial decryptions.
struct PreparedResponse<'a, V: Variant> {
    public_share: &'a Eval<V::Public>,
    response: &'a BatchResponse<V>,
    aggregate_base: V::Public,
    aggregate_share: V::Public,
}

pub fn verify_batch_response<V: Variant>(
    request: &BatchRequest<V>,
    public_share: &Eval<V::Public>,
    response: &BatchResponse<V>,
) -> Result<Vec<V::Public>, BatchError> {
    let prepared = prepare_response(request, public_share, response)?;
    if !verify_prepared_response(&prepared) {
        return Err(BatchError::InvalidAggregatedProof(response.index));
    }
    Ok(response.partials.clone())
}

/// Verify a collection of responses using a single MSM batch check across responders.
///
/// Returns cloned partial decryptions in the same order as the iterator on success or a list of
/// `(share_index, error)` pairs identifying each invalid responder.
pub fn verify_batch_responses<'a, V, I>(
    request: &BatchRequest<V>,
    responses: I,
) -> Result<Vec<Vec<V::Public>>, Vec<(u32, BatchError)>>
where
    V: Variant,
    I: IntoIterator<Item = (&'a Eval<V::Public>, &'a BatchResponse<V>)>,
{
    let mut prepared = Vec::new();
    let mut failures = Vec::new();

    for (public_share, response) in responses.into_iter() {
        match prepare_response(request, public_share, response) {
            Ok(entry) => prepared.push(entry),
            Err(err) => failures.push((response.index, err)),
        }
    }

    if !failures.is_empty() {
        return Err(failures);
    }
    if prepared.is_empty() {
        return Ok(Vec::new());
    }

    if verify_responder_batch(request, &prepared) {
        let partials = prepared
            .iter()
            .map(|entry| entry.response.partials.clone())
            .collect();
        return Ok(partials);
    }

    let mut invalid = find_invalid_responses(request, &prepared);
    if invalid.is_empty() {
        // Fall back to single-response checks if the bisect search could not isolate failures.
        for entry in prepared.iter() {
            if !verify_prepared_response(entry) {
                invalid.push(entry.response.index);
            }
        }
        if invalid.is_empty() {
            invalid.extend(prepared.iter().map(|entry| entry.response.index));
        }
    }
    invalid.sort_unstable();
    invalid.dedup();

    Err(invalid
        .into_iter()
        .map(|idx| (idx, BatchError::InvalidAggregatedProof(idx)))
        .collect())
}

fn prepare_response<'a, V: Variant>(
    request: &BatchRequest<V>,
    public_share: &'a Eval<V::Public>,
    response: &'a BatchResponse<V>,
) -> Result<PreparedResponse<'a, V>, BatchError> {
    if response.index != public_share.index {
        return Err(BatchError::IndexMismatch {
            expected: public_share.index,
            provided: response.index,
        });
    }
    if request.valid_headers.is_empty() {
        return Err(BatchError::NoValidCiphertexts);
    }
    if response.valid_indices != request.valid_indices {
        return Err(BatchError::InvalidCiphertextSet);
    }
    if response.partials.len() != request.valid_headers.len() {
        return Err(BatchError::LengthMismatch {
            expected: request.valid_headers.len(),
            actual: response.partials.len(),
        });
    }

    let rhos = derive_rhos::<V>(
        &request.context,
        response.index,
        &request.valid_headers,
        &response.partials,
    );
    let aggregate_base = V::Public::msm(&request.valid_headers, &rhos);
    let aggregate_share = V::Public::msm(&response.partials, &rhos);

    let expected = aggregated_challenge::<V>(
        &request.context,
        response.index,
        &public_share.value,
        &aggregate_base,
        &aggregate_share,
        &response.proof.commitment_generator,
        &response.proof.commitment_aggregate,
    );
    if expected != response.proof.challenge {
        return Err(BatchError::InvalidAggregatedProof(response.index));
    }

    Ok(PreparedResponse {
        public_share,
        response,
        aggregate_base,
        aggregate_share,
    })
}

fn verify_prepared_response<V: Variant>(prepared: &PreparedResponse<'_, V>) -> bool {
    let proof = &prepared.response.proof;

    let mut lhs = V::Public::one();
    lhs.mul(&proof.response);
    let mut rhs = proof.commitment_generator;
    let mut pk_term = prepared.public_share.value;
    pk_term.mul(&proof.challenge);
    rhs.add(&pk_term);
    if lhs != rhs {
        return false;
    }

    let mut lhs_agg = prepared.aggregate_base;
    lhs_agg.mul(&proof.response);
    let mut rhs_agg = proof.commitment_aggregate;
    let mut agg_term = prepared.aggregate_share;
    agg_term.mul(&proof.challenge);
    rhs_agg.add(&agg_term);

    lhs_agg == rhs_agg
}

fn verify_responder_batch<V: Variant>(
    request: &BatchRequest<V>,
    responses: &[PreparedResponse<'_, V>],
) -> bool {
    if responses.is_empty() {
        return true;
    }
    let betas = derive_responder_mixing_scalars(request, responses);
    verify_msm_equations(responses, &betas)
}

fn derive_responder_mixing_scalars<'a, V: Variant>(
    request: &BatchRequest<V>,
    responses: &[PreparedResponse<'a, V>],
) -> Vec<Scalar> {
    let mut transcript = Transcript::new(RESPONDER_MIX_TRANSCRIPT);
    transcript.commit(request.context.as_slice());
    transcript.commit(
        (request.valid_headers.len() as u64)
            .to_le_bytes()
            .as_slice(),
    );
    for header in request.valid_headers.iter() {
        transcript.commit(encode_field(header).as_slice());
    }
    transcript.commit(
        (request.valid_indices.len() as u64)
            .to_le_bytes()
            .as_slice(),
    );
    for idx in request.valid_indices.iter() {
        transcript.commit(idx.to_le_bytes().as_slice());
    }
    transcript.commit((responses.len() as u64).to_le_bytes().as_slice());
    for prepared in responses.iter() {
        transcript.commit(prepared.response.index.to_le_bytes().as_slice());
        transcript.commit(encode_field(&prepared.public_share.value).as_slice());
        transcript.commit(encode_field(&prepared.aggregate_base).as_slice());
        transcript.commit(encode_field(&prepared.aggregate_share).as_slice());
        transcript.commit(encode_field(&prepared.response.proof.commitment_generator).as_slice());
        transcript.commit(encode_field(&prepared.response.proof.commitment_aggregate).as_slice());
        transcript.commit(encode_field(&prepared.response.proof.challenge).as_slice());
        transcript.commit(encode_field(&prepared.response.proof.response).as_slice());
    }
    let summary = transcript.summarize();

    responses
        .iter()
        .enumerate()
        .map(|(pos, prepared)| {
            let mut mix = Transcript::resume(summary);
            mix.commit((pos as u64).to_le_bytes().as_slice());
            mix.commit(prepared.response.index.to_le_bytes().as_slice());
            scalar_from_transcript(&mix, RESPONDER_MIX_NOISE)
        })
        .collect()
}

fn verify_msm_equations<V: Variant>(
    responses: &[PreparedResponse<'_, V>],
    betas: &[Scalar],
) -> bool {
    debug_assert_eq!(responses.len(), betas.len());
    if responses.is_empty() {
        return true;
    }

    let mut sum_beta_z = Scalar::zero();
    for (entry, beta) in responses.iter().zip(betas.iter()) {
        let mut term = entry.response.proof.response.clone();
        term.mul(beta);
        sum_beta_z.add(&term);
    }

    let mut lhs_g = V::Public::one();
    lhs_g.mul(&sum_beta_z);

    let commitment_generators: Vec<V::Public> = responses
        .iter()
        .map(|entry| entry.response.proof.commitment_generator)
        .collect();
    let mut rhs_g = V::Public::msm(&commitment_generators, betas);

    let public_points: Vec<V::Public> = responses
        .iter()
        .map(|entry| entry.public_share.value)
        .collect();
    let beta_challenges: Vec<Scalar> = responses
        .iter()
        .zip(betas.iter())
        .map(|(entry, beta)| {
            let mut scaled = entry.response.proof.challenge.clone();
            scaled.mul(beta);
            scaled
        })
        .collect();
    let public_term = V::Public::msm(&public_points, &beta_challenges);
    rhs_g.add(&public_term);
    if lhs_g != rhs_g {
        return false;
    }

    let aggregate_bases: Vec<V::Public> =
        responses.iter().map(|entry| entry.aggregate_base).collect();
    let beta_responses: Vec<Scalar> = responses
        .iter()
        .zip(betas.iter())
        .map(|(entry, beta)| {
            let mut scaled = entry.response.proof.response.clone();
            scaled.mul(beta);
            scaled
        })
        .collect();
    let lhs_r = V::Public::msm(&aggregate_bases, &beta_responses);

    let commitment_aggregates: Vec<V::Public> = responses
        .iter()
        .map(|entry| entry.response.proof.commitment_aggregate)
        .collect();
    let mut rhs_r = V::Public::msm(&commitment_aggregates, betas);
    let aggregate_shares: Vec<V::Public> = responses
        .iter()
        .map(|entry| entry.aggregate_share)
        .collect();
    let aggregate_term = V::Public::msm(&aggregate_shares, &beta_challenges);
    rhs_r.add(&aggregate_term);

    lhs_r == rhs_r
}

fn find_invalid_responses<'a, V: Variant>(
    request: &BatchRequest<V>,
    prepared: &[PreparedResponse<'a, V>],
) -> Vec<u32> {
    let mut invalid = Vec::new();
    let mut stack = vec![(0usize, prepared.len())];
    while let Some((start, end)) = stack.pop() {
        if start >= end {
            continue;
        }
        let slice = &prepared[start..end];
        if verify_responder_batch(request, slice) {
            continue;
        }
        if slice.len() == 1 {
            invalid.push(slice[0].response.index);
        } else {
            let mid = start + slice.len() / 2;
            stack.push((mid, end));
            stack.push((start, mid));
        }
    }
    invalid
}

/// Combine verified partials from at least `threshold` distinct servers.
///
/// Returns `(ciphertext_index, plaintext)` pairs for every ciphertext that passed validation.
///
/// `concurrency` controls optional Rayon-based parallelism during the share-scaling phase; pass `1`
/// to keep the operation single-threaded.
pub fn combine_partials<V: Variant>(
    request: &BatchRequest<V>,
    share_indices: &[u32],
    partials: &[Vec<V::Public>],
    concurrency: usize,
) -> Result<Vec<(u32, Vec<u8>)>, BatchError> {
    if share_indices.len() != partials.len() {
        return Err(BatchError::LengthMismatch {
            expected: share_indices.len(),
            actual: partials.len(),
        });
    }

    if share_indices.len() < request.threshold as usize {
        return Err(BatchError::InsufficientResponses {
            expected: request.threshold as usize,
            actual: share_indices.len(),
        });
    }

    let mut sorted = share_indices.to_vec();
    sorted.sort_unstable();
    for window in sorted.windows(2) {
        if window[0] == window[1] {
            return Err(BatchError::DuplicateIndex(window[0]));
        }
    }

    let weights = poly::compute_weights(share_indices.to_vec())?;
    if request.valid_headers.is_empty() {
        return Err(BatchError::NoValidCiphertexts);
    }

    let expected = request.valid_indices.len();
    for set in partials {
        if set.len() != expected {
            return Err(BatchError::LengthMismatch {
                expected,
                actual: set.len(),
            });
        }
    }

    let mut scaled_partials = vec![<V as Variant>::Public::zero(); request.valid_indices.len()];
    if concurrency <= 1 {
        for (share_idx, share_partials) in share_indices.iter().zip(partials.iter()) {
            let lambda = weights
                .get(share_idx)
                .ok_or(BatchError::MissingWeight(*share_idx))?
                .as_scalar()
                .clone();
            for (acc, share_point) in scaled_partials.iter_mut().zip(share_partials.iter()) {
                let mut contrib = *share_point;
                contrib.mul(&lambda);
                acc.add(&contrib);
            }
        }
    } else {
        #[cfg(feature = "std")]
        {
            let pool = ThreadPoolBuilder::new()
                .num_threads(concurrency)
                .build()
                .expect("thread pool");
            let contributions = pool.install(|| {
                share_indices
                    .par_iter()
                    .zip(partials.par_iter())
                    .map(|(share_idx, share_partials)| {
                        let lambda = weights
                            .get(share_idx)
                            .ok_or(BatchError::MissingWeight(*share_idx))?
                            .as_scalar()
                            .clone();
                        let mut vec = Vec::with_capacity(share_partials.len());
                        for point in share_partials.iter() {
                            let mut contrib = *point;
                            contrib.mul(&lambda);
                            vec.push(contrib);
                        }
                        Ok(vec)
                    })
                    .collect::<Result<Vec<_>, BatchError>>()
            })?;
            pool.install(|| {
                scaled_partials
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(idx, acc)| {
                        for vec in contributions.iter() {
                            acc.add(&vec[idx]);
                        }
                    });
            });
        }
        #[cfg(not(feature = "std"))]
        {
            for (share_idx, share_partials) in share_indices.iter().zip(partials.iter()) {
                let lambda = weights
                    .get(share_idx)
                    .ok_or(BatchError::MissingWeight(*share_idx))?
                    .as_scalar()
                    .clone();
                for (acc, share_point) in scaled_partials.iter_mut().zip(share_partials.iter()) {
                    let mut contrib = *share_point;
                    contrib.mul(&lambda);
                    acc.add(&contrib);
                }
            }
        }
    }

    let mut plaintexts = Vec::with_capacity(expected);
    for (pos, &ct_idx) in request.valid_indices.iter().enumerate() {
        let hr = scaled_partials[pos];
        let ct = &request.ciphertexts[ct_idx as usize];
        let keystream = keystream::<V>(&hr, &ct.label, ct.body.len());
        plaintexts.push((ct_idx, xor(&ct.body, &keystream)));
    }

    Ok(plaintexts)
}

/// Fiat–Shamir derive the Chaum–Pedersen challenge for a single ciphertext.
///
/// Transcript commits:
/// * `label`, `body` – pins the payload that the Chaum–Pedersen proof authenticates.
/// * `(header, header_aux)` – TDH commitment pair proven to share the exponent.
/// * `(commitment_generator, commitment_aux)` – prover’s random commitment.
/// * `public` – TDH public key constant term to prevent mix-and-match across keypairs.
fn ciphertext_challenge<V: Variant>(
    public: &PublicKey<V>,
    label: &[u8],
    body: &[u8],
    header: &V::Public,
    header_aux: &V::Public,
    commitment_generator: &V::Public,
    commitment_aux: &V::Public,
) -> Scalar {
    let mut transcript = Transcript::new(CT_TRANSCRIPT);
    transcript.commit(label);
    transcript.commit(body);
    transcript.commit(encode_field(header).as_slice());
    transcript.commit(encode_field(header_aux).as_slice());
    transcript.commit(encode_field(commitment_generator).as_slice());
    transcript.commit(encode_field(commitment_aux).as_slice());
    transcript.commit(encode_field(public.as_point()).as_slice());
    scalar_from_transcript(&transcript, CT_NOISE)
}

/// Fiat–Shamir derive the Chaum–Pedersen challenge for the batched proof sent by each server.
///
/// The transcript binds:
/// * `context` – caller-controlled batch domain so proofs are scoped to a session or epoch.
/// * `index` – responder share index to avoid adversaries swapping proofs between servers.
/// * `public_share` – the server’s long-lived public share (prevents rogue-key substitution).
/// * `(aggregate_base, aggregate_share)` – the random-linear combination of ciphertext headers and
///   claimed partial decryptions.
/// * `(commitment_generator, commitment_aggregate)` – prover commitments to each aggregate.
fn aggregated_challenge<V: Variant>(
    context: &[u8],
    index: u32,
    public_share: &V::Public,
    aggregate_base: &V::Public,
    aggregate_share: &V::Public,
    commitment_generator: &V::Public,
    commitment_aggregate: &V::Public,
) -> Scalar {
    let mut transcript = Transcript::new(DLEQ_TRANSCRIPT);
    transcript.commit(context);
    transcript.commit(index.to_le_bytes().as_slice());
    transcript.commit(encode_field(public_share).as_slice());
    transcript.commit(encode_field(aggregate_base).as_slice());
    transcript.commit(encode_field(aggregate_share).as_slice());
    transcript.commit(encode_field(commitment_generator).as_slice());
    transcript.commit(encode_field(commitment_aggregate).as_slice());
    scalar_from_transcript(&transcript, DLEQ_NOISE)
}

/// Derive the per-ciphertext batching scalars used for the Chaum–Pedersen folding trick.
///
/// The transcript binds:
/// * `context` – caller-chosen batch domain (e.g., request id) so coefficients cannot be replayed
///   across requests.
/// * `index` – responder share index to prevent mix-and-match across servers.
/// * `pos` – the ciphertext position in the canonical filtered list so both sides agree on order.
/// * `header` – the ciphertext’s TDH header; without this the verifier could replace headers.
/// * `partials[pos]` – the responder’s claimed partial decryption for this header; this ensures the
///   aggregated DLEQ challenge commits to every `(header_j, partial_{i,j})` pair.
fn derive_rhos<V: Variant>(
    context: &[u8],
    index: u32,
    headers: &[V::Public],
    partials: &[V::Public],
) -> Vec<Scalar> {
    assert_eq!(
        headers.len(),
        partials.len(),
        "headers and partials must be the same length"
    );

    headers
        .iter()
        .zip(partials.iter())
        .enumerate()
        .map(|(pos, (header, partial))| {
            let mut transcript = Transcript::new(RHO_TRANSCRIPT);
            transcript.commit(context);
            transcript.commit(index.to_le_bytes().as_slice());
            transcript.commit((pos as u64).to_le_bytes().as_slice());
            transcript.commit(encode_field(header).as_slice());
            transcript.commit(encode_field(partial).as_slice());
            scalar_from_transcript(&transcript, RHO_NOISE)
        })
        .collect()
}

/// Expand `h^r` into a deterministic XOR pad used to mask TDH payload bytes.
///
/// The pad is domain-separated by `KDF_LABEL`, includes a counter for streaming expansion, and
/// folds in the ciphertext label so the same `hr` cannot be reused across distinct labels.
fn keystream<V: Variant>(hr: &V::Public, label: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let hr_bytes = encode_field(hr);
    let mut counter = 0u32;
    while out.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(KDF_LABEL);
        hasher.update(&counter.to_le_bytes());
        hasher.update(&hr_bytes);
        hasher.update(label);
        let digest = hasher.finalize();
        let chunk = digest.as_ref();
        let take = min(chunk.len(), len - out.len());
        out.extend_from_slice(&chunk[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// XOR helper that enforces equal-length operands and produces a fresh Vec.
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Sample a non-zero scalar from a transcript-derived RNG, retrying until successful.
fn scalar_from_transcript(transcript: &Transcript, label: &'static [u8]) -> Scalar {
    let mut rng = transcript.noise(label);
    loop {
        let scalar = Scalar::from_rand(&mut rng);
        if scalar != Scalar::zero() {
            return scalar;
        }
    }
}

/// Sample a non-zero scalar from the provided RNG.
fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Scalar {
    loop {
        let scalar = Scalar::from_rand(rng);
        if scalar != Scalar::zero() {
            return scalar;
        }
    }
}

/// Serialize a field element (scalar or group element) in canonical fixed-length form.
fn encode_field<E: FixedSize + Write>(value: &E) -> Vec<u8> {
    let mut buf = Vec::with_capacity(E::SIZE);
    value.write(&mut buf);
    buf
}

/// Deterministically derive the secondary generator used in Chaum–Pedersen proofs.
///
/// The generator is a hash-to-curve of `PROOF_GENERATOR_MSG` using the variant’s MESSAGE DST so all
/// parties agree on the auxiliary base without relying on hard-coded coordinates.
fn proof_generator<V: Variant>() -> V::Public {
    let mut point = V::Public::zero();
    point.map(V::MESSAGE, PROOF_GENERATOR_MSG);
    point
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{dkg::ops::generate_shares, primitives::variant::MinSig};
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, SeedableRng};

    fn setup_request<V: Variant>(
        rng: &mut StdRng,
        count: usize,
    ) -> (PublicKey<V>, BatchRequest<V>, Vec<Vec<u8>>) {
        let (commitment, _) = generate_shares::<_, V>(rng, None, 1, 1);
        let public = PublicKey::<V>::new(*commitment.constant());
        let mut ciphertexts = Vec::with_capacity(count);
        let mut messages = Vec::with_capacity(count);
        for i in 0..count {
            let msg = format!("secret-{i}").into_bytes();
            messages.push(msg.clone());
            ciphertexts.push(encrypt(rng, &public, b"label", &msg));
        }
        let request = BatchRequest::new(&public, ciphertexts, b"context".to_vec(), 1, 1);
        (public, request, messages)
    }

    fn forged_response_from_partials(
        rng: &mut StdRng,
        share: &Share,
        request: &BatchRequest<MinSig>,
        partials: Vec<<MinSig as Variant>::Public>,
    ) -> BatchResponse<MinSig> {
        let index = share.index;
        let rhos = super::derive_rhos::<MinSig>(
            &request.context,
            index,
            &request.valid_headers,
            &partials,
        );
        let aggregate_base = <MinSig as Variant>::Public::msm(&request.valid_headers, &rhos);
        let aggregate_share = <MinSig as Variant>::Public::msm(&partials, &rhos);
        let s = super::random_scalar(rng);
        let mut commitment_generator = <MinSig as Variant>::Public::one();
        commitment_generator.mul(&s);
        let mut commitment_aggregate = aggregate_base;
        commitment_aggregate.mul(&s);
        let public_share = share.public::<MinSig>();
        let challenge = super::aggregated_challenge::<MinSig>(
            &request.context,
            index,
            &public_share,
            &aggregate_base,
            &aggregate_share,
            &commitment_generator,
            &commitment_aggregate,
        );
        let mut response = s;
        let mut tmp = share.private.clone();
        tmp.mul(&challenge);
        response.add(&tmp);
        BatchResponse {
            index,
            valid_indices: request.valid_indices.clone(),
            partials,
            proof: AggregatedProof {
                commitment_generator,
                commitment_aggregate,
                challenge,
                response,
            },
        }
    }

    #[test]
    fn test_ciphertext_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        let (public, request, messages) = setup_request::<MinSig>(&mut rng, 2);
        for (ct, msg) in request.ciphertexts.iter().zip(messages.iter()) {
            let computed = super::ciphertext_challenge::<MinSig>(
                &public,
                &ct.label,
                &ct.body,
                &ct.header,
                &ct.header_aux,
                &ct.proof.commitment_generator,
                &ct.proof.commitment_aux,
            );
            assert_eq!(computed, ct.proof.challenge);
            assert!(verify_ciphertext(&public, ct));
            assert_ne!(ct.body, *msg);
        }
    }

    #[test]
    fn test_batch_flow() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let messages: Vec<Vec<u8>> = (0..3).map(|i| format!("batch-{i}").into_bytes()).collect();
        let ciphertexts: Vec<_> = messages
            .iter()
            .map(|m| encrypt(&mut rng, &public, b"label", m))
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"ctx".to_vec(), threshold, 1);

        let mut indices = Vec::new();
        let mut all_partials = Vec::new();
        for share in shares.iter().take(threshold as usize) {
            let response = respond_to_batch(&mut rng, share, &request);
            let public_share = Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            };
            let partials = verify_batch_response(&request, &public_share, &response).unwrap();
            indices.push(response.index);
            all_partials.push(partials);
        }

        let recovered = combine_partials(&request, &indices, &all_partials, 1).unwrap();
        let mut outputs = recovered
            .into_iter()
            .map(|(idx, msg)| (idx as usize, msg))
            .collect::<Vec<_>>();
        outputs.sort_by_key(|(idx, _)| *idx);
        let recovered_msgs: Vec<Vec<u8>> = outputs.into_iter().map(|(_, msg)| msg).collect();
        assert_eq!(recovered_msgs, messages);
    }

    #[test]
    fn test_verify_batch_responses_success() {
        let mut rng = StdRng::seed_from_u64(58);
        let n = 6;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let ciphertexts: Vec<_> = (0..4)
            .map(|i| {
                encrypt(
                    &mut rng,
                    &public,
                    b"label",
                    format!("batched-{i}").as_bytes(),
                )
            })
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"batch".to_vec(), threshold, 1);

        let responses: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|share| respond_to_batch(&mut rng, share, &request))
            .collect();
        let evals: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|share| Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            })
            .collect();

        let verified =
            verify_batch_responses(&request, evals.iter().zip(responses.iter())).unwrap();
        assert_eq!(verified.len(), threshold as usize);
        for (expected, actual) in responses
            .iter()
            .map(|resp| resp.partials.clone())
            .zip(verified)
        {
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_verify_batch_responses_detects_invalid() {
        let mut rng = StdRng::seed_from_u64(77);
        let n = 6;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let ciphertexts: Vec<_> = (0..3)
            .map(|i| encrypt(&mut rng, &public, b"label", format!("proof-{i}").as_bytes()))
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"ctx".to_vec(), threshold, 1);
        assert!(
            request.valid_len() >= 2,
            "need at least two ciphertexts for tampering test"
        );

        let mut responses: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|share| respond_to_batch(&mut rng, share, &request))
            .collect();
        let evals: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|share| Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            })
            .collect();

        let first = &shares[0];
        let honest = &responses[0];
        let mut forged_partials = honest.partials.clone();
        let tweak = <MinSig as Variant>::Public::one();
        forged_partials[0].add(&tweak);

        let legacy_rhos = super::derive_rhos::<MinSig>(
            &request.context,
            first.index,
            &request.valid_headers,
            &honest.partials,
        );
        let honest_sum = <MinSig as Variant>::Public::msm(&honest.partials, &legacy_rhos);
        let last = forged_partials.len() - 1;
        let mut prefix = <MinSig as Variant>::Public::zero();
        for (point, rho) in forged_partials.iter().zip(legacy_rhos.iter()).take(last) {
            let mut term = *point;
            term.mul(rho);
            prefix.add(&term);
        }
        let mut neg_prefix = prefix;
        let mut neg_one = Scalar::zero();
        neg_one.sub(&Scalar::from(1u64));
        neg_prefix.mul(&neg_one);
        let mut adjusted_last = honest_sum;
        adjusted_last.add(&neg_prefix);
        let rho_last_inv = legacy_rhos[last]
            .inverse()
            .expect("rho scalars are sampled non-zero");
        adjusted_last.mul(&rho_last_inv);
        forged_partials[last] = adjusted_last;

        responses[0] = forged_response_from_partials(&mut rng, first, &request, forged_partials);

        let result = verify_batch_responses(&request, evals.iter().zip(responses.iter()));
        let errors = result.expect_err("batch verification should fail");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, first.index);
        assert!(matches!(errors[0].1, BatchError::InvalidAggregatedProof(_)));
    }

    #[test]
    fn test_verify_batch_responses_reports_structural_errors() {
        let mut rng = StdRng::seed_from_u64(101);
        let n = 5;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let ciphertexts: Vec<_> = (0..3)
            .map(|i| {
                encrypt(
                    &mut rng,
                    &public,
                    b"label",
                    format!("struct-{i}").as_bytes(),
                )
            })
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"struct".to_vec(), threshold, 1);
        let responses: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|share| respond_to_batch(&mut rng, share, &request))
            .collect();
        let evals: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|share| Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            })
            .collect();

        let mut tampered = responses.clone();
        tampered[0].valid_indices.pop();
        let result = verify_batch_responses(&request, evals.iter().zip(tampered.iter()));
        let errors = result.expect_err("structural mismatch should fail");
        assert!(matches!(errors[0].1, BatchError::InvalidCiphertextSet));
    }

    #[test]
    fn test_invalid_ciphertext_detection() {
        let mut rng = StdRng::seed_from_u64(9);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 4, 3);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let msg = b"attack".to_vec();
        let mut ciphertext = encrypt(&mut rng, &public, b"label", &msg);
        ciphertext.proof.challenge = random_scalar(&mut rng);
        let request = BatchRequest::new(&public, vec![ciphertext], b"ctx".to_vec(), 3, 1);
        let share = &shares[0];
        let response = respond_to_batch(&mut rng, share, &request);
        let eval = Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        };
        assert!(matches!(
            verify_batch_response(&request, &eval, &response),
            Err(BatchError::NoValidCiphertexts)
        ));
    }

    #[test]
    fn test_skips_invalid_ciphertext() {
        let mut rng = StdRng::seed_from_u64(55);
        let n = 5;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let mut ciphertexts: Vec<_> = (0..4)
            .map(|i| encrypt(&mut rng, &public, b"label", format!("msg-{i}").as_bytes()))
            .collect();
        ciphertexts[1].proof.challenge = random_scalar(&mut rng);
        let request = BatchRequest::new(&public, ciphertexts, b"skip".to_vec(), threshold, 1);

        let mut indices = Vec::new();
        let mut partials = Vec::new();
        for share in shares.iter().take(threshold as usize) {
            let response = respond_to_batch(&mut rng, share, &request);
            let eval = Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            };
            let verified = verify_batch_response(&request, &eval, &response).unwrap();
            assert_eq!(verified.len(), 3); // one ciphertext skipped
            indices.push(response.index);
            partials.push(verified);
        }

        let recovered = combine_partials(&request, &indices, &partials, 1).unwrap();
        let mut recovered_indices = recovered.iter().map(|(idx, _)| *idx).collect::<Vec<_>>();
        recovered_indices.sort_unstable();
        assert_eq!(recovered_indices, vec![0, 2, 3]);
        for (idx, plaintext) in recovered {
            if idx == 1 {
                panic!("invalid ciphertext should be skipped");
            }
            let expected = format!("msg-{idx}").into_bytes();
            assert_eq!(plaintext, expected);
        }
    }

    #[test]
    fn test_invalid_share_detection() {
        let mut rng = StdRng::seed_from_u64(99);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 4, 3);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let messages: Vec<Vec<u8>> = (0..2).map(|i| format!("secret-{i}").into_bytes()).collect();
        let request = BatchRequest::new(
            &public,
            messages
                .iter()
                .map(|m| encrypt(&mut rng, &public, b"label", m))
                .collect(),
            b"ctx".to_vec(),
            3,
            1,
        );

        let share = &shares[0];
        let mut response = respond_to_batch(&mut rng, share, &request);
        response.proof.challenge = random_scalar(&mut rng);
        let eval = Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        };
        assert!(matches!(
            verify_batch_response(&request, &eval, &response),
            Err(BatchError::InvalidAggregatedProof(_))
        ));
    }

    #[test]
    fn test_verify_batch_response_length_mismatch() {
        let mut rng = StdRng::seed_from_u64(123);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 3, 2);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let request = BatchRequest::new(
            &public,
            (0..2)
                .map(|i| encrypt(&mut rng, &public, b"ctx", format!("msg-{i}").as_bytes()))
                .collect(),
            b"len".to_vec(),
            2,
            1,
        );
        let share = &shares[0];
        let mut response = respond_to_batch(&mut rng, share, &request);
        response.partials.pop();
        let eval = Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        };
        assert!(matches!(
            verify_batch_response(&request, &eval, &response),
            Err(BatchError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_batch_response_index_mismatch() {
        let mut rng = StdRng::seed_from_u64(321);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 3, 2);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let request = BatchRequest::new(
            &public,
            (0..2)
                .map(|i| encrypt(&mut rng, &public, b"ctx", format!("msg-{i}").as_bytes()))
                .collect(),
            b"idx".to_vec(),
            2,
            1,
        );
        let response = respond_to_batch(&mut rng, &shares[0], &request);
        let eval = Eval {
            index: shares[1].index,
            value: shares[1].public::<MinSig>(),
        };
        assert!(matches!(
            verify_batch_response(&request, &eval, &response),
            Err(BatchError::IndexMismatch { .. })
        ));
    }

    #[test]
    fn test_combine_partials_insufficient_responses() {
        let mut rng = StdRng::seed_from_u64(777);
        let n = 4;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let request = BatchRequest::new(
            &public,
            (0..5)
                .map(|i| encrypt(&mut rng, &public, b"ctx", format!("msg-{i}").as_bytes()))
                .collect(),
            b"insufficient".to_vec(),
            threshold,
            1,
        );
        let response = respond_to_batch(&mut rng, &shares[0], &request);
        let eval = Eval {
            index: shares[0].index,
            value: shares[0].public::<MinSig>(),
        };
        let partials = verify_batch_response(&request, &eval, &response).unwrap();
        let err = combine_partials(&request, &[response.index], &[partials], 1).unwrap_err();
        assert!(matches!(
            err,
            BatchError::InsufficientResponses { expected, actual }
            if expected == threshold as usize && actual == 1
        ));
    }

    #[test]
    fn test_combine_partials_duplicate_indices() {
        let mut rng = StdRng::seed_from_u64(888);
        let n = 4;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let request = BatchRequest::new(
            &public,
            (0..3)
                .map(|i| encrypt(&mut rng, &public, b"ctx", format!("msg-{i}").as_bytes()))
                .collect(),
            b"dup".to_vec(),
            threshold,
            1,
        );
        let mut indices = Vec::new();
        let mut partials = Vec::new();
        for share in shares.iter().take(threshold as usize) {
            let response = respond_to_batch(&mut rng, share, &request);
            let eval = Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            };
            let verified = verify_batch_response(&request, &eval, &response).unwrap();
            indices.push(response.index);
            partials.push(verified);
        }
        indices.push(indices[1]);
        partials.push(partials[1].clone());
        let err = combine_partials(&request, &indices, &partials, 1).unwrap_err();
        assert!(matches!(err, BatchError::DuplicateIndex(_)));
    }

    #[test]
    fn test_detects_forged_aggregated_response() {
        let mut rng = StdRng::seed_from_u64(1337);
        let n = 4;
        let threshold = 2;
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let ciphertexts: Vec<_> = (0..3)
            .map(|i| encrypt(&mut rng, &public, b"label", format!("forge-{i}").as_bytes()))
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"ctx".to_vec(), threshold, 2);
        assert!(
            request.valid_len() >= 2,
            "need at least two valid ciphertexts"
        );

        let share = &shares[0];
        let honest = respond_to_batch(&mut rng, share, &request);

        // Malicious server tampers with the first partial and adjusts the last one
        // to keep the old aggregated sum identical.
        let mut forged_partials = honest.partials.clone();
        let tweak = <MinSig as Variant>::Public::one();
        forged_partials[0].add(&tweak);

        let legacy_rhos = super::derive_rhos::<MinSig>(
            &request.context,
            share.index,
            &request.valid_headers,
            &honest.partials,
        );
        let honest_sum = <MinSig as Variant>::Public::msm(&honest.partials, &legacy_rhos);
        let last = forged_partials.len() - 1;
        let mut prefix = <MinSig as Variant>::Public::zero();
        for (point, rho) in forged_partials.iter().zip(legacy_rhos.iter()).take(last) {
            let mut term = *point;
            term.mul(rho);
            prefix.add(&term);
        }
        let mut neg_prefix = prefix;
        let mut neg_one = Scalar::zero();
        neg_one.sub(&Scalar::from(1u64));
        neg_prefix.mul(&neg_one);
        let mut adjusted_last = honest_sum;
        adjusted_last.add(&neg_prefix);
        let rho_last_inv = legacy_rhos[last]
            .inverse()
            .expect("rho scalars are sampled non-zero");
        adjusted_last.mul(&rho_last_inv);
        forged_partials[last] = adjusted_last;

        let forged_response =
            forged_response_from_partials(&mut rng, share, &request, forged_partials);
        let eval = Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        };

        assert!(matches!(
            verify_batch_response(&request, &eval, &forged_response),
            Err(BatchError::InvalidAggregatedProof(_))
        ));
    }
}
