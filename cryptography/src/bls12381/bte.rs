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
//! * Boneh, Bünz, Nayak, Rotem, and Shoup. *Context-Dependent Threshold Decryption and its Applications.*

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
use alloc::{collections::BTreeSet, vec, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;
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
/// Transcript namespace for deriving context binding points.
const CTX_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.ctx-point";
/// Transcript label for context binding scalars.
const CTX_NOISE: &[u8] = b"ctx";
/// Transcript namespace for deriving batch coefficients.
const RHO_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.rho";
/// Transcript label for rho scalars.
const RHO_NOISE: &[u8] = b"rho";
/// Transcript namespace for across-responder batching coefficients.
const BETA_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.beta";
/// Transcript label for beta scalars.
const BETA_NOISE: &[u8] = b"beta";
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
    pub valid_contexts: Vec<V::Public>,
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
        let mut valid_contexts = Vec::new();

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
            let ctx_point = derive_context_point::<V>(&context, idx, &ciphertexts[idx as usize]);
            valid_contexts.push(ctx_point);
        }

        Self {
            ciphertexts,
            context,
            threshold,
            valid_indices,
            valid_headers,
            valid_contexts,
        }
    }

    pub fn valid_len(&self) -> usize {
        self.valid_indices.len()
    }

    pub fn has_valid_ciphertexts(&self) -> bool {
        !self.valid_indices.is_empty()
    }
}

/// Public inputs for context-dependent TDH verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextPublicShare<V: Variant> {
    pub secret: Eval<V::Public>,
    pub mask: Eval<V::Public>,
}

/// Aggregated Schnorr proof binding `(x_i, z_i)` to the batch and context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextProof<V: Variant> {
    pub commitment_secret: V::Public,
    pub commitment_mask: V::Public,
    pub commitment_share: V::Public,
    pub challenge: Scalar,
    pub response_secret: Scalar,
    pub response_mask: Scalar,
}

/// Server response containing partial decryptions and a single proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchResponse<V: Variant> {
    pub index: u32,
    /// Positions of ciphertexts (0-indexed) that the server included in this proof.
    pub valid_indices: Vec<u32>,
    pub partials: Vec<V::Public>,
    pub proof: ContextProof<V>,
}

/// Result of batch-verifying responder proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchVerification<V: Variant> {
    pub valid: Vec<(u32, Vec<V::Public>)>,
    pub invalid: Vec<u32>,
}

#[derive(Clone)]
struct ResponseData<V: Variant> {
    index: u32,
    aggregate_base: V::Public,
    aggregate_context: V::Public,
    aggregate_share: V::Public,
    public_secret: V::Public,
    public_mask: V::Public,
    proof: ContextProof<V>,
    partials: Vec<V::Public>,
}

struct BatchItem<V: Variant> {
    data: ResponseData<V>,
    beta: Scalar,
}

fn prepare_response_data<V: Variant>(
    request: &BatchRequest<V>,
    public_share: &ContextPublicShare<V>,
    response: &BatchResponse<V>,
) -> Result<ResponseData<V>, BatchError> {
    if response.index != public_share.secret.index {
        return Err(BatchError::IndexMismatch {
            expected: public_share.secret.index,
            provided: response.index,
        });
    }
    if response.index != public_share.mask.index {
        return Err(BatchError::IndexMismatch {
            expected: public_share.mask.index,
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
    let aggregate_context = V::Public::msm(&request.valid_contexts, &rhos);
    let aggregate_share = V::Public::msm(&response.partials, &rhos);

    let expected = aggregated_challenge::<V>(
        &request.context,
        response.index,
        &public_share.secret.value,
        &public_share.mask.value,
        &aggregate_base,
        &aggregate_context,
        &aggregate_share,
        &response.proof.commitment_secret,
        &response.proof.commitment_mask,
        &response.proof.commitment_share,
    );

    if expected != response.proof.challenge {
        return Err(BatchError::InvalidAggregatedProof(response.index));
    }

    Ok(ResponseData {
        index: response.index,
        aggregate_base,
        aggregate_context,
        aggregate_share,
        public_secret: public_share.secret.value,
        public_mask: public_share.mask.value,
        proof: response.proof.clone(),
        partials: response.partials.clone(),
    })
}

fn verify_response_equations<V: Variant>(data: &ResponseData<V>) -> bool {
    let mut lhs_secret = V::Public::one();
    lhs_secret.mul(&data.proof.response_secret);
    let mut rhs_secret = data.proof.commitment_secret;
    let mut pk_term = data.public_secret;
    pk_term.mul(&data.proof.challenge);
    rhs_secret.add(&pk_term);
    if lhs_secret != rhs_secret {
        return false;
    }

    let mut lhs_mask = V::Public::one();
    lhs_mask.mul(&data.proof.response_mask);
    let mut rhs_mask = data.proof.commitment_mask;
    let mut mask_term = data.public_mask;
    mask_term.mul(&data.proof.challenge);
    rhs_mask.add(&mask_term);
    if lhs_mask != rhs_mask {
        return false;
    }

    let mut lhs_share = data.aggregate_base;
    lhs_share.mul(&data.proof.response_secret);
    let mut ctx_term = data.aggregate_context;
    ctx_term.mul(&data.proof.response_mask);
    lhs_share.add(&ctx_term);

    let mut rhs_share = data.proof.commitment_share;
    let mut agg_term = data.aggregate_share;
    agg_term.mul(&data.proof.challenge);
    rhs_share.add(&agg_term);

    lhs_share == rhs_share
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
    #[error("missing public share for index {0}")]
    MissingPublicShare(u32),
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

/// Produce a batched response for all valid ciphertexts using the `(x_i, z_i)` shares.
pub fn respond_to_batch<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    secret_share: &Share,
    mask_share: &Share,
    request: &BatchRequest<V>,
) -> BatchResponse<V> {
    assert_eq!(
        secret_share.index, mask_share.index,
        "context-dependent shares must use the same evaluation index"
    );
    let index = secret_share.index;
    let headers = &request.valid_headers;
    let partials: Vec<V::Public> = request
        .valid_headers
        .iter()
        .zip(request.valid_contexts.iter())
        .map(|(header, context_base)| {
            let mut partial = *header;
            partial.mul(&secret_share.private);
            let mut ctx_term = *context_base;
            ctx_term.mul(&mask_share.private);
            partial.add(&ctx_term);
            partial
        })
        .collect();

    if headers.is_empty() {
        return BatchResponse {
            index,
            valid_indices: Vec::new(),
            partials,
            proof: ContextProof {
                commitment_secret: V::Public::zero(),
                commitment_mask: V::Public::zero(),
                commitment_share: V::Public::zero(),
                challenge: Scalar::zero(),
                response_secret: Scalar::zero(),
                response_mask: Scalar::zero(),
            },
        };
    }

    let rhos = derive_rhos::<V>(&request.context, index, headers, &partials);
    let aggregate_base = V::Public::msm(headers, &rhos);
    let aggregate_context = V::Public::msm(&request.valid_contexts, &rhos);
    let aggregate_share = V::Public::msm(&partials, &rhos);

    let s_secret = random_scalar(rng);
    let s_mask = random_scalar(rng);

    let mut commitment_secret = V::Public::one();
    commitment_secret.mul(&s_secret);

    let mut commitment_mask = V::Public::one();
    commitment_mask.mul(&s_mask);

    let mut commitment_share = aggregate_base;
    commitment_share.mul(&s_secret);
    let mut ctx_commitment = aggregate_context;
    ctx_commitment.mul(&s_mask);
    commitment_share.add(&ctx_commitment);

    let public_secret = secret_share.public::<V>();
    let public_mask = mask_share.public::<V>();
    let challenge = aggregated_challenge::<V>(
        &request.context,
        index,
        &public_secret,
        &public_mask,
        &aggregate_base,
        &aggregate_context,
        &aggregate_share,
        &commitment_secret,
        &commitment_mask,
        &commitment_share,
    );

    let mut response_secret = s_secret;
    let mut tmp = secret_share.private.clone();
    tmp.mul(&challenge);
    response_secret.add(&tmp);

    let mut response_mask = s_mask;
    let mut tmp_mask = mask_share.private.clone();
    tmp_mask.mul(&challenge);
    response_mask.add(&tmp_mask);

    BatchResponse {
        index,
        valid_indices: request.valid_indices.clone(),
        partials,
        proof: ContextProof {
            commitment_secret,
            commitment_mask,
            commitment_share,
            challenge,
            response_secret,
            response_mask,
        },
    }
}

/// Verify a server response and return its partial decryptions.
pub fn verify_batch_response<V: Variant>(
    request: &BatchRequest<V>,
    public_share: &ContextPublicShare<V>,
    response: &BatchResponse<V>,
) -> Result<Vec<V::Public>, BatchError> {
    let data = prepare_response_data(request, public_share, response)?;
    if !verify_response_equations(&data) {
        return Err(BatchError::InvalidAggregatedProof(data.index));
    }
    Ok(data.partials)
}

/// Verify many responses at once using a randomized MSM check plus binary-search blame.
pub fn batch_verify_responses<V: Variant>(
    request: &BatchRequest<V>,
    public_shares: &[ContextPublicShare<V>],
    responses: &[BatchResponse<V>],
) -> Result<BatchVerification<V>, BatchError> {
    let mut seen = BTreeSet::new();
    let mut items = Vec::with_capacity(responses.len());
    let mut invalid = Vec::new();
    for response in responses {
        if !seen.insert(response.index) {
            return Err(BatchError::DuplicateIndex(response.index));
        }
        let share = public_shares
            .iter()
            .find(|share| share.secret.index == response.index)
            .ok_or(BatchError::MissingPublicShare(response.index))?;
        let data = prepare_response_data(request, share, response)?;
        if !verify_response_equations(&data) {
            invalid.push(data.index);
            continue;
        }
        let beta = derive_beta(request, &data);
        items.push(BatchItem { data, beta });
    }

    let mut valid_data = Vec::new();
    collect_valid_items(&items, &mut valid_data, &mut invalid);
    let valid = valid_data
        .into_iter()
        .map(|data| (data.index, data.partials))
        .collect();
    Ok(BatchVerification { valid, invalid })
}

fn derive_beta<V: Variant>(request: &BatchRequest<V>, data: &ResponseData<V>) -> Scalar {
    let mut transcript = Transcript::new(BETA_TRANSCRIPT);
    transcript.commit(request.context.as_slice());
    transcript.commit(data.index.to_le_bytes().as_slice());
    transcript.commit(encode_field(&data.public_secret).as_slice());
    transcript.commit(encode_field(&data.public_mask).as_slice());
    transcript.commit(encode_field(&data.aggregate_share).as_slice());
    transcript.commit(encode_field(&data.proof.commitment_secret).as_slice());
    transcript.commit(encode_field(&data.proof.commitment_mask).as_slice());
    transcript.commit(encode_field(&data.proof.commitment_share).as_slice());
    scalar_from_transcript(&transcript, BETA_NOISE)
}

fn collect_valid_items<V: Variant>(
    items: &[BatchItem<V>],
    valid: &mut Vec<ResponseData<V>>,
    invalid: &mut Vec<u32>,
) {
    if items.is_empty() {
        return;
    }
    if batch_equations_hold(items) {
        valid.extend(items.iter().map(|item| item.data.clone()));
        return;
    }
    if items.len() == 1 {
        invalid.push(items[0].data.index);
        return;
    }
    let mid = items.len() / 2;
    collect_valid_items(&items[..mid], valid, invalid);
    collect_valid_items(&items[mid..], valid, invalid);
}

fn batch_equations_hold<V: Variant>(items: &[BatchItem<V>]) -> bool {
    if items.is_empty() {
        return true;
    }

    let mut betas = Vec::with_capacity(items.len());
    let mut points_secret = Vec::with_capacity(items.len());
    let mut points_mask = Vec::with_capacity(items.len());
    let mut points_share = Vec::with_capacity(items.len());
    let mut aggregate_bases = Vec::with_capacity(items.len());
    let mut aggregate_contexts = Vec::with_capacity(items.len());
    let mut scalars_secret = Vec::with_capacity(items.len());
    let mut scalars_mask = Vec::with_capacity(items.len());
    let mut sum_secret = Scalar::zero();
    let mut sum_mask = Scalar::zero();

    for item in items {
        let beta = item.beta.clone();
        betas.push(beta.clone());

        let mut secret_point = item.data.proof.commitment_secret;
        let mut pk_term = item.data.public_secret;
        pk_term.mul(&item.data.proof.challenge);
        secret_point.add(&pk_term);
        points_secret.push(secret_point);

        let mut mask_point = item.data.proof.commitment_mask;
        let mut mask_term = item.data.public_mask;
        mask_term.mul(&item.data.proof.challenge);
        mask_point.add(&mask_term);
        points_mask.push(mask_point);

        let mut share_point = item.data.proof.commitment_share;
        let mut agg_term = item.data.aggregate_share;
        agg_term.mul(&item.data.proof.challenge);
        share_point.add(&agg_term);
        points_share.push(share_point);

        aggregate_bases.push(item.data.aggregate_base);
        aggregate_contexts.push(item.data.aggregate_context);

        let mut resp_secret = item.data.proof.response_secret.clone();
        resp_secret.mul(&beta);
        sum_secret.add(&resp_secret);
        scalars_secret.push(resp_secret.clone());

        let mut resp_mask = item.data.proof.response_mask.clone();
        resp_mask.mul(&beta);
        sum_mask.add(&resp_mask);
        scalars_mask.push(resp_mask);
    }

    let lhs_secret = V::Public::msm(&points_secret, &betas);
    let mut rhs_secret = V::Public::one();
    rhs_secret.mul(&sum_secret);
    if lhs_secret != rhs_secret {
        return false;
    }

    let lhs_mask = V::Public::msm(&points_mask, &betas);
    let mut rhs_mask = V::Public::one();
    rhs_mask.mul(&sum_mask);
    if lhs_mask != rhs_mask {
        return false;
    }

    let lhs_share = V::Public::msm(&points_share, &betas);
    let rhs_share_secret = V::Public::msm(&aggregate_bases, &scalars_secret);
    let rhs_share_mask = V::Public::msm(&aggregate_contexts, &scalars_mask);
    let mut rhs_share = rhs_share_secret;
    rhs_share.add(&rhs_share_mask);
    lhs_share == rhs_share
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
/// * `public_secret` / `public_mask` – long-lived public shares for `x_i` and `z_i`.
/// * `(aggregate_base, aggregate_context, aggregate_share)` – random-linear combination of
///   headers, context bases, and claimed partial decryptions.
/// * `(commitment_secret, commitment_mask, commitment_share)` – prover commitments for each
///   relation.
fn aggregated_challenge<V: Variant>(
    context: &[u8],
    index: u32,
    public_secret: &V::Public,
    public_mask: &V::Public,
    aggregate_base: &V::Public,
    aggregate_context: &V::Public,
    aggregate_share: &V::Public,
    commitment_secret: &V::Public,
    commitment_mask: &V::Public,
    commitment_share: &V::Public,
) -> Scalar {
    let mut transcript = Transcript::new(DLEQ_TRANSCRIPT);
    transcript.commit(context);
    transcript.commit(index.to_le_bytes().as_slice());
    transcript.commit(encode_field(public_secret).as_slice());
    transcript.commit(encode_field(public_mask).as_slice());
    transcript.commit(encode_field(aggregate_base).as_slice());
    transcript.commit(encode_field(aggregate_context).as_slice());
    transcript.commit(encode_field(aggregate_share).as_slice());
    transcript.commit(encode_field(commitment_secret).as_slice());
    transcript.commit(encode_field(commitment_mask).as_slice());
    transcript.commit(encode_field(commitment_share).as_slice());
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

/// Hash the batch context, ciphertext metadata, and canonical index into a curve point used to
/// bind responses to a specific decryption domain.
fn derive_context_point<V: Variant>(
    context: &[u8],
    index: u32,
    ciphertext: &Ciphertext<V>,
) -> V::Public {
    let mut transcript = Transcript::new(CTX_TRANSCRIPT);
    transcript.commit(context);
    transcript.commit(index.to_le_bytes().as_slice());
    transcript.commit(ciphertext.label.as_slice());
    transcript.commit(ciphertext.body.as_slice());
    transcript.commit(encode_field(&ciphertext.header).as_slice());
    transcript.commit(encode_field(&ciphertext.header_aux).as_slice());
    let scalar = scalar_from_transcript(&transcript, CTX_NOISE);
    let mut point = V::Public::one();
    point.mul(&scalar);
    point
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
    use crate::bls12381::{
        dkg::ops::generate_shares,
        primitives::{
            group::{Scalar, Share},
            variant::MinSig,
        },
    };
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

    fn generate_mask_shares<V: Variant>(
        rng: &mut StdRng,
        n: u32,
        threshold: u32,
    ) -> Vec<Share> {
        let zero = Share {
            index: 0,
            private: Scalar::zero(),
        };
        let (_, shares) = generate_shares::<_, V>(rng, Some(zero), n, threshold);
        shares
    }

    fn context_public_share<V: Variant>(
        share: &Share,
        mask: &Share,
    ) -> ContextPublicShare<V> {
        ContextPublicShare {
            secret: Eval {
                index: share.index,
                value: share.public::<V>(),
            },
            mask: Eval {
                index: mask.index,
                value: mask.public::<V>(),
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
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let messages: Vec<Vec<u8>> = (0..3).map(|i| format!("batch-{i}").into_bytes()).collect();
        let ciphertexts: Vec<_> = messages
            .iter()
            .map(|m| encrypt(&mut rng, &public, b"label", m))
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"ctx".to_vec(), threshold, 1);

        let mut indices = Vec::new();
        let mut all_partials = Vec::new();
        for (share, mask, public_share) in shares
            .iter()
            .zip(mask_shares.iter())
            .map(|(share, mask)| (share, mask, context_public_share::<MinSig>(share, mask)))
            .take(threshold as usize)
        {
            let response = respond_to_batch(&mut rng, share, mask, &request);
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
    fn test_invalid_ciphertext_detection() {
        let mut rng = StdRng::seed_from_u64(9);
        let threshold = 3;
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 4, threshold);
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, 4, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let msg = b"attack".to_vec();
        let mut ciphertext = encrypt(&mut rng, &public, b"label", &msg);
        ciphertext.proof.challenge = random_scalar(&mut rng);
        let request = BatchRequest::new(&public, vec![ciphertext], b"ctx".to_vec(), threshold, 1);
        let share = &shares[0];
        let mask = &mask_shares[0];
        let response = respond_to_batch(&mut rng, share, mask, &request);
        let eval = context_public_share::<MinSig>(share, mask);
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
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let mut ciphertexts: Vec<_> = (0..4)
            .map(|i| encrypt(&mut rng, &public, b"label", format!("msg-{i}").as_bytes()))
            .collect();
        ciphertexts[1].proof.challenge = random_scalar(&mut rng);
        let request = BatchRequest::new(&public, ciphertexts, b"skip".to_vec(), threshold, 1);

        let mut indices = Vec::new();
        let mut partials = Vec::new();
        for (share, mask, public_share) in shares
            .iter()
            .zip(mask_shares.iter())
            .map(|(share, mask)| (share, mask, context_public_share::<MinSig>(share, mask)))
            .take(threshold as usize)
        {
            let response = respond_to_batch(&mut rng, share, mask, &request);
            let verified = verify_batch_response(&request, &public_share, &response).unwrap();
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
        let threshold = 3;
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 4, threshold);
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, 4, threshold);
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
        let mask = &mask_shares[0];
        let mut response = respond_to_batch(&mut rng, share, mask, &request);
        response.proof.challenge = random_scalar(&mut rng);
        let eval = context_public_share::<MinSig>(share, mask);
        assert!(matches!(
            verify_batch_response(&request, &eval, &response),
            Err(BatchError::InvalidAggregatedProof(_))
        ));
    }

    #[test]
    fn test_verify_batch_response_length_mismatch() {
        let mut rng = StdRng::seed_from_u64(123);
        let threshold = 2;
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 3, threshold);
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, 3, threshold);
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
        let mask = &mask_shares[0];
        let mut response = respond_to_batch(&mut rng, share, mask, &request);
        response.partials.pop();
        let eval = context_public_share::<MinSig>(share, mask);
        assert!(matches!(
            verify_batch_response(&request, &eval, &response),
            Err(BatchError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_batch_response_index_mismatch() {
        let mut rng = StdRng::seed_from_u64(321);
        let threshold = 2;
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 3, threshold);
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, 3, threshold);
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
        let response = respond_to_batch(&mut rng, &shares[0], &mask_shares[0], &request);
        let eval = context_public_share::<MinSig>(&shares[1], &mask_shares[1]);
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
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, n, threshold);
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
        let response = respond_to_batch(&mut rng, &shares[0], &mask_shares[0], &request);
        let eval = context_public_share::<MinSig>(&shares[0], &mask_shares[0]);
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
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, n, threshold);
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
        for (share, mask, eval) in shares
            .iter()
            .zip(mask_shares.iter())
            .map(|(share, mask)| (share, mask, context_public_share::<MinSig>(share, mask)))
            .take(threshold as usize)
        {
            let response = respond_to_batch(&mut rng, share, mask, &request);
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
        let mask_shares = generate_mask_shares::<MinSig>(&mut rng, n, threshold);
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
        let mask = &mask_shares[0];
        let public_share = context_public_share::<MinSig>(share, mask);
        let honest = respond_to_batch(&mut rng, share, mask, &request);

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

        fn forged_response_from_partials(
            rng: &mut StdRng,
            share: &Share,
            mask: &Share,
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
            let aggregate_context = <MinSig as Variant>::Public::msm(&request.valid_contexts, &rhos);
            let aggregate_share = <MinSig as Variant>::Public::msm(&partials, &rhos);
            let s_secret = super::random_scalar(rng);
            let s_mask = super::random_scalar(rng);
            let mut commitment_secret = <MinSig as Variant>::Public::one();
            commitment_secret.mul(&s_secret);
            let mut commitment_mask = <MinSig as Variant>::Public::one();
            commitment_mask.mul(&s_mask);
            let mut commitment_share = aggregate_base;
            commitment_share.mul(&s_secret);
            let mut ctx_commitment = aggregate_context;
            ctx_commitment.mul(&s_mask);
            commitment_share.add(&ctx_commitment);
            let public_secret = share.public::<MinSig>();
            let public_mask = mask.public::<MinSig>();
            let challenge = super::aggregated_challenge::<MinSig>(
                &request.context,
                index,
                &public_secret,
                &public_mask,
                &aggregate_base,
                &aggregate_context,
                &aggregate_share,
                &commitment_secret,
                &commitment_mask,
                &commitment_share,
            );
            let mut response_secret = s_secret;
            let mut tmp = share.private.clone();
            tmp.mul(&challenge);
            response_secret.add(&tmp);
            let mut response_mask = s_mask;
            let mut tmp_mask = mask.private.clone();
            tmp_mask.mul(&challenge);
            response_mask.add(&tmp_mask);
            BatchResponse {
                index,
                valid_indices: request.valid_indices.clone(),
                partials,
                proof: ContextProof {
                    commitment_secret,
                    commitment_mask,
                    commitment_share,
                    challenge,
                    response_secret,
                    response_mask,
                },
            }
        }

        let forged_response =
            forged_response_from_partials(&mut rng, share, mask, &request, forged_partials);
        let eval = public_share.clone();

        assert!(matches!(
            verify_batch_response(&request, &eval, &forged_response),
            Err(BatchError::InvalidAggregatedProof(_))
        ));

        let other_share = &shares[1];
        let other_mask = &mask_shares[1];
        let other_public = context_public_share::<MinSig>(other_share, other_mask);
        let honest_other = respond_to_batch(&mut rng, other_share, other_mask, &request);
        let verification = batch_verify_responses(
            &request,
            &[public_share.clone(), other_public.clone()],
            &[forged_response.clone(), honest_other.clone()],
        )
        .unwrap();
        assert_eq!(verification.invalid, vec![share.index]);
        assert_eq!(verification.valid.len(), 1);
        assert_eq!(verification.valid[0].0, other_share.index);
    }
}
