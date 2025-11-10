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
    blake3::CoreBlake3,
    bls12381::primitives::{
        group::{Element, MsmScratch, Point, Scalar, Share},
        poly::{self, Eval},
        variant::Variant,
        Error as PrimitivesError,
    },
    transcript::{Summary, Transcript},
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_codec::{FixedSize, Write};
use core::{mem, ptr};
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
    pub header_affines: Vec<<V::Public as Point>::Affine>,
    pub rho_seeds: Vec<Summary>,
    pub concurrency: usize,
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
        let mut header_affines = Vec::new();
        let mut rho_seeds = Vec::new();

        #[cfg(feature = "std")]
        let evaluations: Vec<Option<(u32, V::Public, <V::Public as Point>::Affine)>> =
            if concurrency > 1 {
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
                                Some((idx as u32, ct.header, ct.header.to_affine()))
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
                            Some((idx as u32, ct.header, ct.header.to_affine()))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

        #[cfg(not(feature = "std"))]
        let evaluations: Vec<Option<(u32, V::Public, <V::Public as Point>::Affine)>> = {
            let _ = concurrency;
            ciphertexts
                .iter()
                .enumerate()
                .map(|(idx, ct)| {
                    if verify_ciphertext(public, ct) {
                        Some((idx as u32, ct.header, ct.header.to_affine()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        for (idx, header, affine) in evaluations.into_iter().flatten() {
            valid_indices.push(idx);
            valid_headers.push(header);
            header_affines.push(affine);
            let mut transcript = Transcript::new(RHO_TRANSCRIPT);
            transcript.commit(context.as_slice());
            transcript.commit((rho_seeds.len() as u64).to_le_bytes().as_slice());
            transcript.commit(encode_field(&header).as_slice());
            rho_seeds.push(transcript.summarize());
        }

        Self {
            ciphertexts,
            context,
            threshold,
            valid_indices,
            valid_headers,
            header_affines,
            rho_seeds,
            concurrency,
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

/// Partials plus precomputed affine representations returned by verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPartials<V: Variant> {
    pub points: Vec<V::Public>,
    pub affines: Vec<<V::Public as Point>::Affine>,
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
    let private_raw = share.private.to_raw();
    #[cfg(feature = "std")]
    let partials: Vec<V::Public> =
        if request.concurrency > 1 && request.valid_indices.len() >= request.concurrency {
            let pool = ThreadPoolBuilder::new()
                .num_threads(request.concurrency)
                .build()
                .expect("thread pool");
            pool.install(|| {
                request
                    .valid_indices
                    .par_iter()
                    .map(|idx| {
                        let mut partial = request.ciphertexts[*idx as usize].header;
                        partial.mul_raw(&private_raw);
                        partial
                    })
                    .collect()
            })
        } else {
            request
                .valid_indices
                .iter()
                .map(|idx| {
                    let mut partial = request.ciphertexts[*idx as usize].header;
                    partial.mul_raw(&private_raw);
                    partial
                })
                .collect()
        };
    #[cfg(not(feature = "std"))]
    let partials: Vec<V::Public> = request
        .valid_indices
        .iter()
        .map(|idx| {
            let mut partial = request.ciphertexts[*idx as usize].header;
            partial.mul_raw(&private_raw);
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

    let rhos = derive_rhos::<V>(request, index, &partials);
    let mut scratch = MsmScratch::new();
    let aggregate_base =
        V::Public::msm_affine_with_scratch(&request.header_affines, &rhos, &mut scratch);
    let mut aggregate_share = aggregate_base;
    aggregate_share.mul_raw(&private_raw);

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
pub fn verify_batch_response<V: Variant>(
    request: &BatchRequest<V>,
    public_share: &Eval<V::Public>,
    response: &BatchResponse<V>,
) -> Result<VerifiedPartials<V>, BatchError> {
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

    let rhos = derive_rhos::<V>(request, response.index, &response.partials);
    let mut scratch = MsmScratch::new();
    let aggregate_base =
        V::Public::msm_affine_with_scratch(&request.header_affines, &rhos, &mut scratch);
    let partial_affines: Vec<_> = response.partials.iter().map(Point::to_affine).collect();
    let aggregate_share = V::Public::msm_affine_with_scratch(&partial_affines, &rhos, &mut scratch);

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

    let mut lhs = V::Public::one();
    lhs.mul(&response.proof.response);
    let mut rhs = response.proof.commitment_generator;
    let mut pk_term = public_share.value;
    pk_term.mul(&response.proof.challenge);
    rhs.add(&pk_term);
    if lhs != rhs {
        return Err(BatchError::InvalidAggregatedProof(response.index));
    }

    let mut lhs_agg = aggregate_base;
    lhs_agg.mul(&response.proof.response);
    let mut rhs_agg = response.proof.commitment_aggregate;
    let mut agg_term = aggregate_share;
    agg_term.mul(&response.proof.challenge);
    rhs_agg.add(&agg_term);
    if lhs_agg != rhs_agg {
        return Err(BatchError::InvalidAggregatedProof(response.index));
    }

    Ok(VerifiedPartials {
        points: response.partials.clone(),
        affines: partial_affines,
    })
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
    partials: &[VerifiedPartials<V>],
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
        if set.points.len() != expected {
            return Err(BatchError::LengthMismatch {
                expected,
                actual: set.points.len(),
            });
        }
    }

    let mut lambdas = Vec::with_capacity(share_indices.len());
    for share_idx in share_indices {
        lambdas.push(
            weights
                .get(share_idx)
                .ok_or(BatchError::MissingWeight(*share_idx))?
                .as_scalar()
                .clone(),
        );
    }

    let mut column_affines: Vec<Vec<<V::Public as Point>::Affine>> = Vec::with_capacity(expected);
    for _ in 0..expected {
        column_affines.push(Vec::with_capacity(lambdas.len()));
    }
    for verified in partials.iter() {
        for (pos, affine) in verified.affines.iter().enumerate() {
            column_affines[pos].push(*affine);
        }
    }

    let aggregated = if concurrency <= 1 {
        let mut scratch = MsmScratch::new();
        column_affines
            .into_iter()
            .map(|column| V::Public::msm_affine_with_scratch(&column, &lambdas, &mut scratch))
            .collect::<Vec<_>>()
    } else {
        #[cfg(feature = "std")]
        {
            let pool = ThreadPoolBuilder::new()
                .num_threads(concurrency)
                .build()
                .expect("thread pool");
            pool.install(|| {
                column_affines
                    .into_par_iter()
                    .map(|column| {
                        let mut scratch = MsmScratch::new();
                        V::Public::msm_affine_with_scratch(&column, &lambdas, &mut scratch)
                    })
                    .collect::<Vec<_>>()
            })
        }
        #[cfg(not(feature = "std"))]
        {
            let mut scratch = MsmScratch::new();
            column_affines
                .into_iter()
                .map(|column| V::Public::msm_affine_with_scratch(&column, &lambdas, &mut scratch))
                .collect::<Vec<_>>()
        }
    };

    let mut plaintexts = Vec::with_capacity(expected);
    for (pos, &ct_idx) in request.valid_indices.iter().enumerate() {
        let hr = aggregated[pos];
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
    request: &BatchRequest<V>,
    index: u32,
    partials: &[V::Public],
) -> Vec<Scalar> {
    assert_eq!(
        request.rho_seeds.len(),
        partials.len(),
        "headers and partials must be the same length"
    );

    partials
        .iter()
        .enumerate()
        .map(|(pos, partial)| {
            let mut transcript = Transcript::resume(request.rho_seeds[pos]);
            transcript.commit(index.to_le_bytes().as_slice());
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
    let mut hasher = CoreBlake3::new();
    let hr_bytes = encode_field(hr);
    let label_len = (label.len() as u32).to_le_bytes();
    let out_len = (len as u32).to_le_bytes();
    hasher.update(KDF_LABEL);
    hasher.update(&out_len);
    hasher.update(&hr_bytes);
    hasher.update(&label_len);
    hasher.update(label);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; len];
    reader.fill(&mut out);
    out
}

/// XOR helper that enforces equal-length operands and produces a fresh Vec.
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    let len = a.len();
    let mut out = vec![0u8; len];
    let mut i = 0;
    const CHUNK: usize = mem::size_of::<u64>();
    while i + CHUNK <= len {
        let lhs = unsafe { u64::from_le(ptr::read_unaligned(a.as_ptr().add(i) as *const u64)) };
        let rhs = unsafe { u64::from_le(ptr::read_unaligned(b.as_ptr().add(i) as *const u64)) };
        let value = (lhs ^ rhs).to_le();
        unsafe {
            ptr::write_unaligned(out.as_mut_ptr().add(i) as *mut u64, value);
        }
        i += CHUNK;
    }
    while i < len {
        out[i] = a[i] ^ b[i];
        i += 1;
    }
    out
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
            assert_eq!(verified.points.len(), 3); // one ciphertext skipped
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

        let legacy_rhos = super::derive_rhos::<MinSig>(&request, share.index, &honest.partials);
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
            request: &BatchRequest<MinSig>,
            partials: Vec<<MinSig as Variant>::Public>,
        ) -> BatchResponse<MinSig> {
            let index = share.index;
            let rhos = super::derive_rhos::<MinSig>(&request, index, &partials);
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
