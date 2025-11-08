//! Batched Threshold Diffie–Hellman (TDH2) encryption/decryption over BLS12-381.
//!
//! This module keeps TDH2 encryption intact while batching decryption shares so
//! that each server proves correctness for *all* ciphertexts with a single
//! aggregated Chaum–Pedersen proof. The batching technique follows the classic
//! random-linear-combination approach: clients derive coefficients for every
//! ciphertext header, servers fold them into one DLEQ proof, and verifiers check
//! a single transcript per server.
//!
//! # Overview
//!
//! * **Encryption** – identical to TDH2: sample randomness `r`, compute `u =
//!   r·G`, mask the message with a KDF over `h^{r}`, and attach a per-ciphertext
//!   Chaum–Pedersen proof binding `(u, ū)` to the same exponent.
//! * **Batched partial decryptions** – a server holding share `x_i` returns the
//!   vector `u_j^{x_i}` for all ciphertexts plus a single aggregated proof that
//!   `log_G(h_i) = log_U(U_i)`, where `U = Σ ρ_j u_j` and
//!   `U_i = Σ ρ_j u_{i,j}`.
//! * **Combination** – once `t` distinct, valid servers respond, clients
//!   interpolate the shares at zero (same Lagrange coefficients used for
//!   threshold signatures) and reuse the TDH KDF to recover all plaintexts.
//!
//! The implementation relies entirely on the internal BLS12-381 primitives
//! (`group`, `poly`, and `variant`) and uses the repository transcript utility
//! for Fiat–Shamir challenges.

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchRequest<V: Variant> {
    pub ciphertexts: Vec<Ciphertext<V>>,
    pub context: Vec<u8>,
    pub threshold: u32,
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
    pub partials: Vec<V::Public>,
    pub proof: AggregatedProof<V>,
}

/// Errors that can surface while verifying or combining batches.
#[derive(Error, Debug)]
pub enum BatchError {
    #[error("ciphertext {0} failed verification")]
    InvalidCiphertext(usize),
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
        &public,
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

/// Produce a batched response for all ciphertexts using a private share.
pub fn respond_to_batch<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    share: &Share,
    request: &BatchRequest<V>,
) -> BatchResponse<V> {
    let index = share.index;
    let partials: Vec<V::Public> = request
        .ciphertexts
        .iter()
        .map(|ct| {
            let mut partial = ct.header;
            partial.mul(&share.private);
            partial
        })
        .collect();

    let headers: Vec<V::Public> = request.ciphertexts.iter().map(|ct| ct.header).collect();
    let rhos = derive_rhos::<V>(&request.context, index, &headers);
    let aggregate_base = V::Public::msm(&headers, &rhos);
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
    public: &PublicKey<V>,
    request: &BatchRequest<V>,
    public_share: &Eval<V::Public>,
    response: &BatchResponse<V>,
) -> Result<Vec<V::Public>, BatchError> {
    if response.index != public_share.index {
        return Err(BatchError::IndexMismatch {
            expected: public_share.index,
            provided: response.index,
        });
    }

    if response.partials.len() != request.ciphertexts.len() {
        return Err(BatchError::LengthMismatch {
            expected: request.ciphertexts.len(),
            actual: response.partials.len(),
        });
    }

    for (idx, ciphertext) in request.ciphertexts.iter().enumerate() {
        if !verify_ciphertext(public, ciphertext) {
            return Err(BatchError::InvalidCiphertext(idx));
        }
    }

    let headers: Vec<V::Public> = request.ciphertexts.iter().map(|ct| ct.header).collect();
    let rhos = derive_rhos::<V>(&request.context, response.index, &headers);
    let aggregate_base = V::Public::msm(&headers, &rhos);
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

    Ok(response.partials.clone())
}

/// Combine verified partials from at least `threshold` distinct servers.
pub fn combine_partials<V: Variant>(
    request: &BatchRequest<V>,
    indices: &[u32],
    partials: &[Vec<V::Public>],
) -> Result<Vec<Vec<u8>>, BatchError> {
    if indices.len() != partials.len() {
        return Err(BatchError::LengthMismatch {
            expected: indices.len(),
            actual: partials.len(),
        });
    }

    if indices.len() < request.threshold as usize {
        return Err(BatchError::InsufficientResponses {
            expected: request.threshold as usize,
            actual: indices.len(),
        });
    }

    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    for window in sorted.windows(2) {
        if window[0] == window[1] {
            return Err(BatchError::DuplicateIndex(window[0]));
        }
    }

    let weights = poly::compute_weights(indices.to_vec())?;
    let decrypt_count = request.ciphertexts.len();

    let mut plaintexts = Vec::with_capacity(decrypt_count);
    for idx in 0..decrypt_count {
        let points: Vec<V::Public> = partials.iter().map(|p| p[idx]).collect();
        let scalars: Vec<Scalar> = indices
            .iter()
            .map(|i| {
                weights
                    .get(i)
                    .ok_or(BatchError::MissingWeight(*i))
                    .map(|w| w.as_scalar().clone())
            })
            .collect::<Result<_, _>>()?;

        let hr = V::Public::msm(&points, &scalars);
        let keystream = keystream::<V>(
            &hr,
            &request.ciphertexts[idx].label,
            request.ciphertexts[idx].body.len(),
        );
        plaintexts.push(xor(&request.ciphertexts[idx].body, &keystream));
    }

    Ok(plaintexts)
}

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

fn derive_rhos<V: Variant>(context: &[u8], index: u32, headers: &[V::Public]) -> Vec<Scalar> {
    headers
        .iter()
        .enumerate()
        .map(|(pos, header)| {
            let mut transcript = Transcript::new(RHO_TRANSCRIPT);
            transcript.commit(context);
            transcript.commit(index.to_le_bytes().as_slice());
            transcript.commit((pos as u64).to_le_bytes().as_slice());
            transcript.commit(encode_field(header).as_slice());
            scalar_from_transcript(&transcript, RHO_NOISE)
        })
        .collect()
}

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

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn scalar_from_transcript(transcript: &Transcript, label: &'static [u8]) -> Scalar {
    let mut rng = transcript.noise(label);
    loop {
        let scalar = Scalar::from_rand(&mut rng);
        if scalar != Scalar::zero() {
            return scalar;
        }
    }
}

fn random_scalar<R: CryptoRngCore>(rng: &mut R) -> Scalar {
    loop {
        let scalar = Scalar::from_rand(rng);
        if scalar != Scalar::zero() {
            return scalar;
        }
    }
}

fn encode_field<E: FixedSize + Write>(value: &E) -> Vec<u8> {
    let mut buf = Vec::with_capacity(E::SIZE);
    value.write(&mut buf);
    buf
}

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
        let request = BatchRequest {
            ciphertexts,
            context: b"context".to_vec(),
            threshold: 1,
        };
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
        let (commitment, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, n as u32, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let messages: Vec<Vec<u8>> = (0..3).map(|i| format!("batch-{i}").into_bytes()).collect();
        let ciphertexts: Vec<_> = messages
            .iter()
            .map(|m| encrypt(&mut rng, &public, b"label", m))
            .collect();
        let request = BatchRequest {
            ciphertexts,
            context: b"ctx".to_vec(),
            threshold,
        };

        let mut indices = Vec::new();
        let mut all_partials = Vec::new();
        for share in shares.iter().take(threshold as usize) {
            let response = respond_to_batch(&mut rng, share, &request);
            let public_share = Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            };
            let partials =
                verify_batch_response(&public, &request, &public_share, &response).unwrap();
            indices.push(response.index);
            all_partials.push(partials);
        }

        let recovered = combine_partials(&request, &indices, &all_partials).unwrap();
        assert_eq!(recovered, messages);
    }

    #[test]
    fn test_invalid_ciphertext_detection() {
        let mut rng = StdRng::seed_from_u64(9);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 4, 3);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let msg = b"attack".to_vec();
        let mut ciphertext = encrypt(&mut rng, &public, b"label", &msg);
        ciphertext.proof.challenge = random_scalar(&mut rng);
        let request = BatchRequest {
            ciphertexts: vec![ciphertext],
            context: b"ctx".to_vec(),
            threshold: 3,
        };
        let share = &shares[0];
        let response = respond_to_batch(&mut rng, share, &request);
        let eval = Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        };
        assert!(matches!(
            verify_batch_response(&public, &request, &eval, &response),
            Err(BatchError::InvalidCiphertext(0))
        ));
    }

    #[test]
    fn test_invalid_share_detection() {
        let mut rng = StdRng::seed_from_u64(99);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 4, 3);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let messages: Vec<Vec<u8>> = (0..2).map(|i| format!("secret-{i}").into_bytes()).collect();
        let request = BatchRequest {
            ciphertexts: messages
                .iter()
                .map(|m| encrypt(&mut rng, &public, b"label", m))
                .collect(),
            context: b"ctx".to_vec(),
            threshold: 3,
        };

        let share = &shares[0];
        let mut response = respond_to_batch(&mut rng, share, &request);
        response.proof.challenge = random_scalar(&mut rng);
        let eval = Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        };
        assert!(matches!(
            verify_batch_response(&public, &request, &eval, &response),
            Err(BatchError::InvalidAggregatedProof(_))
        ));
    }
}
