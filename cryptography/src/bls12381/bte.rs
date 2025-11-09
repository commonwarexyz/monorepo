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
        group::{Element, Point, Scalar, Share, G1, G2},
        poly::{self, Eval},
        variant::{MinPk, MinSig, Variant},
        Error as PrimitivesError,
    },
    sha256::Sha256,
    transcript::Transcript,
    Hasher,
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec, vec::Vec};
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_miller_loop, blst_p1_affine,
    blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_affine_is_inf, blst_p1_affine_on_curve,
    blst_p2_affine, blst_p2_affine_compress, blst_p2_affine_in_g2, blst_p2_affine_is_inf,
    blst_p2_affine_on_curve, BLS12_381_G1, BLS12_381_G2,
};
use commonware_codec::{FixedSize, Write};
use core::cmp::min;
use rand_core::{CryptoRngCore, RngCore};
#[cfg(feature = "std")]
use rayon::{prelude::*, ThreadPoolBuilder};
#[cfg(feature = "std")]
use std::collections::BTreeSet;
use thiserror::Error;

/// Transcript namespace for ciphertext Chaum–Pedersen proofs.
const CT_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.ct";
/// Transcript label for ciphertext proof challenges.
const CT_NOISE: &[u8] = b"ct-chal";
/// Transcript namespace for deriving batch coefficients.
const RHO_TRANSCRIPT: &[u8] = b"commonware.bls12381.bte.rho";
/// Transcript label for rho scalars.
const RHO_NOISE: &[u8] = b"rho";
/// Domain label for the TDH KDF.
const KDF_LABEL: &[u8] = b"commonware.bls12381.bte.kdf";
/// Fixed string mapped into a secondary generator for Chaum–Pedersen proofs.
const PROOF_GENERATOR_MSG: &[u8] = b"commonware.bls12381.bte.proof-generator";

fn g1_aff_ok(a: &blst_p1_affine) -> bool {
    unsafe { blst_p1_affine_on_curve(a) && blst_p1_affine_in_g1(a) && !blst_p1_affine_is_inf(a) }
}

fn g2_aff_ok(a: &blst_p2_affine) -> bool {
    unsafe { blst_p2_affine_on_curve(a) && blst_p2_affine_in_g2(a) && !blst_p2_affine_is_inf(a) }
}

fn compress_g1(a: &blst_p1_affine) -> [u8; 48] {
    let mut out = [0u8; 48];
    unsafe { blst_p1_affine_compress(out.as_mut_ptr(), a) };
    out
}

fn compress_g2(a: &blst_p2_affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    unsafe { blst_p2_affine_compress(out.as_mut_ptr(), a) };
    out
}

fn make_beta<R: RngCore + CryptoRngCore>(rng: &mut R) -> [u8; 32] {
    let mut beta = [0u8; 32];
    rng.fill_bytes(&mut beta);
    beta
}

fn derive_rhos<V: PairingVariant>(
    beta: &[u8; 32],
    context: &[u8],
    headers: &[V::Public],
) -> Vec<Scalar> {
    headers
        .iter()
        .enumerate()
        .map(|(pos, header)| {
            let mut transcript = Transcript::new(RHO_TRANSCRIPT);
            transcript.commit(&b"TDH2/RHOS/v2"[..]);
            transcript.commit(&beta[..]);
            transcript.commit(context);
            let pos_bytes = (pos as u64).to_le_bytes();
            transcript.commit(&pos_bytes[..]);
            let affine = V::header_affine(header);
            let compressed = V::compress_header(&affine);
            transcript.commit(compressed.as_slice());
            scalar_from_transcript(&transcript, RHO_NOISE)
        })
        .collect()
}

pub trait PairingVariant: Variant {
    type HeaderAffine: Copy;
    type OtherPoint: Point + Copy;
    type OtherAffine: Copy;

    fn header_affine(point: &Self::Public) -> Self::HeaderAffine;
    fn header_affine_ok(aff: &Self::HeaderAffine) -> bool;
    fn compress_header(aff: &Self::HeaderAffine) -> Vec<u8>;
    fn other_affine(point: &Self::OtherPoint) -> Self::OtherAffine;
    fn other_affine_ok(aff: &Self::OtherAffine) -> bool;
    fn build_pairing_term(
        global_u_aff: &Self::HeaderAffine,
        uhat: &Self::Public,
        other: &Self::OtherPoint,
        alpha: &Scalar,
    ) -> blst_fp12;
}

impl PairingVariant for MinSig {
    type HeaderAffine = blst_p2_affine;
    type OtherPoint = G1;
    type OtherAffine = blst_p1_affine;

    fn header_affine(point: &Self::Public) -> Self::HeaderAffine {
        point.as_blst_p2_affine()
    }

    fn header_affine_ok(aff: &Self::HeaderAffine) -> bool {
        g2_aff_ok(aff)
    }

    fn compress_header(aff: &Self::HeaderAffine) -> Vec<u8> {
        compress_g2(aff).to_vec()
    }

    fn other_affine(point: &Self::OtherPoint) -> Self::OtherAffine {
        point.as_blst_p1_affine()
    }

    fn other_affine_ok(aff: &Self::OtherAffine) -> bool {
        g1_aff_ok(aff)
    }

    fn build_pairing_term(
        global_u_aff: &Self::HeaderAffine,
        uhat: &Self::Public,
        other: &Self::OtherPoint,
        alpha: &Scalar,
    ) -> blst_fp12 {
        let mut scaled_uhat = *uhat;
        let alpha_scalar = alpha.clone();
        scaled_uhat.mul(&alpha_scalar);
        let alpha_scaled_uhat = scaled_uhat.as_blst_p2_affine();

        let mut scaled_other = *other;
        let alpha_other = alpha.clone();
        scaled_other.mul(&alpha_other);
        let mut neg_other = scaled_other;
        let mut neg_one = Scalar::zero();
        neg_one.sub(&Scalar::one());
        neg_other.mul(&neg_one);
        let neg_other_aff = neg_other.as_blst_p1_affine();

        let mut term1 = blst_fp12::default();
        let mut term2 = blst_fp12::default();
        unsafe {
            blst_miller_loop(&mut term1, &alpha_scaled_uhat, &BLS12_381_G1);
            blst_miller_loop(&mut term2, global_u_aff, &neg_other_aff);
        }
        let mut acc = blst_fp12::default();
        unsafe { blst_fp12_mul(&mut acc, &term1, &term2) };
        acc
    }
}

impl PairingVariant for MinPk {
    type HeaderAffine = blst_p1_affine;
    type OtherPoint = G2;
    type OtherAffine = blst_p2_affine;

    fn header_affine(point: &Self::Public) -> Self::HeaderAffine {
        point.as_blst_p1_affine()
    }

    fn header_affine_ok(aff: &Self::HeaderAffine) -> bool {
        g1_aff_ok(aff)
    }

    fn compress_header(aff: &Self::HeaderAffine) -> Vec<u8> {
        compress_g1(aff).to_vec()
    }

    fn other_affine(point: &Self::OtherPoint) -> Self::OtherAffine {
        point.as_blst_p2_affine()
    }

    fn other_affine_ok(aff: &Self::OtherAffine) -> bool {
        g2_aff_ok(aff)
    }

    fn build_pairing_term(
        global_u_aff: &Self::HeaderAffine,
        uhat: &Self::Public,
        other: &Self::OtherPoint,
        alpha: &Scalar,
    ) -> blst_fp12 {
        let mut scaled_uhat = *uhat;
        let alpha_scalar = alpha.clone();
        scaled_uhat.mul(&alpha_scalar);
        let alpha_scaled_uhat = scaled_uhat.as_blst_p1_affine();

        let mut scaled_other = *other;
        let alpha_other = alpha.clone();
        scaled_other.mul(&alpha_other);
        let mut neg_other = scaled_other;
        let mut neg_one = Scalar::zero();
        neg_one.sub(&Scalar::one());
        neg_other.mul(&neg_one);
        let neg_other_aff = neg_other.as_blst_p2_affine();

        let mut term1 = blst_fp12::default();
        let mut term2 = blst_fp12::default();
        unsafe {
            blst_miller_loop(&mut term1, &BLS12_381_G2, &alpha_scaled_uhat);
            blst_miller_loop(&mut term2, &neg_other_aff, global_u_aff);
        }
        let mut acc = blst_fp12::default();
        unsafe { blst_fp12_mul(&mut acc, &term1, &term2) };
        acc
    }
}

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

/// Server response containing partial decryptions and a single proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchResponse<V: Variant> {
    pub index: u32,
    /// Positions of ciphertexts (0-indexed) that the server included in this proof.
    pub valid_indices: Vec<u32>,
    pub partials: Vec<V::Public>,
}

/// Errors that can surface while verifying or combining batches.
#[derive(Error, Debug)]
pub enum BatchError {
    #[error("response index {provided} does not match public share {expected}")]
    IndexMismatch { expected: u32, provided: u32 },
    #[error("partials length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
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
    #[error("missing complementary public share for index {0}")]
    MissingOtherShare(u32),
    #[error("invalid partial point from index {index} at position {position}")]
    InvalidPartialPoint { index: u32, position: usize },
    #[error("invalid complementary public share for index {0}")]
    InvalidOtherShare(u32),
    #[error("batch pairing verification failed; malicious indexes: {malicious:?}")]
    BatchVerificationFailed { malicious: Vec<u32> },
    #[error("insufficient verified responses: need {expected}, have {actual}")]
    InsufficientVerifiedResponses { expected: usize, actual: usize },
}

/// Per-batch verifier state containing the globally derived coefficients and aggregate header.
pub struct BatchVerifierState<'a, V>
where
    V: PairingVariant,
{
    request: &'a BatchRequest<V>,
    rhos: Vec<Scalar>,
    aggregate_affine: V::HeaderAffine,
}

impl<'a, V> BatchVerifierState<'a, V>
where
    V: PairingVariant,
{
    pub fn new<R: CryptoRngCore + RngCore>(
        rng: &mut R,
        request: &'a BatchRequest<V>,
    ) -> Result<Self, BatchError> {
        if request.valid_headers.is_empty() {
            return Err(BatchError::NoValidCiphertexts);
        }
        let beta = make_beta(rng);
        let rhos = derive_rhos::<V>(&beta, &request.context, &request.valid_headers);
        let aggregate = V::Public::msm(&request.valid_headers, &rhos);
        let aggregate_affine = V::header_affine(&aggregate);
        Ok(Self {
            request,
            rhos,
            aggregate_affine,
        })
    }

    pub fn request(&self) -> &BatchRequest<V> {
        self.request
    }

    pub fn rhos(&self) -> &[Scalar] {
        &self.rhos
    }

    pub fn aggregate_affine(&self) -> &V::HeaderAffine {
        &self.aggregate_affine
    }
}

#[derive(Clone, Debug)]
pub struct PreparedResponse<V>
where
    V: PairingVariant,
{
    pub index: u32,
    pub partials: Vec<V::Public>,
    pub uhat: V::Public,
    pub other_share: V::OtherPoint,
}

pub struct VerifiedSet<V>
where
    V: PairingVariant,
{
    pub share_indices: Vec<u32>,
    pub partials: Vec<Vec<V::Public>>,
    pub malicious: Vec<u32>,
}

pub fn batch_verify_responses<V: PairingVariant, R: CryptoRngCore + RngCore>(
    verifier: &BatchVerifierState<V>,
    rng: &mut R,
    prepared: &[PreparedResponse<V>],
    threshold: usize,
) -> Result<VerifiedSet<V>, BatchError> {
    if prepared.len() < threshold {
        return Err(BatchError::InsufficientResponses {
            expected: threshold,
            actual: prepared.len(),
        });
    }

    let mut terms = Vec::with_capacity(prepared.len());
    for resp in prepared {
        let alpha = random_scalar(rng);
        let term = V::build_pairing_term(
            verifier.aggregate_affine(),
            &resp.uhat,
            &resp.other_share,
            &alpha,
        );
        terms.push(term);
    }

    let mut malicious = Vec::new();
    let mut good_positions: Vec<usize> = (0..prepared.len()).collect();
    if !verify_terms_batch(&terms) {
        let mut bad_positions = Vec::new();
        bisect_bad(&terms, 0, &mut bad_positions);
        bad_positions.sort_unstable();
        bad_positions.dedup();
        for &pos in bad_positions.iter() {
            malicious.push(prepared[pos].index);
        }
        let bad_set: BTreeSet<usize> = bad_positions.into_iter().collect();
        good_positions.retain(|pos| !bad_set.contains(pos));
        let survivor_terms: Vec<_> = good_positions.iter().map(|pos| terms[*pos]).collect();
        if !verify_terms_batch(&survivor_terms) {
            return Err(BatchError::BatchVerificationFailed { malicious });
        }
    }

    if good_positions.len() < threshold {
        return Err(BatchError::InsufficientVerifiedResponses {
            expected: threshold,
            actual: good_positions.len(),
        });
    }

    let mut share_indices = Vec::with_capacity(threshold);
    let mut partials = Vec::with_capacity(threshold);
    for pos in good_positions.into_iter().take(threshold) {
        let resp = &prepared[pos];
        share_indices.push(resp.index);
        partials.push(resp.partials.clone());
    }

    Ok(VerifiedSet {
        share_indices,
        partials,
        malicious,
    })
}

fn verify_terms_batch(terms: &[blst_fp12]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let mut acc = terms[0];
    for term in &terms[1..] {
        unsafe { blst_fp12_mul(&mut acc, &acc, term) };
    }
    let mut out = blst_fp12::default();
    unsafe { blst_final_exp(&mut out, &acc) };
    unsafe { blst_fp12_is_one(&out) }
}

fn bisect_bad(terms: &[blst_fp12], offset: usize, out: &mut Vec<usize>) {
    if terms.is_empty() {
        return;
    }
    if verify_terms_batch(terms) {
        return;
    }
    if terms.len() == 1 {
        out.push(offset);
        return;
    }
    let mid = terms.len() / 2;
    bisect_bad(&terms[..mid], offset, out);
    bisect_bad(&terms[mid..], offset + mid, out);
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
pub fn respond_to_batch<V: Variant>(share: &Share, request: &BatchRequest<V>) -> BatchResponse<V> {
    let index = share.index;
    let partials: Vec<V::Public> = request
        .valid_indices
        .iter()
        .map(|idx| {
            let mut partial = request.ciphertexts[*idx as usize].header;
            partial.mul(&share.private);
            partial
        })
        .collect();

    BatchResponse {
        index,
        valid_indices: request.valid_indices.clone(),
        partials,
    }
}

/// Verify a server response structurally and prepare it for batch pairing checks.
pub fn verify_batch_response<V: PairingVariant>(
    verifier: &BatchVerifierState<V>,
    public_share: &Eval<V::Public>,
    other_share: &V::OtherPoint,
    response: &BatchResponse<V>,
) -> Result<PreparedResponse<V>, BatchError> {
    if response.index != public_share.index {
        return Err(BatchError::IndexMismatch {
            expected: public_share.index,
            provided: response.index,
        });
    }

    let request = verifier.request();
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

    let other_aff = V::other_affine(other_share);
    if !V::other_affine_ok(&other_aff) {
        return Err(BatchError::InvalidOtherShare(response.index));
    }

    for (pos, partial) in response.partials.iter().enumerate() {
        let aff = V::header_affine(partial);
        if !V::header_affine_ok(&aff) {
            return Err(BatchError::InvalidPartialPoint {
                index: response.index,
                position: pos,
            });
        }
    }

    let uhat = V::Public::msm(&response.partials, verifier.rhos());

    Ok(PreparedResponse {
        index: response.index,
        partials: response.partials.clone(),
        uhat,
        other_share: *other_share,
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

    fn other_share(share: &Share) -> G1 {
        let mut other = G1::one();
        other.mul(&share.private);
        other
    }

    #[test]
    fn test_ciphertext_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        let (commitment, _) = generate_shares::<_, MinSig>(&mut rng, None, 1, 1);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let ciphertext = encrypt(&mut rng, &public, b"label", b"secret");
        assert!(verify_ciphertext(&public, &ciphertext));
    }

    #[test]
    fn test_batch_flow() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let ciphertexts: Vec<_> = (0..6)
            .map(|i| encrypt(&mut rng, &public, b"label", format!("msg-{i}").as_bytes()))
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"ctx".to_vec(), threshold, 1);
        let verifier = BatchVerifierState::new(&mut rng, &request).unwrap();

        let mut prepared = Vec::new();
        for share in shares.iter().take(threshold as usize) {
            let response = respond_to_batch(share, &request);
            let eval = Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            };
            prepared.push(
                verify_batch_response(&verifier, &eval, &other_share(share), &response).unwrap(),
            );
        }

        let verified =
            batch_verify_responses(&verifier, &mut rng, &prepared, threshold as usize).unwrap();
        let combined =
            combine_partials(&request, &verified.share_indices, &verified.partials, 1).unwrap();
        assert_eq!(combined.len(), request.valid_len());
    }

    #[test]
    fn test_detects_malicious_server() {
        let mut rng = StdRng::seed_from_u64(99);
        let n = 6;
        let threshold = quorum(n);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, threshold);
        let public = PublicKey::<MinSig>::new(*commitment.constant());

        let ciphertexts: Vec<_> = (0..6)
            .map(|i| encrypt(&mut rng, &public, b"label", format!("msg-{i}").as_bytes()))
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"ctx".to_vec(), threshold, 1);
        let verifier = BatchVerifierState::new(&mut rng, &request).unwrap();

        let mut prepared = Vec::new();
        for share in shares.iter().take(threshold as usize + 1) {
            let mut response = respond_to_batch(share, &request);
            if share.index == shares[0].index {
                response.partials[0].add(&G2::one());
            }
            let eval = Eval {
                index: share.index,
                value: share.public::<MinSig>(),
            };
            prepared.push(
                verify_batch_response(&verifier, &eval, &other_share(share), &response).unwrap(),
            );
        }

        let verified =
            batch_verify_responses(&verifier, &mut rng, &prepared, threshold as usize).unwrap();
        assert!(verified.malicious.contains(&shares[0].index));
        assert_eq!(verified.share_indices.len(), threshold as usize);
    }

    #[test]
    fn test_combine_partials_insufficient_responses() {
        let mut rng = StdRng::seed_from_u64(123);
        let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, None, 4, 3);
        let public = PublicKey::<MinSig>::new(*commitment.constant());
        let ciphertexts: Vec<_> = (0..4)
            .map(|i| encrypt(&mut rng, &public, b"label", format!("msg-{i}").as_bytes()))
            .collect();
        let request = BatchRequest::new(&public, ciphertexts, b"ctx".to_vec(), 3, 1);
        let verifier = BatchVerifierState::new(&mut rng, &request).unwrap();

        let share = &shares[0];
        let response = respond_to_batch(share, &request);
        let eval = Eval {
            index: share.index,
            value: share.public::<MinSig>(),
        };
        let prepared =
            verify_batch_response(&verifier, &eval, &other_share(share), &response).unwrap();
        let err =
            combine_partials(&request, &[prepared.index], &[prepared.partials], 1).unwrap_err();
        assert!(matches!(
            err,
            BatchError::InsufficientResponses { expected, actual }
            if expected == request.threshold as usize && actual == 1
        ));
    }
}
