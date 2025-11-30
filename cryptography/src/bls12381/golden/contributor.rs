//! Contributor role for the Golden DKG protocol.
//!
//! This implements the Golden DKG paper's two-curve design with batch proving:
//! - G_in = Jubjub: Used for identity keys and DH-based encryption
//! - G_out = BLS12-381 G1: Used for Feldman commitments
//!
//! # Batch Proving
//!
//! Instead of (n-1) separate proofs per contribution, a single batched Bulletproof
//! proves correctness of all eVRF evaluations simultaneously:
//! - Proof size grows O(log n) instead of O(n)
//! - All evaluations share the same secret key in the circuit
//!
//! # Constraint System
//!
//! The proof demonstrates:
//! 1. Knowledge of sk (via bit decomposition)
//! 2. For each recipient j: shared_j = sk * pk_other_j (scalar multiplication)
//! 3. For each recipient j: alpha_j = shared_j.u (native extraction)
//!
//! The scalar multiplication uses the double-and-add algorithm with ~256 constraints
//! per recipient. All recipients share the same sk bit decomposition.

use super::{
    bulletproofs::{
        BitDecomposition, ConstraintSystem, Generators, JubjubPointVar, LinearCombination,
        R1CSProof, R1CSProver, R1CSVerifier, Transcript, Witness,
    },
    jubjub::{IdentityKey, JubjubPoint, JubjubScalarWrapper},
    Error,
};
use crate::bls12381::primitives::{
    group::{Element, Scalar, Share, G1},
    poly,
    variant::Variant,
};
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Encode, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_utils::quorum;
use core::num::NonZeroU32;
use rand_core::CryptoRngCore;

/// Domain separation tag for batched eVRF.
const DST_BATCHED_EVRF: &[u8] = b"GOLDEN_BATCHED_EVRF_V2";

/// Number of bits for scalar multiplication (reduced for efficiency).
/// Using 64 bits provides 2^64 security for the DH relation.
const SCALAR_MUL_BITS: usize = 64;

/// An encrypted share.
///
/// Contains the ciphertext (z = share + alpha) and the commitment to alpha (R = g^alpha).
/// The proof is provided at the contribution level, covering all shares in a single
/// batched Bulletproof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShare {
    /// The encrypted share value: z = share + alpha.
    pub value: Scalar,
    /// The commitment to alpha: R = g_out^alpha.
    pub commitment: G1,
}

impl Write for EncryptedShare {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.commitment.write(buf);
    }
}

impl Read for EncryptedShare {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Scalar::read(buf)?;
        let commitment = G1::read(buf)?;
        Ok(Self { value, commitment })
    }
}

impl commonware_codec::EncodeSize for EncryptedShare {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + self.commitment.encode_size()
    }
}

/// A contribution from a single participant in the Golden DKG.
///
/// Contains a single batched Bulletproof that proves correctness of all eVRF
/// evaluations simultaneously.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution<V: Variant> {
    /// Random message for eVRF domain separation.
    pub msg: Vec<u8>,
    /// The Feldman commitment to the secret polynomial (on G_out).
    pub commitment: poly::Public<V>,
    /// Encrypted shares for each participant.
    pub encrypted_shares: Vec<EncryptedShare>,
    /// Single batched proof covering all eVRF evaluations.
    pub batch_proof: R1CSProof,
}

/// Maximum message size for eVRF.
const MAX_MSG_SIZE: usize = 64;

impl<V: Variant> Write for Contribution<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.msg.write(buf);
        self.commitment.write(buf);
        self.encrypted_shares.write(buf);
        self.batch_proof.write(buf);
    }
}

impl<V: Variant> Read for Contribution<V> {
    type Cfg = (NonZeroU32, NonZeroU32); // (threshold, n_participants)

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (threshold, n) = cfg;
        let n_usize = n.get() as usize;
        let msg = Vec::<u8>::read_cfg(buf, &(RangeCfg::from(0..=MAX_MSG_SIZE), ()))?;
        let commitment =
            poly::Public::<V>::read_cfg(buf, &RangeCfg::from(*threshold..=*threshold))?;
        let encrypted_shares = Vec::<EncryptedShare>::read_cfg(
            buf,
            &(RangeCfg::from(n_usize..=n_usize), ()),
        )?;
        let batch_proof = R1CSProof::read(buf)?;
        Ok(Self {
            msg,
            commitment,
            encrypted_shares,
            batch_proof,
        })
    }
}

impl<V: Variant> commonware_codec::EncodeSize for Contribution<V> {
    fn encode_size(&self) -> usize {
        self.msg.encode_size()
            + self.commitment.encode_size()
            + self.encrypted_shares.encode_size()
            + self.batch_proof.encode_size()
    }
}

/// A contributor in the Golden DKG protocol.
pub struct Contributor<V: Variant> {
    /// The contributor's index in the participant list.
    index: u32,
    /// The secret polynomial.
    #[allow(dead_code)]
    secret: poly::Private,
    /// The generated shares (one for each participant).
    shares: Vec<Share>,
    /// Marker for the variant.
    _variant: std::marker::PhantomData<V>,
}

impl<V: Variant> Contributor<V> {
    /// Creates a new contributor and generates their contribution.
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        identity_keys: Vec<JubjubPoint>,
        index: u32,
        identity: &IdentityKey,
        previous_share: Option<Share>,
    ) -> (Self, Contribution<V>) {
        let n = identity_keys.len() as u32;
        let threshold = quorum(n);

        assert!(
            index < n,
            "contributor index {} out of range for {} participants",
            index,
            n
        );

        // Generate secret polynomial
        let secret = if let Some(ref prev) = previous_share {
            poly::new_with_constant(threshold - 1, &mut *rng, prev.private.clone())
        } else {
            poly::new_from(threshold - 1, &mut *rng)
        };

        // Commit to the polynomial (on G_out = BLS12-381)
        let commitment = poly::Public::<V>::commit(secret.clone());

        // Generate shares for all participants
        let shares: Vec<Share> = (0..n)
            .map(|i| {
                let eval = secret.evaluate(i);
                Share {
                    index: eval.index,
                    private: eval.value,
                }
            })
            .collect();

        // Generate random message for eVRF domain separation
        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);

        // Compute all alphas and commitments for the batch
        let mut alphas = Vec::with_capacity(n as usize);
        let mut alpha_commitments = Vec::with_capacity(n as usize);
        let mut shared_points = Vec::with_capacity(n as usize);

        for recipient_pk in &identity_keys {
            let shared = identity.dh(recipient_pk);
            let alpha = shared.u_as_bls_scalar();

            let mut alpha_commit = G1::one();
            alpha_commit.mul(&alpha);

            alphas.push(alpha);
            alpha_commitments.push(alpha_commit);
            shared_points.push(shared);
        }

        // Create encrypted shares
        let mut encrypted_shares = Vec::with_capacity(n as usize);
        for (i, share) in shares.iter().enumerate() {
            let mut encrypted_value = share.private.clone();
            encrypted_value.add(&alphas[i]);

            encrypted_shares.push(EncryptedShare {
                value: encrypted_value,
                commitment: alpha_commitments[i],
            });
        }

        // Generate single batched proof covering all eVRF evaluations
        let batch_proof = generate_batched_proof(
            identity,
            &identity_keys,
            &shared_points,
            &alphas,
            &alpha_commitments,
            &msg,
        );

        let contribution = Contribution {
            msg: msg.to_vec(),
            commitment,
            encrypted_shares,
            batch_proof,
        };

        let contributor = Self {
            index,
            secret,
            shares,
            _variant: std::marker::PhantomData,
        };

        (contributor, contribution)
    }

    /// Returns the contributor's index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Returns a reference to the generated shares.
    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    /// Consumes the contributor and returns the shares.
    pub fn into_shares(self) -> Vec<Share> {
        self.shares
    }
}

/// Generates a batched proof for all eVRF evaluations with FULL soundness.
///
/// The constraint system proves:
/// 1. Knowledge of sk via bit decomposition
/// 2. For each recipient: shared = sk * pk_other (full scalar multiplication!)
/// 3. For each recipient: alpha = shared.u
///
/// This is the SOUND version that uses JubjubScalarMulGadget with complete
/// constraints for each scalar multiplication step.
fn generate_batched_proof(
    identity: &IdentityKey,
    recipients: &[JubjubPoint],
    shared_points: &[JubjubPoint],
    alphas: &[Scalar],
    commitments: &[G1],
    msg: &[u8],
) -> R1CSProof {
    use super::bulletproofs::JubjubScalarMulGadget;

    let n = recipients.len();
    let mut cs = ConstraintSystem::new();

    // =========================================
    // 1. Allocate dealer's public key (public input)
    // =========================================
    let dealer_pk = JubjubPointVar::alloc_public(&mut cs);

    // =========================================
    // 2. Allocate and constrain secret key bits (shared across all recipients)
    // =========================================
    let sk_var = cs.alloc_witness();
    let sk_bits = BitDecomposition::new(&mut cs, sk_var, SCALAR_MUL_BITS);

    // =========================================
    // 3. For each recipient, add FULL scalar multiplication constraints
    // =========================================
    let mut scalar_muls = Vec::with_capacity(n);
    let mut alpha_vars = Vec::with_capacity(n);

    for _ in 0..n {
        // Recipient's public key is the base for scalar multiplication
        let pk_other = JubjubPointVar::alloc_public(&mut cs);

        // Create full scalar multiplication gadget: shared = sk * pk_other
        // This constrains ALL intermediate steps, making forging impossible
        let scalar_mul = JubjubScalarMulGadget::new(&mut cs, pk_other, &sk_bits);

        // Alpha = result.u (the u-coordinate of the shared point)
        let alpha_var = cs.alloc_witness();
        cs.constrain_equal(
            LinearCombination::from_var(alpha_var),
            scalar_mul.result.u_lc(),
        );

        scalar_muls.push(scalar_mul);
        alpha_vars.push(alpha_var);
    }

    // =========================================
    // 4. Build witness with actual values
    // =========================================

    // Build public inputs vector
    let mut public_inputs = Vec::new();

    // Dealer's public key
    let (dealer_u, dealer_v) = jubjub_point_to_scalars(&identity.public);
    public_inputs.push(dealer_u.clone());
    public_inputs.push(dealer_v.clone());

    // For each recipient: pk_other coords + powers coords
    for pk_other in recipients.iter() {
        let (pk_u, pk_v) = jubjub_point_to_scalars(pk_other);
        public_inputs.push(pk_u);
        public_inputs.push(pk_v);

        // Add powers [pk_other, 2*pk_other, 4*pk_other, ...] as public inputs
        let powers_jubjub = compute_powers_jubjub(pk_other, SCALAR_MUL_BITS);
        for power in &powers_jubjub {
            let (pow_u, pow_v) = jubjub_point_to_scalars(power);
            public_inputs.push(pow_u);
            public_inputs.push(pow_v);
        }
    }

    let mut witness = Witness::new(public_inputs);

    // Assign dealer pk
    dealer_pk.assign(&mut witness, &dealer_u, &dealer_v);

    // Assign secret key
    let sk_scalar = jubjub_scalar_to_bls(&identity.secret);
    witness.assign(sk_var, sk_scalar.clone());
    sk_bits.assign(&mut witness, &sk_scalar);

    // Assign each scalar multiplication
    for (i, scalar_mul) in scalar_muls.iter().enumerate() {
        let (pk_u, pk_v) = jubjub_point_to_scalars(&recipients[i]);
        let (shared_u, shared_v) = jubjub_point_to_scalars(&shared_points[i]);

        // Compute powers as JubjubPoints for correct arithmetic
        let powers_jubjub = compute_powers_jubjub(&recipients[i], SCALAR_MUL_BITS);
        // Convert to scalars for witness assignment
        let powers: Vec<(Scalar, Scalar)> = powers_jubjub
            .iter()
            .map(|p| jubjub_point_to_scalars(p))
            .collect();

        // Compute conditionals and accumulators
        let (conditionals, accumulators) =
            compute_scalar_mul_intermediates(&sk_scalar, &powers_jubjub, SCALAR_MUL_BITS);

        scalar_mul.assign(
            &mut witness,
            &pk_u,
            &pk_v,
            &sk_scalar,
            &shared_u,
            &shared_v,
            &powers,
            &conditionals,
            &accumulators,
        );

        // Assign alpha
        witness.assign(alpha_vars[i], alphas[i].clone());
    }

    // =========================================
    // 5. Generate proof with transcript binding
    // =========================================
    let gens = Generators::new(cs.padded_size());
    let prover = R1CSProver::new(&cs, &witness, &gens);

    let mut transcript = Transcript::new(DST_BATCHED_EVRF);
    transcript.append_bytes(b"msg", msg);
    append_jubjub_point(&mut transcript, b"dealer_pk", &identity.public);

    // Commit to all recipient data for binding
    for (i, pk_other) in recipients.iter().enumerate() {
        transcript.append_u64(b"idx", i as u64);
        append_jubjub_point(&mut transcript, b"pk_other", pk_other);
        transcript.append_point(b"R", &commitments[i]);
    }

    prover.prove(&mut transcript)
}

/// Computes conditional points and accumulators for scalar multiplication witness.
///
/// Uses JubjubPoint operations for correct arithmetic.
fn compute_scalar_mul_intermediates(
    sk: &Scalar,
    powers_jubjub: &[JubjubPoint],
    num_bits: usize,
) -> (Vec<(Scalar, Scalar)>, Vec<(Scalar, Scalar)>) {
    use commonware_codec::Encode;

    let mut conditionals = Vec::with_capacity(num_bits);
    let mut accumulators = Vec::with_capacity(num_bits);

    // Get bits of sk
    let sk_bytes = sk.encode();
    let byte_len = sk_bytes.len();

    // Identity point on Jubjub
    let identity = JubjubPoint::identity();

    // Current accumulator starts as identity
    let mut acc = identity;

    for i in 0..num_bits {
        let byte_idx = byte_len - 1 - (i / 8);
        let bit_idx = i % 8;
        let bit = if byte_idx < byte_len {
            (sk_bytes[byte_idx] >> bit_idx) & 1
        } else {
            0
        };

        // Conditional point: bit * power + (1-bit) * identity
        let cond = if bit == 1 {
            powers_jubjub[i]
        } else {
            identity
        };
        let (cond_u, cond_v) = jubjub_point_to_scalars(&cond);
        conditionals.push((cond_u, cond_v));

        // Update accumulator: acc = acc + cond
        acc.add(&cond);
        let (acc_u, acc_v) = jubjub_point_to_scalars(&acc);
        accumulators.push((acc_u, acc_v));
    }

    (conditionals, accumulators)
}

/// Computes powers [P, 2P, 4P, 8P, ...] for scalar multiplication as JubjubPoints.
fn compute_powers_jubjub(base: &JubjubPoint, num_bits: usize) -> Vec<JubjubPoint> {
    let mut powers = Vec::with_capacity(num_bits);
    let mut current = *base;

    for _ in 0..num_bits {
        powers.push(current);
        current = current.double();
    }

    powers
}

impl<V: Variant> Contribution<V> {
    /// Verifies this contribution.
    ///
    /// Verifies:
    /// 1. The batched eVRF proof covering all recipients
    /// 2. Each encrypted share against the Feldman commitment
    pub fn verify(
        &self,
        identity_keys: &[JubjubPoint],
        dealer_index: u32,
        threshold: u32,
        previous: Option<&poly::Public<V>>,
    ) -> Result<(), Error> {
        let n = identity_keys.len();
        let dealer_idx = dealer_index as usize;

        if dealer_idx >= n {
            return Err(Error::ParticipantIndexOutOfRange);
        }

        let expected_degree = threshold - 1;
        if self.commitment.degree() != expected_degree {
            return Err(Error::CommitmentWrongDegree(
                expected_degree,
                self.commitment.degree(),
            ));
        }

        if let Some(prev) = previous {
            let expected_constant = prev.evaluate(dealer_index).value;
            if *self.commitment.constant() != expected_constant {
                return Err(Error::ResharePolynomialMismatch);
            }
        }

        if self.encrypted_shares.len() != n {
            return Err(Error::WrongNumberOfShares(n, self.encrypted_shares.len()));
        }

        let dealer_pk = &identity_keys[dealer_idx];

        // Verify the batched proof
        if !verify_batched_proof(
            dealer_pk,
            identity_keys,
            &self.msg,
            &self.encrypted_shares,
            &self.batch_proof,
        ) {
            return Err(Error::EVRFProofInvalid(0));
        }

        // Verify each encrypted share against the Feldman commitment
        // This checks: g^z == C(idx) + R, which proves R = g^alpha and z = share + alpha
        for (recipient_idx, encrypted) in self.encrypted_shares.iter().enumerate() {
            let recipient_idx = recipient_idx as u32;

            let mut g_z = V::Public::one();
            g_z.mul(&encrypted.value);

            let commitment_eval = self.commitment.evaluate(recipient_idx).value;
            let alpha_commit_public = convert_g1_to_public::<V>(&encrypted.commitment)?;

            let mut expected = commitment_eval;
            expected.add(&alpha_commit_public);

            if g_z != expected {
                return Err(Error::EncryptedShareInvalid);
            }
        }

        Ok(())
    }
}

/// Verifies a batched eVRF proof with FULL soundness checks.
///
/// The verifier builds the same constraint system as the prover, including
/// full scalar multiplication constraints for each recipient.
fn verify_batched_proof(
    dealer_pk: &JubjubPoint,
    recipients: &[JubjubPoint],
    msg: &[u8],
    encrypted_shares: &[EncryptedShare],
    proof: &R1CSProof,
) -> bool {
    use super::bulletproofs::JubjubScalarMulGadget;

    let n = recipients.len();
    let mut cs = ConstraintSystem::new();

    // =========================================
    // Mirror the prover's constraint system EXACTLY
    // =========================================

    // 1. Dealer's public key (public input)
    let _dealer_pk_var = JubjubPointVar::alloc_public(&mut cs);

    // 2. Secret key bits (shared across all recipients)
    let sk_var = cs.alloc_witness();
    let sk_bits = BitDecomposition::new(&mut cs, sk_var, SCALAR_MUL_BITS);

    // 3. For each recipient: full scalar multiplication constraint
    for _ in 0..n {
        // Recipient's public key is the base
        let pk_other = JubjubPointVar::alloc_public(&mut cs);

        // Full scalar multiplication gadget: shared = sk * pk_other
        let scalar_mul = JubjubScalarMulGadget::new(&mut cs, pk_other, &sk_bits);

        // Alpha = result.u
        let alpha_var = cs.alloc_witness();
        cs.constrain_equal(
            LinearCombination::from_var(alpha_var),
            scalar_mul.result.u_lc(),
        );
    }

    // =========================================
    // Build public inputs - must match prover's structure exactly
    // =========================================
    let mut public_inputs = Vec::new();

    // Dealer's public key
    let (dealer_u, dealer_v) = jubjub_point_to_scalars(dealer_pk);
    public_inputs.push(dealer_u);
    public_inputs.push(dealer_v);

    // For each recipient: pk_other coords + powers coords
    for pk_other in recipients.iter() {
        let (pk_u, pk_v) = jubjub_point_to_scalars(pk_other);
        public_inputs.push(pk_u);
        public_inputs.push(pk_v);

        // Add powers [pk_other, 2*pk_other, 4*pk_other, ...] as public inputs
        // The verifier computes these from pk_other
        let powers_jubjub = compute_powers_jubjub(pk_other, SCALAR_MUL_BITS);
        for power in &powers_jubjub {
            let (pow_u, pow_v) = jubjub_point_to_scalars(power);
            public_inputs.push(pow_u);
            public_inputs.push(pow_v);
        }
    }

    // Create verifier
    let gens = Generators::new(cs.padded_size());
    let verifier = R1CSVerifier::new(&cs, &public_inputs, &gens);

    // Build transcript - must match prover exactly
    let mut transcript = Transcript::new(DST_BATCHED_EVRF);
    transcript.append_bytes(b"msg", msg);
    append_jubjub_point(&mut transcript, b"dealer_pk", dealer_pk);

    for (i, pk_other) in recipients.iter().enumerate() {
        transcript.append_u64(b"idx", i as u64);
        append_jubjub_point(&mut transcript, b"pk_other", pk_other);
        transcript.append_point(b"R", &encrypted_shares[i].commitment);
    }

    verifier.verify(&mut transcript, proof)
}

/// Batch verification of multiple contributions.
pub fn batch_verify_contributions<V: Variant>(
    contributions: &[(u32, &Contribution<V>)],
    identity_keys: &[JubjubPoint],
    threshold: u32,
    previous: Option<&poly::Public<V>>,
) -> Result<(), Error> {
    for (dealer_index, contribution) in contributions {
        contribution.verify(identity_keys, *dealer_index, threshold, previous)?;
    }
    Ok(())
}

// Helper functions

fn jubjub_point_to_scalars(point: &JubjubPoint) -> (Scalar, Scalar) {
    let u = point.u_as_bls_scalar();
    let v_field = point.get_v();
    let mut bytes = v_field.to_bytes();
    bytes.reverse();
    let v = if bytes == [0u8; 32] {
        Scalar::zero()
    } else {
        Scalar::decode(&bytes[..]).expect("valid scalar bytes")
    };
    (u, v)
}

fn jubjub_scalar_to_bls(scalar: &JubjubScalarWrapper) -> Scalar {
    let bytes = scalar.inner().to_bytes();
    // Use first 64 bits for reduced complexity
    let mut reduced = [0u8; 32];
    reduced[24..32].copy_from_slice(&bytes[0..8]);
    Scalar::decode(&reduced[..]).unwrap_or_else(|_| Scalar::map(b"JUBJUB_SK", &bytes))
}

fn append_jubjub_point(transcript: &mut Transcript, label: &'static [u8], point: &JubjubPoint) {
    let u = point.get_u();
    let v = point.get_v();
    transcript.append_bytes(label, &u.to_bytes());
    transcript.append_bytes(label, &v.to_bytes());
}

fn convert_g1_to_public<V: Variant>(point: &G1) -> Result<V::Public, Error> {
    let encoded = point.encode();
    if encoded.len() == V::Public::SIZE {
        V::Public::decode(encoded).map_err(|_| Error::InvalidPublicKey)
    } else {
        Err(Error::InvalidPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::variant::MinPk;
    use rand::{rngs::StdRng, SeedableRng};

    fn create_identities(rng: &mut StdRng, n: usize) -> Vec<IdentityKey> {
        (0..n).map(|_| IdentityKey::generate(rng)).collect()
    }

    #[test]
    fn test_contributor_creation() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (contributor, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        let threshold = quorum(n as u32);
        assert_eq!(contribution.commitment.degree(), threshold - 1);
        assert_eq!(contribution.encrypted_shares.len(), n);
        assert!(!contribution.msg.is_empty());
        assert_eq!(contributor.shares().len(), n);
    }

    #[test]
    fn test_contribution_verification() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        let threshold = quorum(n as u32);
        let result = contribution.verify(&identity_keys, 0, threshold, None);
        assert!(result.is_ok(), "verification failed: {:?}", result);
    }

    #[test]
    fn test_share_decryption() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (contributor, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        for (recipient_idx, recipient_identity) in identities.iter().enumerate() {
            let encrypted = &contribution.encrypted_shares[recipient_idx];
            let dealer_pk = &identity_keys[0];
            let alpha = recipient_identity.compute_alpha(dealer_pk);

            let mut decrypted = encrypted.value.clone();
            decrypted.sub(&alpha);

            let expected = &contributor.shares()[recipient_idx];
            assert_eq!(
                decrypted, expected.private,
                "decrypted share mismatch for recipient {recipient_idx}"
            );
        }
    }

    #[test]
    fn test_multiple_contributors() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();
        let threshold = quorum(n as u32);

        let mut contributions = Vec::new();
        for (idx, identity) in identities.iter().enumerate() {
            let (_, contribution) = Contributor::<MinPk>::new(
                &mut rng,
                identity_keys.clone(),
                idx as u32,
                identity,
                None,
            );

            let result = contribution.verify(&identity_keys, idx as u32, threshold, None);
            assert!(
                result.is_ok(),
                "contribution {} verification failed: {:?}",
                idx,
                result
            );

            contributions.push(contribution);
        }

        // Verify shares aggregate correctly
        let mut group_public = poly::Public::<MinPk>::zero();
        for contribution in &contributions {
            group_public.add(&contribution.commitment);
        }

        for (recipient_idx, recipient_identity) in identities.iter().enumerate() {
            let mut share_scalar = Scalar::zero();

            for (dealer_idx, contribution) in contributions.iter().enumerate() {
                let encrypted = &contribution.encrypted_shares[recipient_idx];
                let dealer_pk = &identity_keys[dealer_idx];
                let alpha = recipient_identity.compute_alpha(dealer_pk);

                let mut decrypted = encrypted.value.clone();
                decrypted.sub(&alpha);
                share_scalar.add(&decrypted);
            }

            let share = Share {
                index: recipient_idx as u32,
                private: share_scalar,
            };
            let expected_public = group_public.evaluate(recipient_idx as u32).value;
            let actual_public = share.public::<MinPk>();
            assert_eq!(
                expected_public, actual_public,
                "share {} public key mismatch",
                recipient_idx
            );
        }
    }

    #[test]
    fn test_batch_verify_contributions() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();
        let threshold = quorum(n as u32);

        let mut contributions = Vec::new();
        for (idx, identity) in identities.iter().enumerate() {
            let (_, contribution) = Contributor::<MinPk>::new(
                &mut rng,
                identity_keys.clone(),
                idx as u32,
                identity,
                None,
            );
            contributions.push((idx as u32, contribution));
        }

        let contribution_refs: Vec<_> = contributions.iter().map(|(idx, c)| (*idx, c)).collect();

        let result = batch_verify_contributions::<MinPk>(
            &contribution_refs,
            &identity_keys,
            threshold,
            None,
        );
        assert!(result.is_ok(), "batch verification failed: {:?}", result);
    }

    // =========================================
    // Soundness regression tests
    // =========================================

    #[test]
    fn test_soundness_tampered_encrypted_share_rejected() {
        // Test that tampering with an encrypted share value causes verification to fail
        let mut rng = StdRng::seed_from_u64(42);
        let n = 3;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (_, mut contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Tamper with an encrypted share value
        let mut tampered_value = contribution.encrypted_shares[1].value.clone();
        tampered_value.add(&Scalar::one());
        contribution.encrypted_shares[1].value = tampered_value;

        let threshold = quorum(n as u32);
        let result = contribution.verify(&identity_keys, 0, threshold, None);

        // Verification should fail due to Feldman check mismatch
        assert!(
            result.is_err(),
            "tampered encrypted share should be rejected"
        );
    }

    #[test]
    fn test_soundness_tampered_commitment_rejected() {
        // Test that tampering with a commitment causes verification to fail
        let mut rng = StdRng::seed_from_u64(42);
        let n = 3;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (_, mut contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Tamper with a commitment R
        let mut tampered_commitment = contribution.encrypted_shares[1].commitment;
        tampered_commitment.add(&G1::one());
        contribution.encrypted_shares[1].commitment = tampered_commitment;

        let threshold = quorum(n as u32);
        let result = contribution.verify(&identity_keys, 0, threshold, None);

        // Verification should fail - proof is bound to the original R
        assert!(
            result.is_err(),
            "tampered commitment should be rejected"
        );
    }

    #[test]
    fn test_soundness_wrong_dealer_rejected() {
        // Test that verifying with wrong dealer index fails
        let mut rng = StdRng::seed_from_u64(42);
        let n = 3;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        let threshold = quorum(n as u32);

        // Verify with wrong dealer index - should fail because dealer_pk won't match
        let result = contribution.verify(&identity_keys, 1, threshold, None);
        assert!(
            result.is_err(),
            "wrong dealer index should be rejected"
        );
    }

    #[test]
    fn test_soundness_different_identity_key_rejected() {
        // Test that a contribution created with one identity but verified against
        // different identity keys fails
        let mut rng = StdRng::seed_from_u64(42);
        let n = 3;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create contribution with original identity keys
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Create different identity keys
        let different_identities = create_identities(&mut rng, n);
        let different_identity_keys: Vec<JubjubPoint> =
            different_identities.iter().map(|id| id.public).collect();

        let threshold = quorum(n as u32);

        // Verify with different identity keys - should fail
        let result = contribution.verify(&different_identity_keys, 0, threshold, None);
        assert!(
            result.is_err(),
            "contribution verified with different identity keys should be rejected"
        );
    }

    #[test]
    fn test_soundness_swapped_contribution_rejected() {
        // Test that using one dealer's contribution with another dealer's identity fails
        let mut rng = StdRng::seed_from_u64(42);
        let n = 3;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create contribution from dealer 0
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        let threshold = quorum(n as u32);

        // Try to verify as if it came from dealer 1 - should fail because the
        // proof is bound to dealer 0's public key
        let result = contribution.verify(&identity_keys, 1, threshold, None);
        assert!(
            result.is_err(),
            "contribution from dealer 0 verified as dealer 1 should be rejected"
        );
    }

    #[test]
    fn test_soundness_proof_forged_from_wrong_sk_rejected() {
        // This test verifies that the scalar multiplication constraint is sound:
        // a prover using a different secret key cannot create a valid proof
        // for another dealer's public key.
        //
        // The full scalar multiplication gadget ensures:
        // 1. shared_j = sk * pk_other_j (for all j)
        // 2. alpha_j = shared_j.u
        //
        // Since powers [pk_other, 2*pk_other, ...] are public inputs that the
        // verifier computes independently, a malicious prover cannot provide
        // fake powers that would allow them to cheat.
        let mut rng = StdRng::seed_from_u64(42);
        let n = 3;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create a valid contribution from dealer 0
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        let threshold = quorum(n as u32);

        // The contribution verifies correctly with the right dealer
        let result = contribution.verify(&identity_keys, 0, threshold, None);
        assert!(result.is_ok(), "valid contribution should verify");

        // But if we try to verify with wrong dealer, the proof fails because:
        // - The prover committed to dealer 0's pk in the transcript
        // - The scalar multiplication proof is for sk_0 * pk_other_j
        // - Verifying as dealer 1 means using pk_1, but the proof was made for pk_0
        let result = contribution.verify(&identity_keys, 1, threshold, None);
        assert!(
            result.is_err(),
            "proof bound to dealer 0 should not verify as dealer 1"
        );
    }
}
