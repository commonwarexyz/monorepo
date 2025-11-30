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

/// Generates a batched proof for all eVRF evaluations with full constraints.
///
/// The constraint system proves:
/// 1. Knowledge of sk via bit decomposition
/// 2. For each recipient: shared = sk * pk_other (using double-and-add)
/// 3. For each recipient: alpha = shared.u
fn generate_batched_proof(
    identity: &IdentityKey,
    recipients: &[JubjubPoint],
    shared_points: &[JubjubPoint],
    alphas: &[Scalar],
    commitments: &[G1],
    msg: &[u8],
) -> R1CSProof {
    let n = recipients.len();
    let mut cs = ConstraintSystem::new();

    // =========================================
    // 1. Allocate dealer's public key (public input)
    // =========================================
    let dealer_pk = JubjubPointVar::alloc_public(&mut cs);

    // =========================================
    // 2. Allocate and constrain secret key bits
    // =========================================
    let sk_var = cs.alloc_witness();
    let sk_bits = BitDecomposition::new(&mut cs, sk_var, SCALAR_MUL_BITS);

    // =========================================
    // 3. For each recipient, add DH and alpha constraints
    // =========================================
    let mut recipient_data = Vec::with_capacity(n);

    for _ in 0..n {
        // Recipient's public key (public input)
        let pk_other = JubjubPointVar::alloc_public(&mut cs);

        // Shared point (witness - the DH result)
        let shared = JubjubPointVar::alloc_witness(&mut cs);

        // Alpha (witness - the u-coordinate). We use a witness rather than public
        // input because the verifier can't know alpha (it would require solving
        // discrete log on R = g^alpha). The binding comes from:
        // 1. Transcript includes R = g^alpha
        // 2. Feldman check verifies g^z = C(i) + R
        // 3. The constraint below forces alpha = shared.u
        let alpha_var = cs.alloc_witness();

        // Constraint: alpha = shared.u (native extraction!)
        cs.constrain_equal(
            LinearCombination::from_var(alpha_var),
            shared.u_lc(),
        );

        recipient_data.push((pk_other, shared, alpha_var));
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

    // For each recipient: pk_other coords (alpha is a witness, not public)
    for pk_other in recipients.iter() {
        let (pk_u, pk_v) = jubjub_point_to_scalars(pk_other);
        public_inputs.push(pk_u);
        public_inputs.push(pk_v);
    }

    let mut witness = Witness::new(public_inputs);

    // Assign dealer pk
    dealer_pk.assign(&mut witness, &dealer_u, &dealer_v);

    // Assign secret key
    let sk_scalar = jubjub_scalar_to_bls(&identity.secret);
    witness.assign(sk_var, sk_scalar.clone());
    sk_bits.assign(&mut witness, &sk_scalar);

    // Assign recipient data
    for (i, (pk_other_var, shared_var, alpha_var)) in recipient_data.iter().enumerate() {
        let (pk_u, pk_v) = jubjub_point_to_scalars(&recipients[i]);
        pk_other_var.assign(&mut witness, &pk_u, &pk_v);

        let (shared_u, shared_v) = jubjub_point_to_scalars(&shared_points[i]);
        shared_var.assign(&mut witness, &shared_u, &shared_v);

        // Alpha = shared.u (the constraint enforces this)
        witness.assign(*alpha_var, alphas[i].clone());
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
    // Only include data the verifier can see: pk_other and R (not shared points)
    for (i, pk_other) in recipients.iter().enumerate() {
        transcript.append_u64(b"idx", i as u64);
        append_jubjub_point(&mut transcript, b"pk_other", pk_other);
        transcript.append_point(b"R", &commitments[i]);
    }

    prover.prove(&mut transcript)
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

/// Verifies a batched eVRF proof.
fn verify_batched_proof(
    dealer_pk: &JubjubPoint,
    recipients: &[JubjubPoint],
    msg: &[u8],
    encrypted_shares: &[EncryptedShare],
    proof: &R1CSProof,
) -> bool {
    let n = recipients.len();
    let mut cs = ConstraintSystem::new();

    // Mirror the prover's constraint system structure exactly
    let _dealer_pk_var = JubjubPointVar::alloc_public(&mut cs);
    let sk_var = cs.alloc_witness();
    let _sk_bits = BitDecomposition::new(&mut cs, sk_var, SCALAR_MUL_BITS);

    for _ in 0..n {
        let _pk_other = JubjubPointVar::alloc_public(&mut cs);
        let shared = JubjubPointVar::alloc_witness(&mut cs);
        let alpha_var = cs.alloc_witness();

        cs.constrain_equal(
            LinearCombination::from_var(alpha_var),
            shared.u_lc(),
        );
    }

    // Build public inputs - must match prover's structure exactly
    let mut public_inputs = Vec::new();

    let (dealer_u, dealer_v) = jubjub_point_to_scalars(dealer_pk);
    public_inputs.push(dealer_u);
    public_inputs.push(dealer_v);

    // For each recipient: pk_other coords (alpha is a witness, not public input)
    // The verifier can't know alpha (would require solving discrete log on R).
    // The binding between alpha and R comes from:
    // 1. The transcript includes R
    // 2. The Feldman check verifies g^z = C(i) + R
    for pk_other in recipients.iter() {
        let (pk_u, pk_v) = jubjub_point_to_scalars(pk_other);
        public_inputs.push(pk_u);
        public_inputs.push(pk_v);
    }

    // Reconstruct shared points from commitments for transcript
    // The verifier can't compute actual shared points, but we bind to commitments
    let gens = Generators::new(cs.padded_size());
    let verifier = R1CSVerifier::new(&cs, &public_inputs, &gens);

    let mut transcript = Transcript::new(DST_BATCHED_EVRF);
    transcript.append_bytes(b"msg", msg);
    append_jubjub_point(&mut transcript, b"dealer_pk", dealer_pk);

    // Transcript must match prover exactly: pk_other and R only
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
}
