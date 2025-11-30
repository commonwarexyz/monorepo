//! Batched contributor for the Golden DKG protocol.
//!
//! This implements the optimized Golden DKG with batch proving:
//! - Instead of (n-1) separate proofs, a single batched Bulletproof proves
//!   correctness of all eVRF evaluations simultaneously.
//! - Proof size grows logarithmically with the number of recipients.
//! - For n=100 parties, reduces proof size from ~150kB to ~2.2kB.
//!
//! # Structure
//!
//! - `BatchedEncryptedShare`: Just the ciphertext (z) and commitment (R), no individual proof
//! - `BatchedContribution`: Contains a single batched proof covering all shares
//! - `BatchedContributor`: Generates contributions with batched proofs
//!
//! # Status: Prototype
//!
//! This implementation uses a simplified constraint system that verifies:
//! - `alpha = shared.u` (u-coordinate extraction)
//!
//! For production use, the full constraint system should verify:
//! - `pk = sk * G` (knowledge of secret key on Jubjub)
//! - `shared = sk * pk_other` (DH computed correctly)
//!
//! The `EVRFGadget` in `bulletproofs/gadgets.rs` provides these full constraints.
//! Integration with the batched prover is a TODO for production readiness.

use super::{
    bulletproofs::{
        ConstraintSystem, Generators, LinearCombination, R1CSProof, R1CSProver, R1CSVerifier,
        Transcript, Witness,
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
const DST_BATCHED_EVRF: &[u8] = b"GOLDEN_BATCHED_EVRF_V1";

/// An encrypted share without individual proof (for batched contributions).
///
/// The proof is provided at the contribution level, covering all shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedEncryptedShare {
    /// The encrypted share value: z = share + alpha.
    pub value: Scalar,
    /// The commitment to alpha: R = g_out^alpha.
    pub commitment: G1,
}

impl Write for BatchedEncryptedShare {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.commitment.write(buf);
    }
}

impl Read for BatchedEncryptedShare {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Scalar::read(buf)?;
        let commitment = G1::read(buf)?;
        Ok(Self { value, commitment })
    }
}

impl commonware_codec::EncodeSize for BatchedEncryptedShare {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + self.commitment.encode_size()
    }
}

/// A contribution with batched proof.
///
/// Instead of (n-1) individual proofs, contains a single batched Bulletproof
/// that proves correctness of all eVRF evaluations simultaneously.
///
/// # Size Comparison
///
/// For n participants:
/// - Unbatched: n × (48 + 32 + ~1500) ≈ n × 1580 bytes
/// - Batched: n × (48 + 32) + ~2200 ≈ n × 80 + 2200 bytes
///
/// For n=100: ~158kB vs ~10.2kB (15x reduction)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedContribution<V: Variant> {
    /// Random message for eVRF domain separation.
    pub msg: Vec<u8>,
    /// The Feldman commitment to the secret polynomial (on G_out).
    pub commitment: poly::Public<V>,
    /// Encrypted shares for each participant (without individual proofs).
    pub encrypted_shares: Vec<BatchedEncryptedShare>,
    /// Single batched proof covering all eVRF evaluations.
    pub batch_proof: R1CSProof,
}

/// Maximum message size for eVRF.
const MAX_MSG_SIZE: usize = 64;

impl<V: Variant> Write for BatchedContribution<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.msg.write(buf);
        self.commitment.write(buf);
        self.encrypted_shares.write(buf);
        self.batch_proof.write(buf);
    }
}

impl<V: Variant> Read for BatchedContribution<V> {
    type Cfg = (NonZeroU32, NonZeroU32); // (threshold, n_participants)

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (threshold, n) = cfg;
        let n_usize = n.get() as usize;
        let msg = Vec::<u8>::read_cfg(buf, &(RangeCfg::from(0..=MAX_MSG_SIZE), ()))?;
        let commitment =
            poly::Public::<V>::read_cfg(buf, &RangeCfg::from(*threshold..=*threshold))?;
        let encrypted_shares = Vec::<BatchedEncryptedShare>::read_cfg(
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

impl<V: Variant> commonware_codec::EncodeSize for BatchedContribution<V> {
    fn encode_size(&self) -> usize {
        self.msg.encode_size()
            + self.commitment.encode_size()
            + self.encrypted_shares.encode_size()
            + self.batch_proof.encode_size()
    }
}

/// A contributor that generates batched proofs.
pub struct BatchedContributor<V: Variant> {
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

impl<V: Variant> BatchedContributor<V> {
    /// Creates a new contributor with batched proof generation.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `identity_keys` - Jubjub public keys of all participants (G_in)
    /// * `index` - This contributor's index in the participant list
    /// * `identity` - This contributor's Jubjub identity key
    /// * `previous_share` - If resharing, the share from the previous DKG
    ///
    /// # Returns
    ///
    /// A tuple of `(BatchedContributor, BatchedContribution)`.
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        identity_keys: Vec<JubjubPoint>,
        index: u32,
        identity: &IdentityKey,
        previous_share: Option<Share>,
    ) -> (Self, BatchedContribution<V>) {
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

        // Create encrypted shares (without individual proofs)
        let mut encrypted_shares = Vec::with_capacity(n as usize);
        for (i, share) in shares.iter().enumerate() {
            let mut encrypted_value = share.private.clone();
            encrypted_value.add(&alphas[i]);

            encrypted_shares.push(BatchedEncryptedShare {
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

        let contribution = BatchedContribution {
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

/// Generates a single batched proof for all eVRF evaluations.
///
/// The proof covers the relation for all recipients:
/// For each recipient j:
/// 1. S_j = sk * PK_j (DH computed correctly)
/// 2. alpha_j = S_j.u (u-coordinate extraction)
/// 3. R_j = g_out^alpha_j (commitment correct)
///
/// All evaluations share the same secret key sk, which significantly
/// reduces the total constraint count compared to individual proofs.
///
/// # Prototype Note
///
/// Currently uses a simplified constraint system that only verifies
/// `alpha = shared.u`. For production use, integrate the full `EVRFGadget`
/// from `bulletproofs/gadgets.rs` which includes scalar multiplication
/// constraints for both `pk = sk * G` and `shared = sk * pk_other`.
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

    // Allocate prover's public key (shared across all evaluations)
    let _pk_u = cs.alloc_public();
    let _pk_v = cs.alloc_public();

    // Allocate secret key (single witness, reused for all evaluations)
    let sk_var = cs.alloc_witness();

    // For each recipient, allocate variables and add constraints
    let mut recipient_vars = Vec::with_capacity(n);
    for _ in 0..n {
        // Recipient's public key
        let pk_other_u = cs.alloc_public();
        let pk_other_v = cs.alloc_public();

        // Alpha (public output)
        let alpha_var = cs.alloc_public();

        // Shared point coordinates (witness)
        let shared_u = cs.alloc_witness();
        let shared_v = cs.alloc_witness();

        // Constraint: alpha = shared_u (the u-coordinate is alpha)
        cs.constrain_equal(
            LinearCombination::from_var(alpha_var),
            LinearCombination::from_var(shared_u),
        );

        recipient_vars.push((pk_other_u, pk_other_v, alpha_var, shared_u, shared_v));
    }

    // Build public inputs
    let pk_u_scalar = point_coord_to_bls_scalar(&identity.public, true);
    let pk_v_scalar = point_coord_to_bls_scalar(&identity.public, false);

    let mut public_inputs = vec![pk_u_scalar, pk_v_scalar];

    for (i, pk_other) in recipients.iter().enumerate() {
        public_inputs.push(point_coord_to_bls_scalar(pk_other, true));
        public_inputs.push(point_coord_to_bls_scalar(pk_other, false));
        public_inputs.push(alphas[i].clone());
    }

    // Build witness
    let mut witness = Witness::new(public_inputs);

    // Assign secret key
    let sk_scalar = jubjub_scalar_to_bls(&identity.secret);
    witness.assign(sk_var, sk_scalar);

    // Assign shared point coordinates for each recipient
    for (i, (_pk_other_u, _pk_other_v, _alpha_var, shared_u, shared_v)) in
        recipient_vars.iter().enumerate()
    {
        let shared_u_scalar = point_coord_to_bls_scalar(&shared_points[i], true);
        let shared_v_scalar = point_coord_to_bls_scalar(&shared_points[i], false);
        witness.assign(*shared_u, shared_u_scalar);
        witness.assign(*shared_v, shared_v_scalar);
    }

    // Generate proof
    let gens = Generators::new(cs.padded_size());
    let prover = R1CSProver::new(&cs, &witness, &gens);

    let mut transcript = Transcript::new(DST_BATCHED_EVRF);
    transcript.append_bytes(b"msg", msg);
    append_jubjub_point(&mut transcript, b"pk", &identity.public);
    for (i, pk_other) in recipients.iter().enumerate() {
        transcript.append_u64(b"idx", i as u64);
        append_jubjub_point(&mut transcript, b"pk_other", pk_other);
        transcript.append_point(b"commitment", &commitments[i]);
    }

    prover.prove(&mut transcript)
}

impl<V: Variant> BatchedContribution<V> {
    /// Verifies this batched contribution.
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

        // Check dealer index is valid
        if dealer_idx >= n {
            return Err(Error::ParticipantIndexOutOfRange);
        }

        // Check commitment degree
        let expected_degree = threshold - 1;
        if self.commitment.degree() != expected_degree {
            return Err(Error::CommitmentWrongDegree(
                expected_degree,
                self.commitment.degree(),
            ));
        }

        // Check reshare constraint if applicable
        if let Some(prev) = previous {
            let expected_constant = prev.evaluate(dealer_index).value;
            if *self.commitment.constant() != expected_constant {
                return Err(Error::ResharePolynomialMismatch);
            }
        }

        // Check number of encrypted shares
        if self.encrypted_shares.len() != n {
            return Err(Error::WrongNumberOfShares(n, self.encrypted_shares.len()));
        }

        // Get dealer's Jubjub public key
        let dealer_pk = &identity_keys[dealer_idx];

        // Verify the batched proof
        if !verify_batched_proof(
            dealer_pk,
            identity_keys,
            &self.msg,
            &self.encrypted_shares,
            &self.batch_proof,
        ) {
            return Err(Error::EVRFProofInvalid(0)); // Batch proof failed
        }

        // Verify each encrypted share against the Feldman commitment
        for (recipient_idx, encrypted) in self.encrypted_shares.iter().enumerate() {
            let recipient_idx = recipient_idx as u32;

            // Verify encryption correctness:
            // g^z == g^share * g^alpha == C * R
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
    encrypted_shares: &[BatchedEncryptedShare],
    proof: &R1CSProof,
) -> bool {
    let n = recipients.len();
    let mut cs = ConstraintSystem::new();

    // Same constraint system structure as prover
    let _pk_u = cs.alloc_public();
    let _pk_v = cs.alloc_public();
    let _sk_var = cs.alloc_witness();

    for _ in 0..n {
        let _pk_other_u = cs.alloc_public();
        let _pk_other_v = cs.alloc_public();
        let alpha_var = cs.alloc_public();
        let shared_u = cs.alloc_witness();
        let _shared_v = cs.alloc_witness();

        cs.constrain_equal(
            LinearCombination::from_var(alpha_var),
            LinearCombination::from_var(shared_u),
        );
    }

    // Build public inputs
    let pk_u_scalar = point_coord_to_bls_scalar(dealer_pk, true);
    let pk_v_scalar = point_coord_to_bls_scalar(dealer_pk, false);

    let mut public_inputs = vec![pk_u_scalar, pk_v_scalar];

    for (i, pk_other) in recipients.iter().enumerate() {
        public_inputs.push(point_coord_to_bls_scalar(pk_other, true));
        public_inputs.push(point_coord_to_bls_scalar(pk_other, false));
        // Derive alpha from commitment for verification
        let alpha = derive_alpha_from_commitment(&encrypted_shares[i].commitment);
        public_inputs.push(alpha);
    }

    // Verify
    let gens = Generators::new(cs.padded_size());
    let verifier = R1CSVerifier::new(&cs, &public_inputs, &gens);

    let mut transcript = Transcript::new(DST_BATCHED_EVRF);
    transcript.append_bytes(b"msg", msg);
    append_jubjub_point(&mut transcript, b"pk", dealer_pk);
    for (i, pk_other) in recipients.iter().enumerate() {
        transcript.append_u64(b"idx", i as u64);
        append_jubjub_point(&mut transcript, b"pk_other", pk_other);
        transcript.append_point(b"commitment", &encrypted_shares[i].commitment);
    }

    verifier.verify(&mut transcript, proof)
}

/// Batch verification of multiple contributions.
///
/// Verifies multiple batched contributions more efficiently than individual
/// verification by combining MSM operations.
pub fn batch_verify_contributions<V: Variant>(
    contributions: &[(u32, &BatchedContribution<V>)],
    identity_keys: &[JubjubPoint],
    threshold: u32,
    previous: Option<&poly::Public<V>>,
) -> Result<(), Error> {
    // For now, verify each contribution individually
    // A full implementation would batch the MSMs across all proofs
    for (dealer_index, contribution) in contributions {
        contribution.verify(identity_keys, *dealer_index, threshold, previous)?;
    }
    Ok(())
}

// Helper functions

fn point_coord_to_bls_scalar(point: &JubjubPoint, is_u: bool) -> Scalar {
    if is_u {
        point.u_as_bls_scalar()
    } else {
        let v = point.get_v();
        let mut bytes = v.to_bytes();
        bytes.reverse();
        if bytes == [0u8; 32] {
            return Scalar::zero();
        }
        Scalar::decode(&bytes[..]).expect("valid scalar bytes")
    }
}

fn jubjub_scalar_to_bls(scalar: &JubjubScalarWrapper) -> Scalar {
    let bytes = scalar.inner().to_bytes();
    Scalar::map(b"JUBJUB_SK_TO_BLS", &bytes)
}

/// Derives alpha from a commitment.
///
/// # Prototype Note
///
/// This is a placeholder for the simplified constraint system.
/// In the production implementation, the proof should directly verify
/// the relationship between the commitment R = g^alpha and the DH computation
/// without needing to know alpha explicitly on the verifier side.
fn derive_alpha_from_commitment(commitment: &G1) -> Scalar {
    let encoded = commitment.encode();
    Scalar::map(b"ALPHA_FROM_COMMIT", &encoded)
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
    use commonware_codec::EncodeSize;
    use rand::{rngs::StdRng, SeedableRng};

    fn create_identities(rng: &mut StdRng, n: usize) -> Vec<IdentityKey> {
        (0..n).map(|_| IdentityKey::generate(rng)).collect()
    }

    #[test]
    fn test_batched_contributor_creation() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (contributor, contribution) = BatchedContributor::<MinPk>::new(
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
    fn test_batched_contribution_verification() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (_, contribution) = BatchedContributor::<MinPk>::new(
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
    fn test_batched_share_decryption() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let (contributor, contribution) = BatchedContributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Each participant should be able to decrypt their share
        for (recipient_idx, recipient_identity) in identities.iter().enumerate() {
            let encrypted = &contribution.encrypted_shares[recipient_idx];

            // Compute alpha using DH symmetry
            let dealer_pk = &identity_keys[0];
            let alpha = recipient_identity.compute_alpha(dealer_pk);

            // Decrypt: share = encrypted - alpha
            let mut decrypted = encrypted.value.clone();
            decrypted.sub(&alpha);

            // Verify decrypted share matches original
            let expected = &contributor.shares()[recipient_idx];
            assert_eq!(
                decrypted, expected.private,
                "decrypted share mismatch for recipient {recipient_idx}"
            );
        }
    }

    #[test]
    fn test_batched_multiple_contributors() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();
        let threshold = quorum(n as u32);

        let mut contributions = Vec::new();
        for (idx, identity) in identities.iter().enumerate() {
            let (_, contribution) = BatchedContributor::<MinPk>::new(
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

        // Aggregate and recover shares
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
    fn test_batched_vs_unbatched_size() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 10;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create batched contribution
        let (_, batched) = BatchedContributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Create unbatched contribution for comparison
        use super::super::contributor::Contributor;
        let mut rng2 = StdRng::seed_from_u64(42);
        let (_, unbatched) = Contributor::<MinPk>::new(
            &mut rng2,
            identity_keys,
            0,
            &identities[0],
            None,
        );

        let batched_size = batched.encode_size();
        let unbatched_size = unbatched.encode_size();

        println!("Batched size: {} bytes", batched_size);
        println!("Unbatched size: {} bytes", unbatched_size);
        println!("Reduction: {:.1}x", unbatched_size as f64 / batched_size as f64);

        // Batched should be significantly smaller
        assert!(
            batched_size < unbatched_size,
            "batched should be smaller than unbatched"
        );
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
            let (_, contribution) = BatchedContributor::<MinPk>::new(
                &mut rng,
                identity_keys.clone(),
                idx as u32,
                identity,
                None,
            );
            contributions.push((idx as u32, contribution));
        }

        // Batch verify all contributions
        let contribution_refs: Vec<_> = contributions
            .iter()
            .map(|(idx, c)| (*idx, c))
            .collect();

        let result = batch_verify_contributions::<MinPk>(
            &contribution_refs,
            &identity_keys,
            threshold,
            None,
        );
        assert!(result.is_ok(), "batch verification failed: {:?}", result);
    }
}
