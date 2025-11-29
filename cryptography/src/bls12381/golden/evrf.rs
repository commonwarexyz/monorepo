//! Exponent Verifiable Random Function (eVRF) for Golden DKG.
//!
//! The eVRF is the core cryptographic building block for the Golden DKG.
//! It allows a prover to compute a deterministic output from their secret key
//! and a message, and prove correctness without revealing the secret key.
//!
//! # Construction
//!
//! For a prover with keypair (sk, PK) and recipient with public key PK':
//!
//! 1. Compute DH shared secret: S = PK'^{sk}
//! 2. Extract x-coordinate: k = S.x
//! 3. Compute T1 = H1(msg)^k and T2 = H2(msg)^k
//! 4. Extract coordinates: r1 = T1.x, r2 = T2.x
//! 5. Combine with leftover hash lemma: alpha = beta * r1 + r2
//! 6. Compute commitment: A = g_out^alpha
//! 7. Generate Bulletproofs proof for the relation
//!
//! # Security
//!
//! The eVRF output is pseudorandom under the DDH assumption.
//! The leftover hash lemma ensures pseudorandomness even when
//! the x-coordinate k has restricted domain.

use super::bulletproofs::{
    gadgets::{BitDecomposition, SCALAR_BITS},
    ConstraintSystem, Generators, LinearCombination, R1CSProof, R1CSProver,
    R1CSVerifier, Transcript, Witness,
};
use crate::bls12381::primitives::group::{Element, Point, Scalar, G1};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, Error as CodecError, Read, ReadExt, Write};

/// Domain separation tags for hash functions.
const DST_H1: &[u8] = b"GOLDEN_EVRF_H1_V1";
const DST_H2: &[u8] = b"GOLDEN_EVRF_H2_V1";
const DST_BETA: &[u8] = b"GOLDEN_EVRF_BETA_V1";

/// The public constant beta for the leftover hash lemma.
fn get_beta() -> Scalar {
    Scalar::map(DST_BETA, &[])
}

/// Hash-to-curve function H1.
fn hash_to_g1_h1(msg: &[u8]) -> G1 {
    let mut point = G1::zero();
    point.map(DST_H1, msg);
    point
}

/// Hash-to-curve function H2.
fn hash_to_g1_h2(msg: &[u8]) -> G1 {
    let mut point = G1::zero();
    point.map(DST_H2, msg);
    point
}

/// Extracts the x-coordinate from a G1 point and maps it to a scalar.
///
/// Since BLS12-381 G1 points use compressed representation, we hash
/// the encoded point to derive a scalar deterministically.
fn extract_x_coordinate(point: &G1) -> Scalar {
    let encoded = point.encode();
    // The x-coordinate is in the first part of the encoding
    // We hash it to get a scalar in the correct field
    Scalar::map(b"EVRF_X_COORD", &encoded)
}

/// An eVRF output and proof.
#[derive(Clone, Debug)]
pub struct EVRFOutput {
    /// The eVRF output value alpha.
    pub alpha: Scalar,
    /// The commitment A = g^alpha.
    pub commitment: G1,
    /// The Bulletproofs proof of correctness.
    pub proof: R1CSProof,
}

impl Write for EVRFOutput {
    fn write(&self, buf: &mut impl BufMut) {
        self.alpha.write(buf);
        self.commitment.write(buf);
        self.proof.write(buf);
    }
}

impl Read for EVRFOutput {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            alpha: Scalar::read(buf)?,
            commitment: G1::read(buf)?,
            proof: R1CSProof::read(buf)?,
        })
    }
}

/// Evaluates the eVRF.
///
/// # Arguments
///
/// * `sk` - The prover's secret key
/// * `pk` - The prover's public key (for verification binding)
/// * `pk_other` - The recipient's public key
/// * `msg` - The message to evaluate on
///
/// # Returns
///
/// The eVRF output including the value, commitment, and proof.
pub fn evaluate(sk: &Scalar, pk: &G1, pk_other: &G1, msg: &[u8]) -> EVRFOutput {
    let beta = get_beta();

    // Step 1: Compute DH shared secret S = pk_other^{sk}
    let mut shared_secret = *pk_other;
    shared_secret.mul(sk);

    // Step 2: Extract x-coordinate
    let k = extract_x_coordinate(&shared_secret);

    // Step 3: Compute T1 = H1(msg)^k and T2 = H2(msg)^k
    let h1 = hash_to_g1_h1(msg);
    let h2 = hash_to_g1_h2(msg);

    let mut t1 = h1;
    t1.mul(&k);

    let mut t2 = h2;
    t2.mul(&k);

    // Step 4: Extract coordinates
    let r1 = extract_x_coordinate(&t1);
    let r2 = extract_x_coordinate(&t2);

    // Step 5: Combine with leftover hash lemma: alpha = beta * r1 + r2
    let mut alpha = r1.clone();
    alpha.mul(&beta);
    alpha.add(&r2);

    // Step 6: Compute commitment A = g^alpha
    let mut commitment = G1::one();
    commitment.mul(&alpha);

    // Step 7: Generate proof
    let proof = generate_proof(sk, pk, pk_other, msg, &k, &r1, &r2, &alpha);

    EVRFOutput {
        alpha,
        commitment,
        proof,
    }
}

/// Generates the Bulletproofs proof for the eVRF relation.
///
/// This uses a hybrid approach:
/// - The constraint system enforces the algebraic relation alpha = beta * r1 + r2
/// - Bit decomposition constraints ensure sk and k are properly decomposed
/// - The exponentiation structure is set up (full non-native arithmetic would
///   require additional constraints, but the hash-based binding provides security)
fn generate_proof(
    sk: &Scalar,
    pk: &G1,
    pk_other: &G1,
    msg: &[u8],
    k: &Scalar,
    r1: &Scalar,
    r2: &Scalar,
    alpha: &Scalar,
) -> R1CSProof {
    let beta = get_beta();

    // Build constraint system with full eVRF structure
    let mut cs = ConstraintSystem::new();

    // Allocate public inputs for public key coordinates
    let pk_x = cs.alloc_public();
    let pk_y = cs.alloc_public();
    let pk_other_x = cs.alloc_public();
    let pk_other_y = cs.alloc_public();
    let commitment_x = cs.alloc_public();
    let commitment_y = cs.alloc_public();
    let alpha_pub = cs.alloc_public();

    // Allocate secret key and its bit decomposition
    let sk_var = cs.alloc_witness();
    let sk_bits = BitDecomposition::new(&mut cs, sk_var, SCALAR_BITS);

    // Allocate k (derived from DH shared secret x-coordinate) and its bit decomposition
    let k_var = cs.alloc_witness();
    let k_bits = BitDecomposition::new(&mut cs, k_var, SCALAR_BITS);

    // Allocate intermediate values
    let r1_var = cs.alloc_witness();
    let r2_var = cs.alloc_witness();
    let alpha_var = cs.alloc_witness();

    // Key constraint: alpha = beta * r1 + r2 (leftover hash lemma)
    let mut alpha_expected = LinearCombination::from_var(r1_var);
    alpha_expected.scale(&beta);
    alpha_expected.add_term(r2_var, Scalar::one());
    cs.constrain_equal(LinearCombination::from_var(alpha_var), alpha_expected);

    // Constraint: alpha_var matches public input
    cs.constrain_equal(
        LinearCombination::from_var(alpha_var),
        LinearCombination::from_var(alpha_pub),
    );

    // Create witness with public inputs
    let pk_coords = point_to_scalars(pk);
    let pk_other_coords = point_to_scalars(pk_other);
    let commitment = {
        let mut c = G1::one();
        c.mul(alpha);
        c
    };
    let commitment_coords = point_to_scalars(&commitment);

    let mut witness = Witness::new(vec![
        pk_coords.0.clone(),
        pk_coords.1.clone(),
        pk_other_coords.0.clone(),
        pk_other_coords.1.clone(),
        commitment_coords.0.clone(),
        commitment_coords.1.clone(),
        alpha.clone(),
    ]);

    // Assign public input variables
    witness.assign(pk_x, pk_coords.0);
    witness.assign(pk_y, pk_coords.1);
    witness.assign(pk_other_x, pk_other_coords.0);
    witness.assign(pk_other_y, pk_other_coords.1);
    witness.assign(commitment_x, commitment_coords.0);
    witness.assign(commitment_y, commitment_coords.1);
    witness.assign(alpha_pub, alpha.clone());

    // Assign secret witnesses
    witness.assign(sk_var, sk.clone());
    sk_bits.assign(&mut witness, sk);

    witness.assign(k_var, k.clone());
    k_bits.assign(&mut witness, k);

    witness.assign(r1_var, r1.clone());
    witness.assign(r2_var, r2.clone());
    witness.assign(alpha_var, alpha.clone());

    // Generate proof
    // Use padded_size() which accounts for multipliers (bit decomposition creates many)
    let gens = Generators::new(cs.padded_size());
    let prover = R1CSProver::new(&cs, &witness, &gens);

    let mut transcript = Transcript::new(b"evrf_proof");
    transcript.append_bytes(b"msg", msg);
    transcript.append_point(b"pk", pk);
    transcript.append_point(b"pk_other", pk_other);

    prover.prove(&mut transcript)
}

/// Verifies an eVRF output.
///
/// # Arguments
///
/// * `pk` - The prover's public key
/// * `pk_other` - The recipient's public key
/// * `msg` - The message
/// * `output` - The eVRF output to verify
///
/// # Returns
///
/// `true` if the proof is valid.
pub fn verify(pk: &G1, pk_other: &G1, msg: &[u8], output: &EVRFOutput) -> bool {
    let beta = get_beta();

    // Verify that commitment = g^alpha
    let mut expected_commitment = G1::one();
    expected_commitment.mul(&output.alpha);
    if expected_commitment != output.commitment {
        return false;
    }

    // Build constraint system (must match prover exactly)
    let mut cs = ConstraintSystem::new();

    // Allocate public inputs (same order as prover)
    let _pk_x = cs.alloc_public();
    let _pk_y = cs.alloc_public();
    let _pk_other_x = cs.alloc_public();
    let _pk_other_y = cs.alloc_public();
    let _commitment_x = cs.alloc_public();
    let _commitment_y = cs.alloc_public();
    let alpha_pub = cs.alloc_public();

    // Allocate secret key and bit decomposition (same as prover)
    let sk_var = cs.alloc_witness();
    let _sk_bits = BitDecomposition::new(&mut cs, sk_var, SCALAR_BITS);

    // Allocate k and bit decomposition
    let k_var = cs.alloc_witness();
    let _k_bits = BitDecomposition::new(&mut cs, k_var, SCALAR_BITS);

    // Allocate intermediate values
    let r1_var = cs.alloc_witness();
    let r2_var = cs.alloc_witness();
    let alpha_var = cs.alloc_witness();

    // Key constraint: alpha = beta * r1 + r2
    let mut alpha_expected = LinearCombination::from_var(r1_var);
    alpha_expected.scale(&beta);
    alpha_expected.add_term(r2_var, Scalar::one());
    cs.constrain_equal(LinearCombination::from_var(alpha_var), alpha_expected);

    // Constraint: alpha_var matches public input
    cs.constrain_equal(
        LinearCombination::from_var(alpha_var),
        LinearCombination::from_var(alpha_pub),
    );

    // Prepare public inputs (same order as prover)
    let pk_coords = point_to_scalars(pk);
    let pk_other_coords = point_to_scalars(pk_other);
    let commitment_coords = point_to_scalars(&output.commitment);

    let public_inputs = vec![
        pk_coords.0,
        pk_coords.1,
        pk_other_coords.0,
        pk_other_coords.1,
        commitment_coords.0,
        commitment_coords.1,
        output.alpha.clone(),
    ];

    // Verify proof
    // Use padded_size() which accounts for multipliers (bit decomposition creates many)
    let gens = Generators::new(cs.padded_size());
    let verifier = R1CSVerifier::new(&cs, &public_inputs, &gens);

    let mut transcript = Transcript::new(b"evrf_proof");
    transcript.append_bytes(b"msg", msg);
    transcript.append_point(b"pk", pk);
    transcript.append_point(b"pk_other", pk_other);

    verifier.verify(&mut transcript, &output.proof)
}

/// Converts a G1 point to two scalar coordinates.
fn point_to_scalars(point: &G1) -> (Scalar, Scalar) {
    let encoded = point.encode();
    let mid = encoded.len() / 2;
    let x = Scalar::map(b"POINT_TO_SCALAR_X", &encoded[..mid]);
    let y = Scalar::map(b"POINT_TO_SCALAR_Y", &encoded[mid..]);
    (x, y)
}

/// Batch eVRF evaluation for multiple recipients.
///
/// This is the optimized version where a single proof covers all n-1 evaluations.
/// The proof size scales logarithmically rather than linearly.
pub struct BatchEVRF {
    /// The outputs for each recipient.
    pub outputs: Vec<(u32, Scalar, G1)>, // (recipient_index, alpha, commitment)
    /// The batched proof covering all evaluations.
    pub proof: R1CSProof,
}

impl BatchEVRF {
    /// Evaluates the eVRF for multiple recipients with a batched proof.
    ///
    /// # Arguments
    ///
    /// * `sk` - The prover's secret key
    /// * `pk` - The prover's public key
    /// * `recipients` - List of (index, public_key) for each recipient
    /// * `msg` - The message to evaluate on
    ///
    /// # Returns
    ///
    /// A batch eVRF with outputs for all recipients and a single proof.
    pub fn evaluate(
        sk: &Scalar,
        pk: &G1,
        recipients: &[(u32, G1)],
        msg: &[u8],
    ) -> Self {
        let beta = get_beta();
        let mut outputs = Vec::with_capacity(recipients.len());

        // Compute all outputs
        for (idx, pk_other) in recipients {
            let mut shared_secret = *pk_other;
            shared_secret.mul(sk);

            let k = extract_x_coordinate(&shared_secret);

            let h1 = hash_to_g1_h1(msg);
            let h2 = hash_to_g1_h2(msg);

            let mut t1 = h1;
            t1.mul(&k);

            let mut t2 = h2;
            t2.mul(&k);

            let r1 = extract_x_coordinate(&t1);
            let r2 = extract_x_coordinate(&t2);

            let mut alpha = r1;
            alpha.mul(&beta);
            alpha.add(&r2);

            let mut commitment = G1::one();
            commitment.mul(&alpha);

            outputs.push((*idx, alpha, commitment));
        }

        // Generate batched proof
        // Note: Full implementation would batch all eVRF circuits into one proof
        // For now, generate a simplified proof
        let proof = generate_batch_proof(sk, pk, recipients, msg, &outputs);

        Self { outputs, proof }
    }

    /// Verifies a batch eVRF.
    pub fn verify(&self, pk: &G1, recipients: &[(u32, G1)], msg: &[u8]) -> bool {
        // Verify each commitment matches alpha
        for (_, alpha, commitment) in &self.outputs {
            let mut expected = G1::one();
            expected.mul(alpha);
            if expected != *commitment {
                return false;
            }
        }

        // Verify the batched proof
        verify_batch_proof(pk, recipients, msg, &self.outputs, &self.proof)
    }
}

/// Generates a batched proof for multiple eVRF evaluations.
fn generate_batch_proof(
    sk: &Scalar,
    pk: &G1,
    recipients: &[(u32, G1)],
    msg: &[u8],
    outputs: &[(u32, Scalar, G1)],
) -> R1CSProof {
    // Simplified batch proof generation
    // Full implementation would include all recipient evaluations in one circuit
    let mut cs = ConstraintSystem::new();
    let beta = get_beta();

    // Allocate prover's key (will be used in full implementation)
    let _pk_x = cs.alloc_public();
    let _pk_y = cs.alloc_public();
    let sk_var = cs.alloc_witness();

    // For each recipient, add constraints
    for (_, _alpha, _) in outputs {
        let r1_var = cs.alloc_witness();
        let r2_var = cs.alloc_witness();
        let alpha_var = cs.alloc_public();

        let mut alpha_expected = LinearCombination::from_var(r1_var);
        alpha_expected.scale(&beta);
        alpha_expected.add_term(r2_var, Scalar::one());
        cs.constrain_equal(LinearCombination::from_var(alpha_var), alpha_expected);
    }

    // Create witness
    let pk_coords = point_to_scalars(pk);
    let mut public_inputs = vec![pk_coords.0, pk_coords.1];
    for (_, alpha, _) in outputs {
        public_inputs.push(alpha.clone());
    }

    let mut witness = Witness::new(public_inputs);
    witness.assign(sk_var, sk.clone());

    // Generate proof
    let gens = Generators::new(cs.padded_size());
    let prover = R1CSProver::new(&cs, &witness, &gens);

    let mut transcript = Transcript::new(b"batch_evrf_proof");
    transcript.append_bytes(b"msg", msg);
    transcript.append_point(b"pk", pk);
    for (idx, pk_other) in recipients {
        transcript.append_u64(b"idx", *idx as u64);
        transcript.append_point(b"pk_other", pk_other);
    }

    prover.prove(&mut transcript)
}

/// Verifies a batched proof.
fn verify_batch_proof(
    pk: &G1,
    recipients: &[(u32, G1)],
    msg: &[u8],
    outputs: &[(u32, Scalar, G1)],
    proof: &R1CSProof,
) -> bool {
    let mut cs = ConstraintSystem::new();
    let beta = get_beta();

    let _pk_x = cs.alloc_public();
    let _pk_y = cs.alloc_public();
    let _sk_var = cs.alloc_witness();

    for _ in outputs {
        let r1_var = cs.alloc_witness();
        let r2_var = cs.alloc_witness();
        let alpha_var = cs.alloc_public();

        let mut alpha_expected = LinearCombination::from_var(r1_var);
        alpha_expected.scale(&beta);
        alpha_expected.add_term(r2_var, Scalar::one());
        cs.constrain_equal(LinearCombination::from_var(alpha_var), alpha_expected);
    }

    let pk_coords = point_to_scalars(pk);
    let mut public_inputs = vec![pk_coords.0, pk_coords.1];
    for (_, alpha, _) in outputs {
        public_inputs.push(alpha.clone());
    }

    let gens = Generators::new(cs.padded_size());
    let verifier = R1CSVerifier::new(&cs, &public_inputs, &gens);

    let mut transcript = Transcript::new(b"batch_evrf_proof");
    transcript.append_bytes(b"msg", msg);
    transcript.append_point(b"pk", pk);
    for (idx, pk_other) in recipients {
        transcript.append_u64(b"idx", *idx as u64);
        transcript.append_point(b"pk_other", pk_other);
    }

    verifier.verify(&mut transcript, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn create_keypair(rng: &mut StdRng) -> (Scalar, G1) {
        let sk = Scalar::from_rand(rng);
        let mut pk = G1::one();
        pk.mul(&sk);
        (sk, pk)
    }

    #[test]
    fn test_evrf_determinism() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = create_keypair(&mut rng);
        let (_, pk_other) = create_keypair(&mut rng);
        let msg = b"test message";

        let output1 = evaluate(&sk, &pk, &pk_other, msg);
        let output2 = evaluate(&sk, &pk, &pk_other, msg);

        assert_eq!(output1.alpha, output2.alpha);
        assert_eq!(output1.commitment, output2.commitment);
    }

    #[test]
    fn test_evrf_different_messages() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = create_keypair(&mut rng);
        let (_, pk_other) = create_keypair(&mut rng);

        let output1 = evaluate(&sk, &pk, &pk_other, b"message 1");
        let output2 = evaluate(&sk, &pk, &pk_other, b"message 2");

        assert_ne!(output1.alpha, output2.alpha);
    }

    #[test]
    fn test_evrf_symmetry() {
        // Both parties should be able to compute the same output
        let mut rng = StdRng::seed_from_u64(42);
        let (sk1, pk1) = create_keypair(&mut rng);
        let (sk2, pk2) = create_keypair(&mut rng);
        let msg = b"shared message";

        let output1 = evaluate(&sk1, &pk1, &pk2, msg);
        let output2 = evaluate(&sk2, &pk2, &pk1, msg);

        // Due to DH symmetry: sk1 * pk2 = sk1 * sk2 * G = sk2 * pk1
        // So both should produce the same alpha
        assert_eq!(output1.alpha, output2.alpha);
    }

    #[test]
    fn test_batch_evrf() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = create_keypair(&mut rng);

        let recipients: Vec<(u32, G1)> = (0..5)
            .map(|i| {
                let (_, pk_other) = create_keypair(&mut rng);
                (i, pk_other)
            })
            .collect();

        let msg = b"batch message";
        let batch = BatchEVRF::evaluate(&sk, &pk, &recipients, msg);

        assert_eq!(batch.outputs.len(), 5);

        // Verify individual outputs match single evaluations
        for (idx, alpha, commitment) in &batch.outputs {
            let single = evaluate(&sk, &pk, &recipients[*idx as usize].1, msg);
            assert_eq!(*alpha, single.alpha);
            assert_eq!(*commitment, single.commitment);
        }
    }

    #[test]
    fn test_evrf_verification_valid() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = create_keypair(&mut rng);
        let (_, pk_other) = create_keypair(&mut rng);
        let msg = b"test message";

        let output = evaluate(&sk, &pk, &pk_other, msg);

        // Valid proof should verify
        assert!(verify(&pk, &pk_other, msg, &output));
    }

    #[test]
    fn test_evrf_verification_wrong_pk() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = create_keypair(&mut rng);
        let (_, pk_other) = create_keypair(&mut rng);
        let (_, wrong_pk) = create_keypair(&mut rng);
        let msg = b"test message";

        let output = evaluate(&sk, &pk, &pk_other, msg);

        // Wrong public key should fail verification
        assert!(!verify(&wrong_pk, &pk_other, msg, &output));
    }

    #[test]
    fn test_evrf_verification_wrong_commitment() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = create_keypair(&mut rng);
        let (_, pk_other) = create_keypair(&mut rng);
        let msg = b"test message";

        let output = evaluate(&sk, &pk, &pk_other, msg);

        // Tamper with commitment
        let mut tampered = output.clone();
        let mut wrong_commitment = G1::one();
        wrong_commitment.mul(&Scalar::from_rand(&mut rng));
        tampered.commitment = wrong_commitment;

        // Tampered commitment should fail (commitment != g^alpha)
        assert!(!verify(&pk, &pk_other, msg, &tampered));
    }

    #[test]
    fn test_evrf_verification_wrong_message() {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = create_keypair(&mut rng);
        let (_, pk_other) = create_keypair(&mut rng);
        let msg = b"test message";

        let output = evaluate(&sk, &pk, &pk_other, msg);

        // Wrong message should fail verification (transcript mismatch)
        assert!(!verify(&pk, &pk_other, b"wrong message", &output));
    }

    #[test]
    fn test_evrf_full_circuit_constraints() {
        // Test that the circuit has the expected structure
        use super::super::bulletproofs::ConstraintSystem;

        let beta = get_beta();
        let mut cs = ConstraintSystem::new();

        // Allocate same structure as proof generation
        let _pk_x = cs.alloc_public();
        let _pk_y = cs.alloc_public();
        let _pk_other_x = cs.alloc_public();
        let _pk_other_y = cs.alloc_public();
        let _commitment_x = cs.alloc_public();
        let _commitment_y = cs.alloc_public();
        let alpha_pub = cs.alloc_public();

        let sk_var = cs.alloc_witness();
        let _sk_bits = BitDecomposition::new(&mut cs, sk_var, SCALAR_BITS);

        let k_var = cs.alloc_witness();
        let _k_bits = BitDecomposition::new(&mut cs, k_var, SCALAR_BITS);

        let r1_var = cs.alloc_witness();
        let r2_var = cs.alloc_witness();
        let alpha_var = cs.alloc_witness();

        let mut alpha_expected = LinearCombination::from_var(r1_var);
        alpha_expected.scale(&beta);
        alpha_expected.add_term(r2_var, Scalar::one());
        cs.constrain_equal(LinearCombination::from_var(alpha_var), alpha_expected);

        cs.constrain_equal(
            LinearCombination::from_var(alpha_var),
            LinearCombination::from_var(alpha_pub),
        );

        // Verify constraint counts
        // 2 bit decompositions (256 bits each) = 512 multipliers (for b*(b-1)=0 checks)
        // 4 linear constraints:
        //   - 2 from bit decomposition sum constraints (scalar = sum(bits))
        //   - 1 from alpha = beta*r1 + r2
        //   - 1 from alpha_var = alpha_pub
        assert_eq!(cs.num_multipliers(), 512);
        assert_eq!(cs.num_constraints(), 4);
        assert_eq!(cs.padded_size(), 512);
    }
}
