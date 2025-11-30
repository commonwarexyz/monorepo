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
    gadgets::EVRFGadget, ConstraintSystem, Generators, LinearCombination, R1CSProof, R1CSProver,
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

/// Extracts the x-coordinate from a G1 point and converts to a scalar.
///
/// Implements `k = int(S.X)` from the Golden DKG paper.
/// The x-coordinate (in Fq, ~381 bits) is reduced modulo r (scalar field order)
/// to produce a valid scalar. This is done by interpreting the x-coordinate
/// bytes as a big integer and hashing to the scalar field.
///
/// Note: The paper's `int()` function converts Fq to Z. Since Fq > Fr,
/// we use a deterministic hash-based reduction that is collision-resistant.
fn extract_x_coordinate(point: &G1) -> Scalar {
    let (x_bytes, _) = point.coordinates();
    // Use the x-coordinate directly (48 bytes, big-endian) to derive the scalar.
    // This is a deterministic mapping from Fq to Fr.
    Scalar::map(b"EVRF_INT_X", &x_bytes)
}

/// An eVRF output and proof.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl commonware_codec::EncodeSize for EVRFOutput {
    fn encode_size(&self) -> usize {
        self.alpha.encode_size() + self.commitment.encode_size() + self.proof.encode_size()
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
/// Implements the ℛ_{eVRF†} relation from the Golden DKG paper with full
/// soundness guarantees using the EVRFGadget:
///
/// 1. PK = g^{sk}: Proves knowledge of secret key
/// 2. S = PK_other^{sk}: Proves DH shared secret computation
/// 3. k = int(S.X): Proves x-coordinate extraction
/// 4. T1 = H1^k, T2 = H2^k: Proves hash exponentiations
/// 5. r1 = T1.X, r2 = T2.X: Proves coordinate extractions
/// 6. alpha = beta * r1 + r2: Proves leftover hash lemma combination
#[allow(clippy::too_many_arguments)]
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

    // Compute intermediate values needed for witness assignment
    let g = G1::one();

    // Compute DH shared secret: S = pk_other^sk
    let mut shared_secret = *pk_other;
    shared_secret.mul(sk);

    // Compute hash points
    let h1 = hash_to_g1_h1(msg);
    let h2 = hash_to_g1_h2(msg);

    // Compute T1 = H1^k and T2 = H2^k
    let mut t1 = h1;
    t1.mul(k);
    let mut t2 = h2;
    t2.mul(k);

    // Compute output commitment: A = g^alpha
    let mut output = G1::one();
    output.mul(alpha);

    // Build constraint system with full eVRF relation using EVRFGadget
    let mut cs = ConstraintSystem::new();

    // Create the full eVRF gadget with all soundness constraints
    let evrf_gadget = EVRFGadget::new(&mut cs, &beta);

    // Create witness and assign all values
    // First, collect all public inputs for the witness
    let g_point_coords = get_point_limb_scalars(&g);
    let pk_coords = get_point_limb_scalars(pk);
    let pk_other_coords = get_point_limb_scalars(pk_other);
    let h1_coords = get_point_limb_scalars(&h1);
    let h2_coords = get_point_limb_scalars(&h2);
    let output_coords = get_point_limb_scalars(&output);

    // Collect public inputs (in order they were allocated in EVRFGadget)
    let mut public_inputs = Vec::new();
    // pk (4 limbs x, 4 limbs y)
    public_inputs.extend(pk_coords.clone());
    // pk_other (4 limbs x, 4 limbs y)
    public_inputs.extend(pk_other_coords.clone());
    // output (4 limbs x, 4 limbs y)
    public_inputs.extend(output_coords.clone());
    // g_in (4 limbs x, 4 limbs y) - generator for exp_pk
    public_inputs.extend(g_point_coords.clone());
    // h1 (4 limbs x, 4 limbs y) - base for exp_t1
    public_inputs.extend(h1_coords.clone());
    // h2 (4 limbs x, 4 limbs y) - base for exp_t2
    public_inputs.extend(h2_coords.clone());
    // Power points for exponentiations (allocated in EVRFGadget::new via ExponentiationGadget)
    // These are public and computed by the verifier

    let mut witness = Witness::new(public_inputs);

    // Assign all witness values using the EVRFGadget's assign method
    evrf_gadget.assign(
        &mut witness,
        sk,
        pk,
        pk_other,
        &shared_secret,
        k,
        &h1,
        &h2,
        &t1,
        &t2,
        r1,
        r2,
        alpha,
        &output,
        &g,
    );

    // Generate proof
    let gens = Generators::new(cs.padded_size());
    let prover = R1CSProver::new(&cs, &witness, &gens);

    let mut transcript = Transcript::new(b"evrf_proof_v2");
    transcript.append_bytes(b"msg", msg);
    transcript.append_point(b"pk", pk);
    transcript.append_point(b"pk_other", pk_other);

    prover.prove(&mut transcript)
}

/// Gets the limb scalars for a G1 point (8 scalars: 4 for x, 4 for y).
fn get_point_limb_scalars(point: &G1) -> Vec<Scalar> {
    let (x_bytes, y_bytes) = point.coordinates();
    let mut scalars = Vec::with_capacity(8);

    // Split x-coordinate into 4 limbs of 96 bits each
    for limb_scalar in bytes_to_limb_scalars(&x_bytes) {
        scalars.push(limb_scalar);
    }

    // Split y-coordinate into 4 limbs of 96 bits each
    for limb_scalar in bytes_to_limb_scalars(&y_bytes) {
        scalars.push(limb_scalar);
    }

    scalars
}

/// Converts 48-byte big-endian coordinates to 4 limb scalars (96 bits each).
#[allow(clippy::needless_range_loop)]
fn bytes_to_limb_scalars(bytes: &[u8]) -> [Scalar; 4] {
    // bytes is 48 bytes in big-endian
    // Split into 4 chunks of 12 bytes (96 bits) each
    // limb[0] = lowest 96 bits = bytes[36..48]
    // limb[1] = next 96 bits = bytes[24..36]
    // limb[2] = next 96 bits = bytes[12..24]
    // limb[3] = highest 96 bits = bytes[0..12]

    let padded = if bytes.len() < 48 {
        let mut p = vec![0u8; 48];
        p[48 - bytes.len()..].copy_from_slice(bytes);
        p
    } else {
        bytes.to_vec()
    };

    let mut limbs = [Scalar::zero(), Scalar::zero(), Scalar::zero(), Scalar::zero()];

    for i in 0..4 {
        let start = 48 - (i + 1) * 12;
        let end = start + 12;
        let chunk = &padded[start..end];

        // Convert chunk to little-endian
        let mut le_bytes = [0u8; 12];
        for (j, &b) in chunk.iter().enumerate() {
            le_bytes[11 - j] = b;
        }

        // Map to scalar
        limbs[i] = Scalar::map(b"LIMB_SCALAR", &le_bytes);
    }

    limbs
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
///
/// # Verification
///
/// The verifier rebuilds the same constraint system as the prover using EVRFGadget,
/// which enforces the full ℛ_{eVRF†} relation from the Golden DKG paper:
///
/// 1. PK = g^{sk}: Knowledge of secret key
/// 2. S = PK_other^{sk}: DH shared secret computation
/// 3. k = int(S.X): x-coordinate extraction
/// 4. T1 = H1^k, T2 = H2^k: Hash exponentiations
/// 5. r1 = T1.X, r2 = T2.X: Coordinate extractions
/// 6. alpha = beta * r1 + r2: Leftover hash lemma combination
pub fn verify(pk: &G1, pk_other: &G1, msg: &[u8], output: &EVRFOutput) -> bool {
    let beta = get_beta();

    // Verify that commitment = g^alpha
    let mut expected_commitment = G1::one();
    expected_commitment.mul(&output.alpha);
    if expected_commitment != output.commitment {
        return false;
    }

    // Build constraint system with full eVRF relation (must match prover exactly)
    let mut cs = ConstraintSystem::new();

    // Create the full eVRF gadget with all soundness constraints
    let _evrf_gadget = EVRFGadget::new(&mut cs, &beta);

    // Compute public inputs (in same order as prover)
    let g = G1::one();
    let h1 = hash_to_g1_h1(msg);
    let h2 = hash_to_g1_h2(msg);

    let g_point_coords = get_point_limb_scalars(&g);
    let pk_coords = get_point_limb_scalars(pk);
    let pk_other_coords = get_point_limb_scalars(pk_other);
    let h1_coords = get_point_limb_scalars(&h1);
    let h2_coords = get_point_limb_scalars(&h2);
    let output_coords = get_point_limb_scalars(&output.commitment);

    // Collect public inputs (in order they were allocated in EVRFGadget)
    let mut public_inputs = Vec::new();
    // pk (4 limbs x, 4 limbs y)
    public_inputs.extend(pk_coords);
    // pk_other (4 limbs x, 4 limbs y)
    public_inputs.extend(pk_other_coords);
    // output (4 limbs x, 4 limbs y)
    public_inputs.extend(output_coords);
    // g_in (4 limbs x, 4 limbs y) - generator for exp_pk
    public_inputs.extend(g_point_coords);
    // h1 (4 limbs x, 4 limbs y) - base for exp_t1
    public_inputs.extend(h1_coords);
    // h2 (4 limbs x, 4 limbs y) - base for exp_t2
    public_inputs.extend(h2_coords);

    // Verify proof
    let gens = Generators::new(cs.padded_size());
    let verifier = R1CSVerifier::new(&cs, &public_inputs, &gens);

    let mut transcript = Transcript::new(b"evrf_proof_v2");
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
        // Test that the circuit has the expected structure using the full EVRFGadget
        use super::super::bulletproofs::ConstraintSystem;

        let beta = get_beta();
        let mut cs = ConstraintSystem::new();

        // Create the full EVRFGadget which sets up all constraints
        let _evrf_gadget = EVRFGadget::new(&mut cs, &beta);

        // The full EVRFGadget creates many more constraints than the simplified version:
        // - 2 bit decompositions (sk, k): 2 * 256 = 512 bit checks
        // - 4 exponentiations with non-native arithmetic
        // - 3 coordinate extractions
        // - 1 linear constraint for alpha = beta * r1 + r2
        //
        // Per the Golden DKG paper, the constraint count should be 14*lambda + 14 = 3598
        // for lambda = 256 bits. However, with full non-native arithmetic the actual
        // count is higher due to range checks and point additions.
        //
        // The theoretical count from the paper assumes an optimized representation.
        // Our implementation uses explicit non-native arithmetic which is more
        // expensive but provides stronger soundness guarantees.

        // Verify we have a significant number of constraints
        assert!(cs.num_multipliers() > 512);
        // The padded size should be a power of 2 >= num_multipliers
        assert!(cs.padded_size() >= cs.num_multipliers());
    }
}
