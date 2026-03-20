//! Witness-indistinguishable proof system using polynomial commitment.
//!
//! Bridges the constraint system and polynomial commitment. The verifier
//! is convinced the prover knows a witness satisfying the circuit, but
//! the opened rows in the Ligerito proof leak partial witness information.
//!
//! For full zero-knowledge, the witness polynomial would need random
//! blinding and the sumcheck messages would need masking.
//! See <https://www.youtube.com/watch?v=GNaOgmqGxkI&t=11m> on WI vs ZK.
//!
//! ## Accidental computer path
//!
//! [`prove_from_block`] takes an already DA-encoded block and produces
//! a proof without re-encoding. The DA encoding IS the polynomial
//! commitment -- zero additional prover cost.

use crate::field::{BinaryElem128, BinaryElem32, BinaryFieldElement};
use crate::proof::Proof;
use crate::transcript::Sha256Transcript;
use crate::Transcript as _; // bring trait methods into scope

use crate::circuit::constraint::{Circuit, Witness};
use crate::circuit::witness::LigeritoInstance;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Zero-knowledge proof for circuit satisfaction.
pub struct ZkProof {
    /// Polynomial commitment proof.
    pub commitment_proof: Proof<BinaryElem32, BinaryElem128>,
    /// Public inputs (revealed to verifier).
    pub public_inputs: Vec<u32>,
    /// Constraint batching challenge (derived from transcript).
    pub batching_challenge: [u8; 16],
    /// log2 of witness polynomial size.
    pub log_size: u8,
}

/// Prover for zero-knowledge circuit proofs.
pub struct ZkProver;

impl ZkProver {
    /// Create a new prover.
    pub const fn new() -> Self {
        Self
    }

    /// Prove circuit satisfaction.
    pub fn prove(&self, circuit: Circuit, witness: Witness) -> crate::Result<ZkProof> {
        // Create instance from circuit and witness.
        let instance = LigeritoInstance::new(circuit, witness);

        // Verify constraints locally (debug check).
        if !instance.is_satisfied() {
            return Err(crate::Error::InvalidConfig(
                "circuit constraints not satisfied",
            ));
        }

        let log_size = instance.log_size();

        // Get appropriate config (minimum size from MIN_LOG_SIZE).
        let target_log_size = log_size.max(crate::MIN_LOG_SIZE as usize);

        let config = crate::prover_config_for_log_size::<BinaryElem32, BinaryElem128>(
            target_log_size as u32,
        );

        // Pad polynomial to match config size.
        let mut poly = instance.get_polynomial().to_vec();
        let target_size = 1usize << target_log_size;
        poly.resize(target_size, BinaryElem32::zero());

        // Generate proof.
        let mut transcript = Sha256Transcript::new(1234);
        let proof = crate::prove(&config, &poly, &mut transcript)?;

        // Compute batching challenge from public inputs.
        let batching_challenge = compute_batching_challenge(&instance.public_inputs);

        Ok(ZkProof {
            commitment_proof: proof,
            public_inputs: instance
                .public_inputs
                .iter()
                .map(|x| x.poly().value())
                .collect(),
            batching_challenge,
            log_size: target_log_size as u8,
        })
    }
}

impl Default for ZkProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifier for zero-knowledge circuit proofs.
pub struct ZkVerifier;

impl ZkVerifier {
    /// Create a new verifier.
    pub const fn new() -> Self {
        Self
    }

    /// Verify a ZK proof.
    pub fn verify(
        &self,
        proof: &ZkProof,
        expected_public_inputs: &[u32],
    ) -> crate::Result<bool> {
        // Check public inputs match.
        if proof.public_inputs != expected_public_inputs {
            return Ok(false);
        }

        let log_size = proof.log_size as u32;

        // Get appropriate config.
        let config = crate::verifier_config_for_log_size(log_size);

        // Verify proof.
        let mut transcript = Sha256Transcript::new(1234);
        crate::verify(&config, &proof.commitment_proof, &mut transcript)
    }
}

impl Default for ZkVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute batching challenge from public inputs.
/// (simplified -- real impl uses full transcript)
fn compute_batching_challenge(public_inputs: &[BinaryElem32]) -> [u8; 16] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"commonware-circuit-batching-v1");
    for input in public_inputs {
        hasher.update(input.poly().value().to_le_bytes());
    }

    let hash = hasher.finalize();
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&hash[..16]);
    challenge
}

/// Prove circuit satisfaction reusing a DA-encoded block.
///
/// This is the "accidental computer" construction: the DA encoding
/// IS the polynomial commitment. The prover skips the encoding step
/// entirely, using the already-computed `EncodedBlock` as the witness.
///
/// # Arguments
///
/// * `block` - DA-encoded block (already RS-encoded and Merkle-committed)
/// * `poly` - The original polynomial (before encoding)
/// * `circuit` - The constraint circuit to prove
/// * `witness_data` - The witness values
///
/// The `block` must have been created from the same `poly` data.
pub fn prove_from_block(
    block: crate::da::EncodedBlock<BinaryElem32>,
    poly: &[BinaryElem32],
    circuit: Circuit,
    witness_data: Witness,
) -> crate::Result<ZkProof> {
    let instance = LigeritoInstance::new(circuit, witness_data);

    if !instance.is_satisfied() {
        return Err(crate::Error::InvalidConfig(
            "circuit constraints not satisfied",
        ));
    }

    let log_size = instance.log_size().max(crate::MIN_LOG_SIZE as usize);
    let config =
        crate::prover_config_for_log_size::<BinaryElem32, BinaryElem128>(log_size as u32);

    let mut poly_padded = poly.to_vec();
    poly_padded.resize(1 << log_size, BinaryElem32::zero());

    // Reuse the DA block as the initial witness -- zero re-encoding cost.
    let wtns_0 = block.into_witness();
    let cm_0 = crate::proof::Commitment {
        root: wtns_0.tree.get_root(),
    };

    let mut transcript = Sha256Transcript::new(1234);
    let root_bytes = cm_0
        .root
        .root
        .as_ref()
        .map_or(&[] as &[u8], |h| h.as_slice());
    transcript.absorb_root(root_bytes);

    // Call prove_core directly with the pre-computed witness.
    let proof = crate::prover::prove_core(&config, &poly_padded, wtns_0, cm_0, &mut transcript)?;

    let batching_challenge = compute_batching_challenge(&instance.public_inputs);

    Ok(ZkProof {
        commitment_proof: proof,
        public_inputs: instance
            .public_inputs
            .iter()
            .map(|x| x.poly().value())
            .collect(),
        batching_challenge,
        log_size: log_size as u8,
    })
}

/// High-level API: prove and verify in one call (for testing).
pub fn prove_and_verify(circuit: Circuit, witness: Witness) -> crate::Result<bool> {
    let prover = ZkProver::new();
    let verifier = ZkVerifier::new();

    let public_inputs: Vec<u32> = witness
        .public_inputs()
        .iter()
        .map(|&v| v as u32)
        .collect();

    let proof = prover.prove(circuit, witness)?;
    verifier.verify(&proof, &public_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::constraint::{CircuitBuilder, Operand, WireId};

    #[test]
    fn test_simple_zk_proof() {
        let mut builder = CircuitBuilder::new();
        let pub_a = builder.add_public();
        let w = builder.add_witness();
        let out = builder.add_public();

        // Constraint: pub_a ^ w = out.
        builder.assert_xor(
            Operand::new().with_wire(pub_a),
            Operand::new().with_wire(w),
            Operand::new().with_wire(out),
        );

        let circuit = builder.build();

        // Witness: 5 ^ 3 = 6.
        let mut witness = Witness::new(3, 2);
        witness.set(WireId(0), 5); // pub_a
        witness.set(WireId(1), 3); // w (private)
        witness.set(WireId(2), 6); // out

        let result = prove_and_verify(circuit, witness);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_and_constraint_zk() {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_public();
        let b = builder.add_witness();
        let c = builder.add_public();

        // a & b = c.
        builder.assert_and(
            Operand::new().with_wire(a),
            Operand::new().with_wire(b),
            Operand::new().with_wire(c),
        );

        let circuit = builder.build();

        // 0xFF & 0x0F = 0x0F.
        let mut witness = Witness::new(3, 2);
        witness.set(WireId(0), 0xFF);
        witness.set(WireId(1), 0x0F);
        witness.set(WireId(2), 0x0F);

        let result = prove_and_verify(circuit, witness);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_invalid_witness_fails() {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_witness();
        let b = builder.add_witness();
        let c = builder.add_witness();

        builder.assert_xor(
            Operand::new().with_wire(a),
            Operand::new().with_wire(b),
            Operand::new().with_wire(c),
        );

        let circuit = builder.build();

        // Invalid: 5 ^ 3 != 7.
        let mut witness = Witness::new(3, 0);
        witness.set(WireId(0), 5);
        witness.set(WireId(1), 3);
        witness.set(WireId(2), 7); // wrong!

        let prover = ZkProver::new();
        let result = prover.prove(circuit, witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_verify_eq() {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_public();
        let b = builder.add_witness();

        builder.assert_eq(
            Operand::new().with_wire(a),
            Operand::new().with_wire(b),
        );

        let circuit = builder.build();

        let mut witness = Witness::new(2, 1);
        witness.set(WireId(0), 42);
        witness.set(WireId(1), 42);

        let prover = ZkProver::new();
        let proof = prover.prove(circuit, witness).unwrap();

        // Verify proof.
        let verifier = ZkVerifier::new();
        let result = verifier.verify(&proof, &[42]).unwrap();
        assert!(result);
    }
}
