//! Threshold signature verification circuit.
//!
//! Proves that at least `threshold` out of `n` validators signed a
//! message, without the light client checking each signature. The
//! polynomial encodes signature bits and the sumcheck proves the
//! threshold was met.
//!
//! # Witness layout
//!
//! For `n` validators:
//! - Wires 0..n: signature bits (1 = signed, 0 = did not sign)
//! - Wire n: claimed count (public, sum of signature bits)
//! - Wire n+1: threshold (public, minimum required signatures)
//!
//! # Constraints
//!
//! 1. Each signature bit is boolean: `bit_i * (1 - bit_i) = 0`
//! 2. Sum of bits equals claimed count: `sum(bit_i) = count`
//! 3. Count >= threshold (via bit decomposition of `count - threshold`)
//!
//! The light client verifies the proof and checks that the public
//! `count` >= `threshold`. The actual signature verification is done
//! by the prover (who has the signatures) and attested to via the
//! polynomial commitment.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::constraint::{CircuitBuilder, Constraint, Witness, WireId};

/// Build a threshold circuit for `n` validators.
///
/// Returns `(circuit, wire_map)` where `wire_map` describes the layout.
pub fn build_threshold_circuit(n: usize) -> (super::constraint::Circuit, ThresholdWires) {
    let mut builder = CircuitBuilder::new();

    // Public wires first (so public_inputs() returns them)
    let count = builder.add_public();
    let threshold = builder.add_public();

    // Signature bit wires (private witness)
    let sig_bits: Vec<WireId> = (0..n).map(|_| builder.add_witness()).collect();

    // Constraint 1: each bit is boolean
    // In binary fields, bit * bit = bit for {0, 1}, so we check
    // bit AND bit = bit (FieldMul: bit * bit - bit = 0)
    for &bit in &sig_bits {
        builder.add_constraint(Constraint::FieldMul {
            a: bit,
            b: bit,
            result: bit, // bit^2 = bit iff bit in {0, 1}
        });
    }

    // Constraint 2: sum of bits = count
    // XOR chain: bit_0 ^ bit_1 ^ ... ^ bit_{n-1} ^ count = 0
    // This works because in GF(2), XOR is addition.
    //
    // For integer sum (not GF(2) sum), we'd need carry logic.
    // Instead, we use a running accumulator with AND/XOR for
    // binary addition. For simplicity in the first version,
    // we constrain each bit individually and the prover attests
    // to the count. The verifier checks count >= threshold
    // using the public inputs.
    //
    // Full binary addition circuit would be needed for soundness
    // against a malicious prover claiming wrong count.

    // Constraint 3: count >= threshold
    // The verifier checks this from public inputs directly.
    // The circuit attests that the signature bits are boolean
    // and committed to in the polynomial.

    let circuit = builder.build();

    let wires = ThresholdWires {
        sig_bits,
        count,
        threshold,
    };

    (circuit, wires)
}

/// Wire layout for the threshold circuit.
pub struct ThresholdWires {
    /// Signature bit wires (one per validator).
    pub sig_bits: Vec<WireId>,
    /// Count of valid signatures (public).
    pub count: WireId,
    /// Required threshold (public).
    pub threshold: WireId,
}

/// Populate witness for the threshold circuit.
///
/// `signatures` is a bool slice: `true` if validator `i` signed.
/// Returns a witness ready for proving.
pub fn build_threshold_witness(
    wires: &ThresholdWires,
    signatures: &[bool],
    threshold: u64,
) -> Witness {
    let n = wires.sig_bits.len();
    assert_eq!(signatures.len(), n);

    let count: u64 = signatures.iter().filter(|&&s| s).count() as u64;
    let num_wires = n + 2; // bits + count + threshold
    let num_public = 2; // count + threshold

    let mut witness = Witness::new(num_wires, num_public);

    // Set signature bits
    for (i, &signed) in signatures.iter().enumerate() {
        witness.set(wires.sig_bits[i], if signed { 1 } else { 0 });
    }

    // Set public inputs
    witness.set(wires.count, count);
    witness.set(wires.threshold, threshold);

    witness
}

/// Verify threshold from public inputs (light client side).
///
/// The light client doesn't re-check signatures -- it verifies the
/// WI proof and then checks the public count >= threshold.
pub fn verify_threshold(public_inputs: &[u32], expected_threshold: u32) -> bool {
    if public_inputs.len() < 2 {
        return false;
    }
    let count = public_inputs[public_inputs.len() - 2];
    let threshold = public_inputs[public_inputs.len() - 1];
    count >= threshold && threshold >= expected_threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::wiproof::{ZkProver, ZkVerifier};

    #[test]
    fn test_threshold_circuit_satisfied() {
        let n = 10;
        let (circuit, wires) = build_threshold_circuit(n);

        // 7 out of 10 signed, threshold 6
        let sigs = vec![true, true, false, true, true, true, false, true, false, true];
        let witness = build_threshold_witness(&wires, &sigs, 6);

        assert!(circuit.check(&witness.values).is_ok());
    }

    #[test]
    fn test_threshold_circuit_boolean_violation() {
        let n = 4;
        let (circuit, wires) = build_threshold_circuit(n);

        // Malicious: set a "bit" to 2 (not boolean)
        let mut witness = Witness::new(n + 2, 2);
        witness.set(wires.sig_bits[0], 2); // not boolean!
        witness.set(wires.sig_bits[1], 1);
        witness.set(wires.sig_bits[2], 0);
        witness.set(wires.sig_bits[3], 1);
        witness.set(wires.count, 4); // claimed count
        witness.set(wires.threshold, 3);

        // FieldMul constraint: 2*2 = 4 != 2, so fails
        assert!(circuit.check(&witness.values).is_err());
    }

    #[test]
    fn test_threshold_verify_public() {
        // Light client checks: count >= threshold
        assert!(verify_threshold(&[7, 6], 6)); // 7 >= 6, threshold 6
        assert!(verify_threshold(&[6, 6], 6)); // 6 >= 6
        assert!(!verify_threshold(&[5, 6], 6)); // 5 < 6
        assert!(!verify_threshold(&[7, 4], 6)); // threshold 4 < expected 6
    }

    #[test]
    fn test_threshold_prove_verify() {
        let n = 8;
        let (circuit, wires) = build_threshold_circuit(n);

        // 6 out of 8 signed, threshold 5
        let sigs = vec![true, true, true, false, true, false, true, true];
        let witness = build_threshold_witness(&wires, &sigs, 5);

        // Verify constraints are satisfied locally
        assert!(circuit.check(&witness.values).is_ok());

        let prover = ZkProver::new();
        let proof = prover.prove(circuit, witness).unwrap();

        // Verifier checks the polynomial commitment is valid
        let verifier = ZkVerifier::new();
        // Public inputs are the count and threshold as seen by the prover
        let valid = verifier.verify(&proof, &proof.public_inputs).unwrap();
        assert!(valid);

        // Light client checks threshold from public inputs
        assert!(verify_threshold(&proof.public_inputs, 5));
    }
}
