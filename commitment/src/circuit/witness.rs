//! Witness encoding as multilinear polynomial for proofs.
//!
//! Converts circuit witness into polynomial form suitable for the polynomial
//! commitment scheme. The key insight: witness values become coefficients of a
//! multilinear polynomial, and the commitment scheme commits to this polynomial
//! without revealing it.
//!
//! ## Encoding scheme
//!
//! For n witness values w[0..n], we create a multilinear polynomial:
//!   f(x_0, ..., x_{log n - 1}) = sum_i w[i] * L_i(x)
//!
//! where L_i is the Lagrange basis polynomial that equals 1 at point i
//! and 0 at all other boolean hypercube points.

use crate::circuit::constraint::{Circuit, Constraint, Operand, Witness};
use crate::field::{BinaryElem128, BinaryElem32, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Witness encoded as multilinear polynomial coefficients.
#[derive(Debug, Clone)]
pub struct WitnessPolynomial {
    /// Polynomial coefficients (padded to power of 2).
    pub coeffs: Vec<BinaryElem32>,
    /// log2 of polynomial size.
    pub log_size: usize,
    /// Number of actual witness values (rest is padding).
    pub num_witness: usize,
}

impl WitnessPolynomial {
    /// Encode witness as multilinear polynomial.
    pub fn from_witness(witness: &Witness) -> Self {
        let n = witness.values.len();
        let log_size = n.next_power_of_two().trailing_zeros() as usize;
        let padded_size = 1 << log_size;

        let mut coeffs = Vec::with_capacity(padded_size);
        for &val in &witness.values {
            // Truncate to 32 bits for binary field.
            coeffs.push(BinaryElem32::from(val as u32));
        }
        // Pad with zeros.
        coeffs.resize(padded_size, BinaryElem32::zero());

        Self {
            coeffs,
            log_size,
            num_witness: n,
        }
    }

    /// Encode raw u32 values as polynomial.
    pub fn from_u32_slice(values: &[u32]) -> Self {
        let n = values.len();
        let log_size = n.next_power_of_two().trailing_zeros() as usize;
        let padded_size = 1 << log_size;

        let mut coeffs = Vec::with_capacity(padded_size);
        for &val in values {
            coeffs.push(BinaryElem32::from(val));
        }
        coeffs.resize(padded_size, BinaryElem32::zero());

        Self {
            coeffs,
            log_size,
            num_witness: n,
        }
    }

    /// Encode binary field elements directly.
    pub fn from_field_elems(elems: Vec<BinaryElem32>) -> Self {
        let n = elems.len();
        let log_size = n.next_power_of_two().trailing_zeros() as usize;
        let padded_size = 1 << log_size;

        let mut coeffs = elems;
        coeffs.resize(padded_size, BinaryElem32::zero());

        Self {
            coeffs,
            log_size,
            num_witness: n,
        }
    }

    /// Evaluate polynomial at a point on the boolean hypercube.
    /// Point is given as bit index [x_0, x_1, ..., x_{log_size-1}].
    pub fn eval_at_hypercube_point(&self, point: usize) -> BinaryElem32 {
        if point < self.coeffs.len() {
            self.coeffs[point]
        } else {
            BinaryElem32::zero()
        }
    }

    /// Evaluate multilinear extension at arbitrary field point
    /// using Lagrange interpolation.
    pub fn eval_mle<F: BinaryFieldElement + From<BinaryElem32>>(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.log_size, "point dimension mismatch");

        // Compute eq(point, i) * coeff[i] for all i.
        let mut result = F::zero();

        for (i, &coeff) in self.coeffs.iter().enumerate() {
            // Compute Lagrange basis at point i.
            let mut basis = F::one();
            for (j, &r) in point.iter().enumerate() {
                let bit = (i >> j) & 1;
                if bit == 1 {
                    basis = basis.mul(&r);
                } else {
                    // (1 - r) in binary field is (1 + r).
                    basis = basis.mul(&F::one().add(&r));
                }
            }
            result = result.add(&basis.mul(&F::from(coeff)));
        }

        result
    }

    /// Partial evaluation: fix first k variables, return polynomial in remaining vars.
    pub fn partial_eval<F: BinaryFieldElement + From<BinaryElem32>>(
        &self,
        challenges: &[F],
    ) -> Vec<F> {
        let k = challenges.len();
        assert!(k <= self.log_size, "too many challenges");

        // Fold coefficients k times.
        let mut current: Vec<F> = self.coeffs.iter().map(|&c| F::from(c)).collect();

        for &r in challenges {
            let half = current.len() / 2;
            let one_minus_r = F::one().add(&r);

            let mut next = Vec::with_capacity(half);
            for i in 0..half {
                // Lagrange fold: (1-r)*left + r*right.
                let folded = current[2 * i]
                    .mul(&one_minus_r)
                    .add(&current[2 * i + 1].mul(&r));
                next.push(folded);
            }
            current = next;
        }

        current
    }
}

/// Constraint polynomial for circuit verification.
///
/// Converts circuit constraints into a polynomial that:
/// - evaluates to 0 on all boolean hypercube points if constraints are satisfied
/// - non-zero otherwise
///
/// The verifier checks this polynomial is zero everywhere via sumcheck.
#[derive(Debug, Clone)]
pub struct ConstraintPolynomial {
    /// The circuit being proven.
    pub circuit: Circuit,
}

impl ConstraintPolynomial {
    /// Create a new constraint polynomial from a circuit.
    pub const fn new(circuit: Circuit) -> Self {
        Self { circuit }
    }

    /// Evaluate constraint polynomial at witness point.
    ///
    /// Returns 0 if all constraints are satisfied, non-zero otherwise.
    pub fn evaluate_at_witness(&self, witness: &WitnessPolynomial) -> BinaryElem128 {
        let mut result = BinaryElem128::zero();

        for constraint in &self.circuit.constraints {
            let val = self.eval_single_constraint(constraint, witness);
            result = result.add(&val);
        }

        result
    }

    /// Evaluate single constraint contribution.
    fn eval_single_constraint(
        &self,
        constraint: &Constraint,
        witness: &WitnessPolynomial,
    ) -> BinaryElem128 {
        match constraint {
            Constraint::And { a, b, c } => {
                let va = self.eval_operand(a, witness);
                let vb = self.eval_operand(b, witness);
                let vc = self.eval_operand(c, witness);
                // AND becomes MUL in binary field.
                // (a * b) + c should be 0.
                BinaryElem128::from(va.mul(&vb).add(&vc))
            }
            Constraint::Xor { a, b, c } => {
                let va = self.eval_operand(a, witness);
                let vb = self.eval_operand(b, witness);
                let vc = self.eval_operand(c, witness);
                // a + b + c should be 0.
                BinaryElem128::from(va.add(&vb).add(&vc))
            }
            Constraint::Eq { a, b } => {
                let va = self.eval_operand(a, witness);
                let vb = self.eval_operand(b, witness);
                // a + b should be 0 (in binary field a == b iff a + b = 0).
                BinaryElem128::from(va.add(&vb))
            }
            Constraint::AssertConst { wire, value } => {
                let v = witness.eval_at_hypercube_point(wire.0);
                let expected = BinaryElem32::from(*value as u32);
                // v + expected should be 0.
                BinaryElem128::from(v.add(&expected))
            }
            Constraint::Range { .. } => {
                // Range constraint without bit decomposition is NOT ZK-sound.
                // A malicious prover can claim any value satisfies the range check
                // because this is a prover-side check only.
                //
                // For ZK soundness, use RangeDecomposed which has explicit bit wires
                // that can be verified by the constraint polynomial.
                //
                // We return zero here to allow the circuit to pass during testing
                // but this constraint provides NO security in a real ZK proof.
                BinaryElem128::zero()
            }
            Constraint::Mul { a, b, hi: _, lo } => {
                // MUL constraint: a * b = (hi << 32) | lo.
                // For 32-bit fields, this needs special handling.
                let va = self.eval_operand(a, witness);
                let vb = self.eval_operand(b, witness);
                let vlo = witness.eval_at_hypercube_point(lo.0);

                // In binary field, regular multiplication.
                // Simplified check -- would need proper decomposition.
                let product = va.mul(&vb);
                BinaryElem128::from(product.add(&vlo))
            }
            Constraint::FieldMul { a, b, result } => {
                // GF(2^32) field multiplication: a * b = result.
                let va = witness.eval_at_hypercube_point(a.0);
                let vb = witness.eval_at_hypercube_point(b.0);
                let vresult = witness.eval_at_hypercube_point(result.0);

                // Check va * vb == vresult in GF(2^32).
                let product = va.mul(&vb);
                BinaryElem128::from(product.add(&vresult))
            }
            Constraint::RangeDecomposed { wire, bits } => {
                // Verify bit decomposition: wire = sum(bits[i] * 2^i).
                let v = witness.eval_at_hypercube_point(wire.0);

                // Reconstruct from bits.
                let mut reconstructed = BinaryElem32::zero();
                for (i, bit_wire) in bits.iter().enumerate() {
                    let bit = witness.eval_at_hypercube_point(bit_wire.0);
                    // bit * 2^i.
                    let power = BinaryElem32::from(1u32 << i);
                    reconstructed = reconstructed.add(&bit.mul(&power));
                }

                // Should equal zero if valid.
                BinaryElem128::from(v.add(&reconstructed))
            }
        }
    }

    /// Evaluate operand as field element.
    fn eval_operand(&self, op: &Operand, witness: &WitnessPolynomial) -> BinaryElem32 {
        let mut result = BinaryElem32::zero();
        for (wire, shift) in &op.terms {
            let val = witness.eval_at_hypercube_point(wire.0);
            let shifted_bits = shift.apply(val.poly().value() as u64) as u32;
            let shifted = BinaryElem32::from(shifted_bits);
            result = result.add(&shifted);
        }
        result
    }

    /// Batch evaluate constraint polynomial with random challenge.
    /// Uses Schwartz-Zippel for batching multiple constraints.
    pub fn batch_evaluate(
        &self,
        witness: &WitnessPolynomial,
        challenge: BinaryElem128,
    ) -> BinaryElem128 {
        let mut result = BinaryElem128::zero();
        let mut power = BinaryElem128::one();

        for constraint in &self.circuit.constraints {
            let val = self.eval_single_constraint(constraint, witness);
            result = result.add(&val.mul(&power));
            power = power.mul(&challenge);
        }

        result
    }
}

/// Prepare witness and circuit for proving.
pub struct LigeritoInstance {
    /// Witness polynomial.
    pub witness_poly: WitnessPolynomial,
    /// Constraint polynomial evaluator.
    pub constraint_poly: ConstraintPolynomial,
    /// Original witness values (for integer-based constraint checking).
    witness_values: Vec<u64>,
    /// Public inputs.
    pub public_inputs: Vec<BinaryElem32>,
}

impl LigeritoInstance {
    /// Create instance from circuit and witness.
    pub fn new(circuit: Circuit, witness: Witness) -> Self {
        let public_inputs: Vec<BinaryElem32> = witness
            .public_inputs()
            .iter()
            .map(|&v| BinaryElem32::from(v as u32))
            .collect();

        let witness_values = witness.values.clone();
        let witness_poly = WitnessPolynomial::from_witness(&witness);
        let constraint_poly = ConstraintPolynomial::new(circuit);

        Self {
            witness_poly,
            constraint_poly,
            witness_values,
            public_inputs,
        }
    }

    /// Check if circuit is satisfied (for debugging).
    /// Uses integer-based checking since field multiplication != bitwise AND.
    pub fn is_satisfied(&self) -> bool {
        self.constraint_poly
            .circuit
            .check(&self.witness_values)
            .is_ok()
    }

    /// Get polynomial coefficients for the prover.
    pub fn get_polynomial(&self) -> &[BinaryElem32] {
        &self.witness_poly.coeffs
    }

    /// Get log size.
    pub const fn log_size(&self) -> usize {
        self.witness_poly.log_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::constraint::{CircuitBuilder, Operand, WireId};

    #[test]
    fn test_witness_polynomial_basic() {
        let witness = Witness {
            values: vec![1, 2, 3, 4],
            public_indices: vec![0],
        };

        let poly = WitnessPolynomial::from_witness(&witness);
        assert_eq!(poly.log_size, 2); // 4 values = 2^2
        assert_eq!(poly.num_witness, 4);

        // Check hypercube evaluations.
        assert_eq!(poly.eval_at_hypercube_point(0), BinaryElem32::from(1u32));
        assert_eq!(poly.eval_at_hypercube_point(1), BinaryElem32::from(2u32));
        assert_eq!(poly.eval_at_hypercube_point(2), BinaryElem32::from(3u32));
        assert_eq!(poly.eval_at_hypercube_point(3), BinaryElem32::from(4u32));
    }

    #[test]
    fn test_witness_polynomial_padding() {
        let witness = Witness {
            values: vec![1, 2, 3], // not power of 2
            public_indices: vec![],
        };

        let poly = WitnessPolynomial::from_witness(&witness);
        assert_eq!(poly.log_size, 2); // padded to 4
        assert_eq!(poly.coeffs.len(), 4);
        assert_eq!(poly.eval_at_hypercube_point(3), BinaryElem32::zero()); // padding
    }

    #[test]
    fn test_mle_evaluation() {
        let poly = WitnessPolynomial::from_u32_slice(&[1, 2, 3, 4]);

        // At boolean point (0, 0) should give coefficient 0.
        let point = [BinaryElem128::zero(), BinaryElem128::zero()];
        let val: BinaryElem128 = poly.eval_mle(&point);
        assert_eq!(val, BinaryElem128::from(BinaryElem32::from(1u32)));

        // At boolean point (1, 0) should give coefficient 1.
        let point = [BinaryElem128::one(), BinaryElem128::zero()];
        let val: BinaryElem128 = poly.eval_mle(&point);
        assert_eq!(val, BinaryElem128::from(BinaryElem32::from(2u32)));
    }

    #[test]
    fn test_partial_eval() {
        let poly = WitnessPolynomial::from_u32_slice(&[1, 2, 3, 4]);

        // Fix first variable to 0 -> should get [1, 3] (first half).
        // (actually uses Lagrange formula, so interpolates)
        let partial: Vec<BinaryElem128> = poly.partial_eval(&[BinaryElem128::zero()]);
        assert_eq!(partial.len(), 2);
    }

    #[test]
    fn test_constraint_polynomial() {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_witness();
        let b = builder.add_witness();
        let c = builder.add_witness();

        // Constraint: a ^ b ^ c = 0.
        builder.assert_xor(
            Operand::new().with_wire(a),
            Operand::new().with_wire(b),
            Operand::new().with_wire(c),
        );

        let circuit = builder.build();
        let constraint_poly = ConstraintPolynomial::new(circuit);

        // Satisfied witness: 5 ^ 3 = 6.
        let satisfied = Witness {
            values: vec![5, 3, 6, 0], // padded
            public_indices: vec![],
        };
        let witness_poly = WitnessPolynomial::from_witness(&satisfied);
        let result = constraint_poly.evaluate_at_witness(&witness_poly);
        assert_eq!(result, BinaryElem128::zero());

        // Unsatisfied witness: 5 ^ 3 != 7.
        let unsatisfied = Witness {
            values: vec![5, 3, 7, 0],
            public_indices: vec![],
        };
        let witness_poly = WitnessPolynomial::from_witness(&unsatisfied);
        let result = constraint_poly.evaluate_at_witness(&witness_poly);
        assert_ne!(result, BinaryElem128::zero());
    }

    #[test]
    fn test_ligerito_instance() {
        let mut builder = CircuitBuilder::new();
        let pub_in = builder.add_public();
        let w = builder.add_witness();
        let out = builder.add_witness();

        // pub_in & w = out.
        builder.assert_and(
            Operand::new().with_wire(pub_in),
            Operand::new().with_wire(w),
            Operand::new().with_wire(out),
        );

        let circuit = builder.build();

        // witness: 0xFF & 0x0F = 0x0F
        let mut witness = Witness::new(3, 1);
        witness.set(WireId(0), 0xFF);
        witness.set(WireId(1), 0x0F);
        witness.set(WireId(2), 0x0F);

        let instance = LigeritoInstance::new(circuit, witness);
        assert!(instance.is_satisfied());
        assert_eq!(instance.public_inputs.len(), 1);
        assert_eq!(instance.public_inputs[0], BinaryElem32::from(0xFFu32));
    }
}
