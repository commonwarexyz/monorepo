//! Constraint system for circuit-based zero-knowledge proofs.
//!
//! Adapts a constraint model for binary field operations:
//! - AND constraints: A & B ^ C = 0
//! - XOR constraints: A ^ B ^ C = 0 (linear, "free")
//! - Field multiplication constraints: A * B = C in GF(2^32)
//!
//! The witness is encoded as a multilinear polynomial, so the verifier
//! sees only commitments and proofs, never the raw witness values.

use crate::field::{BinaryElem32, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Wire index into the witness vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireId(pub usize);

impl WireId {
    /// Return the underlying index.
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Operand in a constraint (XOR combination of shifted wires).
#[derive(Debug, Clone, Default)]
pub struct Operand {
    /// Wires XOR'd together to form this operand.
    pub terms: Vec<(WireId, ShiftOp)>,
}

impl Operand {
    /// Create an empty operand.
    pub const fn new() -> Self {
        Self { terms: Vec::new() }
    }

    /// Add a wire term.
    pub fn with_wire(mut self, wire: WireId) -> Self {
        self.terms.push((wire, ShiftOp::None));
        self
    }

    /// Add a shifted wire term.
    pub fn with_shifted(mut self, wire: WireId, shift: ShiftOp) -> Self {
        self.terms.push((wire, shift));
        self
    }

    /// Evaluate operand against witness (XOR all terms).
    pub fn evaluate(&self, witness: &[u64]) -> u64 {
        self.terms.iter().fold(0u64, |acc, (wire, shift)| {
            let val = witness[wire.0];
            let shifted = shift.apply(val);
            acc ^ shifted
        })
    }

    /// Evaluate as binary field element.
    pub fn evaluate_field(&self, witness: &[BinaryElem32]) -> BinaryElem32 {
        self.terms
            .iter()
            .fold(BinaryElem32::zero(), |acc, (wire, shift)| {
                let val = witness[wire.0];
                // For binary field shifts, work on the underlying u32.
                let shifted_bits = shift.apply(val.poly().value() as u64) as u32;
                let shifted = BinaryElem32::from(shifted_bits);
                acc.add(&shifted)
            })
    }
}

/// Shift operation on a wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShiftOp {
    /// No shift.
    #[default]
    None,
    /// Logical left shift.
    Sll(u8),
    /// Logical right shift.
    Srl(u8),
    /// Arithmetic right shift (preserves sign).
    Sar(u8),
}

impl ShiftOp {
    /// Apply shift to a 64-bit value.
    pub const fn apply(self, value: u64) -> u64 {
        match self {
            Self::None => value,
            Self::Sll(n) => value << (n as u32),
            Self::Srl(n) => value >> (n as u32),
            Self::Sar(n) => ((value as i64) >> (n as u32)) as u64,
        }
    }
}

/// Constraint types in the circuit.
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Bitwise AND: A & B ^ C = 0 (non-linear, costs 1x).
    And {
        a: Operand,
        b: Operand,
        c: Operand,
    },

    /// Bitwise XOR: A ^ B ^ C = 0 (linear, "free").
    Xor {
        a: Operand,
        b: Operand,
        c: Operand,
    },

    /// Equality: A = B (linear constraint).
    Eq { a: Operand, b: Operand },

    /// Integer multiplication: A * B = (hi, lo) as 128-bit result.
    /// Standard schoolbook multiplication in Z/2^64Z (non-linear, costs ~3-4x).
    Mul {
        a: Operand,
        b: Operand,
        hi: WireId,
        lo: WireId,
    },

    /// GF(2^32) field multiplication: A * B = C in the binary field.
    /// Polynomial multiplication modulo the irreducible polynomial.
    /// Distinct from integer Mul -- field multiplication wraps differently.
    FieldMul {
        a: WireId,
        b: WireId,
        result: WireId,
    },

    /// Assert wire equals constant.
    AssertConst { wire: WireId, value: u64 },

    /// Range check: wire < 2^n.
    /// NOTE: for ZK soundness, this requires bit decomposition.
    /// The verifier cannot just trust the prover's claim about range.
    Range { wire: WireId, bits: u8 },

    /// Range check with explicit bit decomposition for ZK soundness.
    /// bits must satisfy: bits[i] in {0,1} and wire = sum(bits[i] * 2^i).
    /// This is the ZK-sound version of Range.
    RangeDecomposed { wire: WireId, bits: Vec<WireId> },
}

impl Constraint {
    /// Check if constraint is satisfied by witness.
    pub fn check(&self, witness: &[u64]) -> bool {
        match self {
            Self::And { a, b, c } => {
                let va = a.evaluate(witness);
                let vb = b.evaluate(witness);
                let vc = c.evaluate(witness);
                (va & vb) ^ vc == 0
            }
            Self::Xor { a, b, c } => {
                let va = a.evaluate(witness);
                let vb = b.evaluate(witness);
                let vc = c.evaluate(witness);
                va ^ vb ^ vc == 0
            }
            Self::Eq { a, b } => a.evaluate(witness) == b.evaluate(witness),
            Self::Mul { a, b, hi, lo } => {
                let va = a.evaluate(witness) as u128;
                let vb = b.evaluate(witness) as u128;
                let product = va * vb;
                let vhi = witness[hi.0] as u128;
                let vlo = witness[lo.0] as u128;
                product == (vhi << 64) | vlo
            }
            Self::FieldMul { a, b, result } => {
                let va = BinaryElem32::from(witness[a.0] as u32);
                let vb = BinaryElem32::from(witness[b.0] as u32);
                let vresult = BinaryElem32::from(witness[result.0] as u32);
                va.mul(&vb) == vresult
            }
            Self::AssertConst { wire, value } => witness[wire.0] == *value,
            Self::Range { wire, bits } => witness[wire.0] < (1u64 << *bits),
            Self::RangeDecomposed { wire, bits } => {
                // Verify each bit is 0 or 1.
                for bit_wire in bits {
                    if witness[bit_wire.0] > 1 {
                        return false;
                    }
                }
                // Verify wire = sum(bits[i] * 2^i).
                let mut reconstructed = 0u64;
                for (i, bit_wire) in bits.iter().enumerate() {
                    reconstructed |= witness[bit_wire.0] << i;
                }
                witness[wire.0] == reconstructed
            }
        }
    }

    /// Check constraint on binary field witness.
    pub fn check_field(&self, witness: &[BinaryElem32]) -> bool {
        match self {
            Self::And { a, b, c } => {
                let va = a.evaluate_field(witness);
                let vb = b.evaluate_field(witness);
                let vc = c.evaluate_field(witness);
                // AND in binary field is multiplication.
                va.mul(&vb).add(&vc) == BinaryElem32::zero()
            }
            Self::Xor { a, b, c } => {
                let va = a.evaluate_field(witness);
                let vb = b.evaluate_field(witness);
                let vc = c.evaluate_field(witness);
                va.add(&vb).add(&vc) == BinaryElem32::zero()
            }
            Self::Eq { a, b } => a.evaluate_field(witness) == b.evaluate_field(witness),
            // For integer mul, convert to u64 and check.
            Self::Mul { .. } => {
                let witness_u64: Vec<u64> = witness
                    .iter()
                    .map(|x| x.poly().value() as u64)
                    .collect();
                self.check(&witness_u64)
            }
            // Field multiplication is native in binary field.
            Self::FieldMul { a, b, result } => {
                let va = witness[a.0];
                let vb = witness[b.0];
                let vresult = witness[result.0];
                va.mul(&vb) == vresult
            }
            Self::AssertConst { wire, value } => {
                witness[wire.0].poly().value() as u64 == *value
            }
            Self::Range { wire, bits } => {
                (witness[wire.0].poly().value() as u64) < (1u64 << *bits)
            }
            Self::RangeDecomposed { wire, bits } => {
                // Verify each bit is 0 or 1.
                for bit_wire in bits {
                    let val = witness[bit_wire.0].poly().value();
                    if val > 1 {
                        return false;
                    }
                }
                // Verify wire = sum(bits[i] * 2^i).
                let mut reconstructed = 0u32;
                for (i, bit_wire) in bits.iter().enumerate() {
                    reconstructed |= witness[bit_wire.0].poly().value() << i;
                }
                witness[wire.0].poly().value() == reconstructed
            }
        }
    }
}

/// Circuit builder for constructing constraint systems.
#[derive(Debug, Clone)]
pub struct CircuitBuilder {
    /// Number of witness wires.
    num_wires: usize,
    /// Number of public input wires.
    num_public: usize,
    /// Constraints.
    constraints: Vec<Constraint>,
    /// Wire labels for debugging.
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    labels: std::collections::HashMap<WireId, String>,
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBuilder {
    /// Create a new empty circuit builder.
    pub fn new() -> Self {
        Self {
            num_wires: 0,
            num_public: 0,
            constraints: Vec::new(),
            #[cfg(feature = "std")]
            labels: std::collections::HashMap::new(),
        }
    }

    /// Allocate a new witness wire.
    pub const fn add_witness(&mut self) -> WireId {
        let id = WireId(self.num_wires);
        self.num_wires += 1;
        id
    }

    /// Allocate a new public input wire.
    pub const fn add_public(&mut self) -> WireId {
        let id = self.add_witness();
        self.num_public += 1;
        id
    }

    /// Allocate multiple witness wires.
    pub fn add_witnesses(&mut self, n: usize) -> Vec<WireId> {
        (0..n).map(|_| self.add_witness()).collect()
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    /// Assert A & B = C.
    pub fn assert_and(&mut self, a: Operand, b: Operand, c: Operand) {
        self.add_constraint(Constraint::And { a, b, c });
    }

    /// Assert A ^ B = C.
    pub fn assert_xor(&mut self, a: Operand, b: Operand, c: Operand) {
        self.add_constraint(Constraint::Xor { a, b, c });
    }

    /// Assert A = B.
    pub fn assert_eq(&mut self, a: Operand, b: Operand) {
        self.add_constraint(Constraint::Eq { a, b });
    }

    /// Assert wire equals constant.
    pub fn assert_const(&mut self, wire: WireId, value: u64) {
        self.add_constraint(Constraint::AssertConst { wire, value });
    }

    /// Assert wire < 2^bits (simple range check, not ZK-sound without decomposition).
    pub fn assert_range(&mut self, wire: WireId, bits: u8) {
        self.add_constraint(Constraint::Range { wire, bits });
    }

    /// Assert wire < 2^bits with ZK-sound bit decomposition.
    /// Allocates `bits` new wires for the bit decomposition.
    /// Returns the allocated bit wires.
    pub fn assert_range_decomposed(&mut self, wire: WireId, bits: u8) -> Vec<WireId> {
        let bit_wires: Vec<WireId> = (0..bits).map(|_| self.add_witness()).collect();
        self.add_constraint(Constraint::RangeDecomposed {
            wire,
            bits: bit_wires.clone(),
        });
        bit_wires
    }

    /// GF(2^32) field multiplication: a * b = result in the binary field.
    pub fn assert_field_mul(&mut self, a: WireId, b: WireId, result: WireId) {
        self.add_constraint(Constraint::FieldMul { a, b, result });
    }

    /// Build the circuit.
    pub fn build(self) -> Circuit {
        Circuit {
            num_wires: self.num_wires,
            num_public: self.num_public,
            constraints: self.constraints,
        }
    }

    /// Return the current number of wires.
    pub const fn num_wires(&self) -> usize {
        self.num_wires
    }

    /// Return the current number of public wires.
    pub const fn num_public(&self) -> usize {
        self.num_public
    }
}

/// Compiled circuit ready for proving.
#[derive(Debug, Clone)]
pub struct Circuit {
    /// Total number of wires.
    pub num_wires: usize,
    /// Number of public input wires.
    pub num_public: usize,
    /// List of constraints.
    pub constraints: Vec<Constraint>,
}

impl Circuit {
    /// Check all constraints against witness.
    pub fn check(&self, witness: &[u64]) -> Result<(), usize> {
        if witness.len() < self.num_wires {
            return Err(0);
        }
        for (i, constraint) in self.constraints.iter().enumerate() {
            if !constraint.check(witness) {
                return Err(i);
            }
        }
        Ok(())
    }

    /// Check all constraints against binary field witness.
    pub fn check_field(&self, witness: &[BinaryElem32]) -> Result<(), usize> {
        if witness.len() < self.num_wires {
            return Err(0);
        }
        for (i, constraint) in self.constraints.iter().enumerate() {
            if !constraint.check_field(witness) {
                return Err(i);
            }
        }
        Ok(())
    }

    /// Get number of AND constraints (main cost metric).
    pub fn num_and_constraints(&self) -> usize {
        self.constraints
            .iter()
            .filter(|c| matches!(c, Constraint::And { .. }))
            .count()
    }

    /// Get number of integer MUL constraints.
    #[allow(dead_code)]
    pub fn num_mul_constraints(&self) -> usize {
        self.constraints
            .iter()
            .filter(|c| matches!(c, Constraint::Mul { .. }))
            .count()
    }

    /// Get number of field MUL constraints.
    #[allow(dead_code)]
    pub fn num_field_mul_constraints(&self) -> usize {
        self.constraints
            .iter()
            .filter(|c| matches!(c, Constraint::FieldMul { .. }))
            .count()
    }

    /// Get number of range decomposed constraints.
    #[allow(dead_code)]
    pub fn num_range_decomposed_constraints(&self) -> usize {
        self.constraints
            .iter()
            .filter(|c| matches!(c, Constraint::RangeDecomposed { .. }))
            .count()
    }
}

/// Witness for a circuit execution.
#[derive(Debug, Clone)]
pub struct Witness {
    /// Wire values (u64).
    pub values: Vec<u64>,
    /// Public input indices.
    pub public_indices: Vec<usize>,
}

impl Witness {
    /// Create a new witness with the given number of wires and public inputs.
    pub fn new(num_wires: usize, num_public: usize) -> Self {
        Self {
            values: vec![0u64; num_wires],
            public_indices: (0..num_public).collect(),
        }
    }

    /// Set wire value.
    pub fn set(&mut self, wire: WireId, value: u64) {
        self.values[wire.0] = value;
    }

    /// Get wire value.
    pub fn get(&self, wire: WireId) -> u64 {
        self.values[wire.0]
    }

    /// Convert to binary field elements.
    pub fn to_field(&self) -> Vec<BinaryElem32> {
        self.values
            .iter()
            .map(|&v| BinaryElem32::from(v as u32))
            .collect()
    }

    /// Get public inputs.
    pub fn public_inputs(&self) -> Vec<u64> {
        self.public_indices.iter().map(|&i| self.values[i]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_and_constraint() {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_witness();
        let b = builder.add_witness();
        let c = builder.add_witness();

        // a & b = c
        builder.assert_and(
            Operand::new().with_wire(a),
            Operand::new().with_wire(b),
            Operand::new().with_wire(c),
        );

        let circuit = builder.build();

        // valid: 0b1010 & 0b1100 = 0b1000
        let valid = [0b1010u64, 0b1100, 0b1000];
        assert!(circuit.check(&valid).is_ok());

        // invalid: wrong result
        let invalid = [0b1010u64, 0b1100, 0b1111];
        assert!(circuit.check(&invalid).is_err());
    }

    #[test]
    fn test_xor_constraint() {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_witness();
        let b = builder.add_witness();
        let c = builder.add_witness();

        // a ^ b ^ c = 0 (meaning a ^ b = c)
        builder.assert_xor(
            Operand::new().with_wire(a),
            Operand::new().with_wire(b),
            Operand::new().with_wire(c),
        );

        let circuit = builder.build();

        // valid: 5 ^ 3 = 6
        let valid = [5u64, 3, 6];
        assert!(circuit.check(&valid).is_ok());

        // invalid
        let invalid = [5u64, 3, 7];
        assert!(circuit.check(&invalid).is_err());
    }

    #[test]
    fn test_shift_operand() {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_witness();
        let c = builder.add_witness();

        // (a << 1) ^ c = 0
        builder.assert_xor(
            Operand::new().with_shifted(a, ShiftOp::Sll(1)),
            Operand::new(),
            Operand::new().with_wire(c),
        );

        let circuit = builder.build();

        // valid: (5 << 1) = 10
        let valid = [5u64, 10];
        assert!(circuit.check(&valid).is_ok());

        // invalid
        let invalid = [5u64, 11];
        assert!(circuit.check(&invalid).is_err());
    }

    #[test]
    fn test_witness() {
        let mut witness = Witness::new(3, 1);
        witness.set(WireId(0), 42);
        witness.set(WireId(1), 100);
        witness.set(WireId(2), 200);

        assert_eq!(witness.get(WireId(0)), 42);
        assert_eq!(witness.public_inputs(), vec![42]);
    }

    #[test]
    fn test_complex_circuit() {
        let mut builder = CircuitBuilder::new();

        // public inputs
        let pub_a = builder.add_public();
        let pub_b = builder.add_public();

        // witness
        let w = builder.add_witness();

        // constraint: pub_a & pub_b = w
        builder.assert_and(
            Operand::new().with_wire(pub_a),
            Operand::new().with_wire(pub_b),
            Operand::new().with_wire(w),
        );

        let circuit = builder.build();
        assert_eq!(circuit.num_wires, 3);
        assert_eq!(circuit.num_public, 2);
        assert_eq!(circuit.num_and_constraints(), 1);

        let valid = [0xFF00u64, 0x0FF0, 0x0F00];
        assert!(circuit.check(&valid).is_ok());
    }
}
