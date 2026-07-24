//! Batched 64-bit range SR1CS relation used by the payments backend.
//!
//! One proof range-checks `TRANSFER_BATCH` committed values `v_1, v_2` and
//! binds them to the verifier-computed aggregate `v_theta = v_1 + theta v_2`,
//! where `theta` is a Fiat-Shamir challenge derived from the ledger
//! commitments (see [`crate::zkpari::payments`]). The values live in two
//! committed-input blocks:
//!
//! - block 0 holds `(v_1, v_2)` behind a fresh hiding commitment `C_hat`;
//! - block 1 holds the single aggregate slot `v_theta`, whose basis doubles
//!   as the ledger payment-commitment basis. Its commitment is the aggregate
//!   `com_1 + theta com_2` of ledger commitments, recomputed by the verifier
//!   and never transmitted.
//!
//! `theta` enters the circuit as an ordinary public input. Because instance
//! columns may only appear in their outlining rows, the relation copies
//! `theta` into a witness (like the constant-one copy) and forms the product
//! `theta v_2` with the square gadget `theta v_2 = ((theta + v_2)^2 -
//! (theta - v_2)^2) / 4`.

use ark_ec::pairing::Pairing;
use ark_ff::Field;

/// Number of values range-checked by one batched proof.
///
/// Extending this beyond 2 requires power gadgets for `theta^i` in the
/// batched range relation.
pub const TRANSFER_BATCH: usize = 2;

/// Sparse linear combination row over absolute variable indices.
///
/// Index `0` is the constant-one instance variable, index `1` is the
/// aggregation challenge `theta`. Witness variable `w` appears at absolute
/// index `INSTANCE_LEN + w`.
pub(crate) type Row<F> = Vec<(F, usize)>;
pub(crate) type Matrix<F> = Vec<Row<F>>;

/// Instance layout: `[1, theta]`.
const INSTANCE_LEN: usize = 2;

// Witness layout (relative indices).
const V1: usize = 0;
const V2: usize = 1;
const BITS1: usize = 2;
const BITS2: usize = 66;
const S_PLUS: usize = 130;
const S_MINUS: usize = 131;
const V_THETA: usize = 132;
const ONE_COPY: usize = 133;
const THETA_COPY: usize = 134;
const NUM_WITNESS: usize = 135;

/// 2 reconstruction + 128 booleanity + 2 square-gadget + 1 aggregation
/// + 2 instance-outlining rows.
const NUM_CONSTRAINTS: usize = 135;

const fn abs(witness: usize) -> usize {
    INSTANCE_LEN + witness
}

pub(crate) struct RangeRelation<F: Field> {
    pub instance_len: usize,
    pub num_witness: usize,
    pub num_constraints: usize,
    pub committed_witness_indices: Vec<Vec<usize>>,
    pub a: Matrix<F>,
    pub b: Matrix<F>,
}

pub(crate) struct RangeAssignment<F: Field> {
    pub instance: Vec<F>,
    pub witness: Vec<F>,
}

/// Batched-range proof body without the recomputable aggregate commitment.
///
/// `c_hat` is the fresh block-0 commitment to `(v_1, v_2)`; the block-1
/// aggregate commitment is recomputed by the verifier from the ledger
/// commitments and `theta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeProof<E: Pairing> {
    pub c_hat: E::G1Affine,
    pub t_g: E::G1Affine,
    pub u_g: E::G1Affine,
    pub v_a: E::ScalarField,
}

pub(crate) fn batched_range_relation<F: Field>() -> RangeRelation<F> {
    let mut a = Vec::with_capacity(NUM_CONSTRAINTS);
    let mut b = Vec::with_capacity(NUM_CONSTRAINTS);

    // Bit reconstruction: (sum_j 2^j bit_{i,j} - v_i)^2 = 0.
    for (value, bits) in [(V1, BITS1), (V2, BITS2)] {
        let mut recon = vec![(-F::ONE, abs(value))];
        let mut coeff = F::ONE;
        for bit in 0..64 {
            recon.push((coeff, abs(bits + bit)));
            coeff.double_in_place();
        }
        a.push(recon);
        b.push(Vec::new());
    }

    // Booleanity: bit^2 = bit.
    for bits in [BITS1, BITS2] {
        for bit in 0..64 {
            a.push(vec![(F::ONE, abs(bits + bit))]);
            b.push(vec![(F::ONE, abs(bits + bit))]);
        }
    }

    // Square gadget: (theta + v_2)^2 = s_plus, (theta - v_2)^2 = s_minus,
    // so that theta v_2 = (s_plus - s_minus) / 4 is available linearly.
    a.push(vec![(F::ONE, abs(THETA_COPY)), (F::ONE, abs(V2))]);
    b.push(vec![(F::ONE, abs(S_PLUS))]);
    a.push(vec![(F::ONE, abs(THETA_COPY)), (-F::ONE, abs(V2))]);
    b.push(vec![(F::ONE, abs(S_MINUS))]);

    // Aggregation: 0^2 = v_1 + theta v_2 - v_theta.
    let quarter = F::from(4u64).inverse().expect("4 is invertible");
    a.push(Vec::new());
    b.push(vec![
        (F::ONE, abs(V1)),
        (quarter, abs(S_PLUS)),
        (-quarter, abs(S_MINUS)),
        (-F::ONE, abs(V_THETA)),
    ]);

    // Instance outlining rows: (x_i - copy_i)^2 = 0, one per instance
    // variable, in instance order, as the final rows. This lets the prover
    // remove instance contributions by subtracting the instance value on the
    // final rows, matching the SR1CS shape expected by ZK-Pari.
    a.push(vec![(F::ONE, 0), (-F::ONE, abs(ONE_COPY))]);
    b.push(Vec::new());
    a.push(vec![(F::ONE, 1), (-F::ONE, abs(THETA_COPY))]);
    b.push(Vec::new());

    debug_assert_eq!(a.len(), NUM_CONSTRAINTS);

    RangeRelation {
        instance_len: INSTANCE_LEN,
        num_witness: NUM_WITNESS,
        num_constraints: NUM_CONSTRAINTS,
        committed_witness_indices: vec![vec![V1, V2], vec![V_THETA]],
        a,
        b,
    }
}

pub(crate) fn batched_range_assignment<F: Field>(
    values: &[u64; TRANSFER_BATCH],
    theta: F,
) -> RangeAssignment<F> {
    let [v1, v2] = *values;
    let v2_f = F::from(v2);

    let mut witness = Vec::with_capacity(NUM_WITNESS);
    witness.push(F::from(v1));
    witness.push(v2_f);
    for value in [v1, v2] {
        for bit in 0..64 {
            witness.push(if (value >> bit) & 1 == 1 {
                F::ONE
            } else {
                F::ZERO
            });
        }
    }
    witness.push((theta + v2_f).square());
    witness.push((theta - v2_f).square());
    witness.push(F::from(v1) + theta * v2_f);
    witness.push(F::ONE);
    witness.push(theta);
    debug_assert_eq!(witness.len(), NUM_WITNESS);

    RangeAssignment {
        instance: vec![F::ONE, theta],
        witness,
    }
}

pub(crate) fn evaluate_row<F: Field>(row: &Row<F>, assignment: &[F]) -> F {
    row.iter().fold(F::zero(), |acc, (coeff, index)| {
        acc + *coeff * assignment[*index]
    })
}
