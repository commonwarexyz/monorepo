//! Fixed 64-bit range SR1CS relation used by the payments backend.

use ark_ec::pairing::Pairing;
use ark_ff::Field;

/// Sparse linear combination row over absolute variable indices.
///
/// Index `0` is the constant-one instance variable. Witness variable `w`
/// appears at absolute index `1 + w`.
pub(crate) type Row<F> = Vec<(F, usize)>;
pub(crate) type Matrix<F> = Vec<Row<F>>;

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

/// Range-proof body without the committed-input commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeProof<E: Pairing> {
    pub t_g: E::G1Affine,
    pub u_g: E::G1Affine,
    pub v_a: E::ScalarField,
}

pub(crate) fn range_relation<F: Field>() -> RangeRelation<F> {
    const INSTANCE_LEN: usize = 1;
    const VALUE_WITNESS: usize = 0;
    const FIRST_BIT_WITNESS: usize = 1;
    const ONE_COPY_WITNESS: usize = 65;

    let value_abs = INSTANCE_LEN + VALUE_WITNESS;
    let one_copy_abs = INSTANCE_LEN + ONE_COPY_WITNESS;
    let mut a = Vec::with_capacity(66);
    let mut b = Vec::with_capacity(66);

    let mut recon = vec![(-F::ONE, value_abs)];
    let mut coeff = F::ONE;
    for bit in 0..64 {
        recon.push((coeff, INSTANCE_LEN + FIRST_BIT_WITNESS + bit));
        coeff.double_in_place();
    }
    a.push(recon);
    b.push(Vec::new());

    for bit in 0..64 {
        let bit_abs = INSTANCE_LEN + FIRST_BIT_WITNESS + bit;
        a.push(vec![(F::ONE, bit_abs)]);
        b.push(vec![(F::ONE, bit_abs)]);
    }

    // Instance outlining row: (1 - one_copy)^2 = 0. This lets the prover
    // remove instance contributions by subtracting the instance value on the
    // final rows, matching the SR1CS shape expected by ZK-Pari.
    a.push(vec![(F::ONE, 0), (-F::ONE, one_copy_abs)]);
    b.push(Vec::new());

    RangeRelation {
        instance_len: INSTANCE_LEN,
        num_witness: 66,
        num_constraints: 66,
        committed_witness_indices: vec![vec![VALUE_WITNESS]],
        a,
        b,
    }
}

pub(crate) fn range_assignment<F: Field>(value: u64) -> RangeAssignment<F> {
    let mut witness = Vec::with_capacity(66);
    witness.push(F::from(value));
    for bit in 0..64 {
        witness.push(if (value >> bit) & 1 == 1 {
            F::ONE
        } else {
            F::ZERO
        });
    }
    witness.push(F::ONE);

    RangeAssignment {
        instance: vec![F::ONE],
        witness,
    }
}

pub(crate) fn evaluate_row<F: Field>(row: &Row<F>, assignment: &[F]) -> F {
    row.iter().fold(F::zero(), |acc, (coeff, index)| {
        acc + *coeff * assignment[*index]
    })
}
