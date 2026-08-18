//! The batched-transfer range relation.
//!
//! A single proof attests that two committed values `v1` and `v2` each lie in
//! `[0, 2^64)` and that their `theta`-aggregate `v1 + theta * v2` opens the
//! ledger's aggregate commitment. The two values are grouped as committed
//! block 0 (a fresh commitment) and their aggregate as committed block 1
//! (whose basis is the chain's payment-commitment basis).

use commonware_cryptography::{
    bls12381::primitives::group::Scalar,
    zk::{
        circuit::{BoolVar, CircuitIdx, Context, Var, build, build_with_values},
        pari::{InputLayout, Opening, Relation, Witness},
    },
};
use commonware_math::algebra::Additive;

/// Committed values per transfer proof: the amount and the remaining balance.
pub const TRANSFER_BATCH: usize = 2;

/// Bit width of each range-checked value, matching the `u64` balance domain.
pub const VALUE_BITS: usize = 64;

/// Committed block whose basis is the chain's payment-commitment basis (the
/// single aggregate slot `v_theta`).
pub const PAYMENT_BLOCK: usize = 1;

/// Build the circuit for one transfer/burn statement.
///
/// The closure returns the selected vars in the order
/// `[theta, v1, v2, v_theta]`, so the caller maps them to the public input
/// and the two committed blocks.
fn build_circuit<'ctx>(
    ctx: Context<'ctx, Scalar>,
    values: Option<[u64; TRANSFER_BATCH]>,
    theta_value: Option<Scalar>,
) -> Vec<Var<'ctx, Scalar>> {
    let theta_scalar = theta_value.unwrap_or_else(Scalar::zero);
    let theta = Var::witness(ctx, {
        let theta_scalar = theta_scalar.clone();
        move |_| theta_scalar
    });

    let mut committed = Vec::with_capacity(TRANSFER_BATCH);
    for slot in 0..TRANSFER_BATCH {
        let value = values.map(|values| values[slot]);
        let var = Var::witness(ctx, move |_| Scalar::from(value.unwrap_or(0)));

        // Decompose into bits, enforce booleanity, and reconstruct. Constant
        // folding makes the reconstruction free and square fusion makes each
        // booleanity constraint a single row.
        let mut reconstruction = Var::constant(ctx, Scalar::zero());
        for bit in 0..VALUE_BITS {
            let bit_var =
                BoolVar::witness(ctx, move |_| value.is_some_and(|v| (v >> bit) & 1 == 1));
            let weight = Var::constant(ctx, Scalar::from(1u64 << bit));
            reconstruction += &(bit_var.into_var() * &weight);
        }
        var.assert_eq(&reconstruction);
        committed.push(var);
    }

    // v_theta = v1 + theta * v2, committed under the payment basis (block 1).
    let aggregate_expr = committed[0].clone() + &(theta.clone() * &committed[1]);
    let aggregate_value = values
        .map(|values| Scalar::from(values[0]) + &(theta_scalar.clone() * &Scalar::from(values[1])));
    let v_theta = Var::witness(ctx, move |_| aggregate_value.unwrap_or_else(Scalar::zero));
    v_theta.assert_eq(&aggregate_expr);

    vec![theta, committed.remove(0), committed.remove(0), v_theta]
}

/// The committed-input layout for the transfer relation.
fn layout(selected: &[CircuitIdx]) -> InputLayout {
    InputLayout::new(
        vec![selected[0]],
        vec![vec![selected[1], selected[2]], vec![selected[3]]],
    )
    .expect("transfer layout is valid")
}

/// Compile the transfer relation (verifier/setup side, no values).
pub fn relation() -> (Relation, InputLayout) {
    let (circuit, selected) = build(|ctx| build_circuit(ctx, None, None));
    let layout = layout(&selected);
    let relation = Relation::compile(&circuit, &layout).expect("transfer relation compiles");
    (relation, layout)
}

/// Build the prover assignment for concrete values and challenge.
pub fn assignment(
    relation: &Relation,
    layout: &InputLayout,
    values: [u64; TRANSFER_BATCH],
    theta: &Scalar,
    openings: Vec<Opening>,
) -> Witness {
    let theta = theta.clone();
    let (valued, _) = build_with_values(move |ctx| build_circuit(ctx, Some(values), Some(theta)));
    relation
        .witness(&valued, layout, openings)
        .expect("transfer witness compiles")
}
