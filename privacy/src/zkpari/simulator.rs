//! Trapdoor-based transfer-proof simulation for load generation and tests.
//!
//! A simulated proof is accepted by the verifier but carries no witness. It
//! exists so a benchmark or spammer can mint verifier-accepted transfers
//! cheaply. Because it uses the setup trapdoor, it is unsound and must never
//! be produced in an adversarial deployment.

use super::{
    payments::{
        PROOF_NAMESPACE, PaymentCommitment, PaymentsParams, RangeProof, bind_statement,
        derive_theta,
    },
    range::TRANSFER_BATCH,
};
use commonware_cryptography::{
    bls12381::primitives::group::G1,
    zk::pari::{self, Claim},
};
use commonware_math::algebra::CryptoGroup;
use rand_core::CryptoRng;

/// Simulate a transfer proof from the trapdoor.
///
/// A fresh block-0 commitment `c_hat` is chosen uniformly (a real one is
/// uniform by its fresh blinding), and the block-1 aggregate is derived from
/// the ledger exactly as the verifier does.
pub fn simulate_transfer(
    params: &PaymentsParams,
    trapdoor: &pari::Trapdoor,
    input_commitment: &PaymentCommitment,
    amount_commitment: &PaymentCommitment,
    rng: &mut impl CryptoRng,
) -> RangeProof {
    let ledger: [G1; TRANSFER_BATCH] = [
        amount_commitment.0,
        (*input_commitment - amount_commitment).0,
    ];
    let theta = derive_theta(params.verifying_key(), &ledger);
    let com_theta = ledger[0] + &(ledger[1] * &theta);

    // Sample a uniform fresh commitment; a real c_hat is uniform too.
    let c_hat = G1::generator() * pari::Opening::random(rng).scalar();
    let claim = Claim::new(vec![theta.clone()], vec![c_hat, com_theta]);

    let mut transcript = bind_statement(PROOF_NAMESPACE, &theta, &c_hat, &ledger);
    let proof = pari::simulate_prebound(
        rng,
        &mut transcript,
        trapdoor,
        params.verifying_key(),
        &claim,
    )
    .expect("simulation succeeds for the transfer relation");
    RangeProof { c_hat, proof }
}
