use super::{
    payments::{PaymentCommitment, ZkPariBackend},
    range,
};
use crate::payments::{Backend, Opening};
use commonware_cryptography::bls12381::primitives::group::G1;
use commonware_math::algebra::CryptoGroup;
use commonware_utils::test_rng;

const SEED: [u8; 32] = *b"commonware-zkpari-bls12381-tests";

#[test]
fn transfer_relation_fits_domain_256() {
    let (relation, _) = range::relation();
    assert_eq!(relation.domain_size(), 256);
}

#[test]
fn transfer_pipeline_verifies() {
    let params = ZkPariBackend::setup(&SEED).expect("setup is infallible");
    let mut rng = test_rng();

    // Fund a private balance from public funds.
    let (sender, sender_opening, fund_proof) = ZkPariBackend::fund(&params, 1000, &mut rng);
    assert!(ZkPariBackend::batch_verify(
        &params,
        &[(1000, sender, fund_proof)],
        &[],
        &[],
        &mut rng,
    ));

    // Transfer part of it.
    let (amount, amount_opening, proof) =
        ZkPariBackend::transfer(&params, &sender, &sender_opening, 400, &mut rng);
    assert!(ZkPariBackend::batch_verify(
        &params,
        &[],
        &[(sender, amount, proof.clone())],
        &[],
        &mut rng,
    ));

    // The recipient's credited balance is the amount and its opening.
    assert_eq!(amount_opening.value(), 400);

    // Tampering with the amount commitment is rejected.
    let tampered = amount + &PaymentCommitment(G1::generator());
    assert!(!ZkPariBackend::batch_verify(
        &params,
        &[],
        &[(sender, tampered, proof)],
        &[],
        &mut rng,
    ));
}

#[test]
fn burn_verifies() {
    let params = ZkPariBackend::setup(&SEED).expect("setup is infallible");
    let mut rng = test_rng();

    let (sender, sender_opening, _) = ZkPariBackend::fund(&params, 1000, &mut rng);
    let proof = ZkPariBackend::burn(&params, &sender, &sender_opening, 250, &mut rng);
    assert!(ZkPariBackend::batch_verify(
        &params,
        &[],
        &[],
        &[(sender, 250, proof)],
        &mut rng,
    ));
}

#[test]
fn mixed_batch_verifies() {
    let params = ZkPariBackend::setup(&SEED).expect("setup is infallible");
    let mut rng = test_rng();

    let (a, a_open, a_fund) = ZkPariBackend::fund(&params, 500, &mut rng);
    let (b, b_open, _) = ZkPariBackend::fund(&params, 700, &mut rng);
    let (amount, _, transfer) = ZkPariBackend::transfer(&params, &a, &a_open, 100, &mut rng);
    let burn = ZkPariBackend::burn(&params, &b, &b_open, 200, &mut rng);

    assert!(ZkPariBackend::batch_verify(
        &params,
        &[(500, a, a_fund)],
        &[(a, amount, transfer)],
        &[(b, 200, burn)],
        &mut rng,
    ));
}

#[test]
fn fund_commitment_must_match_public_value() {
    let params = ZkPariBackend::setup(&SEED).expect("setup is infallible");
    let mut rng = test_rng();
    let (commitment, _) = ZkPariBackend::commit_public(&params, 10);
    assert!(!ZkPariBackend::batch_verify(
        &params,
        &[(11, commitment, ())],
        &[],
        &[],
        &mut rng,
    ));
}

#[test]
#[should_panic(expected = "payment debit must not underflow")]
fn overspending_panics_before_proving() {
    let params = ZkPariBackend::setup(&SEED).expect("setup is infallible");
    let mut rng = test_rng();
    let (sender, sender_opening, _) = ZkPariBackend::fund(&params, 100, &mut rng);
    let _ = ZkPariBackend::transfer(&params, &sender, &sender_opening, 101, &mut rng);
}

#[test]
fn boundary_amounts_verify() {
    let params = ZkPariBackend::setup(&SEED).expect("setup is infallible");
    let mut rng = test_rng();
    let (sender, sender_opening, _) = ZkPariBackend::fund(&params, u64::MAX, &mut rng);

    // Transfer everything: remaining is zero.
    let (amount, _, proof) =
        ZkPariBackend::transfer(&params, &sender, &sender_opening, u64::MAX, &mut rng);
    assert!(ZkPariBackend::batch_verify(
        &params,
        &[],
        &[(sender, amount, proof)],
        &[],
        &mut rng,
    ));
}

#[cfg(feature = "simulator")]
#[test]
fn simulated_transfer_proof_verifies() {
    let (params, trapdoor) = ZkPariBackend::setup_with_trapdoor(&SEED);
    let mut rng = test_rng();

    let (sender, _, _) = ZkPariBackend::fund(&params, 1000, &mut rng);
    let (amount_commitment, _) = ZkPariBackend::commit_public(&params, 400);
    let proof = ZkPariBackend::simulated_transfer_proof(
        &params,
        &trapdoor,
        &sender,
        &amount_commitment,
        &mut rng,
    );
    assert!(ZkPariBackend::batch_verify(
        &params,
        &[],
        &[(sender, amount_commitment, proof)],
        &[],
        &mut rng,
    ));
}

#[cfg(feature = "codec")]
mod codec {
    use super::*;
    use crate::zkpari::payments::{PaymentOpening, RangeProof};
    use commonware_codec::{DecodeExt, Encode, FixedSize};

    #[test]
    fn wire_sizes_are_fixed() {
        assert_eq!(PaymentCommitment::SIZE, 48);
        assert_eq!(RangeProof::SIZE, 176);
        assert_eq!(PaymentOpening::SIZE, 40);
    }

    #[test]
    fn payment_types_roundtrip() {
        let params = ZkPariBackend::setup(&SEED).expect("setup is infallible");
        let mut rng = test_rng();
        let (sender, sender_opening, _) = ZkPariBackend::fund(&params, 1000, &mut rng);
        let (amount, amount_opening, proof) =
            ZkPariBackend::transfer(&params, &sender, &sender_opening, 400, &mut rng);

        for commitment in [sender, amount] {
            let decoded = PaymentCommitment::decode(commitment.encode()).expect("commitment");
            assert_eq!(commitment, decoded);
        }
        let decoded = RangeProof::decode(proof.encode()).expect("proof");
        assert_eq!(proof, decoded);
        let decoded = PaymentOpening::decode(amount_opening.encode()).expect("opening");
        assert_eq!(amount_opening, decoded);
    }
}
