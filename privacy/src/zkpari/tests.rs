mod core {
    use crate::zkpari::{
        data_structures::{CommittedInputOpening, Proof},
        ZkPari,
    };
    use ark_bn254::Bn254;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    type E = Bn254;
    type Fr = <Bn254 as Pairing>::ScalarField;

    fn seeded_rng() -> impl RngCore {
        ark_std::rand::rngs::StdRng::seed_from_u64(0x5eed)
    }

    fn prove_value(
        value: u64,
    ) -> (
        crate::zkpari::ProvingKey<E>,
        crate::zkpari::VerifyingKey<E>,
        Proof<E>,
    ) {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let opening = CommittedInputOpening::<Fr>::rand(&mut rng);
        let proof = ZkPari::<E>::prove_with_openings(value, &pk, &[opening], &mut rng);
        (pk, vk, proof)
    }

    #[test]
    fn range_proof_roundtrip() {
        let (_pk, vk, proof) = prove_value(37);
        assert!(ZkPari::<E>::verify(&proof, &vk, &[]));
    }

    #[test]
    fn committed_input_pedersen_consistency() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let opening = CommittedInputOpening::<Fr>::rand(&mut rng);
        let proof =
            ZkPari::<E>::prove_with_openings(42, &pk, core::slice::from_ref(&opening), &mut rng);
        let expected = pk.pedersen_commit(0, &[Fr::from(42u64)], &opening);

        assert_eq!(proof.c_ci[0], expected);
        assert!(ZkPari::<E>::verify(&proof, &vk, &[]));
    }

    #[test]
    fn pedersen_commitments_are_homomorphic() {
        let mut rng = seeded_rng();
        let (pk, _vk) = ZkPari::<E>::keygen(&mut rng);
        let a = CommittedInputOpening::<Fr>::rand(&mut rng);
        let b = CommittedInputOpening::<Fr>::rand(&mut rng);
        let sum = &a + &b;

        let com_a = pk.pedersen_commit(0, &[Fr::from(10u64)], &a);
        let com_b = pk.pedersen_commit(0, &[Fr::from(7u64)], &b);
        let com_sum = pk.pedersen_commit(0, &[Fr::from(17u64)], &sum);
        let combined = (com_a.into_group() + com_b.into_group()).into_affine();

        assert_eq!(combined, com_sum);
    }

    #[test]
    fn proofs_are_randomized() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let opening = CommittedInputOpening::<Fr>::rand(&mut rng);
        let first =
            ZkPari::<E>::prove_with_openings(5, &pk, core::slice::from_ref(&opening), &mut rng);
        let second = ZkPari::<E>::prove_with_openings(5, &pk, &[opening], &mut rng);

        assert_ne!(first, second);
        assert!(ZkPari::<E>::verify(&first, &vk, &[]));
        assert!(ZkPari::<E>::verify(&second, &vk, &[]));
    }

    #[test]
    fn batch_verify() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let proofs: Vec<_> = [1u64, 2, 3, 4]
            .into_iter()
            .map(|value| {
                let opening = CommittedInputOpening::<Fr>::rand(&mut rng);
                (
                    ZkPari::<E>::prove_with_openings(value, &pk, &[opening], &mut rng),
                    Vec::new(),
                )
            })
            .collect();

        assert!(ZkPari::<E>::batch_verify(&proofs, &vk, &mut rng));
    }

    #[test]
    fn batch_verify_with_strategy() {
        use commonware_parallel::Rayon;
        use core::num::NonZeroUsize;

        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let proofs: Vec<_> = (0..12u64)
            .map(|value| {
                let opening = CommittedInputOpening::<Fr>::rand(&mut rng);
                (
                    ZkPari::<E>::prove_with_openings(value, &pk, &[opening], &mut rng),
                    Vec::new(),
                )
            })
            .collect();

        let strategy = Rayon::new(NonZeroUsize::new(3).unwrap()).unwrap();
        assert!(ZkPari::<E>::batch_verify_with_strategy(
            &strategy, &proofs, &vk, &mut rng
        ));
    }

    #[test]
    fn proof_serialization_roundtrip_and_malformed_inputs() {
        let (_pk, vk, proof) = prove_value(11);
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let decoded = Proof::<E>::deserialize_compressed(&*bytes).unwrap();

        assert_eq!(decoded, proof);
        assert!(ZkPari::<E>::verify(&decoded, &vk, &[]));
        assert!(!ZkPari::<E>::verify(&decoded, &vk, &[Fr::from(1u64)]));
        let mut wrong_blocks = decoded;
        wrong_blocks.c_ci.push(<E as Pairing>::G1Affine::zero());
        assert!(!ZkPari::<E>::verify(&wrong_blocks, &vk, &[]));
    }

    #[test]
    fn simulate_accepts_for_range_relation() {
        let mut rng = test_rng();
        let (pk, vk, trapdoor) = ZkPari::<E>::keygen_with_trapdoor(&mut rng);
        let commitment = pk.pedersen_commit(
            0,
            &[Fr::from(123u64)],
            &CommittedInputOpening::<Fr>::rand(&mut rng),
        );
        let proof = ZkPari::<E>::simulate(&trapdoor, &vk, &[commitment], &[], &mut rng);

        assert_eq!(proof.c_ci, vec![commitment]);
        assert!(ZkPari::<E>::verify(&proof, &vk, &[]));
    }

    #[test]
    fn simulate_is_bound_to_its_commitment() {
        let mut rng = test_rng();
        let (pk, vk, trapdoor) = ZkPari::<E>::keygen_with_trapdoor(&mut rng);
        let commitment = pk.pedersen_commit(
            0,
            &[Fr::from(9u64)],
            &CommittedInputOpening::<Fr>::rand(&mut rng),
        );
        let other = pk.pedersen_commit(
            0,
            &[Fr::from(10u64)],
            &CommittedInputOpening::<Fr>::rand(&mut rng),
        );
        let proof = ZkPari::<E>::simulate(&trapdoor, &vk, &[commitment], &[], &mut rng);
        let rebound = Proof {
            c_ci: vec![other],
            ..proof
        };

        assert!(!ZkPari::<E>::verify(&rebound, &vk, &[]));
    }
}

mod payments_backend {
    #[cfg(feature = "simulator")]
    use crate::zkpari::ZkPari;
    use crate::{
        payments::{Backend, Commitment, Opening},
        zkpari::payments::{PaymentCommitment, ZkPariBackend},
    };
    use ark_bn254::Bn254;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    type Payments = ZkPariBackend<Bn254>;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x1234_5678)
    }

    fn params() -> <Payments as Backend>::Params {
        <Payments as Backend>::setup(&[7u8; 32]).expect("setup is infallible")
    }

    #[test]
    fn transfer_pipeline_uses_zkpari_backend() {
        let mut rng = rng();
        let params = params();
        let (mut sender_commitment, mut sender_opening, fund_proof) =
            Payments::fund(&params, 100, &mut rng);
        assert!(Payments::batch_verify(
            &params,
            &[(100, sender_commitment.clone(), fund_proof)],
            &[],
            &[],
            &mut rng
        ));

        let (amount_commitment, amount_opening, proof) =
            Payments::transfer(&params, &sender_commitment, &sender_opening, 30, &mut rng);
        assert!(Payments::batch_verify(
            &params,
            &[],
            &[(sender_commitment.clone(), amount_commitment.clone(), proof)],
            &[],
            &mut rng
        ));

        sender_commitment = sender_commitment - &amount_commitment;
        sender_opening = sender_opening - &amount_opening;
        assert_eq!(sender_opening.value(), 70);
        assert_ne!(sender_commitment, PaymentCommitment::zero());
    }

    #[test]
    fn tampered_transfer_commitment_is_rejected() {
        let mut rng = rng();
        let params = params();
        let (sender_commitment, sender_opening, _fund_proof) =
            Payments::fund(&params, 100, &mut rng);

        let (_amount_commitment, _amount_opening, proof) =
            Payments::transfer(&params, &sender_commitment, &sender_opening, 30, &mut rng);
        let (wrong_commitment, _opening, _proof) = Payments::fund(&params, 31, &mut rng);

        assert!(!Payments::batch_verify(
            &params,
            &[],
            &[(sender_commitment, wrong_commitment, proof)],
            &[],
            &mut rng
        ));
    }

    #[test]
    #[should_panic(expected = "payment debit must not underflow")]
    fn overspending_panics_before_proving() {
        let mut rng = rng();
        let params = params();
        let (commitment, opening, _proof) = Payments::fund(&params, 10, &mut rng);
        let _ = Payments::transfer(&params, &commitment, &opening, 11, &mut rng);
    }

    #[test]
    fn burn_de_shields_partial_balance() {
        let mut rng = rng();
        let params = params();
        let (account_commitment, account_opening, _fund_proof) =
            Payments::fund(&params, 100, &mut rng);

        let value = 40;
        let proof = Payments::burn(
            &params,
            &account_commitment,
            &account_opening,
            value,
            &mut rng,
        );
        assert!(Payments::batch_verify(
            &params,
            &[],
            &[],
            &[(account_commitment.clone(), value, proof)],
            &mut rng
        ));

        assert!(!Payments::batch_verify(
            &params,
            &[],
            &[],
            &[(account_commitment.clone(), value + 1, proof)],
            &mut rng
        ));

        let (public_commitment, public_opening) = Payments::commit_public(&params, value);
        let remaining_commitment = account_commitment - &public_commitment;
        let remaining_opening = account_opening - &public_opening;
        assert_eq!(remaining_opening.value(), 60);
        assert_ne!(remaining_commitment, PaymentCommitment::zero());
    }

    #[test]
    fn fund_commitment_must_match_public_value() {
        let mut rng = rng();
        let params = params();
        let (wrong_commitment, _opening, proof) = Payments::fund(&params, 99, &mut rng);

        assert!(!Payments::batch_verify(
            &params,
            &[(100, wrong_commitment, proof)],
            &[],
            &[],
            &mut rng
        ));
    }

    #[test]
    fn backend_batch_verify_with_strategy() {
        use commonware_parallel::Rayon;
        use core::num::NonZeroUsize;

        fn verify_with_generic_backend<B: Backend>(
            strategy: &impl commonware_parallel::Strategy,
            params: &B::Params,
            funds: &[(u64, B::Commitment, B::FundProof)],
            transfers: &[(B::Commitment, B::Commitment, B::TransferProof)],
            burns: &[(B::Commitment, u64, B::BurnProof)],
            rng: &mut impl rand_core::CryptoRngCore,
        ) -> bool {
            B::batch_verify_with_strategy(strategy, params, funds, transfers, burns, rng)
        }

        let mut rng = rng();
        let params = params();
        let (commitment, opening, fund_proof) = Payments::fund(&params, 100, &mut rng);
        let (amount_commitment, _amount_opening, transfer_proof) =
            Payments::transfer(&params, &commitment, &opening, 30, &mut rng);
        let burn_proof = Payments::burn(&params, &commitment, &opening, 40, &mut rng);
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();

        assert!(verify_with_generic_backend::<Payments>(
            &strategy,
            &params,
            &[(100, commitment.clone(), fund_proof)],
            &[(commitment.clone(), amount_commitment, transfer_proof)],
            &[(commitment, 40, burn_proof)],
            &mut rng
        ));
    }

    #[cfg(feature = "simulator")]
    #[test]
    fn simulated_transfer_proof_verifies() {
        fn simulate_with_generic_backend<B: Backend>(
            params: &B::Params,
            trapdoor: &B::Trapdoor,
            input_commitment: &B::Commitment,
            amount_commitment: &B::Commitment,
            rng: &mut impl rand_core::CryptoRngCore,
        ) -> B::TransferProof {
            B::simulated_transfer_proof(params, trapdoor, input_commitment, amount_commitment, rng)
        }

        let mut rng = rng();
        let (range_pk, range_vk, trapdoor) = ZkPari::<Bn254>::keygen_with_trapdoor(&mut rng);
        let params = crate::zkpari::payments::PaymentsParams { range_pk, range_vk };
        let (commitment, _opening, _fund_proof) = Payments::fund(&params, 100, &mut rng);
        let (amount_commitment, _amount_opening, _transfer_proof) =
            Payments::fund(&params, 30, &mut rng);
        let proof = simulate_with_generic_backend::<Payments>(
            &params,
            &trapdoor,
            &commitment,
            &amount_commitment,
            &mut rng,
        );

        assert!(Payments::batch_verify(
            &params,
            &[],
            &[(commitment, amount_commitment, proof)],
            &[],
            &mut rng
        ));
    }
}
