mod core {
    use crate::zkpari::{
        data_structures::{Claim, CommittedInputOpening, Proof, ProvingKey},
        range::RangeProof,
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
    type G1Affine = <Bn254 as Pairing>::G1Affine;

    fn seeded_rng() -> impl RngCore {
        ark_std::rand::rngs::StdRng::seed_from_u64(0x5eed)
    }

    /// Ledger commitments to the individual values in the block-1 basis,
    /// plus the aggregate opening `rho_1 + theta rho_2` matching
    /// `ledger[0] + theta ledger[1]`.
    fn ledger_pair(
        pk: &ProvingKey<E>,
        values: [u64; 2],
        theta: Fr,
        rng: &mut impl RngCore,
    ) -> ([G1Affine; 2], CommittedInputOpening<Fr>) {
        let rho = [
            CommittedInputOpening::<Fr>::rand(rng),
            CommittedInputOpening::<Fr>::rand(rng),
        ];
        let ledger = [
            pk.pedersen_commit(1, &[Fr::from(values[0])], &rho[0]),
            pk.pedersen_commit(1, &[Fr::from(values[1])], &rho[1]),
        ];
        let aggregate_opening = CommittedInputOpening {
            rho: rho[0].rho + theta * rho[1].rho,
        };
        (ledger, aggregate_opening)
    }

    fn slim(proof: &Proof<E>) -> RangeProof<E> {
        RangeProof {
            c_hat: proof.c_ci[0],
            t_g: proof.t_g,
            u_g: proof.u_g,
            v_a: proof.v_a,
        }
    }

    fn make_claim(
        pk: &ProvingKey<E>,
        values: [u64; 2],
        theta: Fr,
        rng: &mut impl RngCore,
    ) -> (Proof<E>, Claim<E>) {
        let (ledger, aggregate_opening) = ledger_pair(pk, values, theta, rng);
        let openings = [CommittedInputOpening::<Fr>::rand(rng), aggregate_opening];
        let proof =
            ZkPari::<E>::prove_with_openings(&values, theta, pk, &openings, &ledger, rng);
        let claim = Claim {
            proof: slim(&proof),
            theta,
            ledger,
        };
        (proof, claim)
    }

    #[test]
    fn range_proof_roundtrip() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let (_proof, claim) = make_claim(&pk, [37, 5], Fr::from(77u64), &mut rng);
        assert!(ZkPari::<E>::verify(&claim, &vk));
    }

    #[test]
    fn committed_input_pedersen_consistency() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let theta = Fr::from(1234u64);
        let (ledger, aggregate_opening) = ledger_pair(&pk, [42, 17], theta, &mut rng);
        let openings = [
            CommittedInputOpening::<Fr>::rand(&mut rng),
            aggregate_opening,
        ];
        let proof =
            ZkPari::<E>::prove_with_openings(&[42, 17], theta, &pk, &openings, &ledger, &mut rng);

        let expected_pair =
            pk.pedersen_commit(0, &[Fr::from(42u64), Fr::from(17u64)], &openings[0]);
        let expected_aggregate =
            (ledger[0].into_group() + ledger[1] * theta).into_affine();

        assert_eq!(proof.c_ci, vec![expected_pair, expected_aggregate]);
        assert!(ZkPari::<E>::verify(
            &Claim {
                proof: slim(&proof),
                theta,
                ledger,
            },
            &vk
        ));
    }

    #[test]
    fn pedersen_commitments_are_homomorphic() {
        let mut rng = seeded_rng();
        let (pk, _vk) = ZkPari::<E>::keygen(&mut rng);
        let a = CommittedInputOpening::<Fr>::rand(&mut rng);
        let b = CommittedInputOpening::<Fr>::rand(&mut rng);
        let sum = &a + &b;

        let com_a = pk.pedersen_commit(1, &[Fr::from(10u64)], &a);
        let com_b = pk.pedersen_commit(1, &[Fr::from(7u64)], &b);
        let com_sum = pk.pedersen_commit(1, &[Fr::from(17u64)], &sum);
        let combined = (com_a.into_group() + com_b.into_group()).into_affine();

        assert_eq!(combined, com_sum);
    }

    #[test]
    fn proofs_are_randomized() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let theta = Fr::from(5u64);
        let (ledger, aggregate_opening) = ledger_pair(&pk, [5, 6], theta, &mut rng);

        // Same statement and ledger, fresh block-0 blinding and masks.
        let openings = [
            CommittedInputOpening::<Fr>::rand(&mut rng),
            aggregate_opening.clone(),
        ];
        let first =
            ZkPari::<E>::prove_with_openings(&[5, 6], theta, &pk, &openings, &ledger, &mut rng);
        let openings = [CommittedInputOpening::<Fr>::rand(&mut rng), aggregate_opening];
        let second =
            ZkPari::<E>::prove_with_openings(&[5, 6], theta, &pk, &openings, &ledger, &mut rng);

        assert_ne!(first, second);
        for proof in [first, second] {
            assert!(ZkPari::<E>::verify(
                &Claim {
                    proof: slim(&proof),
                    theta,
                    ledger,
                },
                &vk
            ));
        }
    }

    #[test]
    fn batch_verify() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let claims: Vec<_> = [1u64, 2, 3, 4]
            .into_iter()
            .map(|value| {
                let theta = Fr::from(1000 + value);
                make_claim(&pk, [value, value + 7], theta, &mut rng).1
            })
            .collect();

        assert!(ZkPari::<E>::batch_verify(&claims, &vk, &mut rng));
    }

    #[test]
    fn batch_verify_with_strategy() {
        use commonware_parallel::Rayon;
        use core::num::NonZeroUsize;

        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let claims: Vec<_> = (0..12u64)
            .map(|value| {
                let theta = Fr::from(9000 + value);
                make_claim(&pk, [value, 2 * value], theta, &mut rng).1
            })
            .collect();

        let strategy = Rayon::new(NonZeroUsize::new(3).unwrap()).unwrap();
        assert!(ZkPari::<E>::batch_verify_with_strategy(
            &strategy, &claims, &vk, &mut rng
        ));
    }

    #[test]
    fn proof_serialization_roundtrip_and_malformed_inputs() {
        let mut rng = seeded_rng();
        let (pk, vk) = ZkPari::<E>::keygen(&mut rng);
        let theta = Fr::from(11u64);
        let (proof, claim) = make_claim(&pk, [11, 4], theta, &mut rng);
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let decoded = Proof::<E>::deserialize_compressed(&*bytes).unwrap();

        assert_eq!(decoded, proof);
        assert!(ZkPari::<E>::verify(&claim, &vk));
        // Wrong theta, tampered c_hat, and tampered ledger are all rejected.
        assert!(!ZkPari::<E>::verify(
            &Claim {
                theta: theta + Fr::from(1u64),
                ..claim
            },
            &vk
        ));
        let mut wrong_c_hat = claim;
        wrong_c_hat.proof.c_hat = <E as Pairing>::G1Affine::zero();
        assert!(!ZkPari::<E>::verify(&wrong_c_hat, &vk));
        let mut wrong_ledger = claim;
        wrong_ledger.ledger[0] = wrong_ledger.ledger[1];
        assert!(!ZkPari::<E>::verify(&wrong_ledger, &vk));
    }

    #[test]
    fn simulate_accepts_for_range_relation() {
        let mut rng = test_rng();
        let (pk, vk, trapdoor) = ZkPari::<E>::keygen_with_trapdoor(&mut rng);
        let theta = Fr::from(31u64);
        // Arbitrary commitments: the simulator needs no witness or openings.
        let (ledger, _aggregate_opening) = ledger_pair(&pk, [123, 45], theta, &mut rng);
        let c_hat = pk.pedersen_commit(
            0,
            &[Fr::from(1u64), Fr::from(2u64)],
            &CommittedInputOpening::<Fr>::rand(&mut rng),
        );
        let proof = ZkPari::<E>::simulate(&trapdoor, &vk, c_hat, theta, &ledger, &mut rng);

        assert_eq!(proof.c_ci[0], c_hat);
        assert!(ZkPari::<E>::verify(
            &Claim {
                proof: slim(&proof),
                theta,
                ledger,
            },
            &vk
        ));
    }

    #[test]
    fn simulate_is_bound_to_its_commitments() {
        let mut rng = test_rng();
        let (pk, vk, trapdoor) = ZkPari::<E>::keygen_with_trapdoor(&mut rng);
        let theta = Fr::from(3u64);
        let (ledger, _aggregate_opening) = ledger_pair(&pk, [9, 1], theta, &mut rng);
        let c_hat = pk.pedersen_commit(
            0,
            &[Fr::from(9u64), Fr::from(1u64)],
            &CommittedInputOpening::<Fr>::rand(&mut rng),
        );
        let other = pk.pedersen_commit(
            0,
            &[Fr::from(10u64), Fr::from(1u64)],
            &CommittedInputOpening::<Fr>::rand(&mut rng),
        );
        let proof = ZkPari::<E>::simulate(&trapdoor, &vk, c_hat, theta, &ledger, &mut rng);
        let mut rebound = Claim {
            proof: slim(&proof),
            theta,
            ledger,
        };
        rebound.proof.c_hat = other;

        assert!(!ZkPari::<E>::verify(&rebound, &vk));
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
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    type Payments = ZkPariBackend<Bn254>;

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(0x1234_5678)
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
    fn transfer_proof_is_bound_to_the_sender() {
        let mut rng = rng();
        let params = params();
        let (sender_commitment, sender_opening, _) = Payments::fund(&params, 100, &mut rng);
        let (other_commitment, _other_opening, _) = Payments::fund(&params, 200, &mut rng);

        let (amount_commitment, _amount_opening, proof) =
            Payments::transfer(&params, &sender_commitment, &sender_opening, 30, &mut rng);

        // Same amount commitment, different sender balance: the remaining
        // commitment (and hence theta and the aggregate) changes.
        assert!(!Payments::batch_verify(
            &params,
            &[],
            &[(other_commitment, amount_commitment, proof)],
            &[],
            &mut rng
        ));
    }

    #[test]
    fn transfer_boundary_values_verify() {
        let mut rng = rng();
        let params = params();
        let (sender_commitment, sender_opening, _) =
            Payments::fund(&params, u64::MAX, &mut rng);

        // Full-balance transfer (remaining = 0) and zero-amount transfer.
        for amount in [u64::MAX, 0] {
            let (amount_commitment, _opening, proof) =
                Payments::transfer(&params, &sender_commitment, &sender_opening, amount, &mut rng);
            assert!(Payments::batch_verify(
                &params,
                &[],
                &[(sender_commitment.clone(), amount_commitment, proof)],
                &[],
                &mut rng
            ));
        }
    }

    #[test]
    fn burn_of_full_balance_verifies() {
        let mut rng = rng();
        let params = params();
        let (account_commitment, account_opening, _) = Payments::fund(&params, 55, &mut rng);
        let proof = Payments::burn(&params, &account_commitment, &account_opening, 55, &mut rng);
        assert!(Payments::batch_verify(
            &params,
            &[],
            &[],
            &[(account_commitment, 55, proof)],
            &mut rng
        ));
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
            rng: &mut impl rand_core::CryptoRng,
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
            rng: &mut impl rand_core::CryptoRng,
        ) -> B::TransferProof {
            B::simulated_transfer_proof(params, trapdoor, input_commitment, amount_commitment, rng)
        }

        let mut rng = rng();
        let (range_pk, range_vk, trapdoor) =
            ZkPari::<Bn254>::keygen_with_trapdoor(&mut crate::zkpari::rng::ArkRng(&mut rng));
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
