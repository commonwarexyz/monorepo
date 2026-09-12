use super::*;

#[test]
fn current_membership_and_absence_bind_root_key_and_positive_balance() {
    deterministic::Runner::default().start(|context| async move {
        let accounts = (0..80)
            .map(|i| SigningKey::from_seed(ACCOUNT_SEED_START + i).public_key())
            .collect::<Vec<_>>();
        let state = new_state(
            context,
            "proofs",
            accounts.iter().map(|key| (key.clone(), 100)).collect(),
        )
        .await;
        let opening = state.opening(accounts[0].clone()).await.unwrap();
        assert_eq!(opening.verify::<Sha256>(&state.root()).unwrap().get(), 100);
        let encoded = opening.encode();
        assert_eq!(encoded.len(), opening.encode_size());
        assert_eq!(
            StateOpening::<VerifyingKey, ShaDigest>::decode_cfg(encoded.clone(), &128).unwrap(),
            opening
        );
        assert!(StateOpening::<VerifyingKey, ShaDigest>::decode_cfg(encoded.clone(), &0).is_err());
        for length in 0..encoded.len() {
            assert!(
                StateOpening::<VerifyingKey, ShaDigest>::decode_cfg(encoded.slice(..length), &128)
                    .is_err()
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(
            StateOpening::<VerifyingKey, ShaDigest>::decode_cfg(Bytes::from(trailing), &128)
                .is_err()
        );
        let mut zero = encoded.to_vec();
        zero[32..40].fill(0);
        assert!(
            StateOpening::<VerifyingKey, ShaDigest>::decode_cfg(Bytes::from(zero), &128).is_err()
        );
        let mut wrong = opening.clone();
        wrong.balance = NonZeroU64::new(101).unwrap();
        assert!(wrong.verify::<Sha256>(&state.root()).is_err());
        wrong = opening.clone();
        wrong.account = accounts[1].clone();
        assert!(wrong.verify::<Sha256>(&state.root()).is_err());
        assert!(
            opening
                .verify::<Sha256>(&StateRoot::new(Sha256::hash(&[b"foreign-root"])))
                .is_err()
        );
        let present = state
            .lookup(&account_key(&accounts[0]).unwrap())
            .await
            .unwrap();
        assert!(
            present
                .resolve::<Sha256>(&state.root(), &account_key(&accounts[1]).unwrap())
                .is_err()
        );
        let missing = SigningKey::from_seed(999).public_key();
        let key = account_key(&missing).unwrap();
        let absence = state.lookup(&key).await.unwrap();
        assert!(matches!(absence, StateLookup::Absent(_)));
        assert_eq!(
            absence.resolve::<Sha256>(&state.root(), &key).unwrap(),
            None
        );
        assert!(
            absence
                .resolve::<Sha256>(&state.root(), &account_key(&accounts[0]).unwrap())
                .is_err()
        );
        assert_eq!(
            StateLookup::<ShaDigest>::decode_cfg(absence.encode(), &128).unwrap(),
            absence
        );
    });
}

#[test]
fn ordered_absence_covers_empty_and_wrapped_key_space() {
    deterministic::Runner::default().start(|context| async move {
        let empty = new_state(context.child("empty"), "empty", vec![]).await;
        let key = account_key(&SigningKey::from_seed(42).public_key()).unwrap();
        assert_eq!(
            empty
                .lookup(&key)
                .await
                .unwrap()
                .resolve::<Sha256>(&empty.root(), &key)
                .unwrap(),
            None
        );
        let mut accounts = (0..5)
            .map(|i| SigningKey::from_seed(i).public_key())
            .collect::<Vec<_>>();
        accounts.sort();
        let state = new_state(
            context,
            "wrapped",
            vec![(accounts[1].clone(), 1), (accounts[3].clone(), 2)],
        )
        .await;
        for index in [0, 2, 4] {
            let key = account_key(&accounts[index]).unwrap();
            let proof = state.lookup(&key).await.unwrap();
            assert!(matches!(proof, StateLookup::Absent(_)));
            assert_eq!(proof.resolve::<Sha256>(&state.root(), &key).unwrap(), None);
        }
    });
}

#[test]
fn validated_closes_retain_balance_and_activity_proofs_after_restart() {
    let ((heads, account, context, header, evidence, ack), checkpoint) =
        deterministic::Runner::default().start_and_recover(|runtime| async move {
            let fixture = fixture(runtime, 8, 8, 4, 1).await;
            let genesis = *fixture.state.head();
            let first = validate(&fixture, fixture.prepared.encoded().clone())
                .await
                .unwrap();
            let first_head = *first.state().head();
            let evidence = first.close().encode_evidence();
            let header = first.close().header;
            let (state, close) = first.apply::<_, Sha256>(fixture.state).await.unwrap();
            let context = EpochContext::new::<Sha256>(
                *fixture.context.deployment(),
                EPOCH + 1,
                fixture.operator.public_key(),
                &fixture.deposits,
                &fixture.withdrawals,
                state.liability(),
                100,
                101,
                CloseLimits::protocol_maximum(),
                *fixture.context.committee(),
            )
            .unwrap()
            .bind::<Sha256, _, _>(&state, &fixture.deposits, &fixture.withdrawals)
            .await
            .unwrap();
            let terminals = fixture
                .terminals
                .iter()
                .map(|terminal| {
                    let payer = terminal.vector.payer();
                    let private = &fixture
                        .accounts
                        .iter()
                        .find(|(key, _)| key == payer)
                        .unwrap()
                        .1;
                    let vector = OutVector::new(
                        EPOCH + 1,
                        payer.clone(),
                        terminal.vector.entries().to_vec(),
                    )
                    .unwrap();
                    let body = VectorSendBody::new(
                        context.payment(),
                        payer.clone(),
                        0,
                        1,
                        vector.root::<Sha256, ShaDigest>().unwrap(),
                    );
                    Terminal {
                        operator_signature: bls_ack(&fixture.operator_bls_private, &body),
                        authorization: SendAuthorization::sign(body, private),
                        vector,
                    }
                })
                .collect();
            let second = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &context,
                &fixture.deposits,
                &fixture.withdrawals,
                terminals,
                &Sequential,
            )
            .await
            .unwrap();
            let dealing = posted::decode(second.encoded().clone(), &context).unwrap();
            let second = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                &state,
                &context,
                &fixture.operator_bls,
                &fixture.deposits,
                &fixture.withdrawals,
                dealing,
                &mut TestRng::new(100),
                &Sequential,
            )
            .await
            .unwrap();
            assert!(second.close().rows.iter().all(|row| {
                row.outgoing.as_ref().is_some_and(|send| {
                    send.body().cumulative_debit() == 1 && send.body().seq() == 0
                })
            }));
            let (state, _) = second.apply::<_, Sha256>(state).await.unwrap();
            let state = state.commit().await.unwrap();
            assert_eq!(first_head.root(), close.roots.successor);
            let heads = [genesis, first_head, *state.head()];
            (
                heads,
                fixture.accounts[0].0.clone(),
                fixture.context,
                header,
                evidence,
                fixture.acks[0].clone(),
            )
        });
    deterministic::Runner::from(checkpoint).start(|runtime| async move {
        let cfg = config(&runtime, "fixture");
        let state = TestState::open(runtime, cfg).await.unwrap();
        assert_eq!(*state.head(), heads[2]);
        for (head, balance) in
            heads
                .into_iter()
                .zip([OPENING_BALANCE, OPENING_BALANCE + 1, OPENING_BALANCE + 2])
        {
            let root = head.root();
            let proof = state
                .opening_at(root, head.operations(), account.clone())
                .await
                .unwrap();
            assert_eq!(proof.verify::<Sha256>(&root).unwrap().get(), balance);
            assert!(state.opening_at(root, 0, account.clone()).await.is_err());
            assert_eq!(*state.head(), heads[2]);
        }
        assert!(
            state
                .opening_at(heads[0].root(), heads[2].operations(), account.clone())
                .await
                .is_err()
        );
        assert_eq!(*state.head(), heads[2]);
        let close = Close::decode_evidence::<Sha256>(evidence, &context, &header).unwrap();
        let index = ChallengeIndex::new::<Sha256>(&context, &close).unwrap();
        let lookup = account_lookup::<Sha256, _, _>(&index, &account).unwrap();
        assert_eq!(
            adjudicate::<Sha256, _, _>(
                &context,
                &header,
                &close.roots,
                &close.amounts,
                &Challenge::HigherAckDebit {
                    ack: Box::new(AckWitness::from_ack(&ack)),
                    payer: Box::new(lookup)
                }
            )
            .unwrap(),
            Verdict::NoContradiction
        );
    });
}
