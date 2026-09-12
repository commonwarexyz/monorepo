use super::*;
use crate::bajillion::{serve::Index, state::SettlementOutput};
use commonware_runtime::Metrics as _;

#[test]
fn complete_activity_keeps_zero_net_boundaries_and_zero_release_withdrawals() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = (20..25).map(SigningKey::from_seed).collect::<Vec<_>>();
        let [payer, closed, offset, fresh, external] = keys.as_slice() else {
            unreachable!()
        };
        let state = new_state(
            runtime,
            "boundaries",
            keys[..3]
                .iter()
                .map(|key| (key.public_key(), 100))
                .collect(),
        )
        .await;
        let operator = SigningKey::from_seed(OPERATOR_SEED);
        let operator_bls_private = BlsPrivate::new(Scalar::from(OPERATOR_SEED));
        let operator_bls =
            compute_public::<crate::bajillion::transition::OperatorVariant>(&operator_bls_private);
        let deployment = Sha256::hash(&[b"boundary-deployment"]);
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(offset.public_key(), 10).unwrap(),
            DepositRecord::new(fresh.public_key(), 25).unwrap(),
        ])
        .unwrap();
        let withdrawals = WithdrawalBatch::new(vec![
            SignedWithdrawal::sign(
                deployment,
                state.root().digest,
                Bytes::from_static(b"payer-destination"),
                WithdrawalAction::Amount(NZU64!(90)),
                99,
                payer,
            ),
            SignedWithdrawal::sign(
                deployment,
                state.root().digest,
                Bytes::from_static(b"close-destination"),
                WithdrawalAction::Close,
                99,
                closed,
            ),
            SignedWithdrawal::sign(
                deployment,
                state.root().digest,
                Bytes::from_static(b"offset-destination"),
                WithdrawalAction::Amount(NZU64!(10)),
                99,
                offset,
            ),
        ])
        .unwrap();
        let context = EpochContext::new::<Sha256>(
            deployment,
            EPOCH,
            operator.public_key(),
            &deposits,
            &withdrawals,
            state.liability(),
            98,
            99,
            CloseLimits::protocol_maximum(),
            Sha256::hash(&[b"committee"]),
        )
        .unwrap()
        .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
        .await
        .unwrap();
        let mut entries = vec![
            OutEntry {
                recipient: closed.public_key(),
                cumulative: 5,
                count: 1,
            },
            OutEntry {
                recipient: fresh.public_key(),
                cumulative: 10,
                count: 1,
            },
            OutEntry {
                recipient: external.public_key(),
                cumulative: 10,
                count: 1,
            },
        ];
        entries.sort_by(|a, b| a.recipient.cmp(&b.recipient));
        let vector = OutVector::new(EPOCH, payer.public_key(), entries).unwrap();
        let body = VectorSendBody::new(
            context.payment(),
            payer.public_key(),
            0,
            25,
            vector.root::<Sha256, ShaDigest>().unwrap(),
        );
        let terminal = Terminal {
            operator_signature: bls_ack(&operator_bls_private, &body),
            authorization: SendAuthorization::sign(body, payer),
            vector,
        };
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![terminal],
            &Sequential,
        )
        .await
        .unwrap();
        let dealing = posted::decode(prepared.encoded().clone(), &context).unwrap();
        let verified = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
            &state,
            &context,
            &operator_bls,
            &deposits,
            &withdrawals,
            dealing,
            &mut TestRng::new(71),
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(verified.close().rows.len(), 5);
        assert_eq!(verified.state().mutations().len(), 3);
        assert!(
            !verified
                .state()
                .mutations()
                .iter()
                .any(|(key, _)| key == &account_key(&offset.public_key()).unwrap())
        );
        assert!(
            !verified
                .state()
                .mutations()
                .iter()
                .any(|(key, _)| key == &account_key(&external.public_key()).unwrap())
        );
        assert_eq!(verified.close().amounts.withdrawal, 115);
        assert_eq!(verified.close().amounts.payout, 10);
        assert_eq!(verified.state().head().liability(), 210);
        let (state, close) = verified.apply::<_, Sha256>(state).await.unwrap();
        let index = Index::new(&close);
        for (account, balance) in [
            (payer, Some(75)),
            (closed, None),
            (offset, Some(100)),
            (fresh, Some(35)),
            (external, None),
        ] {
            assert_eq!(
                state
                    .get(&account_key(&account.public_key()).unwrap())
                    .await
                    .unwrap()
                    .map(NonZeroU64::get),
                balance
            );
            assert!(matches!(
                index
                    .account_lookup::<Sha256>(&account.public_key())
                    .unwrap(),
                AccountLookup::Present(_)
            ));
        }
        for (account, amount, destination) in [
            (payer, 0, b"payer-destination".as_slice()),
            (closed, 105, b"close-destination".as_slice()),
            (offset, 10, b"offset-destination".as_slice()),
        ] {
            let claim = close.withdrawal_claim(&account.public_key()).unwrap();
            let output = claim
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .unwrap();
            assert_eq!(output.amount(), amount);
            assert_eq!(output.destination(), destination);
            assert!(claim.verify::<Sha256>(&close.roots.change).is_err());
        }
        let row = close
            .rows
            .iter()
            .find(|row| row.account == payer.public_key())
            .unwrap();
        assert_eq!(row.output, SettlementOutput::Withdrawal(0));
        let payout = close.external_payout_claim(&external.public_key()).unwrap();
        assert_eq!(
            payout.verify::<Sha256>(&close.roots.change).unwrap().amount,
            10
        );
        assert!(
            payout
                .verify::<Sha256>(&close.roots.withdrawal_outputs)
                .is_err()
        );
        let restored =
            Close::decode_evidence::<Sha256>(close.encode_evidence(), &context, &close.header)
                .unwrap();
        for request in withdrawals.requests() {
            assert_eq!(
                restored.withdrawal_claim(request.account()).unwrap(),
                close.withdrawal_claim(request.account()).unwrap()
            );
        }
        assert_eq!(
            restored
                .external_payout_claim(&external.public_key())
                .unwrap(),
            payout
        );
    });
}

#[test]
fn withdrawal_validation_batches_native_balance_reads() {
    deterministic::Runner::default().start(|runtime| async move {
        let mut signers = (30..33).map(SigningKey::from_seed).collect::<Vec<_>>();
        signers.sort_by_key(|signer| signer.public_key());
        let state = new_state(
            runtime.child("state"),
            "withdrawal-reads",
            vec![
                (signers[0].public_key(), 100),
                (signers[1].public_key(), 200),
            ],
        )
        .await;
        let operator = SigningKey::from_seed(OPERATOR_SEED);
        let operator_bls = compute_public::<crate::bajillion::transition::OperatorVariant>(
            &BlsPrivate::new(Scalar::from(OPERATOR_SEED)),
        );
        let deployment = Sha256::hash(&[b"withdrawal-read-deployment"]);
        let counts = || {
            let metrics = runtime.encode();
            ["_get_calls_total", "_get_many_calls_total"].map(|suffix| {
                metrics
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(' ')?;
                        name.ends_with(suffix)
                            .then(|| value.parse::<u64>().unwrap())
                    })
                    .expect("native QMDB read counter")
            })
        };
        let mut reads = Vec::new();
        for (label, amount, absent_action, deposit, expected) in [
            (
                "covered",
                90,
                WithdrawalAction::Amount(NZU64!(30)),
                30,
                None,
            ),
            (
                "insufficient",
                101,
                WithdrawalAction::Amount(NZU64!(30)),
                30,
                Some(CloseError::WithdrawalCoverage),
            ),
            (
                "absent amount",
                90,
                WithdrawalAction::Amount(NZU64!(1)),
                0,
                Some(CloseError::WithdrawalCoverage),
            ),
            (
                "absent close",
                90,
                WithdrawalAction::Close,
                0,
                Some(CloseError::BoundaryNoStateChange),
            ),
        ] {
            let deposits = if deposit == 0 {
                DepositBatch::empty()
            } else {
                DepositBatch::new(vec![
                    DepositRecord::new(signers[2].public_key(), deposit).unwrap(),
                ])
                .unwrap()
            };
            let actions = [
                WithdrawalAction::Amount(NonZeroU64::new(amount).unwrap()),
                WithdrawalAction::Close,
                absent_action,
            ];
            let withdrawals = WithdrawalBatch::new(
                signers
                    .iter()
                    .zip(actions)
                    .rev()
                    .map(|(signer, action)| {
                        SignedWithdrawal::sign(
                            deployment,
                            state.root().digest,
                            Bytes::from_static(b"destination"),
                            action,
                            99,
                            signer,
                        )
                    })
                    .collect(),
            )
            .unwrap();
            let epoch = EpochContext::new::<Sha256>(
                deployment,
                EPOCH,
                operator.public_key(),
                &deposits,
                &withdrawals,
                state.liability(),
                98,
                99,
                CloseLimits::protocol_maximum(),
                Sha256::hash(&[b"committee"]),
            )
            .unwrap();
            let before = counts();
            let bound = epoch
                .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
                .await;
            reads.push((label, before, counts()));
            if let Some(expected) = expected {
                assert!(
                    matches!(
                        (bound.unwrap_err(), expected),
                        (
                            CloseError::WithdrawalCoverage,
                            CloseError::WithdrawalCoverage
                        ) | (
                            CloseError::BoundaryNoStateChange,
                            CloseError::BoundaryNoStateChange
                        )
                    ),
                    "{label}"
                );
                continue;
            }
            let context = bound.unwrap();
            let before = counts();
            let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &context,
                &deposits,
                &withdrawals,
                vec![],
                &Sequential,
            )
            .await
            .unwrap();
            reads.push(("prepare", before, counts()));
            let dealing = posted::decode(prepared.encoded().clone(), &context).unwrap();
            let before = counts();
            let verified = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                &state,
                &context,
                &operator_bls,
                &deposits,
                &withdrawals,
                dealing,
                &mut TestRng::new(71),
                &Sequential,
            )
            .await
            .unwrap();
            reads.push(("validate", before, counts()));
            assert_eq!(verified.close().header, prepared.close().header);
            assert_eq!(verified.state().head().liability(), 10);
            assert_eq!(verified.close().rows.len(), 3);
            for (row, (signer, old, new, withdrawal)) in verified.close().rows.iter().zip([
                (&signers[0], 100, 10, 90),
                (&signers[1], 200, 0, 200),
                (&signers[2], 0, 0, 30),
            ]) {
                assert_eq!(row.account, signer.public_key());
                assert_eq!((row.predecessor, row.successor), (old, new));
                assert_eq!(row.output, SettlementOutput::Withdrawal(withdrawal));
            }
        }
        for (label, before, after) in reads {
            assert_eq!(after[0] - before[0], 0, "{label}: serial balance reads");
            assert!(after[1] > before[1], "{label}: native batch reads");
        }
    });
}
