use super::*;
use crate::bajillion::custody::{SourceMetadata, SourceProof, SourceRow};
use commonware_codec::{Error as CodecError, FixedSize};
use commonware_cryptography::Verifier;

#[test]
fn source_metadata_withdrawal_count_is_bounded_before_element_decode() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 1, 0, 0, 0).await;
        let request = SignedWithdrawal::sign(
            *fixture.context.deployment(),
            fixture.state.state().root().digest,
            Bytes::new(),
            WithdrawalAction::Close,
            100,
            &fixture.accounts[0].1,
        );
        let minimum = VerifyingKey::SIZE
            + 2 * ShaDigest::SIZE
            + 1
            + 1
            + u64::SIZE
            + <VerifyingKey as Verifier>::Signature::SIZE;
        assert_eq!(request.encode().len(), minimum);
        let withdrawals = WithdrawalBatch::new(vec![request]).unwrap();
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH,
            fixture.operator.public_key(),
            &fixture.deposits,
            &withdrawals,
            fixture.state.state().liability(),
            98,
            99,
            CloseLimits::protocol_maximum(),
            *fixture.context.committee(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &fixture.state,
            &fixture.deposits,
            &withdrawals,
            Floors {
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &fixture.state,
            &context,
            &fixture.deposits,
            &withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        let activity = prepared.close().activity_input();
        let source =
            SourceMetadata::<VerifyingKey, ShaDigest>::decode(activity.metadata().clone()).unwrap();
        assert_eq!(source.withdrawals(), &withdrawals);
        assert_eq!(source.encode(), *activity.metadata());
        let mut truncated = (source.context().clone(), source.rows().to_vec())
            .encode()
            .to_vec();
        truncated.extend(1_usize.encode());
        truncated.push(0);
        let truncated = Bytes::from(truncated);
        assert!(matches!(
            SourceMetadata::<VerifyingKey, ShaDigest>::decode(truncated.clone()),
            Err(CodecError::InvalidLength(1))
        ));
        let proof = SourceProof {
            metadata: truncated,
            opening: prepared.close().change_evidence().2.clone(),
        };
        assert!(matches!(
            proof.verify::<Sha256, VerifyingKey>(prepared.replica().logs().head()),
            Err(CloseError::Logs(_))
        ));
        assert!(matches!(
            SourceProof::<ShaDigest>::decode_cfg(
                proof.encode(),
                &commonware_codec::RangeCfg::new(..=0)
            ),
            Err(CodecError::InvalidLength(_))
        ));
    });
}

#[test]
fn source_row_count_is_bounded_before_element_decode() {
    let mut bytes = 0_u64.encode().to_vec();
    bytes.extend(1_usize.encode());
    bytes.push(0);
    assert!(matches!(
        SourceRow::<VerifyingKey>::decode_cfg(
            Bytes::from(bytes),
            &commonware_codec::RangeCfg::new(..=1)
        ),
        Err(CodecError::InvalidLength(1))
    ));
    let encoded = (0_u64, Vec::<OutEntry<VerifyingKey>>::new()).encode();
    assert_eq!(
        SourceRow::<VerifyingKey>::decode_cfg(
            encoded.clone(),
            &commonware_codec::RangeCfg::new(..=0)
        )
        .unwrap()
        .encode(),
        encoded
    );
}

#[test]
fn native_reopen_rebuilds_source_account_and_outgoing_proofs() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("initial"), 3, 2, 3, 2).await;
        let expected = fixture
            .accounts
            .iter()
            .map(|(account, _)| {
                let lookup =
                    account_lookup::<Sha256, _, _>(&fixture.prepared.close().changes, account)
                        .unwrap();
                let higher = crate::bajillion::serve::Index::new(fixture.prepared.close())
                    .higher_entry_lookup::<Sha256>(account, account)
                    .unwrap();
                (account.clone(), lookup.encode(), higher.encode())
            })
            .collect::<Vec<_>>();
        let context = fixture.context.clone();
        let (replica, close) = Box::pin(fixture.prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let head = replica.head();
        let replica = Box::pin(replica.commit()).await.unwrap();
        drop(close);
        drop(replica);
        let reopened = open_state(runtime, "fixture").await.unwrap();
        assert_eq!(reopened.head(), head);
        let epoch = crate::bajillion::custody::Epoch::<VerifyingKey, ShaDigest>::load(
            reopened.logs(),
            EPOCH,
        )
        .await
        .unwrap();
        assert_eq!(epoch.context(), &context);
        let proof = epoch
            .source_proof(reopened.logs(), &head.logs)
            .await
            .unwrap();
        let source = proof.verify::<Sha256, VerifyingKey>(&head.logs).unwrap();
        assert_eq!(source.context(), &context);
        for (account, expected_account, expected_higher) in expected {
            let lookup = epoch
                .account_lookup(reopened.logs(), &head.logs, &account)
                .await
                .unwrap();
            let higher = epoch
                .higher_entry_lookup(reopened.logs(), &head.logs, &account, &account)
                .await
                .unwrap();
            assert_eq!(lookup.encode(), expected_account);
            assert_eq!(higher.encode(), expected_higher);
            lookup
                .resolve::<Sha256>(source.activity_range(), &account)
                .unwrap();
        }
        assert!(
            crate::bajillion::custody::Epoch::<VerifyingKey, ShaDigest>::load(
                reopened.logs(),
                EPOCH + 1
            )
            .await
            .is_err()
        );
    });
}

#[test]
fn old_empty_source_refreshes_after_append_and_floor_without_changing_range() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("initial"), 1, 0, 0, 0).await;
        let account = fixture.accounts[0].0.clone();
        let (state, close) = Box::pin(fixture.prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let first = state.head();
        let epoch =
            crate::bajillion::custody::Epoch::<VerifyingKey, ShaDigest>::load(state.logs(), EPOCH)
                .await
                .unwrap();
        let old = epoch.source_proof(state.logs(), &first.logs).await.unwrap();
        let first_source = old.verify::<Sha256, VerifyingKey>(&first.logs).unwrap();
        assert_eq!(
            first_source.activity_range().start,
            first_source.activity_range().end
        );
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH + 1,
            fixture.operator.public_key(),
            &fixture.deposits,
            &fixture.withdrawals,
            state.state().liability(),
            100,
            101,
            CloseLimits::protocol_maximum(),
            *fixture.context.committee(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &state,
            &fixture.deposits,
            &fixture.withdrawals,
            Floors {
                activity: first.logs.activity.operations - 1,
                payouts: first.logs.payouts.operations - 1,
            },
        )
        .unwrap();
        let next = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &fixture.deposits,
            &fixture.withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        let (state, next_close) = Box::pin(next.apply::<_, Sha256>(state)).await.unwrap();
        let latest = state.head();
        assert_ne!(first.logs, latest.logs);
        assert!(old.verify::<Sha256, VerifyingKey>(&latest.logs).is_err());
        let state = Box::pin(state.commit()).await.unwrap();
        drop((state, close, next_close, epoch));
        let state = open_state(runtime, "fixture").await.unwrap();
        let epoch =
            crate::bajillion::custody::Epoch::<VerifyingKey, ShaDigest>::load(state.logs(), EPOCH)
                .await
                .unwrap();
        let refreshed = epoch
            .source_proof(state.logs(), &latest.logs)
            .await
            .unwrap();
        let source = refreshed
            .verify::<Sha256, VerifyingKey>(&latest.logs)
            .unwrap();
        assert_eq!(
            source.activity_range().start,
            first_source.activity_range().start
        );
        assert_eq!(
            source.activity_range().end,
            first_source.activity_range().end
        );
        assert_eq!(source.activity_range().head, latest.logs.activity);
        let absent = epoch
            .account_lookup(state.logs(), &latest.logs, &account)
            .await
            .unwrap();
        assert_eq!(
            absent
                .resolve::<Sha256>(source.activity_range(), &account)
                .unwrap(),
            (0, None)
        );
        let mut wrong = refreshed.clone();
        wrong.opening.start -= 1;
        assert!(wrong.verify::<Sha256, VerifyingKey>(&latest.logs).is_err());
        let mut wrong_head = latest.logs;
        wrong_head.activity.root = Sha256::hash(&[b"other-fork"]);
        assert!(
            refreshed
                .verify::<Sha256, VerifyingKey>(&wrong_head)
                .is_err()
        );
    });
}

#[test]
fn source_authenticates_exact_request_despite_equal_payout_bytes() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("initial"), 1, 0, 0, 0).await;
        let request = |deadline| {
            SignedWithdrawal::sign(
                *fixture.context.deployment(),
                fixture.state.state().root().digest,
                Bytes::from_static(b"destination"),
                WithdrawalAction::Amount(NZU64!(1)),
                deadline,
                &fixture.accounts[0].1,
            )
        };
        let original = request(100);
        let alternative = request(101);
        let make_context = |withdrawals: &WithdrawalBatch<VerifyingKey, ShaDigest>| {
            EpochContext::new::<Sha256>(
                *fixture.context.deployment(),
                EPOCH,
                fixture.operator.public_key(),
                &fixture.deposits,
                withdrawals,
                fixture.state.state().liability(),
                98,
                99,
                CloseLimits::protocol_maximum(),
                *fixture.context.committee(),
            )
            .unwrap()
            .bind::<Sha256, _, _>(
                &fixture.state,
                &fixture.deposits,
                withdrawals,
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .unwrap()
        };
        let withdrawals = WithdrawalBatch::new(vec![original.clone()]).unwrap();
        let alternative_withdrawals = WithdrawalBatch::new(vec![alternative.clone()]).unwrap();
        let context = make_context(&withdrawals);
        let other_context = make_context(&alternative_withdrawals);
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &fixture.state,
            &context,
            &fixture.deposits,
            &withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        let other = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &fixture.state,
            &other_context,
            &fixture.deposits,
            &alternative_withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(
            prepared.close().roots.withdrawal_outputs,
            other.close().roots.withdrawal_outputs
        );
        assert_eq!(
            prepared.close().withdrawal_evidence().0,
            other.close().withdrawal_evidence().0
        );
        assert_ne!(prepared.close().roots.change, other.close().roots.change);
        assert_ne!(prepared.close().header, other.close().header);
        let other_metadata = other.close().activity_input().metadata().clone();
        let (state, _) = Box::pin(prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let heads = *state.logs().head();
        let epoch =
            crate::bajillion::custody::Epoch::<VerifyingKey, ShaDigest>::load(state.logs(), EPOCH)
                .await
                .unwrap();
        let proof = epoch.source_proof(state.logs(), &heads).await.unwrap();
        let source = proof.verify::<Sha256, VerifyingKey>(&heads).unwrap();
        let claim = epoch
            .withdrawal_claim(state.logs(), &heads, original.account())
            .await
            .unwrap();
        source
            .verify_withdrawal::<Sha256>(&original, &claim)
            .unwrap();
        assert!(
            source
                .verify_withdrawal::<Sha256>(&alternative, &claim)
                .is_err()
        );
        let mut forged = proof;
        forged.metadata = other_metadata;
        assert!(forged.verify::<Sha256, VerifyingKey>(&heads).is_err());
    });
}

#[test]
fn old_nonempty_source_and_zero_payout_reopen_beyond_the_guard_floor() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("initial"), 1, 0, 0, 0).await;
        let absent = SigningKey::from_seed(900_001);
        let withdrawals = WithdrawalBatch::new(
            [&fixture.accounts[0].1, &absent]
                .into_iter()
                .map(|signer| {
                    SignedWithdrawal::sign(
                        *fixture.context.deployment(),
                        fixture.state.state().root().digest,
                        Bytes::from_static(b"destination"),
                        WithdrawalAction::Close,
                        100,
                        signer,
                    )
                })
                .collect(),
        )
        .unwrap();
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH,
            fixture.operator.public_key(),
            &fixture.deposits,
            &withdrawals,
            fixture.state.state().liability(),
            98,
            99,
            CloseLimits::protocol_maximum(),
            *fixture.context.committee(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &fixture.state,
            &fixture.deposits,
            &withdrawals,
            Floors {
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &fixture.state,
            &context,
            &fixture.deposits,
            &withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        let input = prepared.close().activity_input();
        let outputs = prepared.close().withdrawal_evidence().0.to_vec();
        assert!(outputs.iter().any(|output| output.amount() == 0));
        let metadata =
            SourceMetadata::<VerifyingKey, ShaDigest>::decode(input.metadata().clone()).unwrap();
        let mut rows = metadata.rows().to_vec();
        rows.pop().unwrap();
        let malformed = (context.clone(), rows, withdrawals.clone()).encode();
        let bad_cfg = logs_config(&runtime, "bad-source-count");
        let mut bad_logs =
            Logs::<_, Sha256, VerifyingKey, Sequential>::open(runtime.child("bad_source"), bad_cfg)
                .await
                .unwrap();
        let batch = bad_logs
            .prepare(
                bad_logs.head(),
                ActivityInput::new(input.guards().to_vec(), malformed),
                outputs,
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await
            .unwrap();
        bad_logs = bad_logs.apply(batch).await.unwrap();
        let (metadata, _, opening) = bad_logs
            .activity_metadata_at(
                &bad_logs.head().activity,
                bad_logs.head().activity.operations - 1,
            )
            .await
            .unwrap();
        assert!(matches!(
            SourceProof { metadata, opening }.verify::<Sha256, VerifyingKey>(bad_logs.head()),
            Err(CloseError::LogRange)
        ));
        let (mut state, close) = Box::pin(prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let old_end = close.roots.activity_range(&context).unwrap().end;
        let old_epoch =
            crate::bajillion::custody::Epoch::<VerifyingKey, ShaDigest>::load(state.logs(), EPOCH)
                .await
                .unwrap();
        let old_proof = old_epoch
            .source_proof(state.logs(), state.logs().head())
            .await
            .unwrap();
        let old_claim = old_epoch
            .withdrawal_claim(state.logs(), state.logs().head(), &absent.public_key())
            .await
            .unwrap();
        for offset in 1..=2 {
            let empty = WithdrawalBatch::empty();
            let heads = *state.logs().head();
            let next = EpochContext::new::<Sha256>(
                *context.deployment(),
                EPOCH + offset,
                fixture.operator.public_key(),
                &fixture.deposits,
                &empty,
                state.state().liability(),
                100 + 2 * offset,
                101 + 2 * offset,
                *context.limits(),
                *context.committee(),
            )
            .unwrap()
            .bind::<Sha256, _, _>(
                &state,
                &fixture.deposits,
                &empty,
                Floors {
                    activity: heads.activity.operations - 1,
                    payouts: heads.payouts.operations - 1,
                },
            )
            .unwrap();
            let batch = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &next,
                &fixture.deposits,
                &empty,
                vec![],
                &Sequential,
            )
            .await
            .unwrap();
            state = Box::pin(batch.apply::<_, Sha256>(state)).await.unwrap().0;
        }
        let heads = *state.logs().head();
        assert!(heads.activity.floor > old_end);
        assert!(old_proof.verify::<Sha256, VerifyingKey>(&heads).is_err());
        assert!(old_claim.verify::<Sha256>(&heads.payouts).is_err());
        let state = Box::pin(state.commit()).await.unwrap();
        drop((state, close, old_epoch));
        let state = open_state(runtime, "fixture").await.unwrap();
        let epoch =
            crate::bajillion::custody::Epoch::<VerifyingKey, ShaDigest>::load(state.logs(), EPOCH)
                .await
                .unwrap();
        let proof = epoch.source_proof(state.logs(), &heads).await.unwrap();
        let source = proof.verify::<Sha256, VerifyingKey>(&heads).unwrap();
        for request in withdrawals.requests() {
            let lookup = epoch
                .account_lookup(state.logs(), &heads, request.account())
                .await
                .unwrap();
            assert!(
                lookup
                    .resolve::<Sha256>(source.activity_range(), request.account())
                    .unwrap()
                    .1
                    .is_some()
            );
            let claim = epoch
                .withdrawal_claim(state.logs(), &heads, request.account())
                .await
                .unwrap();
            let output = source.verify_withdrawal::<Sha256>(request, &claim).unwrap();
            assert_eq!(
                output.amount(),
                if request.account() == &absent.public_key() {
                    0
                } else {
                    OPENING_BALANCE
                }
            );
        }
    });
}
