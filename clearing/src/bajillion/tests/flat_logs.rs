use super::*;
use crate::bajillion::{challenge::ChangeAbsence, transition::ProposalId};

#[test]
fn empty_activity_range_excludes_previous_epoch_and_commit_positions() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 1, 1, 1, 1).await;
        let first = fixture.prepared.close();
        let account = fixture.accounts[0].0.clone();
        let first_range = first.roots.activity_range(&fixture.context).unwrap();
        assert_eq!(first_range.end - first_range.start, 1);
        let first_lookup = account_lookup::<Sha256, _, _>(&first.changes, &account).unwrap();
        assert_eq!(
            first_lookup
                .resolve::<Sha256>(&first_range, &account)
                .unwrap()
                .0,
            1
        );
        let (replica, _) = Box::pin(fixture.prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH + 1,
            fixture.operator.public_key(),
            &fixture.deposits,
            &fixture.withdrawals,
            replica.state().liability(),
            100,
            101,
            CloseLimits::protocol_maximum(),
            *fixture.context.committee(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &replica,
            &fixture.deposits,
            &fixture.withdrawals,
            Floors {
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let empty = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &replica,
            &context,
            &fixture.deposits,
            &fixture.withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        let close = empty.close();
        let range = close.roots.activity_range(&context).unwrap();
        assert_eq!(range.start, first_range.head.operations);
        assert_eq!(range.start, range.end);
        assert_eq!(range.head.operations, first_range.head.operations + 1);
        assert!(close.change_evidence().0.is_empty());
        assert_eq!(close.change_evidence().2.start, range.start);
        let absent = account_lookup::<Sha256, _, _>(&close.changes, &account).unwrap();
        assert!(matches!(
            &absent,
            AccountLookup::Absent(ChangeAbsence { opening: None, .. })
        ));
        assert_eq!(
            absent.resolve::<Sha256>(&range, &account).unwrap(),
            (0, None)
        );
        assert!(first_lookup.resolve::<Sha256>(&range, &account).is_err());
        assert!(absent.resolve::<Sha256>(&first_range, &account).is_err());
        let with_commit = AccountLookup::Absent(ChangeAbsence {
            predecessor: None,
            successor: None,
            opening: Some(close.change_evidence().2.clone()),
        });
        assert!(with_commit.resolve::<Sha256>(&range, &account).is_err());
        for field in 0..3 {
            let mut altered = close.clone();
            match field {
                0 => altered.roots.change.root = Sha256::hash(&[b"wrong-empty-activity-root"]),
                1 => altered.roots.change.operations += 1,
                _ => altered.roots.change.floor += 1,
            }
            let served = crate::bajillion::serve::Index::new(&altered);
            assert!(served.account_lookup::<Sha256>(&account).is_err());
            assert!(
                served
                    .higher_entry_lookup::<Sha256>(&account, &account)
                    .is_err()
            );
        }
        let mut wrong = range;
        wrong.start = wrong.end + 1;
        assert!(absent.resolve::<Sha256>(&wrong, &account).is_err());
    });
}

#[test]
fn proposal_identity_distinguishes_equal_balance_results_before_tree_derivation() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 1, 1, 1, 1).await;
        let original = fixture.prepared.close();
        let mut terminals = fixture.terminals.clone();
        let body = terminals[0].authorization.body();
        let changed = VectorSendBody::new(
            fixture.context.payment(),
            body.payer().clone(),
            body.seq() + 1,
            body.cumulative_debit(),
            body.send_root(),
        );
        terminals[0].authorization =
            SendAuthorization::sign(changed.clone(), &fixture.accounts[0].1);
        terminals[0].operator_signature = bls_ack(&fixture.operator_bls_private, &changed);
        let alternative = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &fixture.state,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            terminals,
            &Sequential,
        )
        .await
        .unwrap();
        let checked = validate(&fixture, alternative.encoded().clone())
            .await
            .unwrap();
        assert_eq!(original.roots.successor, checked.close().roots.successor);
        assert_ne!(original.encoded(), checked.encoded());
        let id = ProposalId::for_dealing::<Sha256, _>(
            fixture.context.epoch_context(),
            original.encoded(),
        );
        let other = ProposalId::for_dealing::<Sha256, _>(
            fixture.context.epoch_context(),
            checked.encoded(),
        );
        assert_eq!(id, original.roots.proposal);
        assert_eq!(other, checked.close().roots.proposal);
        assert_ne!(id, other);
        assert_eq!(
            id,
            ProposalId::for_dealing::<Sha256, _>(
                fixture.context.epoch_context(),
                original.encoded()
            )
        );
    });
}

#[test]
fn accepted_replay_rejects_changed_source_metadata() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("source"), 1, 1, 1, 1).await;
        let first = Accepted::prepared(&fixture.prepared);
        let (state, _) = Box::pin(fixture.prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
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
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let second = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &fixture.deposits,
            &fixture.withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        let mut second = Accepted::prepared(&second);
        let good = vec![fixture.genesis.clone(), first.clone(), second.clone()];
        let replayed = replay_state(runtime.child("valid"), "valid-parent", &good)
            .await
            .unwrap();
        assert_eq!(*replayed.logs().head(), second.logs);
        second.activity = ActivityInput::new(
            second.activity.guards().to_vec(),
            Bytes::from_static(b"changed source"),
        );
        let wrong = vec![fixture.genesis, first, second];
        assert!(
            replay_state(runtime.child("wrong"), "wrong-parent", &wrong)
                .await
                .is_err()
        );
    });
}
