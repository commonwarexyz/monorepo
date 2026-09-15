use super::*;
use crate::bajillion::transition::ProposalId;

#[test]
fn empty_activity_range_excludes_previous_epoch_and_commit_positions() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 1, 1, 1, 1).await;
        let account = fixture.accounts[0].0.clone();
        let first_range = fixture
            .prepared
            .close()
            .roots
            .activity_range(&fixture.context)
            .unwrap();
        assert_eq!(first_range.end - first_range.start, 1);
        let successor_liability =
            fixture.context.predecessor_liability() - fixture.prepared.close().withdrawal_total;
        let (replica, _) = Box::pin(fixture.prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let first_epoch = Epoch::at(replica.logs(), EPOCH, first_range).await.unwrap();
        let first_lookup = first_epoch
            .account_lookup(replica.logs(), &account)
            .await
            .unwrap();
        assert_eq!(
            first_lookup
                .resolve::<Sha256>(&first_range, &account)
                .unwrap()
                .0,
            1
        );
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH + 1,
            fixture.operator.public_key(),
            &fixture.deposits,
            &fixture.withdrawals,
            successor_liability,
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
        let range = empty.close().roots.activity_range(&context).unwrap();
        assert_eq!(range.start, first_range.head.operations);
        assert_eq!(range.start, range.end);
        assert_eq!(range.head.operations, first_range.head.operations + 1);
        let (replica, _) = Box::pin(empty.apply::<_, Sha256>(replica)).await.unwrap();
        let epoch = Epoch::at(replica.logs(), EPOCH + 1, range).await.unwrap();
        let absent = epoch
            .account_lookup(replica.logs(), &account)
            .await
            .unwrap();
        assert!(matches!(&absent, AccountLookup::Absent(_)));
        assert_eq!(
            absent.resolve::<Sha256>(&range, &account).unwrap(),
            (0, None)
        );
        assert!(first_lookup.resolve::<Sha256>(&range, &account).is_err());
        assert!(absent.resolve::<Sha256>(&first_range, &account).is_err());
        for field in 0..3 {
            let mut altered = range;
            match field {
                0 => altered.head.root = Sha256::hash(&[b"wrong-empty-activity-root"]),
                1 => altered.head.operations += 1,
                _ => altered.head.floor += 1,
            }
            assert!(Epoch::at(replica.logs(), EPOCH + 1, altered).await.is_err());
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
fn accepted_replay_rejects_changed_original_records() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("source"), 1, 1, 1, 1).await;
        let mut first = Accepted::prepared(&fixture.prepared);
        let successor_liability =
            fixture.context.predecessor_liability() - fixture.prepared.close().withdrawal_total;
        let (state, _) = Box::pin(fixture.prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH + 1,
            fixture.operator.public_key(),
            &fixture.deposits,
            &fixture.withdrawals,
            successor_liability,
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
        let second = Accepted::prepared(&second);
        let good = vec![fixture.genesis.clone(), first.clone(), second.clone()];
        let replayed = replay_state(runtime.child("valid"), "valid-parent", &good)
            .await
            .unwrap();
        assert_eq!(*replayed.logs().head(), second.logs);
        let mut entries = first.activity.entries().to_vec();
        assert!(entries.pop().is_some());
        first.activity = ActivityInput::new(first.activity.rows().to_vec(), entries);
        let wrong = vec![fixture.genesis, first, second];
        assert!(
            replay_state(runtime.child("wrong"), "wrong-parent", &wrong)
                .await
                .is_err()
        );
    });
}
