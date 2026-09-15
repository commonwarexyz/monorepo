use super::*;
use crate::bajillion::{
    commitment::{self, VectorKind},
    custody::Epoch,
    logs::ActivityInput,
    transition::WithdrawalClaim,
};

#[test]
fn native_reopen_rebuilds_compact_account_and_outgoing_proofs() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("initial"), 3, 2, 3, 2).await;
        let range = fixture
            .prepared
            .close()
            .roots
            .activity_range(&fixture.context)
            .unwrap();
        let input = fixture.prepared.close().activity_input::<Sha256>();
        assert_eq!(range.end - range.start, input.rows().len() as u64);
        assert!(!input.entries().is_empty());
        assert!(input.rows().iter().any(|row| {
            !row.has_outgoing()
                && row.terminal_seq() == 0
                && row.send_root() == commitment::empty_root::<Sha256>(VectorKind::OutEntry)
        }));
        assert!(
            input
                .rows()
                .iter()
                .any(|row| row.has_outgoing() && row.terminal_seq() == 0)
        );
        let (replica, close) = Box::pin(fixture.prepared.apply::<_, Sha256>(fixture.state))
            .await
            .unwrap();
        let head = replica.head();
        let replica = Box::pin(replica.sync()).await.unwrap();
        drop(replica);

        let reopened = open_state(runtime, "fixture").await.unwrap();
        assert_eq!(reopened.head(), head);
        let epoch = Epoch::at(reopened.logs(), EPOCH, range).await.unwrap();
        for (account, _) in &fixture.accounts {
            epoch
                .account_lookup(reopened.logs(), account)
                .await
                .unwrap()
                .resolve::<Sha256>(&range, account)
                .unwrap();
            epoch
                .higher_entry_lookup(reopened.logs(), account, account)
                .await
                .unwrap()
                .resolve::<Sha256>(&range, account, account)
                .unwrap();
        }
        assert_eq!(close.roots.activity_range(&fixture.context).unwrap(), range);

        for field in 0..3 {
            let mut wrong = range;
            match field {
                0 => wrong.head.root = Sha256::hash(&[b"wrong-activity-root"]),
                1 => wrong.head.operations += 1,
                _ => wrong.head.floor += 1,
            }
            assert!(Epoch::at(reopened.logs(), EPOCH, wrong).await.is_err());
        }

        let mut mixed = range;
        mixed.end += 1;
        let after = (1_000_000..)
            .map(|seed| SigningKey::from_seed(seed).public_key())
            .find(|account| account.as_ref() > input.rows().last().unwrap().account().as_ref())
            .unwrap();
        let mixed = Epoch::at(reopened.logs(), EPOCH, mixed).await.unwrap();
        assert!(mixed.account_lookup(reopened.logs(), &after).await.is_err());
    });
}

#[test]
fn native_activity_rejects_noncanonical_original_record_grammar() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 3, 2, 3, 2).await;
        let input = fixture.prepared.close().activity_input::<Sha256>();
        let rows = input.rows().to_vec();
        let entries = input.entries().to_vec();
        let mut reversed_rows = rows.clone();
        reversed_rows.reverse();
        let mut underfilled = entries.clone();
        underfilled.pop().unwrap();
        let mut overshot = entries.clone();
        overshot[0].cumulative += 1;
        let mut wrong_order = entries.clone();
        wrong_order[..2].reverse();
        let mut leftover = entries.clone();
        leftover.push(entries[0].clone());
        for (rows, entries, order_error) in [
            (Vec::new(), entries.clone(), false),
            (reversed_rows, entries.clone(), true),
            (rows.clone(), Vec::new(), false),
            (rows.clone(), underfilled, false),
            (rows.clone(), overshot, false),
            (rows.clone(), wrong_order, false),
            (rows.clone(), leftover, false),
        ] {
            let result = fixture
                .state
                .logs()
                .prepare(
                    fixture.state.logs().head(),
                    ActivityInput::new(rows, entries),
                    vec![],
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await;
            assert!(matches!(
                (result, order_error),
                (Err(logs::Error::Order), true) | (Err(logs::Error::Original), false)
            ));
        }

        fixture
            .state
            .logs()
            .prepare(
                fixture.state.logs().head(),
                ActivityInput::new(rows, entries),
                vec![],
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await
            .unwrap();
    });
}

#[test]
fn native_activity_accepts_recipient_local_decreasing_totals() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 3, 2, 3, 2).await;
        let mut terminals = fixture.terminals.clone();
        let terminal = &mut terminals[0];
        let mut entries = terminal.vector.entries().to_vec();
        entries[0].cumulative = 2;
        assert_eq!(entries[1].cumulative, 1);
        terminal.vector = OutVector::new(EPOCH, terminal.vector.payer().clone(), entries).unwrap();
        let body = VectorSendBody::new(
            fixture.context.payment(),
            terminal.vector.payer().clone(),
            0,
            3,
            terminal.vector.root::<Sha256, ShaDigest>().unwrap(),
        );
        terminal.authorization = SendAuthorization::sign(body.clone(), &fixture.accounts[0].1);
        terminal.operator_signature = bls_ack(&fixture.operator_bls_private, &body);
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &fixture.state,
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            terminals,
            &Sequential,
        )
        .await
        .unwrap();
        let input = prepared.close().activity_input::<Sha256>();
        assert!(
            input
                .entries()
                .windows(2)
                .any(|entries| entries[0].cumulative > entries[1].cumulative)
        );
        fixture
            .state
            .logs()
            .prepare(
                fixture.state.logs().head(),
                input,
                vec![],
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await
            .unwrap();
    });
}

#[test]
fn current_payout_proof_survives_old_activity_retirement() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("initial"), 1, 0, 0, 0).await;
        let request = SignedWithdrawal::sign(
            *fixture.context.deployment(),
            fixture.state.state().root().digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            &fixture.accounts[0].1,
        );
        let withdrawals = WithdrawalBatch::new(vec![request]).unwrap();
        let (balance_state, old_logs) = fixture.state.into_parts();
        old_logs.destroy().await.unwrap();
        let mut log_cfg = logs_config(&runtime, "fixture");
        log_cfg.activity.log.items_per_section = commonware_utils::NZU64!(1);
        let reopen_log_cfg = log_cfg.clone();
        let logs = Logs::<_, Sha256, VerifyingKey, Sequential>::open(
            runtime.child("small_activity_sections"),
            log_cfg,
        )
        .await
        .unwrap();
        let state = Replica::from_parts(balance_state, logs);
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH,
            fixture.operator.public_key(),
            &fixture.deposits,
            &withdrawals,
            fixture.context.predecessor_liability(),
            98,
            99,
            CloseLimits::protocol_maximum(),
            *fixture.context.committee(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &state,
            &fixture.deposits,
            &withdrawals,
            Floors {
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &fixture.deposits,
            &withdrawals,
            vec![],
            &Sequential,
        )
        .await
        .unwrap();
        let old_range = prepared.close().roots.activity_range(&context).unwrap();
        let position = context.predecessor_logs().payouts.operations;
        let (mut state, close) = Box::pin(prepared.apply::<_, Sha256>(state)).await.unwrap();
        let liability = context.predecessor_liability() - close.withdrawal_total;

        for offset in 1..=2 {
            let empty = WithdrawalBatch::empty();
            let heads = *state.logs().head();
            let next = EpochContext::new::<Sha256>(
                *context.deployment(),
                EPOCH + offset,
                fixture.operator.public_key(),
                &fixture.deposits,
                &empty,
                liability,
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
                    payouts: 0,
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
        let checkpoint = state.head();
        let current = checkpoint.logs.payouts;
        let output = state.logs().payout_at(position).await.unwrap();
        let (opening, _) = state
            .logs()
            .payout_opening(&current, position, std::num::NonZeroU64::MIN)
            .await
            .unwrap();
        let claim = WithdrawalClaim::new(output, opening);
        assert_eq!(
            claim.verify::<Sha256>(&current).unwrap().amount(),
            OPENING_BALANCE
        );

        let state_cut = checkpoint.state.sync_boundary();
        state = state
            .prune(
                &checkpoint,
                state_cut,
                Floors {
                    activity: checkpoint.logs.activity.floor,
                    payouts: 0,
                },
            )
            .await
            .unwrap();
        assert!(
            state
                .logs()
                .raw_activity_record_at(&old_range.head, old_range.start)
                .await
                .is_err()
        );
        let state = Box::pin(state.sync()).await.unwrap();
        drop((state, close));
        let state = Replica::<_, Sha256, VerifyingKey, Sequential>::open(
            runtime.child("reopen"),
            crate::bajillion::replica::Config {
                state: config(&runtime, "fixture"),
                logs: reopen_log_cfg,
            },
        )
        .await
        .unwrap();
        assert!(
            state
                .logs()
                .raw_activity_record_at(&old_range.head, old_range.start)
                .await
                .is_err()
        );
        assert_eq!(
            claim.verify::<Sha256>(&current).unwrap().amount(),
            OPENING_BALANCE
        );
    });
}
