use super::*;
use crate::bajillion::state::SettlementOutput;

fn epoch(
    state: &TestState,
    epoch: u64,
    predecessor_liability: u64,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, ShaDigest>,
) -> CloseContext<VerifyingKey, ShaDigest> {
    EpochContext::new::<Sha256>(
        Sha256::hash(&[b"virtual-balances"]),
        epoch,
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        deposits,
        withdrawals,
        predecessor_liability,
        98,
        99,
        CloseLimits::protocol_maximum(),
        Sha256::hash(&[b"committee"]),
    )
    .unwrap()
    .bind::<Sha256, _, _>(
        state,
        deposits,
        withdrawals,
        Floors {
            activity: 0,
            payouts: 0,
        },
    )
    .unwrap()
}

fn terminal(
    context: &CloseContext<VerifyingKey, ShaDigest>,
    payer: &SigningKey,
    payments: &[(&SigningKey, u64)],
) -> Terminal<VerifyingKey, ShaDigest> {
    let mut entries = payments
        .iter()
        .map(|(recipient, amount)| OutEntry {
            recipient: recipient.public_key(),
            cumulative: *amount,
            count: 1,
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.recipient.clone());
    let vector = OutVector::new(context.payment().epoch(), payer.public_key(), entries).unwrap();
    let body = VectorSendBody::new(
        context.payment(),
        payer.public_key(),
        0,
        payments.iter().map(|(_, amount)| amount).sum(),
        vector.root::<Sha256, ShaDigest>().unwrap(),
    );
    Terminal {
        operator_signature: bls_ack(&BlsPrivate::new(Scalar::from(OPERATOR_SEED)), &body),
        authorization: SendAuthorization::sign(body, payer),
        vector,
    }
}

async fn verify(
    state: &TestState,
    context: &CloseContext<VerifyingKey, ShaDigest>,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, ShaDigest>,
    mut terminals: Vec<Terminal<VerifyingKey, ShaDigest>>,
) -> PreparedClose<VerifyingKey, ShaDigest> {
    terminals.sort_by(|a, b| {
        a.authorization
            .body()
            .payer()
            .cmp(b.authorization.body().payer())
    });
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        state,
        context,
        deposits,
        withdrawals,
        terminals,
        &Sequential,
    )
    .await
    .unwrap();
    let dealing = posted::decode(prepared.encoded().clone(), context).unwrap();
    let operator = compute_public::<crate::bajillion::transition::OperatorVariant>(
        &BlsPrivate::new(Scalar::from(OPERATOR_SEED)),
    );
    let verified = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
        state,
        context,
        &operator,
        deposits,
        withdrawals,
        dealing,
        &mut TestRng::new(83),
        &Sequential,
    )
    .await
    .unwrap();
    assert_eq!(verified.close().header, prepared.close().header);
    verified
}

#[test]
fn absent_credit_and_multilateral_payments_create_virtual_balances() {
    deterministic::Runner::default().start(|runtime| async move {
        let [a, b, c, d] = [101, 102, 103, 104].map(SigningKey::from_seed);
        let state = new_state(
            runtime,
            "virtual",
            vec![(a.public_key(), 100), (b.public_key(), 40)],
        )
        .await;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = epoch(&state, EPOCH, 140, &deposits, &withdrawals);
        let prepared = verify(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![
                terminal(&context, &a, &[(&b, 20), (&c, 10)]),
                terminal(&context, &b, &[(&c, 5), (&d, 8)]),
            ],
        )
        .await;
        assert!(
            prepared
                .close()
                .rows
                .iter()
                .all(|row| row.output == SettlementOutput::None)
        );
        assert!(prepared.close().withdrawal_outputs().is_empty());
        let range = prepared.close().roots.activity_range(&context).unwrap();
        let (state, close) = Box::pin(prepared.apply::<_, Sha256>(state)).await.unwrap();
        for (key, balance) in [(&a, 70), (&b, 47), (&c, 15), (&d, 8)] {
            assert_eq!(
                state
                    .state()
                    .get(&account_key(&key.public_key()).unwrap())
                    .await
                    .unwrap()
                    .map(NonZeroU64::get),
                Some(balance)
            );
        }
        assert_eq!(state.state().live_accounts(), 4);
        let retained = Epoch::at(state.logs(), EPOCH, range).await.unwrap();
        for key in [&a, &b, &c, &d] {
            let account = key.public_key();
            retained
                .account_lookup(state.logs(), &account)
                .await
                .unwrap()
                .resolve::<Sha256>(&range, &account)
                .unwrap();
        }
        assert_eq!(close.roots.activity_range(&context).unwrap(), range);
    });
}

#[test]
fn absent_recipient_cannot_originate_until_successor_epoch() {
    deterministic::Runner::default().start(|runtime| async move {
        let [a, b] = [101, 102].map(SigningKey::from_seed);
        let state = new_state(runtime, "eligibility", vec![(a.public_key(), 100)]).await;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = epoch(&state, EPOCH, 100, &deposits, &withdrawals);
        let rejected = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![
                terminal(&context, &a, &[(&b, 20)]),
                terminal(&context, &b, &[(&a, 5)]),
            ],
            &Sequential,
        )
        .await;
        assert!(matches!(rejected, Err(CloseError::AccountActivity)));
        let first = verify(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![terminal(&context, &a, &[(&b, 20)])],
        )
        .await;
        let (state, _) = Box::pin(first.apply::<_, Sha256>(state)).await.unwrap();
        assert_eq!(
            state
                .state()
                .get(&account_key(&b.public_key()).unwrap())
                .await
                .unwrap()
                .map(NonZeroU64::get),
            Some(20)
        );
        let next = epoch(&state, EPOCH + 1, 100, &deposits, &withdrawals);
        let second = verify(
            &state,
            &next,
            &deposits,
            &withdrawals,
            vec![terminal(&next, &b, &[(&a, 5)])],
        )
        .await;
        let (state, _) = Box::pin(second.apply::<_, Sha256>(state)).await.unwrap();
        assert_eq!(
            state
                .state()
                .get(&account_key(&b.public_key()).unwrap())
                .await
                .unwrap()
                .map(NonZeroU64::get),
            Some(15)
        );
    });
}

#[test]
fn eligible_recipient_reuses_incoming_credit() {
    deterministic::Runner::default().start(|runtime| async move {
        let [a, b, c] = [101, 102, 103].map(SigningKey::from_seed);
        let state = new_state(
            runtime,
            "reuse",
            vec![(a.public_key(), 100), (b.public_key(), 1)],
        )
        .await;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = epoch(&state, EPOCH, 101, &deposits, &withdrawals);
        let close = verify(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![
                terminal(&context, &a, &[(&b, 20)]),
                terminal(&context, &b, &[(&c, 21)]),
            ],
        )
        .await;
        let (state, _) = Box::pin(close.apply::<_, Sha256>(state)).await.unwrap();
        assert!(
            state
                .state()
                .get(&account_key(&b.public_key()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state
                .state()
                .get(&account_key(&c.public_key()).unwrap())
                .await
                .unwrap()
                .map(NonZeroU64::get),
            Some(21)
        );
    });
}

#[test]
fn close_deletes_balance_and_recredit_recreates_same_owner() {
    deterministic::Runner::default().start(|runtime| async move {
        let [a, b] = [101, 102].map(SigningKey::from_seed);
        let state = new_state(
            runtime,
            "recreate",
            vec![(a.public_key(), 100), (b.public_key(), 40)],
        )
        .await;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(vec![SignedWithdrawal::sign(
            Sha256::hash(&[b"virtual-balances"]),
            state.state().root().digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            99,
            &b,
        )])
        .unwrap();
        let context = epoch(&state, EPOCH, 140, &deposits, &withdrawals);
        let first = verify(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![terminal(&context, &a, &[(&b, 10)])],
        )
        .await;
        let payout_head = first.close().roots.withdrawal_outputs;
        let payout_position = context.predecessor_logs().payouts.operations;
        let (state, _) = Box::pin(first.apply::<_, Sha256>(state)).await.unwrap();
        let output = state.logs().payout_at(payout_position).await.unwrap();
        let (opening, _) = state
            .logs()
            .payout_opening(&payout_head, payout_position, NonZeroU64::MIN)
            .await
            .unwrap();
        let claim = WithdrawalClaim::new(output, opening);
        assert_eq!(claim.verify::<Sha256>(&payout_head).unwrap().amount(), 50);
        assert!(
            state
                .state()
                .get(&account_key(&b.public_key()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        let withdrawals = WithdrawalBatch::empty();
        let next = epoch(&state, EPOCH + 1, 90, &deposits, &withdrawals);
        let second = verify(
            &state,
            &next,
            &deposits,
            &withdrawals,
            vec![terminal(&next, &a, &[(&b, 7)])],
        )
        .await;
        assert!(
            second
                .close()
                .rows
                .iter()
                .all(|row| row.output == SettlementOutput::None)
        );
        let (state, _) = Box::pin(second.apply::<_, Sha256>(state)).await.unwrap();
        assert_eq!(
            state
                .state()
                .opening(b.public_key())
                .await
                .unwrap()
                .verify::<Sha256>(&state.state().root())
                .unwrap()
                .get(),
            7
        );
    });
}

#[test]
fn new_balance_recovery_replays_only_missing_suffix_and_retains_historical_proofs() {
    let ((mut accepted, _first_context), checkpoint) = deterministic::Runner::default()
        .start_and_recover(|runtime| async move {
            let [a, b] = [101, 102].map(SigningKey::from_seed);
            let state = new_state(runtime, "virtual-recovery", vec![(a.public_key(), 100)]).await;
            let genesis = Accepted::genesis(
                &state,
                vec![(account_key(&a.public_key()).unwrap(), NonZeroU64::new(100))],
            );
            let deposits = DepositBatch::empty();
            let withdrawals = WithdrawalBatch::empty();
            let context = epoch(&state, EPOCH, 100, &deposits, &withdrawals);
            let first = verify(
                &state,
                &context,
                &deposits,
                &withdrawals,
                vec![terminal(&context, &a, &[(&b, 20)])],
            )
            .await;
            let first_record = Accepted::prepared(&first);
            let (state, _) = Box::pin(first.apply::<_, Sha256>(state)).await.unwrap();
            let state = Box::pin(state.sync()).await.unwrap();
            let next = epoch(&state, EPOCH + 1, 100, &deposits, &withdrawals);
            let second = verify(
                &state,
                &next,
                &deposits,
                &withdrawals,
                vec![terminal(&next, &b, &[(&a, 5)])],
            )
            .await;
            let second_record = Accepted::prepared(&second);
            (vec![genesis, first_record, second_record], context)
        });
    // The application has retained the next accepted batch, while QMDB contains the first.
    // Removing earlier payloads makes recovery depend only on the missing journal suffix.
    accepted[0].mutations.clear();
    accepted[1].mutations.clear();
    deterministic::Runner::from(checkpoint).start(|runtime| async move {
        let b = SigningKey::from_seed(102).public_key();
        let state = replay_state(runtime, "virtual-recovery", &accepted)
            .await
            .unwrap();
        assert_eq!(*state.state().head(), accepted[2].head);
        for (record, expected) in accepted.iter().zip([None, Some(20), Some(15)]) {
            let root = record.head.root();
            let key = account_key(&b).unwrap();
            let lookup = state
                .state()
                .lookup_at(root, record.head.operations(), &key)
                .await
                .unwrap();
            assert_eq!(
                lookup
                    .resolve::<Sha256>(&root, &key)
                    .unwrap()
                    .map(NonZeroU64::get),
                expected
            );
            assert_eq!(*state.state().head(), accepted[2].head);
        }
        let start = accepted[0].logs.activity.operations;
        let epoch = Epoch::at(
            state.logs(),
            EPOCH,
            crate::bajillion::transition::ActivityRange {
                start,
                end: start + accepted[1].activity.rows().len() as u64,
                head: accepted[1].logs.activity,
            },
        )
        .await
        .unwrap();
        let lookup = epoch.account_lookup(state.logs(), &b).await.unwrap();
        assert!(matches!(lookup, AccountLookup::Present(_)));
    });
}

#[test]
fn receiving_balance_creation_respects_live_account_limit() {
    deterministic::Runner::default().start(|runtime| async move {
        let [a, b] = [101, 102].map(SigningKey::from_seed);
        let state = new_state(runtime, "virtual-limit", vec![(a.public_key(), 100)]).await;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"virtual-balances"]),
            EPOCH,
            SigningKey::from_seed(OPERATOR_SEED).public_key(),
            &deposits,
            &withdrawals,
            100,
            98,
            99,
            CloseLimits::new(1, 2, 0, 1, 1, 100, 0, 0),
            Sha256::hash(&[b"committee"]),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &state,
            &deposits,
            &withdrawals,
            Floors {
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let before = *state.state().head();
        let rejected = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![terminal(&context, &a, &[(&b, 20)])],
            &Sequential,
        )
        .await;
        assert!(matches!(rejected, Err(CloseError::CloseLimit)));
        assert_eq!(*state.state().head(), before);
        let prepared = verify(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![terminal(&context, &a, &[(&b, 100)])],
        )
        .await;
        let (state, _) = Box::pin(prepared.apply::<_, Sha256>(state)).await.unwrap();
        assert_eq!(state.state().live_accounts(), 1);
        assert!(
            state
                .state()
                .get(&account_key(&a.public_key()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state
                .state()
                .opening(b.public_key())
                .await
                .unwrap()
                .verify::<Sha256>(&state.state().root())
                .unwrap()
                .get(),
            100
        );
    });
}
