use super::*;
use crate::bajillion::state::SettlementOutput;

async fn epoch(
    state: &TestState,
    epoch: u64,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, ShaDigest>,
) -> CloseContext<VerifyingKey, ShaDigest> {
    EpochContext::new::<Sha256>(
        Sha256::hash(&[b"virtual-balances"]),
        epoch,
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        deposits,
        withdrawals,
        state.liability(),
        98,
        99,
        CloseLimits::protocol_maximum(),
        Sha256::hash(&[b"committee"]),
    )
    .unwrap()
    .bind::<Sha256, _, _>(state, deposits, withdrawals)
    .await
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
        let context = epoch(&state, EPOCH, &deposits, &withdrawals).await;
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
        assert!(prepared.close().withdrawal_evidence().0.is_empty());
        assert_eq!(prepared.state().head().liability(), 140);
        let (state, close) = prepared.apply::<_, Sha256>(state).await.unwrap();
        for (key, balance) in [(&a, 70), (&b, 47), (&c, 15), (&d, 8)] {
            assert_eq!(
                state
                    .get(&account_key(&key.public_key()).unwrap())
                    .await
                    .unwrap()
                    .map(NonZeroU64::get),
                Some(balance)
            );
        }
        assert_eq!(state.live_accounts(), 4);
        let restored =
            Close::decode_evidence::<Sha256>(close.encode_evidence(), &context, &close.header)
                .unwrap();
        assert!(
            restored
                .rows
                .iter()
                .all(|row| row.output == SettlementOutput::None)
        );
        assert_eq!(restored.roots, close.roots);
    });
}

#[test]
fn absent_recipient_cannot_originate_until_successor_epoch() {
    deterministic::Runner::default().start(|runtime| async move {
        let [a, b] = [101, 102].map(SigningKey::from_seed);
        let state = new_state(runtime, "eligibility", vec![(a.public_key(), 100)]).await;
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = epoch(&state, EPOCH, &deposits, &withdrawals).await;
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
        let (state, _) = first.apply::<_, Sha256>(state).await.unwrap();
        assert_eq!(
            state
                .get(&account_key(&b.public_key()).unwrap())
                .await
                .unwrap()
                .map(NonZeroU64::get),
            Some(20)
        );
        let next = epoch(&state, EPOCH + 1, &deposits, &withdrawals).await;
        let second = verify(
            &state,
            &next,
            &deposits,
            &withdrawals,
            vec![terminal(&next, &b, &[(&a, 5)])],
        )
        .await;
        let (state, _) = second.apply::<_, Sha256>(state).await.unwrap();
        assert_eq!(
            state
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
        let context = epoch(&state, EPOCH, &deposits, &withdrawals).await;
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
        let (state, _) = close.apply::<_, Sha256>(state).await.unwrap();
        assert!(
            state
                .get(&account_key(&b.public_key()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state
                .get(&account_key(&c.public_key()).unwrap())
                .await
                .unwrap()
                .map(NonZeroU64::get),
            Some(21)
        );
        assert_eq!(state.liability(), 101);
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
            state.root().digest,
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            99,
            &b,
        )])
        .unwrap();
        let context = epoch(&state, EPOCH, &deposits, &withdrawals).await;
        let first = verify(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![terminal(&context, &a, &[(&b, 10)])],
        )
        .await;
        let claim = first.withdrawal_claim(&b.public_key()).unwrap();
        assert_eq!(
            claim
                .verify::<Sha256>(&first.close().roots.withdrawal_outputs)
                .unwrap()
                .amount(),
            50
        );
        let (state, _) = first.apply::<_, Sha256>(state).await.unwrap();
        assert!(
            state
                .get(&account_key(&b.public_key()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        let withdrawals = WithdrawalBatch::empty();
        let next = epoch(&state, EPOCH + 1, &deposits, &withdrawals).await;
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
        let (state, _) = second.apply::<_, Sha256>(state).await.unwrap();
        assert_eq!(
            state
                .opening(b.public_key())
                .await
                .unwrap()
                .verify::<Sha256>(&state.root())
                .unwrap()
                .get(),
            7
        );
        assert_eq!(state.liability(), 90);
    });
}

#[test]
fn new_balance_recovery_replays_only_missing_suffix_and_retains_historical_proofs() {
    let ((mut accepted, first_context, first_header, evidence), checkpoint) =
        deterministic::Runner::default().start_and_recover(|runtime| async move {
            let [a, b] = [101, 102].map(SigningKey::from_seed);
            let state = new_state(runtime, "virtual-recovery", vec![(a.public_key(), 100)]).await;
            let genesis = Accepted {
                head: *state.head(),
                mutations: vec![(account_key(&a.public_key()).unwrap(), NonZeroU64::new(100))],
            };
            let deposits = DepositBatch::empty();
            let withdrawals = WithdrawalBatch::empty();
            let context = epoch(&state, EPOCH, &deposits, &withdrawals).await;
            let first = verify(
                &state,
                &context,
                &deposits,
                &withdrawals,
                vec![terminal(&context, &a, &[(&b, 20)])],
            )
            .await;
            let first_record = Accepted {
                head: *first.state().head(),
                mutations: first.state().mutations().to_vec(),
            };
            let header = first.close().header;
            let evidence = first.close().encode_evidence();
            let (state, _) = first.apply::<_, Sha256>(state).await.unwrap();
            let state = state.commit().await.unwrap();
            let next = epoch(&state, EPOCH + 1, &deposits, &withdrawals).await;
            let second = verify(
                &state,
                &next,
                &deposits,
                &withdrawals,
                vec![terminal(&next, &b, &[(&a, 5)])],
            )
            .await;
            let second_record = Accepted {
                head: *second.state().head(),
                mutations: second.state().mutations().to_vec(),
            };
            (
                vec![genesis, first_record, second_record],
                context,
                header,
                evidence,
            )
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
        assert_eq!(*state.head(), accepted[2].head);
        assert_eq!(state.liability(), 100);
        for (record, expected) in accepted.iter().zip([None, Some(20), Some(15)]) {
            let root = record.head.root();
            let key = account_key(&b).unwrap();
            let lookup = state
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
            assert_eq!(*state.head(), accepted[2].head);
        }
        let close =
            Close::decode_evidence::<Sha256>(evidence, &first_context, &first_header).unwrap();
        let lookup = crate::bajillion::serve::Index::new(&close)
            .account_lookup::<Sha256>(&b)
            .unwrap();
        assert!(matches!(lookup, AccountLookup::Present(_)));
        assert!(close.withdrawal_evidence().0.is_empty());
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
            state.liability(),
            98,
            99,
            CloseLimits::new(1, 2, 0, 1, 1, 100, 0, 0),
            Sha256::hash(&[b"committee"]),
        )
        .unwrap()
        .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
        .await
        .unwrap();
        let before = *state.head();
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
        assert_eq!(*state.head(), before);
        let prepared = verify(
            &state,
            &context,
            &deposits,
            &withdrawals,
            vec![terminal(&context, &a, &[(&b, 100)])],
        )
        .await;
        let (state, _) = prepared.apply::<_, Sha256>(state).await.unwrap();
        assert_eq!(state.live_accounts(), 1);
        assert!(
            state
                .get(&account_key(&a.public_key()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state
                .opening(b.public_key())
                .await
                .unwrap()
                .verify::<Sha256>(&state.root())
                .unwrap()
                .get(),
            100
        );
    });
}
