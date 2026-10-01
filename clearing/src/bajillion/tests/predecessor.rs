//! Terminal payer signatures bind the payer's vector root in the preceding admitted close.

use super::*;
use crate::bajillion::{
    challenge::HigherEntryLookup,
    transition::{TERMINAL_BATCH_HASH_NAMESPACE, TERMINAL_BATCH_SIGNATURE_NAMESPACE},
    vector::OutTipLookup,
};
use commonware_codec::FixedSize;

// Funds every key and sorts the keys by public key, so an index names a row position.
fn keys(count: u64) -> Vec<SigningKey> {
    let mut keys = (0..count)
        .map(|index| SigningKey::from_seed(ACCOUNT_SEED_START + index))
        .collect::<Vec<_>>();
    keys.sort_by_key(SigningKey::public_key);
    keys
}

async fn genesis(runtime: deterministic::Context, prefix: &str, keys: &[SigningKey]) -> TestState {
    new_state(
        runtime,
        prefix,
        keys.iter()
            .map(|key| (key.public_key(), OPENING_BALANCE))
            .collect(),
    )
    .await
}

const fn liability(keys: &[SigningKey]) -> u64 {
    keys.len() as u64 * OPENING_BALANCE
}

// Binds an epoch without deposits or withdrawals to `state` and the predecessor close's rows.
fn context(
    state: &TestState,
    epoch: u64,
    rows: Range<u64>,
    liability: u64,
) -> CloseContext<VerifyingKey, ShaDigest> {
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    EpochContext::new::<Sha256>(
        Sha256::hash(&[b"predecessor-deployment"]),
        epoch,
        SigningKey::from_seed(OPERATOR_SEED).public_key(),
        &deposits,
        &withdrawals,
        CloseLimits::protocol_maximum(),
        Sha256::hash(&[b"predecessor-committee"]),
    )
    .unwrap()
    .bind::<Sha256, _, _>(
        state,
        &deposits,
        &withdrawals,
        rows,
        liability,
        98,
        99,
        Floors {
            activity: 0,
            payouts: 0,
        },
    )
    .unwrap()
}

fn operator() -> SigningKey {
    SigningKey::from_seed(OPERATOR_SEED)
}

fn vector(
    context: &CloseContext<VerifyingKey, ShaDigest>,
    payer: &SigningKey,
    payments: &[(&SigningKey, u64)],
) -> OutVector<VerifyingKey> {
    let mut entries = payments
        .iter()
        .map(|(recipient, amount)| OutEntry {
            recipient: recipient.public_key(),
            cumulative: *amount,
            count: 1,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.recipient.cmp(&b.recipient));
    OutVector::new(context.payment().epoch(), payer.public_key(), entries).unwrap()
}

fn body(
    context: &CloseContext<VerifyingKey, ShaDigest>,
    payer: &SigningKey,
    seq: u64,
    vector: &OutVector<VerifyingKey>,
) -> VectorSendBody<VerifyingKey, ShaDigest> {
    VectorSendBody::new(
        context.payment(),
        payer.public_key(),
        seq,
        vector.totals().unwrap().0,
        vector.root::<Sha256, ShaDigest>().unwrap(),
    )
}

// Signs `payer`'s epoch-cumulative vector at `seq` over `predecessor`.
fn terminal(
    context: &CloseContext<VerifyingKey, ShaDigest>,
    predecessor: VectorRoot<ShaDigest>,
    payer: &SigningKey,
    seq: u64,
    payments: &[(&SigningKey, u64)],
) -> Terminal<VerifyingKey, ShaDigest> {
    let vector = vector(context, payer, payments);
    let authorization =
        SendAuthorization::sign(body(context, payer, seq, &vector), predecessor, payer);
    Terminal {
        authorization,
        vector,
    }
}

async fn prepare(
    state: &TestState,
    context: &CloseContext<VerifyingKey, ShaDigest>,
    mut terminals: Vec<Terminal<VerifyingKey, ShaDigest>>,
) -> PreparedClose<VerifyingKey, ShaDigest> {
    terminals.sort_by(|a, b| {
        a.authorization
            .body()
            .payer()
            .cmp(b.authorization.body().payer())
    });
    prepare_close_with_strategy::<Sha256, _, _, _, _>(
        state,
        context,
        &operator(),
        &DepositBatch::empty(),
        &WithdrawalBatch::empty(),
        terminals,
        &Sequential,
    )
    .await
    .unwrap()
}

// Checks the shared dealing the way every validator does.
async fn validate(
    state: &TestState,
    context: &CloseContext<VerifyingKey, ShaDigest>,
    prepared: &PreparedClose<VerifyingKey, ShaDigest>,
) -> Result<PreparedClose<VerifyingKey, ShaDigest>, CloseError> {
    let dealing = posted::decode(prepared.encoded().clone(), context)?;
    validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
        state,
        context,
        &DepositBatch::empty(),
        &WithdrawalBatch::empty(),
        dealing,
        &mut TestRng::new(11),
        &Sequential,
    )
    .await
}

async fn apply(
    state: TestState,
    prepared: PreparedClose<VerifyingKey, ShaDigest>,
) -> (TestState, Close<VerifyingKey, ShaDigest>) {
    Box::pin(prepared.apply::<_, Sha256>(state)).await.unwrap()
}

const fn is_invalid_payer(
    result: &Result<PreparedClose<VerifyingKey, ShaDigest>, CloseError>,
) -> bool {
    matches!(
        result,
        Err(CloseError::Ack(AckError::InvalidPayerSignature))
    )
}

/// A lying operator reports the payer's endpoint before the original body but carries the
/// original in `x`. The payment re-signed into `x+1` against the reported root cannot be
/// carried there. When `x` really ends at the reported endpoint, the same re-sign validates.
/// The payer takes the first predecessor row and then the last.
#[test]
fn resign_is_rejected_when_predecessor_carries_original() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = keys(3);
        let placements = [
            (&keys[0], &keys[1], &keys[2]),
            (&keys[2], &keys[0], &keys[1]),
        ];
        for (index, ((payer, first, second), carried)) in placements
            .into_iter()
            .flat_map(|placement| [(placement, true), (placement, false)])
            .enumerate()
        {
            // Epoch x: the reported endpoint pays `first`, and the original also pays `second`.
            let label = if carried { "lying" } else { "control" };
            let state = genesis(
                runtime.child(label).with_attribute("placement", index),
                &format!("{label}{index}"),
                &keys,
            )
            .await;
            let current = context(&state, EPOCH, 0..0, liability(&keys));
            let reported = terminal(&current, empty_root(), payer, 0, &[(first, 1)]);
            let original = terminal(&current, empty_root(), payer, 1, &[(first, 1), (second, 2)]);
            let root = reported.authorization.body().send_root();
            assert_ne!(root, empty_root());
            let prepared = prepare(
                &state,
                &current,
                vec![if carried { original } else { reported }],
            )
            .await;
            validate(&state, &current, &prepared).await.unwrap();
            let rows = rows(&current, prepared.close());
            let (state, _) = apply(state, prepared).await;

            // Epoch x+1: the payer re-signs the payment to `second` against the reported root.
            let next = context(&state, EPOCH + 1, rows, liability(&keys));
            let resigned = terminal(&next, root, payer, 0, &[(second, 2)]);
            let prepared = prepare(&state, &next, vec![resigned]).await;
            let result = validate(&state, &next, &prepared).await;
            if carried {
                assert!(
                    is_invalid_payer(&result),
                    "a carried original rejects the re-sign"
                );
            } else {
                result.unwrap();
            }
        }
    });
}

/// A payer absent from the predecessor close, a payer with only credits there, and every payer
/// in the first epoch sign the empty vector root. A terminal at sequence zero still leaves a
/// nonempty root that its payer must sign.
#[test]
fn predecessor_is_empty_root_without_outgoing_terminal() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = keys(4);
        let (sender, credited, absent, recipient) = (&keys[0], &keys[1], &keys[2], &keys[3]);
        let state = genesis(runtime, "empty-root", &keys).await;

        // The first epoch has no predecessor close, so only the empty root verifies.
        let first = context(&state, EPOCH, 0..0, liability(&keys));
        assert!(first.predecessor_range().is_none());
        let payment = vector(&first, sender, &[(credited, 3)]);
        let unbound = terminal(
            &first,
            payment.root::<Sha256, ShaDigest>().unwrap(),
            sender,
            0,
            &[(credited, 3)],
        );
        let prepared = prepare(&state, &first, vec![unbound]).await;
        assert!(is_invalid_payer(&validate(&state, &first, &prepared).await));
        let bound = terminal(&first, empty_root(), sender, 0, &[(credited, 3)]);
        let prepared = prepare(&state, &first, vec![bound]).await;
        validate(&state, &first, &prepared).await.unwrap();
        let rows = rows(&first, prepared.close());
        let (state, close) = apply(state, prepared).await;

        // The sequence-zero terminal leaves a nonempty root, the credited row keeps the empty
        // root, and the absent payer has no row.
        let root = predecessor(&close, &sender.public_key());
        assert_ne!(root, empty_root());
        assert_eq!(root, payment.root::<Sha256, ShaDigest>().unwrap());
        assert!(
            close
                .rows
                .iter()
                .any(|row| row.account == credited.public_key() && row.outgoing.is_none())
        );
        assert!(
            close
                .rows
                .iter()
                .all(|row| row.account != absent.public_key())
        );

        // Epoch x+1 validates only when every payer signs exactly those roots.
        let next = context(&state, EPOCH + 1, rows, liability(&keys));
        let signed = [
            (sender, root),
            (credited, empty_root()),
            (absent, empty_root()),
        ];
        let terminals = |wrong: Option<usize>| {
            signed
                .iter()
                .enumerate()
                .map(|(index, (payer, predecessor))| {
                    let predecessor = match wrong {
                        Some(wrong) if wrong == index && *predecessor == root => empty_root(),
                        Some(wrong) if wrong == index => root,
                        _ => *predecessor,
                    };
                    terminal(&next, predecessor, payer, 0, &[(recipient, 1)])
                })
                .collect::<Vec<_>>()
        };
        let prepared = prepare(&state, &next, terminals(None)).await;
        validate(&state, &next, &prepared).await.unwrap();
        for wrong in 0..signed.len() {
            let prepared = prepare(&state, &next, terminals(Some(wrong))).await;
            assert!(
                is_invalid_payer(&validate(&state, &next, &prepared).await),
                "payer {wrong} signed another predecessor"
            );
        }
    });
}

/// Galloping lookups agree with a linear scan of the predecessor rows for payers before the
/// first row, after the last row, between rows, and on payer and credit-only rows. After a
/// predecessor close with no rows, every payer reads the empty root.
#[test]
fn predecessor_lookup_matches_linear_scan() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = keys(24);
        let state = genesis(runtime, "lookup", &keys).await;

        // Epoch x: rows are four adjacent pairs separated by gaps. The first and last rows pay,
        // and every pair has one payer row and one credit-only row.
        let first = context(&state, EPOCH, 0..0, liability(&keys));
        let terminals = [(4, 5), (8, 9), (13, 12), (17, 16)]
            .map(|(payer, recipient)| {
                terminal(
                    &first,
                    empty_root(),
                    &keys[payer],
                    0,
                    &[(&keys[recipient], payer as u64)],
                )
            })
            .to_vec();
        let prepared = prepare(&state, &first, terminals).await;
        let range = rows(&first, prepared.close());
        assert_eq!(range.end - range.start, 8);
        let (state, close) = apply(state, prepared).await;

        // Epoch x+1: each payer set reads exactly the roots a linear scan finds.
        let next = context(&state, EPOCH + 1, range, liability(&keys));
        for payers in [
            (0..24).collect::<Vec<usize>>(),
            vec![0, 1, 2, 3],
            vec![18, 23],
            vec![6, 7, 10, 11, 14, 15],
            vec![4, 5, 12, 13, 16, 17],
            vec![0, 17, 23],
            vec![4],
            vec![17],
        ] {
            let terminals = payers
                .iter()
                .map(|index| {
                    let payer = &keys[*index];
                    terminal(
                        &next,
                        predecessor(&close, &payer.public_key()),
                        payer,
                        0,
                        &[(&keys[(index + 1) % keys.len()], 1)],
                    )
                })
                .collect();
            let prepared = prepare(&state, &next, terminals).await;
            let derived = prepared
                .close()
                .rows
                .iter()
                .filter_map(|row| row.outgoing.as_ref())
                .map(|send| (send.body().payer().clone(), send.predecessor()))
                .collect::<Vec<_>>();
            assert_eq!(derived.len(), payers.len());
            for (payer, root) in derived {
                assert_eq!(root, predecessor(&close, &payer), "payers {payers:?}");
            }
            validate(&state, &next, &prepared).await.unwrap();
        }

        // Epoch x+2 follows a close with no rows, so every payer reads the empty root.
        let empty = prepare(&state, &next, Vec::new()).await;
        let after_rows = rows(&next, empty.close());
        let (state, _) = apply(state, empty).await;
        let after = context(&state, EPOCH + 2, after_rows, liability(&keys));
        assert!(after.predecessor_range().is_none());
        let terminals = [4, 5, 17, 23]
            .map(|index| {
                terminal(
                    &after,
                    empty_root(),
                    &keys[index],
                    0,
                    &[(&keys[(index + 1) % keys.len()], 1)],
                )
            })
            .to_vec();
        let prepared = prepare(&state, &after, terminals).await;
        assert!(
            prepared
                .close()
                .rows
                .iter()
                .filter_map(|row| row.outgoing.as_ref())
                .all(|send| send.predecessor() == empty_root())
        );
        validate(&state, &after, &prepared).await.unwrap();
    });
}

/// The batch signature binds the epoch context, terminal body, and derived predecessor.
#[test]
fn batch_signature_covers_context_body_and_predecessor() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = keys(2);
        let (payer, recipient) = (&keys[0], &keys[1]);
        let state = genesis(runtime, "batch-signature", &keys).await;

        let first = context(&state, EPOCH, 0..0, liability(&keys));
        let prepared = prepare(
            &state,
            &first,
            vec![terminal(&first, empty_root(), payer, 0, &[(recipient, 1)])],
        )
        .await;
        let rows = rows(&first, prepared.close());
        let (state, close) = apply(state, prepared).await;
        let root = predecessor(&close, &payer.public_key());
        assert_ne!(root, empty_root());

        let next = context(&state, EPOCH + 1, rows, liability(&keys));
        let signed = terminal(&next, root, payer, 0, &[(recipient, 2)]);
        signed.authorization.verify(next.payment()).unwrap();
        let body = signed.authorization.body();
        let epoch = next.epoch_context().encode();
        let complete = body.message(&root);
        let mut canonical = epoch.to_vec();
        canonical.extend_from_slice(&complete);
        let mut omitted_predecessor = epoch.to_vec();
        omitted_predecessor.extend_from_slice(&body.encode());
        let mut wrong_predecessor = epoch.to_vec();
        wrong_predecessor.extend_from_slice(&body.message(&empty_root()));
        let mut wrong_context = canonical.clone();
        wrong_context[0] ^= 1;
        let mut wrong_body = canonical.clone();
        wrong_body[epoch.len()] ^= 1;
        let prepared = prepare(&state, &next, vec![signed]).await;
        let wire = prepared.encoded();
        let signature_start =
            wire.len() - <VerifyingKey as commonware_cryptography::Verifier>::Signature::SIZE;
        for (message, valid) in [
            (canonical, true),
            (complete.to_vec(), false),
            (wrong_context, false),
            (wrong_body, false),
            (omitted_predecessor, false),
            (wrong_predecessor, false),
        ] {
            let digest = Sha256::hash(&[TERMINAL_BATCH_HASH_NAMESPACE, &message]);
            let signature = operator().sign(TERMINAL_BATCH_SIGNATURE_NAMESPACE, digest.as_ref());
            let mut tampered = wire[..signature_start].to_vec();
            tampered.extend_from_slice(&signature.encode());
            let dealing = posted::decode(tampered.into(), &next).unwrap();
            let result = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                &state,
                &next,
                &DepositBatch::empty(),
                &WithdrawalBatch::empty(),
                dealing,
                &mut TestRng::new(11),
                &Sequential,
            )
            .await;
            if valid {
                let validated = result.unwrap();
                assert_eq!(validated.close().header, prepared.close().header);
            } else {
                assert!(matches!(
                    result,
                    Err(CloseError::Ack(AckError::InvalidOperatorSignature))
                ));
            }
        }
    });
}

/// The operator countersigns an `x+1` body bound to a root that `x` contradicts. No `x+1` close
/// can carry it, so the admitted close reports a lower debit and entry for the payer, whether
/// the payer is absent or only credited there, and the receipt proves both mismatches.
#[test]
fn uncarryable_acknowledgment_proves_debit_and_entry_mismatch() {
    deterministic::Runner::default().start(|runtime| async move {
        let keys = keys(3);
        let (payer, recipient, other) = (&keys[0], &keys[1], &keys[2]);
        let operator_key = SigningKey::from_seed(OPERATOR_SEED);
        for credited in [false, true] {
            // Epoch x leaves the payer a nonempty root.
            let prefix = if credited { "credited" } else { "uncarried" };
            let state = genesis(runtime.child(prefix), prefix, &keys).await;
            let first = context(&state, EPOCH, 0..0, liability(&keys));
            let prepared = prepare(
                &state,
                &first,
                vec![terminal(&first, empty_root(), payer, 0, &[(recipient, 1)])],
            )
            .await;
            let rows = rows(&first, prepared.close());
            let (state, close) = apply(state, prepared).await;
            assert_ne!(predecessor(&close, &payer.public_key()), empty_root());

            // The operator receipts an x+1 body bound to the empty root, and the receipt verifies
            // with its carried predecessor.
            let next = context(&state, EPOCH + 1, rows, liability(&keys));
            let payment = vector(&next, payer, &[(recipient, 2)]);
            let ack = VectorAck::sign_by_authorities(
                body(&next, payer, 0, &payment),
                empty_root(),
                payer,
                &operator_key,
            );
            let OutTipLookup::Present {
                cumulative,
                count,
                opening,
            } = payment
                .lookup::<Sha256, ShaDigest>(&recipient.public_key())
                .unwrap()
            else {
                panic!("the acknowledged vector credits the recipient");
            };
            let receipt = EntryReceipt {
                ack: ack.clone(),
                recipient: recipient.public_key(),
                cumulative,
                count,
                opening: opening.clone(),
            };
            receipt.verify::<Sha256>(next.payment()).unwrap();

            // No x+1 close can carry the acknowledged body.
            let authorization = SendAuthorization::from_raw_unchecked(
                ack.body().clone(),
                ack.predecessor(),
                ack.payer_signature().clone(),
            );
            let carried = Terminal {
                authorization,
                vector: payment.clone(),
            };
            let prepared = prepare(&state, &next, vec![carried]).await;
            assert!(is_invalid_payer(&validate(&state, &next, &prepared).await));

            // The admitted x+1 close omits the payer or only credits it.
            let terminals = if credited {
                vec![terminal(
                    &next,
                    predecessor(&close, &other.public_key()),
                    other,
                    0,
                    &[(payer, 1)],
                )]
            } else {
                Vec::new()
            };
            let prepared = prepare(&state, &next, terminals).await;
            let admitted = validate(&state, &next, &prepared).await.unwrap();
            let range = admitted.close().roots.activity_range(&next).unwrap();
            let (state, admitted) = apply(state, admitted).await;
            let epoch = Epoch::at(state.logs(), EPOCH + 1, range).await.unwrap();

            // The receipt proves both the debit and the entry mismatch.
            let lookup = epoch
                .account_lookup(state.logs(), &payer.public_key())
                .await
                .unwrap();
            assert_eq!(
                lookup
                    .resolve::<Sha256>(&range, &payer.public_key())
                    .unwrap()
                    .0,
                0
            );
            assert_eq!(matches!(lookup, AccountLookup::Present(_)), credited);
            let sender = epoch
                .higher_entry_lookup(state.logs(), &payer.public_key(), &recipient.public_key())
                .await
                .unwrap();
            assert_eq!(
                matches!(sender, HigherEntryLookup::Present { .. }),
                credited
            );
            for (challenge, kind) in [
                (
                    Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(&ack)),
                        payer: Box::new(lookup),
                    },
                    ChallengeKind::HigherAckDebit,
                ),
                (
                    Challenge::HigherAckEntry {
                        entry: Box::new(EntryWitness {
                            ack: AckWitness::from_ack(&ack),
                            recipient: recipient.public_key(),
                            cumulative,
                            count,
                            opening: opening.clone(),
                        }),
                        sender: Box::new(sender),
                    },
                    ChallengeKind::HigherAckEntry,
                ),
            ] {
                assert_eq!(
                    adjudicate::<Sha256, _, _>(
                        &next,
                        &admitted.header,
                        &admitted.roots,
                        admitted.withdrawal_total,
                        &challenge,
                    )
                    .unwrap(),
                    Verdict::Proven(kind)
                );
            }
        }
    });
}

/// A witness carries the signed predecessor through its codec. Replacing the predecessor breaks
/// both signatures.
#[test]
fn witness_predecessor_is_signed() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 4, 4, 2, 1).await;
        let ack = &fixture.acks[0];

        // The projected witness reconstructs the acknowledged body under both signatures.
        let witness = AckWitness::from_ack(ack);
        assert_eq!(witness.predecessor, ack.predecessor());
        assert_eq!(&witness.reconstruct(&fixture.context).unwrap(), ack.body());
        assert_eq!(
            &witness.reconstruct_operator(&fixture.context).unwrap(),
            ack.body()
        );
        let encoded = witness.encode();
        assert_eq!(encoded.len(), AckWitness::<VerifyingKey, ShaDigest>::SIZE);
        assert_eq!(
            AckWitness::<VerifyingKey, ShaDigest>::decode(encoded).unwrap(),
            witness
        );

        // Another predecessor authenticates under neither signature.
        let mut changed = witness;
        changed.predecessor = VectorRoot {
            digest: Sha256::hash(&[b"other-predecessor"]),
        };
        assert!(matches!(
            changed.reconstruct(&fixture.context),
            Err(ChallengeError::Ack(AckError::InvalidPayerSignature))
        ));
        assert!(matches!(
            changed.reconstruct_operator(&fixture.context),
            Err(ChallengeError::Ack(AckError::InvalidOperatorSignature))
        ));
    });
}

/// Two operator countersignatures at one payer sequence number over the same body but different
/// predecessors prove a fork. Identical messages do not.
#[test]
fn fork_on_predecessor_is_proven() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 4, 4, 2, 1).await;
        let close = fixture.prepared.close();
        let private = &fixture.accounts[0].1;
        let body = fixture.acks[0].body().clone();
        let forked = VectorRoot {
            digest: Sha256::hash(&[b"forked-predecessor"]),
        };
        let left =
            VectorAck::sign_by_authorities(body.clone(), empty_root(), private, &fixture.operator);
        let right = VectorAck::sign_by_authorities(body, forked, private, &fixture.operator);
        for (other, verdict) in [
            (&right, Verdict::Proven(ChallengeKind::AckFork)),
            (&left, Verdict::NoContradiction),
        ] {
            assert_eq!(
                adjudicate::<Sha256, _, _>(
                    &fixture.context,
                    &close.header,
                    &close.roots,
                    close.withdrawal_total,
                    &Challenge::AckFork {
                        left: Box::new(AckWitness::from_ack(&left)),
                        right: Box::new(AckWitness::from_ack(other)),
                    },
                )
                .unwrap(),
                verdict
            );
        }
    });
}
