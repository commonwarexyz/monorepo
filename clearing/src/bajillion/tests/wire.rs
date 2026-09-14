use super::*;
use crate::bajillion::transition::prepare_dealing;
use commonware_codec::{FixedSize as _, Read as _, ReadExt as _, varint::UInt};
use commonware_parallel::Rayon;
use std::sync::OnceLock;

fn decode_with_each_strategy(
    wire: Bytes,
    context: &CloseContext<VerifyingKey, ShaDigest>,
) -> Result<posted::Dealing<VerifyingKey>, commonware_codec::Error> {
    static STRATEGY: OnceLock<Rayon> = OnceLock::new();
    let parallel = STRATEGY.get_or_init(|| Rayon::new(NZUsize!(4)).unwrap());
    let serial = posted::decode(wire.clone(), context);
    let concurrent = posted::decode_with_strategy(wire, context, parallel);
    assert_eq!(serial.is_ok(), concurrent.is_ok());
    if let (Ok(serial), Ok(concurrent)) = (&serial, &concurrent) {
        assert_eq!(serial.aggregate, concurrent.aggregate);
        assert_eq!(serial.rows.len(), concurrent.rows.len());
        for (serial, concurrent) in serial.rows.iter().zip(&concurrent.rows) {
            assert_eq!(serial.account, concurrent.account);
            assert_eq!(serial.outgoing, concurrent.outgoing);
            assert_eq!(serial.vector, concurrent.vector);
        }
    }
    concurrent
}

struct Offsets {
    accounts: Vec<usize>,
    outgoing: Vec<usize>,
    vectors: Vec<usize>,
    entries: Vec<Vec<[usize; 3]>>,
    aggregate: usize,
}

#[test]
fn empty_dealing_contains_only_activity_and_operator_acceptance() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 4, 0, 4, 1).await;
        assert_eq!(fixture.prepared.encoded().as_ref(), &[0, 0]);
    });
}

#[test]
fn validators_derive_the_commitment_from_their_registered_predecessor() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("fixture"), 4, 4, 2, 1).await;
        let dealing = prepare_dealing::<Sha256, _, _>(
            fixture.context.epoch_context(),
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.terminals.clone(),
        )
        .unwrap();
        assert_eq!(dealing.encoded(), fixture.prepared.encoded());

        let balances = fixture
            .accounts
            .iter()
            .enumerate()
            .map(|(index, (key, _))| {
                let balance = match index {
                    0 => OPENING_BALANCE + 1,
                    1 => OPENING_BALANCE - 1,
                    _ => OPENING_BALANCE,
                };
                (key.clone(), balance)
            })
            .collect();
        let state = new_state(runtime, "other-predecessor", balances).await;
        let context = fixture
            .context
            .epoch_context()
            .clone()
            .bind::<Sha256, _, _>(&state, &fixture.deposits, &fixture.withdrawals)
            .unwrap();
        let original = state.root();
        let candidate = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
            &state,
            &context,
            &fixture.operator_bls,
            &fixture.deposits,
            &fixture.withdrawals,
            dealing,
            &mut TestRng::new(5),
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(state.root(), original);
        assert_ne!(
            candidate.close().roots.successor,
            fixture.prepared.close().roots.successor
        );
        assert_ne!(candidate.close().header, fixture.prepared.close().header);
        assert_eq!(
            candidate.close().roots.change,
            fixture.prepared.close().roots.change
        );
        assert!(candidate.close().header.verify::<Sha256, VerifyingKey>(
            &context,
            &candidate.close().roots,
            candidate.close().withdrawal_total,
        ));
    });
}

#[test]
fn preparing_dealing_enforces_the_sender_entry_limit() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 4, 1, 2, 2).await;
        for limit in [1, 2] {
            let context = EpochContext::new::<Sha256>(
                *fixture.context.deployment(),
                EPOCH,
                fixture.operator.public_key(),
                &fixture.deposits,
                &fixture.withdrawals,
                fixture.state.liability(),
                98,
                99,
                CloseLimits::new(4, 4, 0, limit, 4, 100, 0, 0),
                *fixture.context.committee(),
            )
            .unwrap();
            let mut terminal = fixture.terminals[0].clone();
            let body = VectorSendBody::new(
                context.payment(),
                fixture.accounts[0].0.clone(),
                0,
                2,
                terminal.vector.root::<Sha256, ShaDigest>().unwrap(),
            );
            let ack =
                VectorAck::sign_by_authorities(body, &fixture.accounts[0].1, &fixture.operator);
            terminal.authorization = SendAuthorization::from_raw_unchecked(
                ack.body().clone(),
                ack.payer_signature().clone(),
            );
            terminal.operator_signature = bls_ack(&fixture.operator_bls_private, ack.body());
            let result = prepare_dealing::<Sha256, _, _>(
                &context,
                &fixture.deposits,
                &fixture.withdrawals,
                vec![terminal],
            );
            if limit == 1 {
                assert!(matches!(result, Err(CloseError::CloseLimit)));
            } else {
                assert!(result.is_ok());
            }
        }
    });
}

fn offsets(wire: &Bytes) -> Offsets {
    let mut reader = wire.clone();
    let position = |reader: &Bytes| wire.len() - reader.len();
    let count = usize::read_cfg(&mut reader, &(0..=wire.len()).into()).unwrap();
    let mut accounts = Vec::new();
    let mut outgoing = Vec::new();
    for _ in 0..count {
        accounts.push(position(&reader));
        VerifyingKey::read(&mut reader).unwrap();
    }
    for _ in 0..count {
        outgoing.push(position(&reader));
        if u8::read(&mut reader).unwrap() == 1 {
            UInt::<u64>::read(&mut reader).unwrap();
            <VerifyingKey as commonware_cryptography::Verifier>::Signature::read(&mut reader)
                .unwrap();
        }
    }
    let mut vectors = Vec::new();
    let mut entries = Vec::new();
    for _ in 0..count {
        vectors.push(position(&reader));
        let count = usize::read_cfg(&mut reader, &(0..=100).into()).unwrap();
        let mut vector = Vec::new();
        for _ in 0..count {
            let index = position(&reader);
            UInt::<u64>::read(&mut reader).unwrap();
            let amount = position(&reader);
            UInt::<u64>::read(&mut reader).unwrap();
            let count = position(&reader);
            UInt::<u64>::read(&mut reader).unwrap();
            vector.push([index, amount, count]);
        }
        entries.push(vector);
    }
    Offsets {
        accounts,
        outgoing,
        vectors,
        entries,
        aggregate: position(&reader),
    }
}

#[test]
fn keyed_dealing_validates_unsigned_account_keys() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 4, 4, 2, 1).await;
        let encode = |key: &[u8]| {
            let mut wire = Vec::new();
            wire.push(1);
            wire.extend_from_slice(key);
            wire.extend_from_slice(&[0, 0, 0]);
            Bytes::from(wire)
        };
        assert!(
            decode_with_each_strategy(encode(fixture.accounts[0].0.as_ref()), &fixture.context)
                .is_ok()
        );
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut negative_zero = identity;
        negative_zero[31] = 0x80;
        let mut order_four = [0; 32];
        order_four[31] = 0x80;
        let mut order_two = [0xff; 32];
        order_two[0] = 0xec;
        order_two[31] = 0x7f;
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xed;
        noncanonical[31] = 0x7f;
        for key in [
            identity,
            negative_zero,
            [0; 32],
            order_four,
            order_two,
            noncanonical,
        ] {
            assert!(
                decode_with_each_strategy(encode(&key), &fixture.context).is_err(),
                "unsigned key {key:?}"
            );
        }
    });
}

#[test]
fn keyed_dealing_rejects_noncanonical_keys_indices_tags_and_infeasible_edges() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 2).await;
        let wire = fixture.prepared.encoded();
        let offsets = offsets(wire);
        let mut cases = Vec::new();
        let mut duplicate = wire.to_vec();
        duplicate.copy_within(
            offsets.accounts[0]..offsets.accounts[0] + 32,
            offsets.accounts[1],
        );
        cases.push(("duplicate account", duplicate));
        let mut reversed = wire.to_vec();
        for byte in 0..32 {
            reversed.swap(offsets.accounts[0] + byte, offsets.accounts[1] + byte);
        }
        cases.push(("reversed accounts", reversed));
        for (name, offset, value) in [
            ("outgoing tag", offsets.outgoing[0], 2),
            ("sender missing vector", offsets.vectors[0], 0),
            ("recipient outside activity", offsets.entries[0][0][0], 8),
            ("zero amount", offsets.entries[0][0][1], 0),
            ("zero count", offsets.entries[0][0][2], 0),
            ("count exceeds amount", offsets.entries[0][0][2], 2),
            ("aggregate tag", offsets.aggregate, 2),
        ] {
            let mut tampered = wire.to_vec();
            tampered[offset] = value;
            cases.push((name, tampered));
        }
        let mut duplicate = wire.to_vec();
        duplicate[offsets.entries[0][1][0]] = duplicate[offsets.entries[0][0][0]];
        cases.push(("duplicate recipient", duplicate));
        let mut reversed = wire.to_vec();
        reversed.swap(offsets.entries[0][1][0], offsets.entries[0][0][0]);
        cases.push(("reversed recipients", reversed));
        let mut missing = wire[..offsets.aggregate].to_vec();
        missing.push(0);
        cases.push(("missing aggregate", missing));
        for (name, wire) in cases {
            assert!(
                decode_with_each_strategy(wire.into(), &fixture.context).is_err(),
                "{name}"
            );
        }
    });
}

#[test]
fn keyed_dealing_binds_resource_limits_before_allocating_rows_or_edges() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 8, 8, 4, 2).await;
        for (rows, per_account, total) in [(7, 2, 16), (8, 1, 16), (8, 2, 15)] {
            let limits = CloseLimits::new(8, rows, 0, per_account, total, 100, 0, 0);
            let context = EpochContext::new::<Sha256>(
                *fixture.context.deployment(),
                EPOCH,
                fixture.operator.public_key(),
                &fixture.deposits,
                &fixture.withdrawals,
                fixture.state.liability(),
                98,
                99,
                limits,
                *fixture.context.committee(),
            )
            .unwrap()
            .bind::<Sha256, _, _>(&fixture.state, &fixture.deposits, &fixture.withdrawals)
            .unwrap();
            assert!(
                decode_with_each_strategy(fixture.prepared.encoded().clone(), &context).is_err()
            );
        }
        // The claimed row count cannot exceed what the remaining bytes can encode, even
        // when the authenticated context permits the protocol maximum.
        let mut huge = Vec::new();
        huge.extend_from_slice(&[0xff; 10]);
        assert!(decode_with_each_strategy(huge.into(), &fixture.context).is_err());
    });
}

#[test]
fn keyed_dealing_strategies_preserve_alignment_and_authenticated_state() {
    for (senders, recipients, degree) in [(0, 8, 1), (96, 129, 4), (129, 64, 2)] {
        deterministic::Runner::default().start(|runtime| async move {
            let fixture = fixture(runtime, 129, senders, recipients, degree).await;
            let wire = fixture.prepared.encoded();
            let dealing = decode_with_each_strategy(wire.clone(), &fixture.context).unwrap();
            let prepared = validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                &fixture.state,
                &fixture.context,
                &fixture.operator_bls,
                &fixture.deposits,
                &fixture.withdrawals,
                dealing,
                &mut TestRng::new(5),
                &Sequential,
            )
            .await
            .unwrap();
            assert_eq!(prepared.close().header, fixture.prepared.close().header);
            assert_eq!(prepared.close().roots, fixture.prepared.close().roots);
            assert_eq!(
                prepared.state().mutations(),
                fixture.prepared.state().mutations()
            );
            let offsets = offsets(wire);
            let cuts = [0, 1, wire.len() - 1].into_iter().chain(
                [&offsets.accounts, &offsets.outgoing, &offsets.vectors]
                    .into_iter()
                    .flat_map(|positions| {
                        [0, positions.len() / 2, positions.len().saturating_sub(1)]
                            .into_iter()
                            .filter_map(move |index| positions.get(index).copied())
                    }),
            );
            for length in cuts {
                assert!(decode_with_each_strategy(wire.slice(..length), &fixture.context).is_err());
            }
            let (state, close) = prepared.apply(fixture.state).await.unwrap();
            assert_eq!(state.root(), close.roots.successor);
        });
    }
}

#[test]
fn headers_bind_every_root_amount_and_registered_context() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 8, 8, 4, 2).await;
        let close = fixture.prepared.close();
        assert!(close.header.verify::<Sha256, VerifyingKey>(
            &fixture.context,
            &close.roots,
            close.withdrawal_total
        ));
        let foreign = Sha256::hash(&[b"changed-root"]);
        for which in 0..3 {
            let mut roots = close.roots;
            match which {
                0 => roots.change.digest = foreign,
                1 => roots.withdrawal_outputs.digest = foreign,
                _ => roots.successor.digest = foreign,
            }
            assert!(!close.header.verify::<Sha256, VerifyingKey>(
                &fixture.context,
                &roots,
                close.withdrawal_total
            ));
        }
        assert!(!close.header.verify::<Sha256, VerifyingKey>(
            &fixture.context,
            &close.roots,
            close.withdrawal_total + 1
        ));
        let next = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH + 1,
            fixture.operator.public_key(),
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.state.liability(),
            98,
            99,
            CloseLimits::protocol_maximum(),
            *fixture.context.committee(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(&fixture.state, &fixture.deposits, &fixture.withdrawals)
        .unwrap();
        assert!(!close.header.verify::<Sha256, VerifyingKey>(
            &next,
            &close.roots,
            close.withdrawal_total
        ));
    });
}

#[test]
fn retained_evidence_round_trips_and_rejects_corruption_or_foreign_headers() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 8, 8, 4, 2).await;
        let close = fixture.prepared.close();
        let encoded = close.encode_evidence();
        let restored =
            Close::decode_evidence::<Sha256>(encoded.clone(), &fixture.context, &close.header)
                .unwrap();
        assert_eq!(restored.encoded(), close.encoded());
        assert_eq!(restored.header, close.header);
        assert_eq!(restored.roots, close.roots);
        assert_eq!(restored.withdrawal_total, close.withdrawal_total);
        let original = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let reopened = ChallengeIndex::new::<Sha256>(&fixture.context, &restored).unwrap();
        for (account, _) in &fixture.accounts {
            assert_eq!(
                account_lookup::<Sha256, _, _>(&original, account).unwrap(),
                account_lookup::<Sha256, _, _>(&reopened, account).unwrap()
            );
        }
        for length in [0, 31, encoded.len() / 2, encoded.len() - 1] {
            assert!(
                Close::<VerifyingKey, ShaDigest>::decode_evidence::<Sha256>(
                    encoded.slice(..length),
                    &fixture.context,
                    &close.header
                )
                .is_err()
            );
        }
        for position in [0, 32, 64, 96, 104] {
            let mut damaged = encoded.to_vec();
            damaged[position] ^= 1;
            assert!(
                Close::<VerifyingKey, ShaDigest>::decode_evidence::<Sha256>(
                    damaged.into(),
                    &fixture.context,
                    &close.header
                )
                .is_err(),
                "damaged {position}"
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(
            Close::<VerifyingKey, ShaDigest>::decode_evidence::<Sha256>(
                trailing.into(),
                &fixture.context,
                &close.header
            )
            .is_err()
        );
        let wrong = crate::bajillion::transition::Header::new::<Sha256, VerifyingKey>(
            &fixture.context,
            &close.roots,
            close.withdrawal_total + 1,
        );
        assert!(
            Close::<VerifyingKey, ShaDigest>::decode_evidence::<Sha256>(
                encoded,
                &fixture.context,
                &wrong
            )
            .is_err()
        );
    });
}

#[test]
fn malformed_terminal_material_is_rejected_before_state_preparation() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 8, 8, 4, 2).await;
        let before = *fixture.state.head();
        for case in 0..6 {
            let mut terminals = fixture.terminals.clone();
            match case {
                0 => terminals.insert(0, terminals[0].clone()),
                1 => terminals.swap(0, 1),
                2 => {
                    terminals[0].vector =
                        OutVector::empty(EPOCH, terminals[0].vector.payer().clone())
                }
                3 => terminals[0].vector = terminals[1].vector.clone(),
                4 | 5 => {
                    let old = terminals[0].authorization.body();
                    let body = VectorSendBody::from_raw_unchecked(
                        if case == 4 {
                            Sha256::hash(&[b"foreign-anchor"])
                        } else {
                            *old.anchor()
                        },
                        EPOCH,
                        old.payer().clone(),
                        old.seq(),
                        old.cumulative_debit() + 1,
                        old.send_root(),
                    );
                    terminals[0].authorization =
                        SendAuthorization::sign(body, &fixture.accounts[0].1);
                }
                _ => unreachable!(),
            }
            assert!(
                prepare_close_with_strategy::<Sha256, _, _, _, _>(
                    &fixture.state,
                    &fixture.context,
                    &fixture.deposits,
                    &fixture.withdrawals,
                    terminals,
                    &Sequential
                )
                .await
                .is_err(),
                "case {case}"
            );
            assert_eq!(*fixture.state.head(), before);
        }
    });
}

#[test]
fn complete_proof_service_matches_direct_activity_and_entry_openings() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 12, 6, 8, 2).await;
        let close = fixture.prepared.close();
        let served = crate::bajillion::serve::Index::new(close);
        let whole = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let mut accounts = fixture
            .accounts
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        accounts.extend((100..120).map(|seed| SigningKey::from_seed(seed).public_key()));
        for account in &accounts {
            let expected = account_lookup::<Sha256, _, _>(&whole, account).unwrap();
            assert_eq!(served.account_lookup::<Sha256>(account).unwrap(), expected);
            match expected {
                AccountLookup::Present(opening) => {
                    assert_eq!(served.change_opening::<Sha256>(account).unwrap(), *opening)
                }
                AccountLookup::Absent(_) => {
                    assert!(served.change_opening::<Sha256>(account).is_err())
                }
            }
            let vector = close
                .rows
                .binary_search_by(|row| row.account.cmp(account))
                .ok()
                .map(|index| &close.out_vectors[index]);
            for recipient in &accounts {
                assert_eq!(
                    served
                        .higher_entry_lookup::<Sha256>(account, recipient)
                        .unwrap(),
                    higher_entry_lookup::<Sha256, _, _>(&whole, account, vector, recipient)
                        .unwrap()
                );
            }
        }
        let mut wrong_root = close.clone();
        wrong_root.roots.change.digest = Sha256::hash(&[b"wrong-activity-root"]);
        let served = crate::bajillion::serve::Index::new(&wrong_root);
        assert!(served.account_lookup::<Sha256>(&accounts[0]).is_err());
        assert!(
            served
                .higher_entry_lookup::<Sha256>(&accounts[0], &accounts[1])
                .is_err()
        );
    });
}

#[test]
fn decoded_context_cannot_change_limits_or_deadlines_behind_the_signed_anchor() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 8, 8, 4, 2).await;
        let close = fixture.prepared.close();
        let encoded = fixture.context.encode();
        let payment_size =
            crate::bajillion::payment::PaymentContext::<VerifyingKey, ShaDigest>::SIZE;
        let liability_offset = payment_size + 32 * 3;
        // Payment context is left byte-identical while a registered scalar is changed.
        for offset in [
            liability_offset + 8,
            liability_offset + 16,
            liability_offset + 24,
        ] {
            let mut altered = encoded.to_vec();
            altered[offset + 7] ^= 1;
            let context =
                CloseContext::<VerifyingKey, ShaDigest>::decode(Bytes::from(altered)).unwrap();
            assert_eq!(context.payment(), fixture.context.payment());
            assert!(!close.header.verify::<Sha256, VerifyingKey>(
                &context,
                &close.roots,
                close.withdrawal_total
            ));
            let dealing = posted::decode(fixture.prepared.encoded().clone(), &context).unwrap();
            assert!(
                validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                    &fixture.state,
                    &context,
                    &fixture.operator_bls,
                    &fixture.deposits,
                    &fixture.withdrawals,
                    dealing,
                    &mut TestRng::new(90),
                    &Sequential
                )
                .await
                .is_err()
            );
        }
    });
}
