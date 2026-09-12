use super::*;
use commonware_codec::{FixedSize as _, Read as _, ReadExt as _, varint::UInt};

struct Offsets {
    accounts: Vec<usize>,
    outgoing: Vec<usize>,
    vectors: Vec<usize>,
    entries: Vec<Vec<[usize; 3]>>,
    aggregate: usize,
}

fn offsets(wire: &Bytes) -> Offsets {
    let mut reader = wire.clone();
    let position = |reader: &Bytes| wire.len() - reader.len();
    crate::bajillion::transition::Header::<ShaDigest>::read(&mut reader).unwrap();
    let count = usize::read_cfg(&mut reader, &(0..=100).into()).unwrap();
    let mut accounts = Vec::new();
    let mut outgoing = Vec::new();
    for _ in 0..count {
        accounts.push(position(&reader));
        VerifyingKey::read(&mut reader).unwrap();
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
                posted::decode::<VerifyingKey, ShaDigest>(wire.into(), &fixture.context).is_err(),
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
            .await
            .unwrap();
            assert!(
                posted::decode::<VerifyingKey, ShaDigest>(
                    fixture.prepared.encoded().clone(),
                    &context
                )
                .is_err()
            );
        }
        // The claimed row count cannot exceed what the remaining bytes can encode, even
        // when the authenticated context permits the protocol maximum.
        let mut huge = fixture.prepared.encoded()[..32].to_vec();
        huge.extend_from_slice(&[0xff; 10]);
        assert!(posted::decode::<VerifyingKey, ShaDigest>(huge.into(), &fixture.context).is_err());
    });
}

#[test]
fn headers_bind_every_root_amount_and_registered_context() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 8, 8, 4, 2).await;
        let close = fixture.prepared.close();
        assert!(close.header.verify::<Sha256, VerifyingKey>(
            &fixture.context,
            &close.roots,
            &close.amounts
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
                &close.amounts
            ));
        }
        for which in 0..2 {
            let mut amounts = close.amounts;
            if which == 0 {
                amounts.withdrawal += 1;
            } else {
                amounts.payout += 1;
            }
            assert!(!close.header.verify::<Sha256, VerifyingKey>(
                &fixture.context,
                &close.roots,
                &amounts
            ));
        }
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
        .await
        .unwrap();
        assert!(
            !close
                .header
                .verify::<Sha256, VerifyingKey>(&next, &close.roots, &close.amounts)
        );
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
        assert_eq!(restored.amounts, close.amounts);
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
        let mut amounts = close.amounts;
        amounts.payout += 1;
        let wrong = crate::bajillion::transition::Header::new::<Sha256, VerifyingKey>(
            &fixture.context,
            &close.roots,
            &amounts,
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
                &close.amounts
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
