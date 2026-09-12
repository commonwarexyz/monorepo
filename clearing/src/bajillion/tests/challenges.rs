use super::*;
use crate::bajillion::{challenge::HigherEntryLookup, vector::OutTipLookup};

fn acknowledge(
    fixture: &Fixture,
    payer: &SigningKey,
    vector: &OutVector<VerifyingKey>,
    seq: u64,
    debit: u64,
) -> VectorAck<VerifyingKey, ShaDigest> {
    VectorAck::sign_by_authorities(
        VectorSendBody::new(
            fixture.context.payment(),
            payer.public_key(),
            seq,
            debit,
            vector.root::<Sha256, ShaDigest>().unwrap(),
        ),
        payer,
        &fixture.operator,
    )
}

fn entry_witness(
    ack: &VectorAck<VerifyingKey, ShaDigest>,
    vector: &OutVector<VerifyingKey>,
    recipient: &VerifyingKey,
) -> EntryWitness<VerifyingKey, ShaDigest> {
    let OutTipLookup::Present {
        cumulative,
        count,
        opening,
    } = vector.lookup::<Sha256, ShaDigest>(recipient).unwrap()
    else {
        panic!("retained entry is present");
    };
    EntryWitness {
        ack: AckWitness::from_ack(ack),
        recipient: recipient.clone(),
        cumulative,
        count,
        opening,
    }
}

fn check(
    fixture: &Fixture,
    close: &Close<VerifyingKey, ShaDigest>,
    challenge: Challenge<VerifyingKey, ShaDigest>,
) -> Result<Verdict, ChallengeError> {
    assert_eq!(
        Challenge::<VerifyingKey, ShaDigest>::decode(challenge.encode()).unwrap(),
        challenge
    );
    adjudicate::<Sha256, _, _>(
        &fixture.context,
        &close.header,
        &close.roots,
        &close.amounts,
        &challenge,
    )
}

#[test]
fn challenges_adjudicate() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 16, 16, 8, 2).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let position = 3;
        let (payer, private) = &fixture.accounts[position];
        let committed = &close.out_vectors[position];
        let mut entries = committed.entries().to_vec();
        entries[0].cumulative += 1;
        entries[0].count += 1;
        let recipient = entries[0].recipient.clone();
        let retained = OutVector::new(EPOCH, payer.clone(), entries).unwrap();
        let ack = acknowledge(&fixture, private, &retained, 1, 3);
        let sender =
            higher_entry_lookup::<Sha256, _, _>(&index, payer, Some(committed), &recipient)
                .unwrap();
        assert_eq!(
            check(
                &fixture,
                close,
                Challenge::HigherAckEntry {
                    entry: Box::new(entry_witness(&ack, &retained, &recipient)),
                    sender: Box::new(sender.clone()),
                }
            )
            .unwrap(),
            Verdict::Proven(ChallengeKind::HigherAckEntry)
        );
        let lookup = account_lookup::<Sha256, _, _>(&index, payer).unwrap();
        assert_eq!(
            check(
                &fixture,
                close,
                Challenge::HigherAckDebit {
                    ack: Box::new(AckWitness::from_ack(&ack)),
                    payer: Box::new(lookup.clone()),
                }
            )
            .unwrap(),
            Verdict::Proven(ChallengeKind::HigherAckDebit)
        );
        let committed_ack = &fixture.acks[position];
        assert_eq!(
            check(
                &fixture,
                close,
                Challenge::HigherAckDebit {
                    ack: Box::new(AckWitness::from_ack(committed_ack)),
                    payer: Box::new(lookup),
                }
            )
            .unwrap(),
            Verdict::NoContradiction
        );
        assert_eq!(
            check(
                &fixture,
                close,
                Challenge::HigherAckEntry {
                    entry: Box::new(entry_witness(committed_ack, committed, &recipient)),
                    sender: Box::new(sender),
                }
            )
            .unwrap(),
            Verdict::NoContradiction
        );
        let fork = acknowledge(&fixture, private, &retained, 0, 7);
        assert_eq!(
            check(
                &fixture,
                close,
                Challenge::AckFork {
                    left: Box::new(AckWitness::from_ack(committed_ack)),
                    right: Box::new(AckWitness::from_ack(&fork)),
                }
            )
            .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
    });
}

#[test]
fn ack_debit_arms_convict_same_seq_forks_and_later_batches() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 16, 16, 8, 2).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let (payer, private) = &fixture.accounts[3];
        let lookup = account_lookup::<Sha256, _, _>(&index, payer).unwrap();
        let mut entries = close.out_vectors[3].entries().to_vec();
        let moved = entries.remove(0).cumulative;
        entries[0].cumulative += moved;
        let rearranged = OutVector::new(EPOCH, payer.clone(), entries).unwrap();
        for (seq, debit, verdict) in [
            (0, 1, Verdict::Proven(ChallengeKind::HigherAckDebit)),
            (0, 2, Verdict::Proven(ChallengeKind::HigherAckDebit)),
            (0, 3, Verdict::Proven(ChallengeKind::HigherAckDebit)),
            (1, 2, Verdict::Proven(ChallengeKind::HigherAckDebit)),
            (1, 3, Verdict::Proven(ChallengeKind::HigherAckDebit)),
            (1, 1, Verdict::NoContradiction),
        ] {
            let ack = acknowledge(&fixture, private, &rearranged, seq, debit);
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(&ack)),
                        payer: Box::new(lookup.clone()),
                    }
                )
                .unwrap(),
                verdict,
                "seq {seq}, debit {debit}"
            );
        }
    });
}

#[test]
fn ack_debit_arms_decline_earlier_retries() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 16, 16, 8, 2).await;
        let (payer, private) = &fixture.accounts[3];
        let mut terminals = fixture.terminals.clone();
        let terminal = &mut terminals[3];
        let ack = acknowledge(&fixture, private, &terminal.vector, 1, 2);
        terminal.authorization = SendAuthorization::sign(ack.body().clone(), private);
        terminal.operator_signature = bls_ack(&fixture.operator_bls_private, ack.body());
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
        let close = prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let lookup = account_lookup::<Sha256, _, _>(&index, payer).unwrap();
        let mut entries = close.out_vectors[3].entries().to_vec();
        let moved = entries.remove(0).cumulative;
        entries[0].cumulative += moved;
        let rearranged = OutVector::new(EPOCH, payer.clone(), entries).unwrap();
        for debit in [1, 2, 3] {
            let earlier = acknowledge(&fixture, private, &rearranged, 0, debit);
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(&earlier)),
                        payer: Box::new(lookup.clone()),
                    }
                )
                .unwrap(),
                if debit > 2 {
                    Verdict::Proven(ChallengeKind::HigherAckDebit)
                } else {
                    Verdict::NoContradiction
                },
                "debit {debit}"
            );
        }
    });
}

#[test]
fn credit_only_rows_decline_zero_debit_retries() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 1, 4, 2).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let row = close
            .rows
            .iter()
            .find(|row| row.outgoing.is_none())
            .unwrap();
        assert!(row.successor > row.predecessor);
        let (payer, private) = fixture
            .accounts
            .iter()
            .find(|(key, _)| key == &row.account)
            .unwrap();
        let vector = OutVector::empty(EPOCH, payer.clone());
        let lookup = account_lookup::<Sha256, _, _>(&index, payer).unwrap();
        assert!(matches!(lookup, AccountLookup::Present(_)));
        for seq in [0, 1, 7] {
            let ack = acknowledge(&fixture, private, &vector, seq, 0);
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(&ack)),
                        payer: Box::new(lookup.clone()),
                    }
                )
                .unwrap(),
                Verdict::NoContradiction,
                "seq {seq}"
            );
        }
    });
}

#[test]
fn absent_payer_arms_convict_from_zero() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 4, 4, 1).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let phantom = SigningKey::from_seed(999_999);
        // Both a funded inactive payer and a payer absent from state resolve to no activity.
        for private in [&fixture.accounts[7].1, &phantom] {
            let payer = private.public_key();
            let recipient = fixture.accounts[0].0.clone();
            let vector = OutVector::new(
                EPOCH,
                payer.clone(),
                vec![OutEntry {
                    recipient: recipient.clone(),
                    cumulative: 5,
                    count: 1,
                }],
            )
            .unwrap();
            let ack = acknowledge(&fixture, private, &vector, 0, 5);
            let lookup = account_lookup::<Sha256, _, _>(&index, &payer).unwrap();
            assert!(matches!(lookup, AccountLookup::Absent(_)));
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckDebit {
                        ack: Box::new(AckWitness::from_ack(&ack)),
                        payer: Box::new(lookup),
                    }
                )
                .unwrap(),
                Verdict::Proven(ChallengeKind::HigherAckDebit)
            );
            let sender =
                higher_entry_lookup::<Sha256, _, _>(&index, &payer, None, &recipient).unwrap();
            assert!(matches!(sender, HigherEntryLookup::Absent(_)));
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckEntry {
                        entry: Box::new(entry_witness(&ack, &vector, &recipient)),
                        sender: Box::new(sender),
                    }
                )
                .unwrap(),
                Verdict::Proven(ChallengeKind::HigherAckEntry)
            );
        }
    });
}

#[test]
fn entry_amount_and_count_contradictions_are_independent() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let (payer, private) = &fixture.accounts[2];
        let mut terminals = fixture.terminals.clone();
        let mut entries = terminals[2].vector.entries().to_vec();
        entries[0].cumulative = 2;
        let recipient = entries[0].recipient.clone();
        terminals[2].vector = OutVector::new(EPOCH, payer.clone(), entries).unwrap();
        let ack = acknowledge(&fixture, private, &terminals[2].vector, 0, 2);
        terminals[2].authorization = SendAuthorization::sign(ack.body().clone(), private);
        terminals[2].operator_signature = bls_ack(&fixture.operator_bls_private, ack.body());
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
        let close = prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let sender = higher_entry_lookup::<Sha256, _, _>(
            &index,
            payer,
            Some(&close.out_vectors[2]),
            &recipient,
        )
        .unwrap();
        assert!(matches!(
            sender,
            HigherEntryLookup::Present {
                entry: OutTipLookup::Present { .. },
                ..
            }
        ));
        for (cumulative, count, verdict) in [
            (3, 1, Verdict::Proven(ChallengeKind::HigherAckEntry)),
            (2, 2, Verdict::Proven(ChallengeKind::HigherAckEntry)),
            (2, 1, Verdict::NoContradiction),
            (1, 1, Verdict::NoContradiction),
        ] {
            let vector = OutVector::new(
                EPOCH,
                payer.clone(),
                vec![OutEntry {
                    recipient: recipient.clone(),
                    cumulative,
                    count,
                }],
            )
            .unwrap();
            let ack = acknowledge(&fixture, private, &vector, 1, cumulative);
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckEntry {
                        entry: Box::new(entry_witness(&ack, &vector, &recipient)),
                        sender: Box::new(sender.clone()),
                    }
                )
                .unwrap(),
                verdict,
                "amount {cumulative}, count {count}"
            );
        }
    });
}

#[test]
fn entry_absence_and_empty_vectors_convict() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 1, 4, 2).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let recipient = fixture.accounts[7].0.clone();
        for row in &close.rows {
            let (payer, private) = fixture
                .accounts
                .iter()
                .find(|(key, _)| key == &row.account)
                .unwrap();
            let committed = close
                .out_vectors
                .iter()
                .find(|vector| vector.payer() == payer)
                .unwrap();
            assert_eq!(committed.entries().is_empty(), row.outgoing.is_none());
            let retained = OutVector::new(
                EPOCH,
                payer.clone(),
                vec![OutEntry {
                    recipient: recipient.clone(),
                    cumulative: 1,
                    count: 1,
                }],
            )
            .unwrap();
            let ack = acknowledge(&fixture, private, &retained, 1, 1);
            let sender =
                higher_entry_lookup::<Sha256, _, _>(&index, payer, Some(committed), &recipient)
                    .unwrap();
            assert!(matches!(sender, HigherEntryLookup::Present { .. }));
            assert_eq!(
                sender
                    .resolve::<Sha256>(&close.roots.change, payer, &recipient)
                    .unwrap(),
                (0, 0)
            );
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckEntry {
                        entry: Box::new(entry_witness(&ack, &retained, &recipient)),
                        sender: Box::new(sender),
                    }
                )
                .unwrap(),
                Verdict::Proven(ChallengeKind::HigherAckEntry)
            );
        }
    });
}

#[test]
fn infeasible_retained_entries_are_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let vector = &close.out_vectors[2];
        let recipient = &vector.entries()[0].recipient;
        let sender =
            higher_entry_lookup::<Sha256, _, _>(&index, vector.payer(), Some(vector), recipient)
                .unwrap();
        for (cumulative, count) in [(1, 2), (0, 1), (1, 0), (0, 0)] {
            let mut entry = entry_witness(&fixture.acks[2], vector, recipient);
            entry.cumulative = cumulative;
            entry.count = count;
            assert!(matches!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckEntry {
                        entry: Box::new(entry),
                        sender: Box::new(sender.clone()),
                    }
                ),
                Err(ChallengeError::Ack(AckError::InfeasibleEntry))
            ));
        }
    });
}

#[test]
fn forged_entry_openings_are_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let (payer, private) = &fixture.accounts[2];
        let committed = &close.out_vectors[2];
        let recipient = &committed.entries()[0].recipient;
        let sender =
            higher_entry_lookup::<Sha256, _, _>(&index, payer, Some(committed), recipient).unwrap();
        let doubled = OutVector::new(
            EPOCH,
            payer.clone(),
            vec![OutEntry {
                recipient: recipient.clone(),
                cumulative: 2,
                count: 1,
            }],
        )
        .unwrap();
        let doubled_ack = acknowledge(&fixture, private, &doubled, 1, 2);
        for (ack, vector, cumulative, count) in [
            (&fixture.acks[2], committed, 2, 1),
            (&doubled_ack, &doubled, 3, 1),
            (&doubled_ack, &doubled, 2, 2),
        ] {
            let mut entry = entry_witness(ack, vector, recipient);
            entry.cumulative = cumulative;
            entry.count = count;
            let receipt = EntryReceipt {
                ack: ack.clone(),
                recipient: recipient.clone(),
                cumulative,
                count,
                opening: entry.opening.clone(),
            };
            assert!(matches!(
                receipt.verify::<Sha256>(fixture.context.payment()),
                Err(AckError::InvalidEntryOpening)
            ));
            assert!(matches!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckEntry {
                        entry: Box::new(entry),
                        sender: Box::new(sender.clone()),
                    }
                ),
                Err(ChallengeError::Ack(AckError::InvalidEntryOpening))
            ));
        }
    });
}

#[test]
fn ack_fork_requires_only_operator_signatures() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let close = fixture.prepared.close();
        let (payer, private) = &fixture.accounts[2];
        let ack = acknowledge(&fixture, private, &close.out_vectors[2], 0, 2);
        let mut left = AckWitness::from_ack(&fixture.acks[2]);
        let mut right = AckWitness::from_ack(&ack);
        left.payer_signature = fixture.operator.sign(b"unrelated-payer", b"left");
        right.payer_signature = fixture.operator.sign(b"unrelated-payer", b"right");
        assert!(matches!(
            left.reconstruct(&fixture.context),
            Err(ChallengeError::Ack(AckError::InvalidPayerSignature))
        ));
        assert!(matches!(
            right.reconstruct(&fixture.context),
            Err(ChallengeError::Ack(AckError::InvalidPayerSignature))
        ));
        assert_eq!(
            check(
                &fixture,
                close,
                Challenge::AckFork {
                    left: Box::new(left.clone()),
                    right: Box::new(right.clone())
                }
            )
            .unwrap(),
            Verdict::Proven(ChallengeKind::AckFork)
        );
        assert_eq!(
            check(
                &fixture,
                close,
                Challenge::AckFork {
                    left: Box::new(left.clone()),
                    right: Box::new(left.clone())
                }
            )
            .unwrap(),
            Verdict::NoContradiction
        );
        for (other_private, seq) in [(private, 1), (&fixture.accounts[3].1, 0)] {
            let other = acknowledge(
                &fixture,
                other_private,
                &OutVector::empty(EPOCH, other_private.public_key()),
                seq,
                2,
            );
            assert_eq!(
                check(
                    &fixture,
                    close,
                    Challenge::AckFork {
                        left: Box::new(left.clone()),
                        right: Box::new(AckWitness::from_ack(&other)),
                    }
                )
                .unwrap(),
                Verdict::NoContradiction
            );
        }
        right.operator_signature = private.sign(b"unrelated-operator", payer.as_ref());
        assert!(matches!(
            check(
                &fixture,
                close,
                Challenge::AckFork {
                    left: Box::new(left),
                    right: Box::new(right)
                }
            ),
            Err(ChallengeError::Ack(AckError::InvalidOperatorSignature))
        ));
    });
}

#[test]
fn foreign_context_acks_are_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let (payer, private) = &fixture.accounts[2];
        let committed = fixture.acks[2].body();
        for (anchor, epoch) in [
            (*fixture.context.payment().anchor(), EPOCH + 1),
            (Sha256::hash(&[b"foreign-payment-anchor"]), EPOCH),
        ] {
            let foreign = VectorSendBody::from_raw_unchecked(
                anchor,
                epoch,
                payer.clone(),
                committed.seq(),
                committed.cumulative_debit(),
                committed.send_root(),
            );
            let mut terminals = fixture.terminals.clone();
            terminals[2].operator_signature = bls_ack(&fixture.operator_bls_private, &foreign);
            terminals[2].authorization = SendAuthorization::sign(foreign, private);
            assert!(matches!(
                prepare_close_with_strategy::<Sha256, _, _, _, _>(
                    &fixture.state,
                    &fixture.context,
                    &fixture.deposits,
                    &fixture.withdrawals,
                    terminals,
                    &Sequential,
                )
                .await,
                Err(CloseError::Ack(AckError::WrongContext))
            ));
        }
    });
}

#[test]
fn cross_epoch_and_anchor_challenge_replays_are_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let (payer, private) = &fixture.accounts[2];
        let vector = &close.out_vectors[2];
        let recipient = &vector.entries()[0].recipient;
        let lookup = account_lookup::<Sha256, _, _>(&index, payer).unwrap();
        let sender =
            higher_entry_lookup::<Sha256, _, _>(&index, payer, Some(vector), recipient).unwrap();
        for (anchor, epoch) in [
            (*fixture.context.payment().anchor(), EPOCH + 1),
            (Sha256::hash(&[b"foreign-payment-anchor"]), EPOCH),
        ] {
            let foreign = VectorAck::sign_by_authorities(
                VectorSendBody::from_raw_unchecked(
                    anchor,
                    epoch,
                    payer.clone(),
                    0,
                    2,
                    vector.root::<Sha256, ShaDigest>().unwrap(),
                ),
                private,
                &fixture.operator,
            );
            let witness = AckWitness::from_ack(&foreign);
            assert!(matches!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckDebit {
                        ack: Box::new(witness.clone()),
                        payer: Box::new(lookup.clone())
                    }
                ),
                Err(ChallengeError::Ack(AckError::InvalidPayerSignature))
            ));
            assert!(matches!(
                check(
                    &fixture,
                    close,
                    Challenge::HigherAckEntry {
                        entry: Box::new(entry_witness(&foreign, vector, recipient)),
                        sender: Box::new(sender.clone()),
                    }
                ),
                Err(ChallengeError::Ack(AckError::InvalidPayerSignature))
            ));
            assert!(matches!(
                check(
                    &fixture,
                    close,
                    Challenge::AckFork {
                        left: Box::new(AckWitness::from_ack(&fixture.acks[2])),
                        right: Box::new(witness),
                    }
                ),
                Err(ChallengeError::Ack(AckError::InvalidOperatorSignature))
            ));
        }
    });
}

#[test]
fn signatures_for_other_roles_cannot_authorize_challenges() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = fixture(context, 8, 8, 4, 1).await;
        let close = fixture.prepared.close();
        let index = ChallengeIndex::new::<Sha256>(&fixture.context, close).unwrap();
        let (payer, private) = &fixture.accounts[2];
        let ack = acknowledge(&fixture, private, &close.out_vectors[2], 0, 2);
        let lookup = account_lookup::<Sha256, _, _>(&index, payer).unwrap();
        let mut wrong_payer_role = AckWitness::from_ack(&ack);
        wrong_payer_role.payer_signature = private.sign(
            crate::bajillion::payment::VECTOR_ACK_SIGNATURE_NAMESPACE,
            &ack.body().encode(),
        );
        assert!(matches!(
            check(
                &fixture,
                close,
                Challenge::HigherAckDebit {
                    ack: Box::new(wrong_payer_role),
                    payer: Box::new(lookup.clone())
                }
            ),
            Err(ChallengeError::Ack(AckError::InvalidPayerSignature))
        ));
        let mut wrong_operator_role = AckWitness::from_ack(&ack);
        wrong_operator_role.operator_signature = fixture.operator.sign(
            crate::bajillion::payment::VECTOR_SEND_SIGNATURE_NAMESPACE,
            &ack.body().encode(),
        );
        assert!(matches!(
            check(
                &fixture,
                close,
                Challenge::HigherAckDebit {
                    ack: Box::new(wrong_operator_role.clone()),
                    payer: Box::new(lookup)
                }
            ),
            Err(ChallengeError::Ack(AckError::InvalidOperatorSignature))
        ));
        assert!(matches!(
            check(
                &fixture,
                close,
                Challenge::AckFork {
                    left: Box::new(AckWitness::from_ack(&fixture.acks[2])),
                    right: Box::new(wrong_operator_role),
                }
            ),
            Err(ChallengeError::Ack(AckError::InvalidOperatorSignature))
        ));
    });
}
