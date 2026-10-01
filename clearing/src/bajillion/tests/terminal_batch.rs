use super::*;
use crate::bajillion::{
    admission::{Committee, bls12381, seal},
    payment::VECTOR_ACK_SIGNATURE_NAMESPACE,
    transition::{
        TERMINAL_BATCH_HASH_NAMESPACE, TERMINAL_BATCH_SIGNATURE_NAMESPACE, prepare_dealing,
    },
};
use commonware_codec::FixedSize as _;
use commonware_cryptography::bls12381::primitives::variant::MinSig;

#[test]
fn terminal_batch_authenticates_every_context_and_message_byte() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 3, 3, 3, 1).await;
        let context = fixture.context.epoch_context().encode();
        let messages = fixture
            .terminals
            .iter()
            .map(|terminal| terminal.authorization.message())
            .collect::<Vec<_>>();
        let mut transcript = context.to_vec();
        for message in &messages {
            transcript.extend_from_slice(message);
        }
        assert_eq!(context.len(), EpochContext::<VerifyingKey, ShaDigest>::SIZE);
        assert!(messages.iter().all(|message| {
            message.len()
                == VectorSendBody::<VerifyingKey, ShaDigest>::SIZE + VectorRoot::<ShaDigest>::SIZE
        }));
        let digest = Sha256::hash(&[TERMINAL_BATCH_HASH_NAMESPACE, &transcript]);
        let dealing = posted::decode(fixture.prepared.encoded().clone(), &fixture.context).unwrap();
        assert_eq!(
            dealing.signature,
            fixture
                .operator
                .sign(TERMINAL_BATCH_SIGNATURE_NAMESPACE, digest.as_ref())
        );
        validate(&fixture, dealing.encoded().clone()).await.unwrap();
        assert!(matches!(
            validate(
                &fixture,
                posted::encode(&dealing.rows, fixture.acks[0].operator_signature()).unwrap(),
            )
            .await,
            Err(CloseError::Ack(AckError::InvalidOperatorSignature))
        ));

        // The independent transcript contains every registered field and each terminal's anchor,
        // epoch, payer, sequence, debit, vector root, and predecessor root.
        for position in 0..transcript.len() {
            let mut changed = transcript.clone();
            changed[position] ^= 1;
            let digest = Sha256::hash(&[TERMINAL_BATCH_HASH_NAMESPACE, &changed]);
            assert!(
                !fixture.operator.public_key().verify(
                    TERMINAL_BATCH_SIGNATURE_NAMESPACE,
                    digest.as_ref(),
                    &dealing.signature,
                ),
                "transcript byte {position}"
            );
        }

        let mut reversed = context.to_vec();
        for message in messages.iter().rev() {
            reversed.extend_from_slice(message);
        }
        let mut bodies_only = context.to_vec();
        for terminal in &fixture.terminals {
            bodies_only.extend_from_slice(&terminal.authorization.body().encode());
        }
        let mut duplicated = transcript.clone();
        duplicated.extend_from_slice(&messages[0]);
        for changed in [
            context.to_vec(),
            transcript[context.len()..].to_vec(),
            transcript[..transcript.len() - messages[0].len()].to_vec(),
            reversed,
            bodies_only,
            duplicated,
        ] {
            let digest = Sha256::hash(&[TERMINAL_BATCH_HASH_NAMESPACE, &changed]);
            let signature = fixture
                .operator
                .sign(TERMINAL_BATCH_SIGNATURE_NAMESPACE, digest.as_ref());
            let wire = posted::encode(&dealing.rows, &signature).unwrap();
            assert!(matches!(
                validate(&fixture, wire).await,
                Err(CloseError::Ack(AckError::InvalidOperatorSignature))
            ));
        }

        let subset = prepare_dealing::<Sha256, _, _>(
            fixture.context.epoch_context(),
            &fixture.operator,
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.terminals[..2].to_vec(),
        )
        .unwrap();
        validate(&fixture, subset.encoded().clone()).await.unwrap();
        for (rows, signature) in [
            (&subset.rows, &dealing.signature),
            (&dealing.rows, &subset.signature),
        ] {
            assert!(matches!(
                validate(&fixture, posted::encode(rows, signature).unwrap()).await,
                Err(CloseError::Ack(AckError::InvalidOperatorSignature))
            ));
        }
        let mut reversed = fixture.terminals.clone();
        reversed.reverse();
        let mut duplicate = fixture.terminals.clone();
        duplicate.insert(0, duplicate[0].clone());
        for terminals in [reversed, duplicate] {
            assert!(matches!(
                prepare_dealing::<Sha256, _, _>(
                    fixture.context.epoch_context(),
                    &fixture.operator,
                    &fixture.deposits,
                    &fixture.withdrawals,
                    terminals,
                ),
                Err(CloseError::NonCanonicalRows)
            ));
        }
    });
}

#[test]
fn empty_and_deposit_only_batches_require_the_exact_registered_context() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime, 2, 0, 2, 1).await;
        let other_operator = SigningKey::from_seed(99);
        for deposit in [0, 7] {
            let mut original = None;
            for changed in 0..8 {
                let deployment = if changed == 1 {
                    Sha256::hash(&[b"other-deployment"])
                } else {
                    *fixture.context.deployment()
                };
                let operator = if changed == 3 {
                    &other_operator
                } else {
                    &fixture.operator
                };
                let amount = deposit + u64::from(changed == 4);
                let deposits = DepositBatch::new(if amount == 0 {
                    Vec::new()
                } else {
                    vec![DepositRecord::new(fixture.accounts[0].0.clone(), amount).unwrap()]
                })
                .unwrap();
                let withdrawals = WithdrawalBatch::new(if changed == 5 {
                    vec![SignedWithdrawal::sign(
                        deployment,
                        Bytes::from_static(b"batch-withdrawal"),
                        WithdrawalAction::Close,
                        99,
                        &fixture.accounts[0].1,
                    )]
                } else {
                    Vec::new()
                })
                .unwrap();
                let limits = if changed == 6 {
                    CloseLimits::new(2, 2, 1, 1, 1, 10, 100, OPENING_BALANCE * 2)
                } else {
                    CloseLimits::protocol_maximum()
                };
                let committee = if changed == 7 {
                    Sha256::hash(&[b"other-committee"])
                } else {
                    *fixture.context.committee()
                };
                let context = EpochContext::new::<Sha256>(
                    deployment,
                    EPOCH + u64::from(changed == 2),
                    operator.public_key(),
                    &deposits,
                    &withdrawals,
                    limits,
                    committee,
                )
                .unwrap()
                .bind::<Sha256, _, _>(
                    &fixture.state,
                    &deposits,
                    &withdrawals,
                    0..0,
                    OPENING_BALANCE * 2,
                    98,
                    99,
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .unwrap();
                let dealing = prepare_dealing::<Sha256, _, _>(
                    context.epoch_context(),
                    operator,
                    &deposits,
                    &withdrawals,
                    Vec::new(),
                )
                .unwrap();
                validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                    &fixture.state,
                    &context,
                    &deposits,
                    &withdrawals,
                    dealing.clone(),
                    &mut TestRng::new(12),
                    &Sequential,
                )
                .await
                .unwrap();
                if let Some(signature) = &original {
                    let replay =
                        posted::decode(posted::encode(&dealing.rows, signature).unwrap(), &context)
                            .unwrap();
                    assert!(
                        matches!(
                        validate_close_with_strategy::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                            &fixture.state, &context, &deposits, &withdrawals, replay,
                            &mut TestRng::new(13), &Sequential,
                        ).await,
                        Err(CloseError::Ack(AckError::InvalidOperatorSignature))
                    ),
                        "context mutation {changed}, deposit {deposit}"
                    );
                } else {
                    original = Some(dealing.signature);
                }
            }
        }
    });
}

#[test]
fn certified_batch_acceptance_preserves_independent_private_receipt_challenges() {
    deterministic::Runner::default().start(|runtime| async move {
        let fixture = fixture(runtime.child("fixture"), 2, 0, 2, 1).await;
        let keys = (1_000_u64..1_004)
            .map(|seed| BlsPrivate::new(Scalar::from(seed)))
            .collect::<Vec<_>>();
        let committee =
            Committee::new(keys.iter().map(compute_public::<MinSig>).collect()).unwrap();
        let schemes = keys
            .into_iter()
            .map(|key| bls12381::Scheme::signer(committee.clone(), key).unwrap())
            .collect::<Vec<_>>();
        let context = EpochContext::new::<Sha256>(
            *fixture.context.deployment(),
            EPOCH,
            fixture.operator.public_key(),
            &fixture.deposits,
            &fixture.withdrawals,
            CloseLimits::protocol_maximum(),
            committee.commitment::<Sha256>(),
        )
        .unwrap()
        .bind::<Sha256, _, _>(
            &fixture.state,
            &fixture.deposits,
            &fixture.withdrawals,
            0..0,
            OPENING_BALANCE * 2,
            98,
            99,
            Floors {
                activity: 0,
                payouts: 0,
            },
        )
        .unwrap();
        let payer = &fixture.accounts[0].1;
        let vectors = [fixture.accounts[1].0.clone(), payer.public_key()].map(|recipient| {
            OutVector::new(
                EPOCH,
                payer.public_key(),
                vec![OutEntry {
                    recipient,
                    cumulative: 1,
                    count: 1,
                }],
            )
            .unwrap()
        });
        let receipt = VectorAck::sign_by_authorities(
            VectorSendBody::new(
                context.payment(),
                payer.public_key(),
                3,
                1,
                vectors[0].root::<Sha256, ShaDigest>().unwrap(),
            ),
            empty_root(),
            payer,
            &fixture.operator,
        );
        receipt.verify(context.payment()).unwrap();
        let terminal = Terminal {
            authorization: SendAuthorization::sign(
                VectorSendBody::new(
                    context.payment(),
                    payer.public_key(),
                    3,
                    1,
                    vectors[1].root::<Sha256, ShaDigest>().unwrap(),
                ),
                empty_root(),
                payer,
            ),
            vector: vectors[1].clone(),
        };
        let dealing = prepare_dealing::<Sha256, _, _>(
            context.epoch_context(),
            &fixture.operator,
            &fixture.deposits,
            &fixture.withdrawals,
            vec![terminal],
        )
        .unwrap();
        let mut votes = Vec::new();
        let mut prepared = None;
        for scheme in schemes.iter().take(committee.quorum()) {
            let (vote, candidate) = seal::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                scheme,
                &fixture.state,
                &context,
                &fixture.deposits,
                &fixture.withdrawals,
                dealing.encoded().clone(),
                &mut TestRng::new(14),
                &Sequential,
            )
            .await
            .unwrap();
            votes.push(vote);
            prepared = Some(candidate);
        }
        let prepared = prepared.unwrap();
        let close = prepared.close();
        let certificate = schemes[0].assemble(votes).unwrap();
        assert!(bls12381::Scheme::verifier(committee).verify(&close.header, &certificate));
        let index = NativeIndex::replay(
            runtime.child("proof"),
            "batch-proof",
            &fixture.genesis,
            &context,
            &prepared,
        )
        .await;
        let lookup = index.account_lookup(&payer.public_key()).await;
        let check = |ack: &VectorAck<VerifyingKey, ShaDigest>| {
            adjudicate::<Sha256, _, _>(
                &context,
                &close.header,
                &close.roots,
                close.withdrawal_total,
                &Challenge::HigherAckDebit {
                    ack: Box::new(AckWitness::from_ack(ack)),
                    payer: Box::new(lookup.clone()),
                },
            )
        };
        assert_eq!(
            check(&receipt).unwrap(),
            Verdict::Proven(ChallengeKind::HigherAckDebit)
        );
        for signature in [
            dealing.signature,
            fixture.operator.sign(
                TERMINAL_BATCH_SIGNATURE_NAMESPACE,
                receipt.body().message(&receipt.predecessor()).as_ref(),
            ),
            SigningKey::from_seed(99).sign(
                VECTOR_ACK_SIGNATURE_NAMESPACE,
                receipt.body().message(&receipt.predecessor()).as_ref(),
            ),
        ] {
            let forged = VectorAck::from_raw_unchecked(
                receipt.body().clone(),
                receipt.predecessor(),
                receipt.payer_signature().clone(),
                signature,
            );
            assert_eq!(
                forged.verify(context.payment()),
                Err(AckError::InvalidOperatorSignature)
            );
            assert!(matches!(
                check(&forged),
                Err(ChallengeError::Ack(AckError::InvalidOperatorSignature))
            ));
        }
    });
}
