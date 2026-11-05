//! Checking closes and applying them.

use super::*;
use crate::bajillion::{BalanceProof, Checkpoint, Error, State};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_runtime::{Runner as _, deterministic::FaultConfig};
use commonware_utils::Probability;

/// Returns the row a sender signs for `payments` in `epoch` on top of `previous`.
fn row(
    sender: u64,
    epoch: Epoch,
    payments: Amounts<PublicKey>,
    previous: &Amounts<PublicKey>,
) -> Row<PublicKey> {
    let state = State {
        epoch,
        account: account(sender),
        payments: payments.root::<Sha256>(),
        previous: previous.root::<Sha256>(),
    };
    Row {
        signature: state.sign(&user(sender), &namespace()),
        account: account(sender),
        payments,
    }
}

#[test]
fn test_validators_agree_on_closes() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "agree", 4).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.ledger.deposit(account(1), 50).unwrap();
        let (_, first) = deployment.close(&mut context).await;
        assert_eq!(first.epoch, 1);
        assert_eq!(first.deposits, 2);

        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 30), (2, 20)]), false).unwrap();
        alice
            .acknowledged(&deployment.operator.accept(&request).unwrap())
            .unwrap();
        let (close, second) = deployment.close(&mut context).await;
        assert_eq!(second.parent, first.digest::<Sha256>());
        assert_eq!(second.matrix, close.matrix::<Sha256>().root());
        assert_eq!(deployment.ledger.parent(), &second.digest::<Sha256>());

        // Every validator holds the operator's view of the balances and can prove it.
        for validator in &deployment.validators {
            assert_eq!(validator.summary(), &second);
            for (index, expected) in [(0, 50), (1, 80), (2, 20), (3, 0)] {
                assert_eq!(validator.balance(&account(index)).await.unwrap(), expected);
                assert_eq!(deployment.operator.balance(&account(index)), expected);
                let proof = validator.prove(&account(index)).await.unwrap();
                match proof {
                    Some(proof) => {
                        assert_eq!(BalanceProof::decode(proof.encode()).unwrap(), proof);
                        assert_eq!(proof.balance.get(), expected);
                        assert!(proof.verify::<Sha256, _>(&second.balances, &account(index)));
                        assert!(!proof.verify::<Sha256, _>(&second.balances, &account(3)));
                        assert!(!proof.verify::<Sha256, _>(&first.balances, &account(index)));
                    }
                    None => assert_eq!(expected, 0),
                }
            }
        }
    });
}

#[test]
fn test_validators_reject_invalid_closes() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "invalid", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.close(&mut context).await;
        let operator = operator_key();
        deployment.ledger.deposit(account(1), 5).unwrap();
        deployment.ledger.withdraw(account(0), 1).unwrap();
        let queue = deployment.ledger.queue();
        let validator = &deployment.validators[0];
        let empty = Amounts::empty();
        let valid = row(0, 2, amounts(&[(1, 10)]), &empty);

        // A close of the expected epoch processing the queue is valid.
        let close = sign_close(&operator, 2, vec![valid.clone()], Vec::new(), 1, 1);
        validator.verify(close, &queue).await.unwrap();

        // It must be the expected epoch and process the queue within its bounds.
        let close = sign_close(&operator, 3, vec![valid.clone()], Vec::new(), 1, 1);
        assert!(matches!(
            validator.verify(close, &queue).await,
            Err(Error::WrongEpoch {
                expected: 2,
                found: 3
            })
        ));
        for (deposits, forced) in [(2, 1), (1, 2)] {
            let close = sign_close(&operator, 2, Vec::new(), Vec::new(), deposits, forced);
            assert!(matches!(
                validator.verify(close, &queue).await,
                Err(Error::InvalidCount)
            ));
        }

        // Validators reject a close the operator did not sign before checking any user signature.
        let mut forged = valid.clone();
        forged.signature = user(5).sign(b"forged", b"forged");
        let close = sign_close(&user(5), 2, vec![forged], Vec::new(), 1, 1);
        assert!(matches!(
            validator.verify(close, &queue).await,
            Err(Error::InvalidOperatorSignature)
        ));
        let signed = sign_close(&operator, 2, vec![valid.clone()], Vec::new(), 1, 1);
        let altered = Close::new(
            2,
            signed.rows().to_vec(),
            Vec::new(),
            0,
            1,
            signed.signature().clone(),
        );
        assert!(matches!(
            validator.verify(altered, &queue).await,
            Err(Error::InvalidOperatorSignature)
        ));

        // Every sender must sign its row for this epoch on top of its row in the last close.
        let mut altered = valid.clone();
        altered.payments = amounts(&[(1, 9)]);
        let stale = row(0, 1, amounts(&[(1, 10)]), &empty);
        let unanchored = row(0, 2, amounts(&[(1, 10)]), &amounts(&[(1, 1)]));
        for row in [altered, stale, unanchored] {
            let close = sign_close(&operator, 2, vec![row], Vec::new(), 1, 1);
            assert!(matches!(
                validator.verify(close, &queue).await,
                Err(Error::InvalidSignature)
            ));
        }

        // Soft withdrawals must be for this epoch and signed by their account.
        let wrong_epoch = Withdrawal::sign(&user(0), &namespace(), 3, 1, 0);
        let close = sign_close(&operator, 2, Vec::new(), vec![wrong_epoch], 1, 1);
        assert!(matches!(
            validator.verify(close, &queue).await,
            Err(Error::WrongEpoch {
                expected: 2,
                found: 3
            })
        ));
        let mut forged = Withdrawal::sign(&user(0), &namespace(), 2, 1, 0);
        forged.amount = 2;
        let close = sign_close(&operator, 2, Vec::new(), vec![forged], 1, 1);
        assert!(matches!(
            validator.verify(close, &queue).await,
            Err(Error::InvalidSignature)
        ));

        // No balance may go negative, even when the sender signed the payment.
        let overdraft = row(1, 2, amounts(&[(0, 6)]), &empty);
        let close = sign_close(&operator, 2, vec![overdraft], Vec::new(), 1, 1);
        assert!(matches!(
            validator.verify(close, &queue).await,
            Err(Error::Overdraft)
        ));

        // Checking changes nothing, so the honest close still verifies.
        deployment.close(&mut context).await;
    });
}

#[test]
fn test_pipelined_request_settles_at_most_once() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "settled", 1).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;

        // The operator settles the request's state for epoch 2.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 10)]), true).unwrap();
        deployment.operator.accept(&request).unwrap();
        deployment.close(&mut context).await;

        // A close of epoch 3 that also settles the pipelined state is invalid, because that state
        // commits to a previous map the close of epoch 2 did not settle.
        let pipelined = Row {
            account: account(0),
            payments: amounts(&[(1, 10)]),
            signature: request.pipelined.clone().unwrap(),
        };
        let queue = deployment.ledger.queue();
        let close = sign_close(
            &operator_key(),
            3,
            vec![pipelined.clone()],
            Vec::new(),
            0,
            0,
        );
        assert!(matches!(
            deployment.validators[0].verify(close, &queue).await,
            Err(Error::InvalidSignature)
        ));

        // Had the close of epoch 2 omitted the request, the same state would settle in epoch 3.
        let omitted = context.child("omitted");
        let mut deployment = Deployment::new(&omitted, "omitted", 1).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;
        deployment.close(&mut context).await;
        let queue = deployment.ledger.queue();
        let close = sign_close(&operator_key(), 3, vec![pipelined], Vec::new(), 0, 0);
        let proposals = [deployment.validators[0]
            .verify(close, &queue)
            .await
            .unwrap()];
        assert_eq!(
            proposals[0].matrix().payments(&account(0)),
            Some(&amounts(&[(1, 10)]))
        );
    });
}

#[test]
fn test_validator_applies_only_the_posted_close() {
    deterministic::Runner::default().start(|context| async move {
        let mut deployment = Deployment::new(&context, "competing", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.ledger.deposit(account(1), 20).unwrap();

        // Two closes for epoch 1 differ in how many deposits they process.
        let queue = deployment.ledger.queue();
        let first = sign_close(&operator_key(), 1, Vec::new(), Vec::new(), 1, 0);
        let second = sign_close(&operator_key(), 1, Vec::new(), Vec::new(), 2, 0);
        let validator = deployment.validators.pop().unwrap();
        let first = validator.verify(first, &queue).await.unwrap();
        let second = validator.verify(second, &queue).await.unwrap();
        assert_ne!(first.summary(), second.summary());

        // Applying one makes the other stale.
        let validator = validator.apply(second).await.unwrap();
        assert_eq!(validator.balance(&account(1)).await.unwrap(), 20);
        assert!(matches!(
            validator.apply(first).await,
            Err(Error::StaleProposal)
        ));
    });
}

#[test]
fn test_validator_resumes_from_checkpoint() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "resume", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        let (close, summary) = deployment.close(&mut context).await;
        let applied = Checkpoint::new::<Sha256, _>(summary, &close).unwrap();

        // A checkpoint must pair a summary with the close it summarizes.
        let other = sign_close(
            &operator_key(),
            1,
            vec![row(0, 1, amounts(&[(1, 1)]), &Amounts::empty())],
            Vec::new(),
            0,
            0,
        );
        let later = sign_close(&operator_key(), 2, Vec::new(), Vec::new(), 0, 0);
        for close in [other, later] {
            assert!(matches!(
                Checkpoint::<PublicKey, Digest>::new::<Sha256, _>(summary, &close),
                Err(Error::InvalidCheckpoint)
            ));
        }
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 4)]), false).unwrap();
        deployment.operator.accept(&request).unwrap();

        // The application persisted the next posted close, but the validator stopped before
        // applying it.
        let queue = deployment.ledger.queue();
        let next = deployment.operator.close(&queue, 0, 0).unwrap();
        let proposal = deployment.validators[0]
            .verify(next.clone(), &queue)
            .await
            .unwrap();
        let pending = proposal.checkpoint();
        drop(proposal);
        drop(deployment);

        // The validator resumes from the checkpoint matching its database.
        let open = |label, checkpoints| {
            TestValidator::init(context.child(label), config("resume-0"), checkpoints)
        };
        assert!(matches!(
            open("missing", Vec::new()).await,
            Err(Error::InvalidCheckpoint)
        ));
        assert!(matches!(
            open("ahead", vec![pending.clone()]).await,
            Err(Error::InvalidCheckpoint)
        ));
        let validator = open("resumed", vec![pending.clone(), applied.clone()])
            .await
            .unwrap();
        assert_eq!(validator.summary(), &applied.summary);
        assert_eq!(validator.balance(&account(0)).await.unwrap(), 10);

        // It then applies the close it was applying.
        let proposal = validator.verify(next, &queue).await.unwrap();
        assert_eq!(proposal.summary(), &pending.summary);
        let validator = validator.apply(proposal).await.unwrap();
        assert_eq!(validator.balance(&account(1)).await.unwrap(), 4);
        drop(validator);
        let validator = open("restarted", vec![applied, pending.clone()])
            .await
            .unwrap();
        assert_eq!(validator.summary(), &pending.summary);
    });
}

#[test]
fn test_withdrawals_pay_up_to_the_balance() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "withdrawals", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.ledger.deposit(account(1), 10).unwrap();
        deployment.ledger.deposit(account(2), 10).unwrap();
        deployment.close(&mut context).await;

        // Forced and soft withdrawals add up, and pay out at most the balance.
        deployment.ledger.withdraw(account(0), 3).unwrap();
        deployment.ledger.withdraw(account(1), 25).unwrap();
        for (index, amount, tag) in [(0, 4, 0), (0, 4, 1), (2, 6, 0)] {
            let withdrawal = Withdrawal::sign(&user(index), &namespace(), 2, amount, tag);
            deployment.operator.withdraw(withdrawal.clone()).unwrap();
            deployment.operator.withdraw(withdrawal).unwrap();
        }

        // Payments settle before withdrawals.
        let mut carol = sender(2);
        let request = carol.send(2, amounts(&[(1, 5)]), false).unwrap();
        deployment.operator.accept(&request).unwrap();

        let custody = deployment.ledger.custody();
        let queue = deployment.ledger.queue();
        let close = deployment.operator.close(&queue, 0, 2).unwrap();
        assert_eq!(close.withdrawals().len(), 3);
        let proposals = deployment.verify(&close).await;
        let payouts = proposals[0].payouts().clone();
        assert_eq!(payouts, amounts(&[(0, 10), (1, 15), (2, 5)]));
        deployment.post(&mut context, proposals).await;
        assert_eq!(deployment.ledger.custody(), custody - 30);
        for index in 0..3 {
            assert_eq!(
                deployment.validators[0]
                    .balance(&account(index))
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(deployment.operator.balance(&account(index)), 0);
        }
    });
}

#[test]
fn test_validator_recovers_from_interrupted_apply() {
    let mut resumed = Vec::new();
    for seed in 0..8 {
        let (state, checkpoint) =
            deterministic::Runner::seeded(seed).start_and_recover(|mut context| async move {
                let mut deployment = Deployment::new(&context, "interrupted", 1).await;
                deployment.ledger.deposit(account(0), 10).unwrap();
                let (close, summary) = deployment.close(&mut context).await;
                let applied = Checkpoint::new::<Sha256, _>(summary, &close).unwrap();
                let mut alice = sender(0);
                let request = alice.send(2, amounts(&[(1, 4)]), false).unwrap();
                deployment.operator.accept(&request).unwrap();
                let queue = deployment.ledger.queue();
                let next = deployment.operator.close(&queue, 0, 0).unwrap();
                let validator = deployment.validators.pop().unwrap();
                let proposal = validator.verify(next.clone(), &queue).await.unwrap();
                let pending = proposal.checkpoint();

                // Storage starts failing to sync while the validator applies the close, so the
                // close may or may not become durable before the crash.
                *context.storage_fault_config().write() = FaultConfig {
                    sync_rate: Some(Probability::new(1 + seed % 3, 4).unwrap()),
                    ..Default::default()
                };
                drop(validator.apply(proposal).await);
                (applied, pending, next, queue)
            });
        let (applied, pending, next, queue) = state;
        let caught_up = deterministic::Runner::from(checkpoint).start(|context| async move {
            *context.storage_fault_config().write() = FaultConfig::default();
            let validator = TestValidator::init(
                context.child("recovered"),
                config("interrupted-0"),
                vec![applied.clone(), pending.clone()],
            )
            .await
            .unwrap();

            // The validator resumes from whichever close its database holds and catches up.
            let caught_up = validator.summary() == &applied.summary;
            let validator = if caught_up {
                let proposal = validator.verify(next, &queue).await.unwrap();
                assert_eq!(proposal.summary(), &pending.summary);
                validator.apply(proposal).await.unwrap()
            } else {
                validator
            };
            assert_eq!(validator.summary(), &pending.summary);
            assert_eq!(validator.balance(&account(0)).await.unwrap(), 6);
            assert_eq!(validator.balance(&account(1)).await.unwrap(), 4);
            caught_up
        });
        resumed.push(caught_up);
    }

    // The crashes left some databases before the close and others after it.
    assert!(resumed.contains(&true));
    assert!(resumed.contains(&false));
}

#[test]
fn test_applied_close_is_durable() {
    let (state, checkpoint) =
        deterministic::Runner::default().start_and_recover(|mut context| async move {
            let mut deployment = Deployment::new(&context, "durable", 1).await;
            deployment.ledger.deposit(account(0), 10).unwrap();
            let (close, summary) = deployment.close(&mut context).await;
            let applied = Checkpoint::new::<Sha256, _>(summary, &close).unwrap();
            let mut alice = sender(0);
            let request = alice.send(2, amounts(&[(1, 4)]), false).unwrap();
            deployment.operator.accept(&request).unwrap();
            let queue = deployment.ledger.queue();
            let next = deployment.operator.close(&queue, 0, 0).unwrap();
            let validator = deployment.validators.pop().unwrap();
            let proposal = validator.verify(next, &queue).await.unwrap();
            let pending = proposal.checkpoint();
            drop(validator.apply(proposal).await.unwrap());
            (applied, pending)
        });

    // Once apply returns, the close survives a crash.
    let (applied, pending) = state;
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let validator = TestValidator::init(
            context.child("recovered"),
            config("durable-0"),
            vec![applied, pending.clone()],
        )
        .await
        .unwrap();
        assert_eq!(validator.summary(), &pending.summary);
        assert_eq!(validator.balance(&account(1)).await.unwrap(), 4);
    });
}
