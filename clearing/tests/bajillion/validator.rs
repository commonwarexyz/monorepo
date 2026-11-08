//! Checking closes, applying posted closes, and resuming validators.

use super::*;
use commonware_clearing::bajillion::{BalanceProof, Error, ForcedWithdrawal, Payout, PayoutLog};
use commonware_codec::DecodeExt as _;
use commonware_runtime::{Runner as _, deterministic::FaultConfig};
use commonware_utils::Probability;

/// Validators agree on every close, and each holds the operator's balances and proves them.
#[test]
fn test_validators_agree_on_closes() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "agree", 4).await;

        // The funding close processes both deposits.
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.ledger.deposit(account(1), 50).unwrap();
        let (_, first) = deployment.close(&mut context).await;
        assert_eq!(first.epoch, 1);
        assert_eq!(first.deposits.count, 2);

        // Alice pays bob 30 and carol 20, and the close of epoch 2 follows the first and commits
        // to its matrix.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 30), (2, 20)]), false).unwrap();
        alice
            .acknowledged(&deployment.operator.accept(&request).unwrap())
            .unwrap();
        let (close, second) = deployment.close(&mut context).await;
        assert_eq!(second.parent, first.digest());
        assert_eq!(second.matrix, close.matrix::<Sha256>().root());
        assert_eq!(deployment.ledger.parent(), &second.digest());

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
                        assert_eq!(proof.balance, expected);
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

/// A pipelined request whose state for its own epoch settled cannot settle again in the next,
/// and settles there if its own epoch's close omitted it.
#[test]
fn test_pipelined_request_settles_at_most_once() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "settled", 1).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;

        // The close of epoch 2 settles the request's state for epoch 2.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 10)]), true).unwrap();
        deployment.operator.accept(&request).unwrap();
        deployment.close(&mut context).await;

        // A close of epoch 3 that also settles the pipelined state is invalid, because that state
        // commits to a previous map the close of epoch 2 did not settle.
        let pipelined = Row {
            account: account(0),
            payments: amounts(&[(1, 10)]),
            signature: request.pipelined.clone().unwrap().1,
        };
        let queue = deployment.ledger.queue();
        let close = forge(
            &operator_key(),
            &queue,
            vec![pipelined.clone()],
            Vec::new(),
            0,
            0,
        );
        assert!(matches!(
            deployment.validators[0].verify(close, &queue).await,
            Err(Error::InvalidSignature)
        ));

        // Had the close of epoch 2 omitted the request, the operator would admit its state for
        // epoch 3, and validators would certify the close carrying it with its pipelined
        // signature.
        let omitted = context.child("omitted");
        let mut deployment = TestDeployment::new(&omitted, "omitted", 1).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;
        deployment.close(&mut context).await;
        deployment.operator.accept(&request).unwrap();
        let (close, _) = deployment.close(&mut context).await;
        assert_eq!(close.rows(), &[pipelined]);
        deployment
            .check_balances(&[(account(0), 90), (account(1), 10)])
            .await;
    });
}

/// A restarted validator resumes from the posted summary it persisted whose balances root its
/// database holds, found along the chain ending at the ledger's last post. A close it attested
/// that did not post is off that chain, even when it wrote the same balances. A database that
/// applied nothing starts from genesis.
#[test]
fn test_validator_resumes_from_its_records() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "resume", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();

        // The validator attests a candidate for epoch 1 in which alice also pays herself. It
        // writes the same balance as the operator's close, and the operator's close posts.
        let queue = deployment.ledger.queue();
        let paying = vec![row(1, 0, amounts(&[(0, 5)]), &Amounts::empty())];
        let candidate = forge(&operator_key(), &queue, paying, Vec::new(), 1, 0);
        let candidate = deployment.verify(&candidate).await.remove(0);
        let (_, first) = deployment.close(&mut context).await;
        assert_eq!(candidate.summary().balances, first.balances);
        assert_ne!(candidate.summary(), &first);

        // The close of epoch 2 posts, but the validator stops before applying it.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 4)]), false).unwrap();
        deployment.operator.accept(&request).unwrap();
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 0, 0);
        let proposals = deployment.verify(&close).await;
        let certificate = deployment.certify(&proposals);
        let second = *proposals[0].summary();
        deployment
            .ledger
            .post(&mut context, &second, &certificate)
            .unwrap();
        let posted = *deployment.ledger.parent();
        let persisted = deployment.validators[0].persisted().clone();
        drop(proposals);
        drop(deployment);

        // Without its records, the validator cannot tell which close its database applied.
        let open = |label, persisted| {
            TestValidator::init(
                context.child(label),
                config("resume-0"),
                persisted,
                Some(&posted),
            )
        };
        assert!(matches!(
            open("missing", Persisted::default()).await,
            Err(Error::InvalidCheckpoint)
        ));

        // With them, it resumes from the posted close of epoch 1 and replays the close of epoch 2.
        let mut validator = open("resumed", persisted.clone()).await.unwrap();
        assert_eq!(validator.summary(), &first);
        assert_eq!(validator.catch_up(&posted).await.unwrap(), 1);
        assert_eq!(validator.summary(), &second);
        assert_eq!(validator.balance(&account(1)).await.unwrap(), 4);
        drop(validator);
        let mut validator = open("restarted", persisted).await.unwrap();
        assert_eq!(validator.summary(), &second);
        assert_eq!(validator.catch_up(&posted).await.unwrap(), 0);

        // A database that applied nothing starts from genesis, even after the ledger has posted.
        let fresh = TestValidator::init(
            context.child("fresh"),
            config("resume-fresh"),
            Persisted::default(),
            Some(&posted),
        )
        .await
        .unwrap();
        assert_eq!(fresh.summary().epoch, 0);
    });
}

/// Forced and soft withdrawals add up and pay out at most the balance, after the epoch's payments
/// settle, and the payouts stay owed until withdrawn.
#[test]
fn test_withdrawals_pay_up_to_the_balance() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "withdrawals", 1).await;
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

        // The close processes both forced withdrawals and all three soft ones, and the payouts
        // stay in custody until withdrawn.
        let custody = deployment.ledger.custody();
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 0, 2);
        assert_eq!(close.withdrawals().len(), 3);
        let proposals = deployment.verify(&close).await;
        let payouts = proposals[0].payouts().clone();
        assert_eq!(payouts, amounts(&[(0, 10), (1, 15), (2, 5)]));
        deployment.post(&mut context, proposals).await;
        assert_eq!(deployment.ledger.custody(), custody);
        deployment.withdraw_payouts(2, &payouts).await;
        assert_eq!(deployment.ledger.custody(), custody - 30);

        // The withdrawals empty every balance, and validators keep no record of an empty one.
        let validator = &deployment.validators[0];
        for index in 0..3 {
            assert_eq!(validator.balance(&account(index)).await.unwrap(), 0);
            assert!(validator.prove(&account(index)).await.unwrap().is_none());
            assert_eq!(deployment.operator.balance(&account(index)), 0);
        }
    });
}

/// Validators refuse a close that overdrafts an account (O3). Alice's soft withdrawal of epoch 2
/// empties her balance. An operator that countersigned her payment in epoch 3 before fixing that
/// withdrawal has no acceptable close of epoch 3 holding her row.
#[test]
fn test_validators_refuse_a_close_that_overdrafts() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "overdraft", 1).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;

        // The close of epoch 2 pays alice's whole balance out through a soft withdrawal.
        let withdrawal = Withdrawal::sign(&user(0), &namespace(), 2, 100, 0);
        let queue = deployment.ledger.queue();
        let emptying = forge(&operator_key(), &queue, Vec::new(), vec![withdrawal], 0, 0);
        let proposals = deployment.verify(&emptying).await;
        assert_eq!(proposals[0].payouts(), &amounts(&[(0, 100)]));
        deployment.post(&mut context, proposals).await;
        assert_eq!(
            deployment.validators[0].balance(&account(0)).await.unwrap(),
            0
        );

        // A close of epoch 3 settling alice's payment of 100 to bob overdrafts her balance, so
        // the validator refuses it and stays at the close of epoch 2.
        let paying = row(3, 0, amounts(&[(1, 100)]), &Amounts::empty());
        let queue = deployment.ledger.queue();
        let overdrafting = forge(&operator_key(), &queue, vec![paying], Vec::new(), 0, 0);
        let validator = &mut deployment.validators[0];
        assert!(matches!(
            validator.verify(overdrafting, &queue).await,
            Err(Error::Overdraft)
        ));
        assert_eq!(validator.summary().epoch, 2);

        // The same validator then settles a close of epoch 3 without her row.
        let affordable = forge(&operator_key(), &queue, Vec::new(), Vec::new(), 0, 0);
        let proposals = deployment.verify(&affordable).await;
        assert_eq!(deployment.post(&mut context, proposals).await.epoch, 3);
    });
}

/// A close settles credits and debits whose sums exceed the largest amount, as long as every
/// final balance fits.
#[test]
fn test_close_settles_gross_flows_beyond_the_largest_amount() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "gross", 1).await;
        deployment.ledger.deposit(account(0), u64::MAX).unwrap();
        deployment.close(&mut context).await;

        // Alice pays herself and bob her whole balance each, and bob pays her back from the same
        // epoch's receipt. Her credits and debits each exceed `u64::MAX`, but no balance does.
        let empty = Amounts::empty();
        let rows = vec![
            row(2, 0, amounts(&[(0, u64::MAX), (1, u64::MAX)]), &empty),
            row(2, 1, amounts(&[(0, u64::MAX)]), &empty),
        ];
        let queue = deployment.ledger.queue();
        let close = forge(&operator_key(), &queue, rows, Vec::new(), 0, 0);
        let proposals = deployment.verify(&close).await;
        assert!(proposals[0].payouts().is_empty());
        deployment.post(&mut context, proposals).await;
        let validator = &mut deployment.validators[0];
        assert_eq!(validator.balance(&account(0)).await.unwrap(), u64::MAX);
        assert_eq!(validator.balance(&account(1)).await.unwrap(), 0);

        // Withdrawal requests adding up to more than `u64::MAX` pay out the whole balance.
        let withdrawal = ForcedWithdrawal {
            account: account(0),
            amount: u64::MAX,
        };
        let queue = Queue {
            forced_withdrawals: vec![withdrawal.clone(), withdrawal],
            ..deposits(3, &[])
        };
        let close = forge(&operator_key(), &queue, Vec::new(), Vec::new(), 0, 2);
        let proposal = validator.verify(close, &queue).await.unwrap();
        assert_eq!(proposal.payouts(), &amounts(&[(0, u64::MAX)]));

        // A balance above `u64::MAX` does not settle.
        let queue = deposits(3, &[(0, 1)]);
        let close = forge(&operator_key(), &queue, Vec::new(), Vec::new(), 1, 0);
        assert!(matches!(
            validator.verify(close, &queue).await,
            Err(Error::Overflow)
        ));
    });
}

/// Starts a deployment named `name` with one validator and posts a funding close. Alice then pays
/// bob 4, carol deposits 5, and alice forces out 1, and the ledger posts the close of epoch 2 that
/// processes both requests. Returns the deployment without its validator, the validator, and the
/// validator's unapplied proposal for epoch 2.
async fn interrupted(
    context: &mut deterministic::Context,
    name: &str,
) -> (TestDeployment, TestValidator, TestProposal) {
    let mut deployment = TestDeployment::new(context, name, 1).await;
    deployment.ledger.deposit(account(0), 10).unwrap();
    deployment.close(context).await;
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 4)]), false).unwrap();
    deployment.operator.accept(&request).unwrap();
    deployment.ledger.deposit(account(2), 5).unwrap();
    deployment.ledger.withdraw(account(0), 1).unwrap();
    let queue = deployment.ledger.queue();
    let close = close_epoch(&mut deployment.operator, &queue, 1, 1);
    let mut proposals = deployment.verify(&close).await;
    let certificate = deployment.certify(&proposals);
    let summary = *proposals[0].summary();
    deployment
        .ledger
        .post(context, &summary, &certificate)
        .unwrap();
    assert!(deployment.ledger.queue().deposits.is_empty());
    let validator = deployment.validators.pop().unwrap();
    (deployment, validator, proposals.remove(0))
}

/// Checks that `validator` holds the balances after the close of epoch 2 of [interrupted].
async fn check_epoch_2(validator: &TestValidator) {
    for (index, expected) in [(0, 5), (1, 4), (2, 5)] {
        assert_eq!(validator.balance(&account(index)).await.unwrap(), expected);
    }
}

/// A validator that crashes while applying a posted close recovers from its records and the
/// ledger's final state alone. The ledger has drained the deposit the close processed, so the
/// validator replays the close from the prefix it persisted. After a later post, it still serves
/// openings of the recovered close.
#[test]
fn test_validator_recovers_from_interrupted_apply() {
    let mut resumed = Vec::new();
    for seed in 0..8 {
        let (state, checkpoint) =
            deterministic::Runner::seeded(seed).start_and_recover(|mut context| async move {
                let (deployment, mut validator, proposal) =
                    interrupted(&mut context, "interrupted").await;
                let persisted = validator.persisted().clone();

                // Storage starts failing to sync while the validator applies the close, so the
                // close may or may not become durable before the crash.
                *context.storage_fault_config().write() = FaultConfig {
                    sync_rate: Some(Probability::new(1 + seed % 3, 4).unwrap()),
                    ..Default::default()
                };
                let posted = proposal.summary().digest();
                drop(validator.apply(proposal, &posted).await);
                let TestDeployment {
                    operator,
                    schemes,
                    ledger,
                    ..
                } = deployment;
                (persisted, operator, schemes, ledger)
            });
        let (persisted, operator, schemes, ledger) = state;
        let behind = deterministic::Runner::from(checkpoint).start(|mut context| async move {
            *context.storage_fault_config().write() = FaultConfig::default();
            let posted = *ledger.parent();
            let mut validator = TestValidator::init(
                context.child("recovered"),
                config("interrupted-0"),
                persisted,
                Some(&posted),
            )
            .await
            .unwrap();

            // The validator resumes from whichever posted close its database holds and replays
            // the rest.
            let behind = validator.summary().epoch == 1;
            let replayed = validator.catch_up(&posted).await.unwrap();
            assert_eq!(replayed, usize::from(behind));
            assert_eq!(validator.summary().digest(), posted);
            check_epoch_2(&validator).await;

            // After the close of epoch 3 posts, the validator still opens alice's payment to bob
            // in epoch 2 under the root the ledger posted.
            let mut deployment = TestDeployment {
                operator,
                validators: vec![validator],
                schemes,
                ledger,
            };
            deployment.close(&mut context).await;
            let opening = deployment.validators[0]
                .open(2, &account(0), &account(1))
                .unwrap();
            let root = deployment.ledger.matrix(2).unwrap();
            assert_eq!(
                opening
                    .verify::<Sha256>(root, &account(0), &account(1))
                    .unwrap(),
                4
            );
            behind
        });
        resumed.push(behind);
    }

    // The crashes left some databases before the close and others after it.
    assert!(resumed.contains(&true));
    assert!(resumed.contains(&false));
}

/// Once the validator applies a posted close, the close survives a crash, and the validator
/// resumes from it with nothing to replay.
#[test]
fn test_applied_close_is_durable() {
    let (state, checkpoint) =
        deterministic::Runner::default().start_and_recover(|mut context| async move {
            let (deployment, mut validator, proposal) = interrupted(&mut context, "durable").await;
            let posted = proposal.summary().digest();
            validator.apply(proposal, &posted).await.unwrap();
            (validator.persisted().clone(), *deployment.ledger.parent())
        });
    let (persisted, posted) = state;
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let mut validator = TestValidator::init(
            context.child("recovered"),
            config("durable-0"),
            persisted,
            Some(&posted),
        )
        .await
        .unwrap();
        assert_eq!(validator.summary().digest(), posted);
        assert_eq!(validator.catch_up(&posted).await.unwrap(), 0);
        check_epoch_2(&validator).await;
    });
}

/// A validator that crashes after its payout log commits a posted close, but before its balances
/// apply it, restarts with the log one close ahead. It reopens the log at the payouts size its
/// balances' close certifies, replays the close, and proves the payout the close owes.
#[test]
fn test_validator_realigns_its_payout_log_after_a_crash() {
    deterministic::Runner::default().start(|mut context| async move {
        let (mut deployment, validator, proposal) = interrupted(&mut context, "realign").await;
        let persisted = validator.persisted().clone();
        let first = *validator.summary();
        let second = *proposal.summary();
        drop(validator);

        // The crash leaves the log at the close of epoch 2 and the balances at the close of
        // epoch 1.
        let config = config("realign-0");
        let log = PayoutLog::<_, PublicKey, Sha256, Sequential, u64>::init(
            context.child("crashed"),
            config.payouts.clone(),
            None,
        )
        .await
        .unwrap();
        let batch = Payout::stage(&log, proposal.payouts()).await.unwrap();
        let log = log
            .apply_batch(batch)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        assert_eq!(log.root(), second.payouts.root);
        drop(log);

        // The restart resumes from epoch 1, replays epoch 2, and proves alice's payout of 1.
        let posted = *deployment.ledger.parent();
        let mut validator =
            TestValidator::init(context.child("restarted"), config, persisted, Some(&posted))
                .await
                .unwrap();
        assert_eq!(validator.summary(), &first);
        assert_eq!(validator.catch_up(&posted).await.unwrap(), 1);
        assert_eq!(validator.summary(), &second);
        check_epoch_2(&validator).await;
        let proof = validator
            .prove_payout(2, &account(0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            deployment.ledger.withdraw_payout(&proof).unwrap(),
            (account(0), 1)
        );
    });
}
