//! Posting closes, challenging them, withdrawing payouts, and claiming funds after a halt.

use super::*;
use crate::roles::ledger::{Halt, Refusal};
use commonware_clearing::bajillion::{Challenge, Error, Matrix};
use commonware_cryptography::Digest as _;
use commonware_runtime::Runner as _;

/// The ledger queues nonzero deposits and forced withdrawals, and never takes custody of more than
/// the largest amount.
#[test]
fn test_ledger_queues_requests() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = TestDeployment::new(&context, "queues", 1).await.ledger;
        assert!(matches!(
            ledger.deposit(account(0), 0),
            Err(Refusal::Error(Error::ZeroAmount))
        ));
        assert!(matches!(
            ledger.withdraw(account(0), 0),
            Err(Refusal::Error(Error::ZeroAmount))
        ));

        // The ledger never holds more than `u64::MAX`, so no balance can overflow.
        ledger.deposit(account(0), u64::MAX - 1).unwrap();
        assert!(matches!(
            ledger.deposit(account(1), 2),
            Err(Refusal::Custody)
        ));
        ledger.deposit(account(1), 1).unwrap();
        ledger.withdraw(account(0), 5).unwrap();
        assert_eq!(ledger.custody(), u64::MAX);

        let queue = ledger.queue();
        assert_eq!(queue.epoch, 1);
        assert_eq!(
            queue.deposits,
            vec![
                Deposit {
                    account: account(0),
                    amount: u64::MAX - 1
                },
                Deposit {
                    account: account(1),
                    amount: 1
                },
            ]
        );
        assert_eq!(queue.forced_withdrawals.len(), 1);
        assert_eq!(
            (queue.required_deposits, queue.required_forced_withdrawals),
            (0, 0)
        );
    });
}

/// A close may defer requests queued while its epoch is open, and the next close must process
/// them.
#[test]
fn test_close_processes_requests_queued_before_its_epoch() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "required", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.ledger.deposit(account(1), 20).unwrap();
        deployment.ledger.withdraw(account(0), 1).unwrap();

        // The close of epoch 1 may defer requests queued while epoch 1 is open.
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 1, 0);
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;

        // The close of epoch 2 must process them, and the operator refuses a close that does not,
        // leaving its epoch open.
        let queue = deployment.ledger.queue();
        assert_eq!(
            (queue.required_deposits, queue.required_forced_withdrawals),
            (1, 1)
        );
        for (deposits, forced_withdrawals) in [(0, 1), (1, 0)] {
            assert!(matches!(
                deployment
                    .operator
                    .close(&queue, deposits, forced_withdrawals),
                Err(Error::InvalidCount)
            ));
        }
        assert_eq!(deployment.operator.epoch(), 2);
        let (_, summary) = deployment.close(&mut context).await;
        assert_eq!((summary.deposits, summary.forced_withdrawals), (1, 1));
        assert_eq!(deployment.operator.balance(&account(0)), 9);
        assert_eq!(deployment.ledger.custody(), 29);
    });
}

/// The ledger refuses a certified summary that defers a request queued before its epoch opened.
#[test]
fn test_ledger_rejects_closes_deferring_required_requests() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "deferred", 4).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.close(&mut context).await;
        deployment.ledger.deposit(account(1), 20).unwrap();
        deployment.ledger.withdraw(account(0), 5).unwrap();
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 0, 0);
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;

        // The deposit and the forced withdrawal were queued while epoch 2 was open, so the close of
        // epoch 3 must process both, even if a certificate covers a summary that defers either.
        for (deposits, forced_withdrawals) in [(0, 1), (1, 0)] {
            let deferring = Summary {
                epoch: 3,
                parent: *deployment.ledger.parent(),
                matrix: Matrix::<PublicKey, Digest, u64>::empty::<Sha256>().root(),
                balances: *deployment.ledger.balances(),
                payouts: Amounts::<PublicKey, u64>::empty().root::<Sha256>(),
                deposits,
                forced_withdrawals,
            };
            let certificate = certify(&deployment.schemes, &deferring);
            assert!(matches!(
                deployment
                    .ledger
                    .post(&mut context, &deferring, &Amounts::empty(), &certificate),
                Err(Refusal::Error(Error::InvalidCount))
            ));
        }
    });
}

/// The ledger posts only a certified summary of the close it expects, following the last post,
/// within its queues and the funds it holds.
#[test]
fn test_ledger_posts_only_certified_successors() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "post", 4).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 1, 0);
        let proposals = deployment.verify(&close).await;
        let summary = *proposals[0].summary();
        let payouts = proposals[0].payouts().clone();
        let certificate = deployment.certify(&proposals);
        let schemes = &deployment.schemes;
        let ledger = &mut deployment.ledger;

        // The summary must be for the expected epoch and follow the last posted one.
        let wrong = Summary {
            epoch: 2,
            ..summary
        };
        assert!(matches!(
            ledger.post(&mut context, &wrong, &payouts, &certify(schemes, &wrong)),
            Err(Refusal::Error(Error::WrongEpoch {
                expected: 1,
                found: 2
            }))
        ));
        let wrong = Summary {
            parent: Digest::EMPTY,
            ..summary
        };
        assert!(matches!(
            ledger.post(&mut context, &wrong, &payouts, &certify(schemes, &wrong)),
            Err(Refusal::Error(Error::WrongParent))
        ));

        // It must process the queue within its bounds.
        for wrong in [
            Summary {
                deposits: 2,
                ..summary
            },
            Summary {
                forced_withdrawals: 1,
                ..summary
            },
        ] {
            assert!(matches!(
                ledger.post(&mut context, &wrong, &payouts, &certify(schemes, &wrong)),
                Err(Refusal::Error(Error::InvalidCount))
            ));
        }

        // The payouts must match the summary and stay within the funds held.
        assert!(matches!(
            ledger.post(&mut context, &summary, &amounts(&[(0, 1)]), &certificate),
            Err(Refusal::Error(Error::InvalidPayouts))
        ));
        let excessive = amounts(&[(0, 11)]);
        let wrong = Summary {
            payouts: excessive.root::<Sha256>(),
            ..summary
        };
        assert!(matches!(
            ledger.post(&mut context, &wrong, &excessive, &certify(schemes, &wrong)),
            Err(Refusal::Custody)
        ));

        // The certificate must cover this summary.
        let other = Summary {
            balances: Digest::EMPTY,
            ..summary
        };
        assert!(matches!(
            ledger.post(&mut context, &summary, &payouts, &certify(schemes, &other)),
            Err(Refusal::Error(Error::InvalidCertificate))
        ));

        ledger
            .post(&mut context, &summary, &payouts, &certificate)
            .unwrap();
        assert_eq!(ledger.epoch(), 2);
        assert_eq!(ledger.balances(), &summary.balances);
        assert_eq!(ledger.matrix(1), Some(&summary.matrix));
        assert!(matches!(
            ledger.post(&mut context, &summary, &payouts, &certificate),
            Err(Refusal::Error(Error::WrongEpoch {
                expected: 2,
                found: 1
            }))
        ));
    });
}

/// A halted ledger posts no close, even one its validators certified.
#[test]
fn test_halted_ledger_posts_nothing() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "halted", 1).await;
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 0, 0);
        let proposals = deployment.verify(&close).await;
        let certificate = deployment.certify(&proposals);
        deployment.ledger.halt();
        assert!(matches!(
            deployment.ledger.post(
                &mut context,
                proposals[0].summary(),
                proposals[0].payouts(),
                &certificate
            ),
            Err(Refusal::Halted)
        ));
        assert_eq!(deployment.ledger.epoch(), 1);
    });
}

/// A challenge halts the ledger only with a receipt of a posted epoch that the posted close
/// credits less than it promised.
#[test]
fn test_challenges_need_a_contradicted_receipt() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "challenge", 1).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
        let receipt = alice
            .acknowledged(&deployment.operator.accept(&request).unwrap())
            .unwrap()
            .pop()
            .unwrap();

        // The receipt's epoch has not closed.
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 0, 0);
        let matrix = close.matrix::<Sha256>();
        let challenge = Challenge {
            receipt: receipt.clone(),
            opening: matrix.open(&account(0), &account(1)),
        };
        assert!(matches!(
            deployment.ledger.challenge(&challenge),
            Err(Refusal::NotPosted)
        ));

        // Once it closes, a close crediting the receipt's amount is not contradicted.
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;
        assert!(matches!(
            deployment.ledger.challenge(&challenge),
            Err(Refusal::Error(Error::NoContradiction))
        ));

        // A receipt raised to 11 fails its proof, and an opening of another pair proves nothing.
        let mut forged = challenge.clone();
        forged.receipt.amount = 11;
        assert!(matches!(
            deployment.ledger.challenge(&forged),
            Err(Refusal::Error(Error::InvalidReceipt))
        ));
        let mut misopened = challenge.clone();
        misopened.opening = matrix.open(&account(0), &account(2));
        assert!(matches!(
            deployment.ledger.challenge(&misopened),
            Err(Refusal::Error(Error::InvalidOpening))
        ));
        assert_eq!(deployment.ledger.halted(), None);
    });
}

/// After a halt, each account claims its balance as of the last post once, proven against that
/// post's balances root, and its unprocessed deposits once.
#[test]
fn test_halted_ledger_pays_balance_and_deposit_claims() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "claims", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.ledger.deposit(account(1), 20).unwrap();
        deployment.close(&mut context).await;
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(2, 3)]), false).unwrap();
        deployment.operator.accept(&request).unwrap();
        deployment.close(&mut context).await;
        deployment.ledger.deposit(account(0), 4).unwrap();
        deployment.ledger.deposit(account(3), 7).unwrap();
        deployment.ledger.withdraw(account(1), 20).unwrap();
        let custody = deployment.ledger.custody();
        assert_eq!(custody, 41);
        let validator = &deployment.validators[0];
        let mut proofs = Vec::new();
        for index in 0..3 {
            proofs.push(validator.prove(&account(index)).await.unwrap().unwrap());
        }
        assert!(validator.prove(&account(3)).await.unwrap().is_none());
        let [alice_proof, bob_proof, carol_proof] = <[_; 3]>::try_from(proofs).unwrap();

        let ledger = &mut deployment.ledger;
        assert!(matches!(
            ledger.claim(&account(0), Some(&alice_proof)),
            Err(Refusal::NotHalted)
        ));
        ledger.halt();
        assert_eq!(ledger.halted(), Some(Halt::Fault));
        assert!(matches!(
            ledger.deposit(account(0), 1),
            Err(Refusal::Halted)
        ));
        assert!(matches!(
            ledger.withdraw(account(0), 1),
            Err(Refusal::Halted)
        ));

        // Each account claims its balance at the last posted close once, proven against that
        // close's balances root, and its unprocessed deposits once.
        assert!(matches!(
            ledger.claim(&account(1), Some(&alice_proof)),
            Err(Refusal::InvalidProof)
        ));
        let mut inflated = bob_proof.clone();
        inflated.balance += 1;
        assert!(matches!(
            ledger.claim(&account(1), Some(&inflated)),
            Err(Refusal::InvalidProof)
        ));
        let mut claimed = 0;
        claimed += ledger.claim(&account(0), None).unwrap();
        assert_eq!(claimed, 4);
        claimed += ledger.claim(&account(0), Some(&alice_proof)).unwrap();
        assert_eq!(claimed, 11);
        assert!(matches!(
            ledger.claim(&account(0), Some(&alice_proof)),
            Err(Refusal::NothingToClaim)
        ));
        let mut forged = alice_proof.clone();
        forged.balance += 1;
        assert!(matches!(
            ledger.claim(&account(0), Some(&forged)),
            Err(Refusal::InvalidProof)
        ));
        claimed += ledger.claim(&account(1), Some(&bob_proof)).unwrap();
        claimed += ledger.claim(&account(2), Some(&carol_proof)).unwrap();
        claimed += ledger.claim(&account(3), None).unwrap();
        assert!(matches!(
            ledger.claim(&account(3), None),
            Err(Refusal::NothingToClaim)
        ));
        assert_eq!(claimed, custody);
        assert_eq!(ledger.custody(), 0);
    });
}

/// A post transfers nothing. Each payout stays in custody until its account withdraws it, once,
/// and a halt does not stop the withdrawal.
#[test]
fn test_payouts_are_withdrawn_once_before_or_after_a_halt() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "payouts", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.ledger.deposit(account(1), 10).unwrap();
        deployment.close(&mut context).await;
        deployment.ledger.withdraw(account(0), 4).unwrap();
        deployment.ledger.withdraw(account(1), 6).unwrap();
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 0, 2);
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;
        assert_eq!(deployment.ledger.custody(), 20);
        assert_eq!(deployment.ledger.owed(&account(0)), 4);
        assert_eq!(deployment.ledger.owed(&account(1)), 6);

        let ledger = &mut deployment.ledger;
        assert!(matches!(
            ledger.withdraw_payout(&account(2)),
            Err(Refusal::NothingOwed)
        ));
        assert_eq!(ledger.withdraw_payout(&account(0)).unwrap(), 4);
        assert!(matches!(
            ledger.withdraw_payout(&account(0)),
            Err(Refusal::NothingOwed)
        ));
        ledger.halt();
        assert_eq!(ledger.withdraw_payout(&account(1)).unwrap(), 6);
        assert_eq!(ledger.custody(), 10);
    });
}

/// Owed payouts stay in custody, so they count toward the largest amount the ledger may hold. A
/// deposit that would take the funds held past it is refused until the payouts are withdrawn.
#[test]
fn test_owed_payouts_count_toward_the_custody_bound() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "bound", 1).await;
        deployment.ledger.deposit(account(0), u64::MAX - 1).unwrap();
        deployment.close(&mut context).await;
        deployment.ledger.withdraw(account(0), 10).unwrap();
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 0, 1);
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;
        assert_eq!(deployment.ledger.owed(&account(0)), 10);
        assert_eq!(deployment.ledger.custody(), u64::MAX - 1);

        // The liability and the unprocessed deposits leave room for 11 more, but the owed payout
        // takes 10 of it.
        let ledger = &mut deployment.ledger;
        assert!(matches!(
            ledger.deposit(account(1), 2),
            Err(Refusal::Custody)
        ));
        ledger.deposit(account(1), 1).unwrap();
        assert_eq!(ledger.custody(), u64::MAX);

        // Withdrawing the payout frees its room.
        assert_eq!(ledger.withdraw_payout(&account(0)).unwrap(), 10);
        ledger.deposit(account(1), 10).unwrap();
        assert_eq!(ledger.custody(), u64::MAX);
    });
}

mod reorg {
    //! What the finality precondition prevents. A summary commits to how many queued requests a
    //! close processes, not to which, so a ledger holding other requests at those queue positions
    //! posts it anyway.

    use super::*;

    /// Validators certify a summary against one ledger's queue, and a ledger holding a different
    /// deposit at the same position posts it, as a reorg of the chain under the ledger could make
    /// happen. The custody then differs from the balances validators credit, so after a halt the
    /// credited account's claim is refused and the other account's deposit is gone.
    #[test]
    fn test_summary_posts_against_other_queue_contents() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut deployment = TestDeployment::new(&context, "reorg", 1).await;
            let (_, verifier) = committee(1);
            let mut canonical = TestLedger::new(
                namespace(),
                operator_key().public_key(),
                verifier,
                deployment.validators[0].summary().balances,
            );
            deployment.ledger.deposit(account(0), 100).unwrap();
            canonical.deposit(account(1), 5).unwrap();

            // The operator and validators read the queue the deployment's ledger holds, and the
            // canonical ledger posts the summary they certify with the same epoch, parent, counts,
            // payouts, and certificate.
            let queue = deployment.ledger.queue();
            let close = close_epoch(&mut deployment.operator, &queue, 1, 0);
            let proposals = deployment.verify(&close).await;
            let certificate = deployment.certify(&proposals);
            let summary = *proposals[0].summary();
            canonical
                .post(&mut context, &summary, proposals[0].payouts(), &certificate)
                .unwrap();
            let validator = &mut deployment.validators[0];
            let proposal = proposals.into_iter().next().unwrap();
            validator
                .apply(proposal, &summary.digest::<Sha256>())
                .await
                .unwrap();
            assert_eq!(validator.balance(&account(0)).await.unwrap(), 100);
            assert_eq!(validator.balance(&account(1)).await.unwrap(), 0);
            assert_eq!(canonical.custody(), 5);

            canonical.halt();
            let proof = validator.prove(&account(0)).await.unwrap().unwrap();
            assert!(matches!(
                canonical.claim(&account(0), Some(&proof)),
                Err(Refusal::Custody)
            ));
            assert!(matches!(
                canonical.claim(&account(1), None),
                Err(Refusal::NothingToClaim)
            ));
        });
    }
}
