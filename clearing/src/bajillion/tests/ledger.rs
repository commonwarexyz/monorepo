//! Posting closes, challenging them, and refunding after a halt.

use super::*;
use crate::bajillion::{Challenge, Error, Halt};
use commonware_cryptography::Digest as _;
use commonware_runtime::Runner as _;

#[test]
fn test_ledger_queues_requests() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = Deployment::new(&context, "queues", 1).await.ledger;
        assert!(matches!(
            ledger.deposit(account(0), 0),
            Err(Error::ZeroAmount)
        ));
        assert!(matches!(
            ledger.withdraw(account(0), 0),
            Err(Error::ZeroAmount)
        ));

        // The ledger never holds more than `u64::MAX`, so no balance can overflow.
        ledger.deposit(account(0), u64::MAX - 1).unwrap();
        assert!(matches!(ledger.deposit(account(1), 2), Err(Error::Custody)));
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

#[test]
fn test_close_processes_requests_queued_before_its_epoch() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "required", 1).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.ledger.deposit(account(1), 20).unwrap();
        deployment.ledger.withdraw(account(0), 1).unwrap();

        // The close of epoch 1 may defer requests queued while epoch 1 is open.
        let queue = deployment.ledger.queue();
        let close = deployment.operator.close(&queue, 1, 0).unwrap();
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;

        // The close of epoch 2 must process them.
        let queue = deployment.ledger.queue();
        assert_eq!(
            (queue.required_deposits, queue.required_forced_withdrawals),
            (1, 1)
        );
        assert!(matches!(
            deployment.operator.close(&queue, 0, 1),
            Err(Error::InvalidCount)
        ));
        assert!(matches!(
            deployment.operator.close(&queue, 1, 0),
            Err(Error::InvalidCount)
        ));
        let (_, summary) = deployment.close(&mut context).await;
        assert_eq!((summary.deposits, summary.forced_withdrawals), (1, 1));
        assert_eq!(deployment.operator.balance(&account(0)), 9);
        assert_eq!(deployment.ledger.custody(), 29);
    });
}

#[test]
fn test_ledger_rejects_closes_deferring_required_requests() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "deferred", 4).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.close(&mut context).await;
        deployment.ledger.deposit(account(1), 20).unwrap();
        let queue = deployment.ledger.queue();
        let close = deployment.operator.close(&queue, 0, 0).unwrap();
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;

        // The deposit was queued while epoch 2 was open, so the close of epoch 3 must process it,
        // even if a certificate covers a summary that does not.
        let deferring = Summary {
            epoch: 3,
            parent: *deployment.ledger.parent(),
            matrix: Matrix::<PublicKey, Digest>::empty::<Sha256>().root(),
            balances: *deployment.ledger.balances(),
            payouts: Amounts::<PublicKey>::empty().root::<Sha256>(),
            deposits: 0,
            forced_withdrawals: 0,
        };
        let certificate = certify(&deployment.schemes, &deferring);
        assert!(matches!(
            deployment
                .ledger
                .post(&mut context, &deferring, &Amounts::empty(), &certificate),
            Err(Error::InvalidCount)
        ));
    });
}

#[test]
fn test_ledger_posts_only_certified_successors() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "post", 4).await;
        deployment.ledger.deposit(account(0), 10).unwrap();
        let queue = deployment.ledger.queue();
        let close = deployment.operator.close(&queue, 1, 0).unwrap();
        let proposals = deployment.verify(&close).await;
        let summary = *proposals[0].summary();
        let payouts = proposals[0].payouts().clone();
        let certificate = deployment.certify(&proposals);

        let ledger = &mut deployment.ledger;

        // The summary must be for the expected epoch and follow the last posted one.
        let wrong = Summary {
            epoch: 2,
            ..summary
        };
        assert!(matches!(
            ledger.post(
                &mut context,
                &wrong,
                &payouts,
                &certify(&deployment.schemes, &wrong)
            ),
            Err(Error::WrongEpoch {
                expected: 1,
                found: 2
            })
        ));
        let wrong = Summary {
            parent: Digest::EMPTY,
            ..summary
        };
        assert!(matches!(
            ledger.post(
                &mut context,
                &wrong,
                &payouts,
                &certify(&deployment.schemes, &wrong)
            ),
            Err(Error::WrongParent)
        ));

        // It must process the queue within its bounds.
        let wrong = Summary {
            deposits: 2,
            ..summary
        };
        assert!(matches!(
            ledger.post(
                &mut context,
                &wrong,
                &payouts,
                &certify(&deployment.schemes, &wrong)
            ),
            Err(Error::InvalidCount)
        ));

        // The payouts must match the summary and stay within the funds held.
        assert!(matches!(
            ledger.post(&mut context, &summary, &amounts(&[(0, 1)]), &certificate),
            Err(Error::InvalidPayouts)
        ));
        let excessive = amounts(&[(0, 11)]);
        let wrong = Summary {
            payouts: excessive.root::<Sha256>(),
            ..summary
        };
        assert!(matches!(
            ledger.post(
                &mut context,
                &wrong,
                &excessive,
                &certify(&deployment.schemes, &wrong)
            ),
            Err(Error::Custody)
        ));

        // The certificate must cover this summary.
        let other = Summary {
            balances: Digest::EMPTY,
            ..summary
        };
        assert!(matches!(
            ledger.post(
                &mut context,
                &summary,
                &payouts,
                &certify(&deployment.schemes, &other)
            ),
            Err(Error::InvalidCertificate)
        ));

        ledger
            .post(&mut context, &summary, &payouts, &certificate)
            .unwrap();
        assert_eq!(ledger.epoch(), 2);
        assert_eq!(ledger.balances(), &summary.balances);
        assert_eq!(ledger.matrix(1), Some(&summary.matrix));
        assert!(matches!(
            ledger.post(&mut context, &summary, &payouts, &certificate),
            Err(Error::WrongEpoch {
                expected: 2,
                found: 1
            })
        ));
    });
}

#[test]
fn test_challenges_need_a_contradicted_receipt() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "challenge", 1).await;
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
        let close = deployment.operator.close(&queue, 0, 0).unwrap();
        let matrix = close.matrix::<Sha256>();
        let challenge = Challenge {
            receipt: receipt.clone(),
            opening: matrix.open(&account(0), &account(1)),
        };
        assert!(matches!(
            deployment.ledger.challenge(&challenge),
            Err(Error::NotClosed)
        ));

        // Once it closes, a close crediting the receipt's amount is not contradicted.
        let proposals = deployment.verify(&close).await;
        deployment.post(&mut context, proposals).await;
        assert!(matches!(
            deployment.ledger.challenge(&challenge),
            Err(Error::NoContradiction)
        ));

        // Receipts the operator did not countersign and openings of other pairs prove nothing.
        let mut forged = challenge.clone();
        forged.receipt.amount = 11;
        assert!(matches!(
            deployment.ledger.challenge(&forged),
            Err(Error::InvalidReceipt)
        ));
        let mut misopened = challenge.clone();
        misopened.opening = matrix.open(&account(0), &account(2));
        assert!(matches!(
            deployment.ledger.challenge(&misopened),
            Err(Error::InvalidOpening)
        ));
        assert_eq!(deployment.ledger.halted(), None);
    });
}

#[test]
fn test_halted_ledger_refunds_balances_and_deposits() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "refunds", 1).await;
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
            ledger.refund(&account(0), Some(&alice_proof)),
            Err(Error::NotHalted)
        ));
        ledger.halt();
        assert_eq!(ledger.halted(), Some(Halt::Fault));
        ledger.halt();
        assert_eq!(ledger.halted(), Some(Halt::Fault));
        assert!(matches!(ledger.deposit(account(0), 1), Err(Error::Halted)));
        assert!(matches!(ledger.withdraw(account(0), 1), Err(Error::Halted)));

        // Each account recovers its balance at the last posted close once, proven against that
        // close's balances root, and its unprocessed deposits once.
        assert!(matches!(
            ledger.refund(&account(1), Some(&alice_proof)),
            Err(Error::InvalidBalanceProof)
        ));
        let mut inflated = bob_proof.clone();
        inflated.balance = inflated.balance.checked_add(1).unwrap();
        assert!(matches!(
            ledger.refund(&account(1), Some(&inflated)),
            Err(Error::InvalidBalanceProof)
        ));
        let mut refunded = 0;
        refunded += ledger.refund(&account(0), None).unwrap();
        assert_eq!(refunded, 4);
        refunded += ledger.refund(&account(0), Some(&alice_proof)).unwrap();
        assert_eq!(refunded, 11);
        assert!(matches!(
            ledger.refund(&account(0), Some(&alice_proof)),
            Err(Error::NothingToRefund)
        ));
        refunded += ledger.refund(&account(1), Some(&bob_proof)).unwrap();
        refunded += ledger.refund(&account(2), Some(&carol_proof)).unwrap();
        refunded += ledger.refund(&account(3), None).unwrap();
        assert!(matches!(
            ledger.refund(&account(3), None),
            Err(Error::NothingToRefund)
        ));
        assert_eq!(refunded, custody);
        assert_eq!(ledger.custody(), 0);
    });
}
