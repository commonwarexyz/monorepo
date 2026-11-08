//! Posting closes, challenging them, withdrawing payouts, and claiming funds after a halt.

use super::*;
use crate::roles::ledger::{Halt, Refusal};
use commonware_clearing::bajillion::{Challenge, Error, Matrix, Processed};
use commonware_cryptography::Digest as _;
use commonware_runtime::Runner as _;

/// The ledger queues nonzero deposits and forced withdrawals, and never takes custody of more than
/// the largest amount.
#[test]
fn test_ledger_queues_requests() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = TestDeployment::new(&context, "queues", 1).await.ledger;

        // Zero amounts are refused.
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

        // Both deposits and the forced withdrawal queue in order for epoch 1, and none is required
        // yet.
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

        // Alice and bob deposit and alice forces a withdrawal while epoch 1 is open.
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
        assert_eq!(
            (summary.deposits.count, summary.forced_withdrawals.count),
            (1, 1)
        );
        assert_eq!(deployment.operator.balance(&account(0)), 9);
        assert_eq!(deployment.ledger.custody(), 29);
    });
}

/// The ledger refuses a certified summary that defers a request queued before its epoch opened.
#[test]
fn test_ledger_rejects_closes_deferring_required_requests() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "deferred", 4).await;

        // After a funding close, the close of epoch 2 defers a deposit and a forced withdrawal
        // queued while epoch 2 was open.
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
                payouts: deployment.validators[0].summary().payouts,
                deposits: Processed {
                    count: deposits,
                    hash: Digest::EMPTY,
                },
                forced_withdrawals: Processed {
                    count: forced_withdrawals,
                    hash: Digest::EMPTY,
                },
            };
            let certificate = certify(&deployment.schemes, &deferring);
            assert!(matches!(
                deployment
                    .ledger
                    .post(&mut context, &deferring, &certificate),
                Err(Refusal::Error(Error::InvalidCount))
            ));
        }
    });
}

/// The ledger posts only a certified summary of the close it expects, following the last post and
/// within its queues.
#[test]
fn test_ledger_posts_only_certified_successors() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "post", 4).await;

        // The close of epoch 1 processes alice's deposit, and validators certify it.
        deployment.ledger.deposit(account(0), 10).unwrap();
        let queue = deployment.ledger.queue();
        let close = close_epoch(&mut deployment.operator, &queue, 1, 0);
        let proposals = deployment.verify(&close).await;
        let summary = *proposals[0].summary();
        let certificate = deployment.certify(&proposals);
        let schemes = &deployment.schemes;
        let ledger = &mut deployment.ledger;

        // The summary must be for the expected epoch and follow the last posted one.
        let wrong = Summary {
            epoch: 2,
            ..summary
        };
        assert!(matches!(
            ledger.post(&mut context, &wrong, &certify(schemes, &wrong)),
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
            ledger.post(&mut context, &wrong, &certify(schemes, &wrong)),
            Err(Refusal::Error(Error::WrongParent))
        ));

        // It must process the queue within its bounds.
        for wrong in [
            Summary {
                deposits: Processed {
                    count: 2,
                    ..summary.deposits
                },
                ..summary
            },
            Summary {
                forced_withdrawals: Processed {
                    count: 1,
                    ..summary.forced_withdrawals
                },
                ..summary
            },
        ] {
            assert!(matches!(
                ledger.post(&mut context, &wrong, &certify(schemes, &wrong)),
                Err(Refusal::Error(Error::InvalidCount))
            ));
        }

        // The certificate must cover this summary.
        let other = Summary {
            balances: Digest::EMPTY,
            ..summary
        };
        assert!(matches!(
            ledger.post(&mut context, &summary, &certify(schemes, &other)),
            Err(Refusal::Error(Error::InvalidCertificate))
        ));

        // The certified summary posts once, and its commit joins the claimed ranges.
        ledger.post(&mut context, &summary, &certificate).unwrap();
        assert_eq!(ledger.epoch(), 2);
        assert_eq!(ledger.balances(), &summary.balances);
        assert_eq!(ledger.matrix(1), Some(&summary.matrix));
        assert_eq!(ledger.ranges(), vec![(0, summary.payouts.size)]);
        assert!(matches!(
            ledger.post(&mut context, &summary, &certificate),
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
            deployment
                .ledger
                .post(&mut context, proposals[0].summary(), &certificate),
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

        // After a funding close, alice pays bob 10 in epoch 2, and the acknowledgement yields
        // bob's receipt.
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
/// post's balances root. The deposits no close processed are paid to it once.
#[test]
fn test_halted_ledger_pays_balance_and_deposit_claims() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "claims", 1).await;

        // Alice and bob are funded, and alice pays carol 3 in epoch 2. Then alice and dave deposit
        // and bob forces out his whole balance, and no close processes those requests.
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

        // The ledger holds every deposit, and the validator proves the balances of alice, bob, and
        // carol as of the last post. Dave has none.
        let custody = deployment.ledger.custody();
        assert_eq!(custody, 41);
        let validator = &deployment.validators[0];
        let mut proofs = Vec::new();
        for index in 0..3 {
            proofs.push(validator.prove(&account(index)).await.unwrap().unwrap());
        }
        assert!(validator.prove(&account(3)).await.unwrap().is_none());
        let [alice_proof, bob_proof, carol_proof] = <[_; 3]>::try_from(proofs).unwrap();

        // Claims wait for a halt, and a halted ledger queues no more requests.
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

        // A proof for another account or of a raised balance is refused. Each account's balance
        // and unprocessed deposits pay once, and the claims together pay out everything the
        // ledger held.
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

/// Across epochs of payments, deposits, and withdrawals, the ledger's custody equals the balances
/// of the last post plus the deposits still queued and the payouts not yet paid. After a halt,
/// claims of the balances and queued deposits, with withdrawals of the payouts still owed, take
/// all of it.
#[test]
fn test_custody_backs_balances_deposits_and_payouts() {
    deterministic::Runner::default().start(|mut context| async move {
        const USERS: u64 = 4;
        let mut deployment = TestDeployment::new(&context, "custody", 1).await;
        for index in 0..USERS {
            deployment.ledger.deposit(account(index), 100).unwrap();
        }
        deployment.close(&mut context).await;
        let mut senders: Vec<_> = (0..USERS).map(sender).collect();
        let mut owed = Vec::new();

        for epoch in 2..=5 {
            // Each user pays the next one. One user asks the operator for a soft withdrawal,
            // another forces a withdrawal through the ledger, and a third deposits.
            for from in 0..USERS {
                let to = (from + 1) % USERS;
                let sender = &mut senders[from as usize];
                let request = sender
                    .send(epoch, amounts(&[(to, 5 + epoch)]), false)
                    .unwrap();
                let acknowledgement = deployment.operator.accept(&request).unwrap();
                sender.acknowledged(&acknowledgement).unwrap();
            }
            let (soft, forced, depositing) =
                (epoch % USERS, (epoch + 1) % USERS, (epoch + 2) % USERS);
            let withdrawal = Withdrawal::sign(&user(soft), &namespace(), epoch, 12, 0);
            deployment.operator.withdraw(withdrawal).unwrap();
            deployment.ledger.withdraw(account(forced), 9).unwrap();
            deployment.ledger.deposit(account(depositing), 20).unwrap();

            // The close processes the queued deposit and forced withdrawal. The payouts of even
            // epochs are withdrawn at once, and those of odd epochs stay owed.
            let queue = deployment.ledger.queue();
            let close = close_epoch(&mut deployment.operator, &queue, 1, 1);
            let proposals = deployment.verify(&close).await;
            let payouts = proposals[0].payouts().clone();
            deployment.post(&mut context, proposals).await;
            if epoch % 2 == 0 {
                deployment.withdraw_payouts(epoch, &payouts).await;
            } else {
                owed.push((epoch, payouts));
            }

            // The close leaves no deposit queued, so the funds held are the posted balances plus
            // the payouts still owed.
            let mut backed: u64 = owed
                .iter()
                .map(|(_, payouts)| payouts.total().unwrap())
                .sum();
            for index in 0..USERS {
                backed += deployment.validators[0]
                    .balance(&account(index))
                    .await
                    .unwrap();
            }
            assert_eq!(deployment.ledger.custody(), backed);
        }

        // A deposit and a forced withdrawal queue after the last post. The halt drops the forced
        // withdrawal, and claims of every balance and of the queued deposit, with withdrawals of
        // the owed payouts, empty the custody.
        deployment.ledger.deposit(account(0), 15).unwrap();
        deployment.ledger.withdraw(account(1), 50).unwrap();
        let held = deployment.ledger.custody();
        deployment.ledger.halt();
        let mut claimed = 0;
        for index in 0..USERS {
            let proof = deployment.validators[0]
                .prove(&account(index))
                .await
                .unwrap();
            claimed += deployment
                .ledger
                .claim(&account(index), proof.as_ref())
                .unwrap();
        }
        for (epoch, payouts) in &owed {
            deployment.withdraw_payouts(*epoch, payouts).await;
            claimed += payouts.total().unwrap();
        }
        assert_eq!(claimed, held);
        assert_eq!(deployment.ledger.custody(), 0);
    });
}

/// A post transfers nothing. Each payout stays in custody until its account withdraws it with a
/// proof, or claims it after a halt, and it is paid once.
#[test]
fn test_payouts_are_withdrawn_once_before_or_after_a_halt() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "payouts", 1).await;

        // Alice and bob force withdrawals of 4 and 6, and the posted close pays them out while the
        // ledger keeps holding the funds.
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

        // The close owes nothing to an account it did not pay out.
        let validator = &deployment.validators[0];
        assert!(
            validator
                .prove_payout(2, &account(2))
                .await
                .unwrap()
                .is_none()
        );
        let alice = validator
            .prove_payout(2, &account(0))
            .await
            .unwrap()
            .unwrap();
        let bob = validator
            .prove_payout(2, &account(1))
            .await
            .unwrap()
            .unwrap();

        // A proof of a raised amount fails, and the payout is withdrawn once.
        let ledger = &mut deployment.ledger;
        let mut forged = alice.clone();
        forged.payout.amount += 1;
        assert!(matches!(
            ledger.withdraw_payout(&forged),
            Err(Refusal::InvalidProof)
        ));
        assert_eq!(ledger.withdraw_payout(&alice).unwrap(), (account(0), 4));
        assert_eq!(ledger.custody(), 16);
        assert!(matches!(
            ledger.withdraw_payout(&alice),
            Err(Refusal::Withdrawn)
        ));

        // After a halt, the payouts root freezes and the remaining payout is claimed against it.
        ledger.halt();
        assert_eq!(ledger.withdraw_payout(&bob).unwrap(), (account(1), 6));
        assert!(matches!(
            ledger.withdraw_payout(&bob),
            Err(Refusal::Withdrawn)
        ));
        assert_eq!(ledger.custody(), 10);
    });
}

/// A payout proof verifies only under the last posted payouts root. After a later post, the account
/// fetches a fresh proof of the same index.
#[test]
fn test_payout_proofs_follow_the_last_post() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "stale", 1).await;

        // Alice's forced withdrawal of 4 pays out in epoch 2, and the post of an idle close of
        // epoch 3 moves the payouts root past the proof served before it.
        deployment.ledger.deposit(account(0), 10).unwrap();
        deployment.close(&mut context).await;
        deployment.ledger.withdraw(account(0), 4).unwrap();
        let queue = deployment.ledger.queue();
        let withdrawing = close_epoch(&mut deployment.operator, &queue, 0, 1);
        let proposals = deployment.verify(&withdrawing).await;
        deployment.post(&mut context, proposals).await;
        let stale = deployment.validators[0]
            .prove_payout(2, &account(0))
            .await
            .unwrap()
            .unwrap();
        let idle = close(&mut deployment.operator);
        let proposals = deployment.verify(&idle).await;
        deployment.post(&mut context, proposals).await;

        // The proof under the earlier root is refused, and a fresh proof of the same index pays.
        assert!(matches!(
            deployment.ledger.withdraw_payout(&stale),
            Err(Refusal::InvalidProof)
        ));
        let fresh = deployment.validators[0]
            .prove_payout(2, &account(0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fresh.index, stale.index);
        assert_eq!(
            deployment.ledger.withdraw_payout(&fresh).unwrap(),
            (account(0), 4)
        );
    });
}

/// Ranges of withdrawn payouts and commits never overlap or touch. With U payouts outstanding,
/// there are at most U + 1 ranges in any withdrawal order, and once every payout is withdrawn
/// the ranges collapse to one range over the whole log.
#[test]
fn test_withdrawn_ranges_stay_compact() {
    for order in ["alternating", "reversed", "strided"] {
        deterministic::Runner::default().start(|mut context| async move {
            let mut deployment = TestDeployment::new(&context, "ranges", 1).await;
            let funded: Vec<_> = (0..9).map(|index| (index, 10 + index)).collect();
            for (index, amount) in &funded {
                deployment.ledger.deposit(account(*index), *amount).unwrap();
            }
            deployment.close(&mut context).await;

            // Two closes pay out every account, the first five and then the other four.
            let mut owed = Vec::new();
            for accounts in [0..5, 5..9] {
                for index in accounts.clone() {
                    deployment.ledger.withdraw(account(index), 3).unwrap();
                }
                let queue = deployment.ledger.queue();
                let count = queue.forced_withdrawals.len() as u64;
                let close = close_epoch(&mut deployment.operator, &queue, 0, count);
                let proposals = deployment.verify(&close).await;
                let summary = deployment.post(&mut context, proposals).await;
                owed.extend(accounts.map(|index| (summary.epoch, account(index))));
            }
            let size = deployment.validators[0].summary().payouts.size;

            // Prove every payout, then order the proofs for this run.
            let mut proofs = Vec::new();
            for (epoch, account) in &owed {
                let validator = &deployment.validators[0];
                proofs.push(
                    validator
                        .prove_payout(*epoch, account)
                        .await
                        .unwrap()
                        .unwrap(),
                );
            }
            proofs.sort_by_key(|proof| proof.index);
            match order {
                "alternating" => proofs.sort_by_key(|proof| (proof.index % 2 == 0, proof.index)),
                "reversed" => proofs.reverse(),
                _ => {
                    // A stride coprime with the 9 payouts visits each once.
                    let sorted = proofs.clone();
                    for (position, proof) in proofs.iter_mut().enumerate() {
                        *proof = sorted[position * 4 % sorted.len()].clone();
                    }
                }
            }

            // After each withdrawal the ranges stay apart and number at most one more than the
            // payouts outstanding. The last leaves one range over the whole log, and the funds held
            // are then the deposits less every payout.
            let mut outstanding = proofs.len();
            let check = |ranges: Vec<(u64, u64)>, outstanding: usize| {
                assert!(ranges.len() <= outstanding + 1, "{order}: {ranges:?}");
                for pair in ranges.windows(2) {
                    assert!(pair[0].1 < pair[1].0, "{order}: {ranges:?}");
                }
            };
            check(deployment.ledger.ranges(), outstanding);
            for proof in &proofs {
                deployment.ledger.withdraw_payout(proof).unwrap();
                outstanding -= 1;
                check(deployment.ledger.ranges(), outstanding);
            }
            assert_eq!(deployment.ledger.ranges(), vec![(0, size)], "{order}");
            let funded: u64 = funded.iter().map(|(_, amount)| amount).sum();
            assert_eq!(
                deployment.ledger.custody(),
                funded - 3 * proofs.len() as u64
            );
        });
    }
}

/// Unpaid payouts stay in custody, so they count toward the largest amount the ledger may hold. A
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
        assert_eq!(deployment.ledger.custody(), u64::MAX - 1);
        let proof = deployment.validators[0]
            .prove_payout(2, &account(0))
            .await
            .unwrap()
            .unwrap();

        // Alice's balance alone leaves room for 11 more, but her unpaid payout of 10 is still held.
        let ledger = &mut deployment.ledger;
        assert!(matches!(
            ledger.deposit(account(1), 2),
            Err(Refusal::Custody)
        ));
        ledger.deposit(account(1), 1).unwrap();
        assert_eq!(ledger.custody(), u64::MAX);

        // Withdrawing the payout frees its room.
        assert_eq!(ledger.withdraw_payout(&proof).unwrap(), (account(0), 10));
        ledger.deposit(account(1), 10).unwrap();
        assert_eq!(ledger.custody(), u64::MAX);
    });
}

mod reorg {
    //! What the finality precondition prevents. The ledger checks a summary's counts but not its
    //! running hashes, so a ledger holding other requests at the positions the counts select posts
    //! it anyway. An auditor holding the ledger's requests sees the mismatch in the running hashes.

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
            let parent = *deployment.validators[0].summary();
            let queue = deployment.ledger.queue();
            let drained = canonical.queue();
            let close = close_epoch(&mut deployment.operator, &queue, 1, 0);
            let proposals = deployment.verify(&close).await;
            let certificate = deployment.certify(&proposals);
            let summary = *proposals[0].summary();
            canonical
                .post(&mut context, &summary, &certificate)
                .unwrap();
            let validator = &mut deployment.validators[0];
            let proposal = proposals.into_iter().next().unwrap();
            validator.apply(proposal, &summary.digest()).await.unwrap();
            assert_eq!(validator.balance(&account(0)).await.unwrap(), 100);
            assert_eq!(validator.balance(&account(1)).await.unwrap(), 0);
            assert_eq!(canonical.custody(), 5);

            // The summary's running hash names the deposit validators read, not the one the
            // canonical ledger drained.
            assert_chained(&parent, &summary, &queue);
            assert_ne!(
                summary.deposits.hash,
                chain(parent.deposits.hash, &drained.deposits)
            );

            // After a halt, the canonical ledger holds too little for alice's credited balance,
            // and bob's deposit is gone.
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
