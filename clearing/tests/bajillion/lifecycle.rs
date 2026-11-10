//! Deployments running over several epochs.

use super::*;
use crate::roles::{
    ledger::{Halt, Refusal},
    validator::Refusal as Verifying,
};
use commonware_clearing::bajillion::{Challenge, ChallengeError, CheckError};
use commonware_runtime::Runner as _;

/// Over several epochs of payments, soft and forced withdrawals, and deposits, every balance and
/// payout matches one computed by hand, and the operator, validators, and ledger agree.
#[test]
fn test_epochs_settle_payments_and_withdrawals() {
    deterministic::Runner::default().start(|mut context| async move {
        const USERS: u64 = 6;
        let mut deployment = TestDeployment::new(&context, "epochs", 4).await;
        let mut senders: Vec<_> = (0..USERS).map(sender).collect();
        let mut receivers: Vec<_> = (0..USERS).map(|index| receiver(index, 1)).collect();

        // Every user deposits 1,000. After the funding close, the operator, validators, and
        // ledger agree on every balance.
        for index in 0..USERS {
            deployment.ledger.deposit(account(index), 1_000).unwrap();
        }
        let mut parent = *deployment.validators[0].summary();
        let queue = deployment.ledger.queue();
        let (_, summary) = deployment.close(&mut context).await;
        assert_chained(&parent, &summary, &queue);
        parent = summary;
        for receiver in &mut receivers {
            receiver.posted(1);
        }
        let mut expected = vec![1_000; slot(USERS)];
        let held = |expected: &[u64]| {
            (0..USERS)
                .map(|index| (account(index), expected[slot(index)]))
                .collect::<Vec<_>>()
        };
        deployment.check_balances(&held(&expected)).await;

        for epoch in 2..=6 {
            // Every user pays the next two users, one request each. Each amount depends on the
            // payer, so no user's payments and receipts cancel.
            for from in 0..USERS {
                for offset in [1, 2] {
                    let to = (from + offset) % USERS;
                    let amount = epoch * 10 + offset + from;
                    expected[slot(from)] -= amount;
                    expected[slot(to)] += amount;
                    let sender = &mut senders[slot(from)];
                    let request = sender.send(epoch, amounts(&[(to, amount)])).unwrap();
                    let acknowledgement = deployment.operator.accept(&request).unwrap();
                    for receipt in sender.acknowledged(&acknowledgement).unwrap() {
                        receivers[slot(to)].receive(receipt).unwrap();
                    }
                }
            }

            // One user withdraws through the operator, another through the ledger, and a third
            // deposits. Every balance covers its withdrawal, so each pays out in full.
            let (soft, forced, deposited) =
                (epoch % USERS, (epoch + 3) % USERS, (epoch + 1) % USERS);
            let withdrawal = Withdrawal::sign(&user(soft), &namespace(), epoch, 25, 0);
            deployment.operator.withdraw(withdrawal).unwrap();
            deployment.ledger.withdraw(account(forced), 15).unwrap();
            deployment.ledger.deposit(account(deposited), 40).unwrap();
            expected[slot(soft)] -= 25;
            expected[slot(forced)] -= 15;
            expected[slot(deposited)] += 40;

            // The close processes the deposit and the forced withdrawal, and appends the payouts
            // of both withdrawals and its commit to the payout log.
            let queue = deployment.ledger.queue();
            let (close, summary) = deployment.close(&mut context).await;
            assert_eq!(summary.epoch, epoch);
            assert_eq!(
                (summary.deposits.count, summary.forced_withdrawals.count),
                (1, 1)
            );
            assert_eq!(summary.payouts.size, parent.payouts.size + 3);

            // The running hashes extend the parent's over the requests the close processed.
            assert_chained(&parent, &summary, &queue);
            parent = summary;

            // Every receiver records the post and finds each payment it was promised.
            let matrix = close.matrix::<Sha256>(&Sequential);
            for receiver in &mut receivers {
                receiver.posted(epoch);
                let senders: Vec<_> = receiver
                    .receipts(epoch)
                    .map(|receipt| receipt.state.account.clone())
                    .collect();
                assert_eq!(senders.len(), 2);
                for sender in senders {
                    let opening = matrix.open(&sender, receiver.account());
                    assert!(
                        receiver
                            .audit(epoch, &summary.matrix, &sender, &opening)
                            .unwrap()
                            .is_none()
                    );
                }
                receiver.prune(epoch);
            }
            for sender in &mut senders {
                sender.prune(epoch);
            }
            deployment.check_balances(&held(&expected)).await;
        }
    });
}

/// A posted close that omits a preconfirmed payment lets its receiver halt the ledger, and every
/// account then claims the balance of the last posted close.
#[test]
fn test_omitted_payment_halts_ledger() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "omitted", 4).await;

        // Alice and bob are funded in epoch 1.
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.ledger.deposit(account(1), 100).unwrap();
        deployment.close(&mut context).await;

        // The operator preconfirms a payment to bob.
        let mut alice = sender(0);
        let mut bob = receiver(1, 2);
        let request = alice.send(2, amounts(&[(1, 30)])).unwrap();
        let receipt = alice
            .acknowledged(&deployment.operator.accept(&request).unwrap())
            .unwrap()
            .pop()
            .unwrap();
        bob.receive(receipt).unwrap();

        // It then closes the epoch without it. Nothing else about the close is wrong, so validators
        // certify it and it posts.
        let queue = deployment.ledger.queue();
        let omitting = forge(&operator_key(), &queue, Vec::new(), Vec::new(), 0, 0);
        let proposals = deployment.verify(&omitting).await;
        let summary = deployment.post(&mut context, proposals).await;
        bob.posted(2);

        // Bob finds the omission in the posted matrix and halts the ledger.
        let opening = omitting
            .matrix::<Sha256>(&Sequential)
            .open(&account(0), &account(1));
        let challenge = bob
            .audit(2, &summary.matrix, &account(0), &opening)
            .unwrap()
            .unwrap();
        deployment.ledger.challenge(&challenge).unwrap();
        assert_eq!(
            deployment.ledger.halted(),
            Some(Halt::Challenge { epoch: 2 })
        );
        assert!(matches!(
            deployment.ledger.challenge(&challenge),
            Err(Refusal::Halted)
        ));

        // Halting again, as a deployment's own policy might, keeps the challenge as the reason.
        deployment.ledger.halt();
        assert_eq!(
            deployment.ledger.halted(),
            Some(Halt::Challenge { epoch: 2 })
        );

        // Everyone claims the balances the posted closes finalized.
        let custody = deployment.ledger.custody();
        let mut claimed = 0;
        for index in 0..2 {
            let proof = deployment.validators[0]
                .prove(&account(index))
                .await
                .unwrap()
                .unwrap();
            claimed += deployment
                .ledger
                .claim(&account(index), Some(&proof))
                .unwrap();
        }
        assert_eq!(claimed, 200);
        assert_eq!(claimed, custody);
    });
}

/// A challenge is judged against the posted close of its receipt's epoch, even after later closes
/// with other payment matrices posted.
#[test]
fn test_late_challenge_halts_after_later_closes() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "late", 4).await;

        // After a funding close, alice pays bob 30 and carol pays bob 10 in epoch 2, and bob
        // holds alice's receipt.
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.ledger.deposit(account(3), 100).unwrap();
        deployment.close(&mut context).await;
        let mut alice = sender(0);
        let mut carol = sender(3);
        let mut bob = receiver(1, 2);
        let request = alice.send(2, amounts(&[(1, 30)])).unwrap();
        let receipt = alice
            .acknowledged(&deployment.operator.accept(&request).unwrap())
            .unwrap()
            .pop()
            .unwrap();
        bob.receive(receipt).unwrap();
        let paid = carol.send(2, amounts(&[(1, 10)])).unwrap();
        let credited = carol
            .acknowledged(&deployment.operator.accept(&paid).unwrap())
            .unwrap()
            .pop()
            .unwrap();

        // The close of epoch 2 omits alice's payment and settles carol's. The close of epoch 3,
        // in which alice pays bob as much again, posts before bob checks the close of epoch 2.
        let carol_row = Row {
            account: account(3),
            payments: paid.batch.clone(),
            signature: paid.signatures.current.clone(),
        };
        let queue = deployment.ledger.queue();
        let omitting = forge(&operator_key(), &queue, vec![carol_row], Vec::new(), 0, 0);
        let proposals = deployment.verify(&omitting).await;
        let omitted = deployment.post(&mut context, proposals).await;
        bob.posted(2);
        deployment.ledger.deposit(account(2), 50).unwrap();
        let rows = vec![row(3, 0, amounts(&[(1, 30)]), &Amounts::empty())];
        let queue = deployment.ledger.queue();
        let next = forge(&operator_key(), &queue, rows, Vec::new(), 1, 0);
        let proposals = deployment.verify(&next).await;
        let latest = deployment.post(&mut context, proposals).await;
        bob.posted(3);
        assert_ne!(latest.matrix, omitted.matrix);

        // A receipt the close of its epoch credits in full shows no contradiction.
        let matrix = omitting.matrix::<Sha256>(&Sequential);
        let settled = Challenge {
            receipt: credited,
            opening: matrix.open(&account(3), &account(1)),
        };
        assert!(matches!(
            deployment.ledger.challenge(&settled),
            Err(Refusal::Challenge(ChallengeError::NoContradiction))
        ));

        // The omitted payment still halts the ledger. Claims follow the balances of the latest
        // close.
        let opening = matrix.open(&account(0), &account(1));
        let challenge = bob
            .audit(2, &omitted.matrix, &account(0), &opening)
            .unwrap()
            .unwrap();
        deployment.ledger.challenge(&challenge).unwrap();
        assert_eq!(deployment.ledger.balances(), &latest.balances);
        let proof = deployment.validators[0]
            .prove(&account(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            deployment.ledger.claim(&account(2), Some(&proof)).unwrap(),
            50
        );
    });
}

/// A posted close that settles a state earlier than the one a receipt carries credits the receiver
/// less than the receipt promised, so the receiver's challenge halts the ledger.
#[test]
fn test_partial_credit_halts_ledger() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "partial", 4).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;

        // Alice pays bob 5 and then 5 more, and bob holds the receipt for the cumulative 10.
        let mut alice = sender(0);
        let mut bob = receiver(1, 2);
        let first = alice.send(2, amounts(&[(1, 5)])).unwrap();
        alice
            .acknowledged(&deployment.operator.accept(&first).unwrap())
            .unwrap();
        let second = alice.send(2, amounts(&[(1, 5)])).unwrap();
        let receipt = alice
            .acknowledged(&deployment.operator.accept(&second).unwrap())
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(bob.receive(receipt).unwrap(), 10);

        // The close settles an earlier state alice did sign, so it posts.
        let earlier = Row {
            account: account(0),
            payments: amounts(&[(1, 5)]),
            signature: first.signatures.current,
        };
        let queue = deployment.ledger.queue();
        let underpaying = forge(&operator_key(), &queue, vec![earlier], Vec::new(), 0, 0);
        let proposals = deployment.verify(&underpaying).await;
        let summary = deployment.post(&mut context, proposals).await;
        bob.posted(2);

        // Bob is credited 5 of the 10 promised, so his challenge halts the ledger.
        let opening = underpaying
            .matrix::<Sha256>(&Sequential)
            .open(&account(0), &account(1));
        assert_eq!(
            opening
                .verify::<Sha256>(&summary.matrix, &account(0), &account(1))
                .unwrap(),
            5
        );
        let challenge = bob
            .audit(2, &summary.matrix, &account(0), &opening)
            .unwrap()
            .unwrap();
        deployment.ledger.challenge(&challenge).unwrap();
        assert_eq!(
            deployment.ledger.halted(),
            Some(Halt::Challenge { epoch: 2 })
        );
    });
}

/// A countersigned map keeps its predecessor when an earlier post contradicts the operator's
/// acknowledgement. Extending that map cannot authorize its payments under the posted root.
#[test]
fn test_sender_keeps_its_epoch_anchor_after_a_conflicting_post() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = TestDeployment::new(&context, "conflicting_post", 4).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;
        let mut alice = sender(0);
        let batch = amounts(&[(1, 10)]);
        let request = alice.send(2, batch.clone()).unwrap();

        // The operator preconfirms the next state while retaining the signed current state.
        let next = State {
            epoch: 3,
            account: account(0),
            payments: batch.root::<Sha256>(),
            previous: request.latest,
        };
        alice
            .acknowledged(&next.acknowledge(&operator_key(), &namespace()))
            .unwrap();

        // The current state pays bob in epoch 2, making the next state's predecessor invalid.
        let queue = deployment.ledger.queue();
        let current = forge(
            &operator_key(),
            &queue,
            vec![Row {
                account: account(0),
                payments: batch,
                signature: request.signatures.current,
            }],
            Vec::new(),
            0,
            0,
        );
        let proposals = deployment.verify(&current).await;
        let summary = deployment.post(&mut context, proposals).await;
        let opening = current
            .matrix::<Sha256>(&Sequential)
            .open(&account(0), &account(0));
        assert_eq!(alice.posted(2, &summary.matrix, &opening).unwrap(), None);

        // A new payment to carol must not make bob's payment settle again in epoch 3.
        let successor = alice.send(3, amounts(&[(2, 1)])).unwrap();
        let queue = deployment.ledger.queue();
        let repeated = forge(
            &operator_key(),
            &queue,
            vec![Row {
                account: account(0),
                payments: amounts(&[(1, 10), (2, 1)]),
                signature: successor.signatures.current,
            }],
            Vec::new(),
            0,
            0,
        );
        for validator in &mut deployment.validators {
            assert_eq!(validator.balance(&account(0)).await.unwrap(), 90);
            assert_eq!(validator.balance(&account(1)).await.unwrap(), 10);
            assert!(matches!(
                validator.verify(repeated.clone(), &queue).await,
                Err(Verifying::Check(CheckError::InvalidSignature))
            ));
        }
    });
}

mod schemes {
    //! A deployment whose users, operator, and validators sign with three different schemes, and
    //! whose amounts exceed `u128::MAX`.

    use super::*;
    use commonware_clearing::bajillion::BalanceProof;
    use commonware_codec::{DecodeExt as _, U256};
    use commonware_cryptography::{
        bls12381,
        secp256r1::{self, standard},
    };

    /// secp256r1 certificates over summaries from at least `2f + 1` of `3f + 1` validators.
    // The macro gates its fixture on a `mocks` feature that this crate does not define.
    #[allow(unexpected_cfgs)]
    mod scheme {
        use commonware_clearing::bajillion::{Namespace, Summary};
        use commonware_cryptography::{Sha256, impl_certificate_secp256r1};
        use commonware_utils::N3f1;

        impl_certificate_secp256r1!(&'a Summary<Sha256>, Namespace, N3f1);
    }

    type User = standard::PublicKey;
    type Scheme = scheme::Scheme<PublicKey>;

    /// One more than `u128::MAX`.
    const UNIT: U256 = U256::from_limbs([0, 0, 1, 0]);

    /// Returns `units` times [UNIT].
    const fn units(units: u64) -> U256 {
        U256::from_limbs([0, 0, units, 0])
    }

    /// Returns `amount` plus one.
    fn above(amount: U256) -> U256 {
        amount
            .checked_add(U256::ONE)
            .expect("the amount must be below the largest")
    }

    /// Returns `amount` less one.
    fn below(amount: U256) -> U256 {
        amount
            .checked_sub(U256::ONE)
            .expect("the amount must be positive")
    }

    /// The reference roles run with secp256r1 users, a BLS12-381 operator, secp256r1 validator
    /// certificates, and `U256` amounts beyond `u128::MAX`.
    #[test]
    fn test_schemes_and_amounts_are_independent() {
        deterministic::Runner::default().start(|mut context| async move {
            let users: Vec<_> = (0..3).map(standard::PrivateKey::from_seed).collect();
            let key = bls12381::PrivateKey::from_seed(0);
            let fixture = secp256r1::certificate::mocks::fixture(
                &mut test_rng(),
                NAMESPACE,
                4,
                Scheme::signer,
                Scheme::verifier,
            );
            let mut deployment = Deployment::<User, _, _, U256>::start(
                &context,
                "schemes",
                key.clone(),
                fixture.schemes,
                fixture.verifier,
            )
            .await;
            deployment
                .ledger
                .deposit(users[0].public_key(), units(5))
                .unwrap();
            deployment.close(&mut context).await;

            // A user pays another and withdraws part of its balance through the operator, and the
            // receiver withdraws part of the payment through the ledger in the same epoch.
            let mut alice =
                Sender::<_, _, Sha256, U256>::new(users[0].clone(), namespace(), key.public_key());
            let mut bob = Receiver::<User, _, Sha256, U256>::new(
                users[1].public_key(),
                namespace(),
                key.public_key(),
                2,
            );
            let batch = Amounts::new([(users[1].public_key(), above(units(2)))]).unwrap();
            let request = alice.send(2, batch).unwrap();
            let acknowledgement = deployment.operator.accept(&request).unwrap();
            for receipt in alice.acknowledged(&acknowledgement).unwrap() {
                assert_eq!(bob.receive(receipt).unwrap(), above(units(2)));
            }
            assert_eq!(
                deployment.operator.live(&users[0].public_key()),
                below(units(3))
            );
            deployment
                .operator
                .withdraw(Withdrawal::sign(&users[0], &namespace(), 2, UNIT, 0))
                .unwrap();
            deployment
                .ledger
                .withdraw(users[1].public_key(), UNIT)
                .unwrap();
            let (_, summary) = deployment.close(&mut context).await;

            // The receiver records the post and finds the payment in the posted matrix.
            bob.posted(2);
            let opening = deployment.validators[0]
                .matrix()
                .open(&users[0].public_key(), &users[1].public_key());
            assert!(
                bob.audit(2, &summary.matrix, &users[0].public_key(), &opening)
                    .unwrap()
                    .is_none()
            );
            let balances = [
                (users[0].public_key(), below(units(2))),
                (users[1].public_key(), above(UNIT)),
            ];
            deployment.check_balances(&balances).await;
            assert_eq!(deployment.ledger.custody(), units(3));

            // After a halt, each user claims its balance with a proof against the last close.
            deployment.ledger.halt();
            for (account, expected) in balances {
                let proof = deployment.validators[0]
                    .prove(&account)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(BalanceProof::decode(proof.encode()).unwrap(), proof);
                assert_eq!(
                    deployment.ledger.claim(&account, Some(&proof)).unwrap(),
                    expected
                );
            }
            assert_eq!(deployment.ledger.custody(), U256::ZERO);
        });
    }
}
