//! Deployments running over several epochs.

use super::*;
use crate::bajillion::{Error, Halt};
use commonware_runtime::Runner as _;

/// Checks that validators and the operator agree on every user's balance, and that the ledger holds
/// exactly those balances and the deposits no close processed.
async fn check_balances(deployment: &Deployment, users: u64) {
    let mut total = 0;
    for index in 0..users {
        let expected = deployment.operator.balance(&account(index)).await.unwrap();
        for validator in &deployment.validators {
            assert_eq!(validator.balance(&account(index)).await.unwrap(), expected);
        }
        total += expected;
    }
    let unprocessed: u64 = deployment
        .ledger
        .queue()
        .deposits
        .iter()
        .map(|deposit| deposit.amount)
        .sum();
    assert_eq!(deployment.ledger.custody(), total + unprocessed);
}

#[test]
fn test_epochs_settle_payments_and_withdrawals() {
    deterministic::Runner::default().start(|mut context| async move {
        const USERS: u64 = 6;
        let mut deployment = Deployment::new(&context, "epochs", 4).await;
        let mut senders: Vec<_> = (0..USERS).map(sender).collect();
        let mut receivers: Vec<_> = (0..USERS).map(|index| receiver(index, 1)).collect();
        for index in 0..USERS {
            deployment.ledger.deposit(account(index), 1_000).unwrap();
        }
        deployment.close(&mut context).await;
        for receiver in &mut receivers {
            receiver.posted(1);
        }
        check_balances(&deployment, USERS).await;

        for epoch in 2..=6 {
            // Every user pays the next two users, one request each.
            for from in 0..USERS {
                for offset in [1, 2] {
                    let to = (from + offset) % USERS;
                    let sender = &mut senders[from as usize];
                    let request = sender
                        .send(epoch, amounts(&[(to, epoch * 10 + offset)]), false)
                        .unwrap();
                    let acknowledgement = deployment.operator.accept(&request).await.unwrap();
                    for receipt in sender.acknowledged(&acknowledgement).unwrap() {
                        receivers[to as usize].receive(receipt).unwrap();
                    }
                }
            }

            // One user withdraws through the operator, another through the ledger, and a third
            // deposits.
            let withdrawal = Withdrawal::sign(&user(epoch % USERS), &namespace(), epoch, 25, 0);
            deployment.operator.withdraw(withdrawal).unwrap();
            deployment
                .ledger
                .withdraw(account((epoch + 3) % USERS), 15)
                .unwrap();
            deployment
                .ledger
                .deposit(account((epoch + 1) % USERS), 40)
                .unwrap();

            let (close, summary) = deployment.close(&mut context).await;
            assert_eq!(summary.epoch, epoch);
            assert_eq!((summary.deposits, summary.forced_withdrawals), (1, 1));

            // Every receiver finds each payment it was promised.
            let matrix = close.matrix::<Sha256>();
            for receiver in &mut receivers {
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
                receiver.posted(epoch);
                receiver.prune(epoch);
            }
            for sender in &mut senders {
                sender.prune(epoch);
            }
            check_balances(&deployment, USERS).await;
        }
    });
}

#[test]
fn test_omitted_payment_halts_ledger() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "omitted", 4).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.ledger.deposit(account(1), 100).unwrap();
        deployment.close(&mut context).await;

        // The operator preconfirms a payment to bob...
        let mut alice = sender(0);
        let mut bob = receiver(1, 2);
        let request = alice.send(2, amounts(&[(1, 30)]), false).unwrap();
        let receipt = alice
            .acknowledged(&deployment.operator.accept(&request).await.unwrap())
            .unwrap()
            .pop()
            .unwrap();
        bob.receive(receipt).unwrap();

        // ...but closes the epoch without it. Nothing else about the close is wrong, so validators
        // certify it and it posts.
        let omitting = sign_close(&operator_key(), 2, Vec::new(), Vec::new(), 0, 0);
        let proposals = deployment.verify(&omitting).await;
        let summary = deployment.post(&mut context, proposals).await;
        bob.posted(2);

        // Bob finds the omission in the posted matrix and halts the ledger.
        let opening = omitting.matrix::<Sha256>().open(&account(0), &account(1));
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
            Err(Error::Halted)
        ));

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

#[test]
fn test_late_challenge_halts_after_later_closes() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "late", 4).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;
        let mut alice = sender(0);
        let mut bob = receiver(1, 2);
        let request = alice.send(2, amounts(&[(1, 30)]), false).unwrap();
        let receipt = alice
            .acknowledged(&deployment.operator.accept(&request).await.unwrap())
            .unwrap()
            .pop()
            .unwrap();
        bob.receive(receipt).unwrap();

        // The close of epoch 2 omits the payment, and the close of epoch 3 posts before bob
        // checks it.
        let omitting = sign_close(&operator_key(), 2, Vec::new(), Vec::new(), 0, 0);
        let proposals = deployment.verify(&omitting).await;
        let omitted = deployment.post(&mut context, proposals).await;
        deployment.ledger.deposit(account(2), 50).unwrap();
        let next = sign_close(&operator_key(), 3, Vec::new(), Vec::new(), 1, 0);
        let proposals = deployment.verify(&next).await;
        let latest = deployment.post(&mut context, proposals).await;

        // The challenge still halts the ledger. Claims follow the balances of the latest close.
        let opening = omitting.matrix::<Sha256>().open(&account(0), &account(1));
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

#[test]
fn test_partial_credit_halts_ledger() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "partial", 4).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        deployment.close(&mut context).await;

        // Alice pays bob 5 and then 5 more, and bob holds the receipt for the cumulative 10.
        let mut alice = sender(0);
        let mut bob = receiver(1, 2);
        let first = alice.send(2, amounts(&[(1, 5)]), false).unwrap();
        alice
            .acknowledged(&deployment.operator.accept(&first).await.unwrap())
            .unwrap();
        let second = alice.send(2, amounts(&[(1, 5)]), false).unwrap();
        let receipt = alice
            .acknowledged(&deployment.operator.accept(&second).await.unwrap())
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(bob.receive(receipt).unwrap(), 10);

        // The close settles an earlier state alice did sign, so it posts.
        let earlier = Row {
            account: account(0),
            payments: amounts(&[(1, 5)]),
            signature: first.signature,
        };
        let underpaying = sign_close(&operator_key(), 2, vec![earlier], Vec::new(), 0, 0);
        let proposals = deployment.verify(&underpaying).await;
        let summary = deployment.post(&mut context, proposals).await;

        // Bob is credited 5 of the 10 promised, so his challenge halts the ledger.
        let opening = underpaying
            .matrix::<Sha256>()
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

mod schemes {
    //! A deployment whose users, operator, and validators sign with three different schemes, and
    //! whose amounts exceed `u64::MAX`.

    use super::*;
    use crate::bajillion::{
        BalanceProof, Ledger, MemoryBalances, Operator, Receiver, Sender, Validator,
    };
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{bls12381, secp256r1::standard};

    /// The macro gates its fixture on a `mocks` feature that this crate does not define.
    #[allow(unexpected_cfgs)]
    mod certificate {
        use crate::bajillion::{Namespace, Summary};
        use commonware_cryptography::impl_certificate_secp256r1;
        use commonware_utils::N3f1;

        impl_certificate_secp256r1!(&'a Summary<D>, Namespace, N3f1);
    }

    type Scheme = certificate::Scheme<PublicKey>;
    type User = standard::PublicKey;
    type OperatorKey = bls12381::PublicKey;
    type SchemesOperator =
        Operator<User, OperatorKey, bls12381::PrivateKey, Sha256, u128, MemoryBalances<User, u128>>;

    /// One more than `u64::MAX`.
    const UNIT: u128 = 1 << 64;

    #[test]
    fn test_schemes_and_amounts_are_independent() {
        deterministic::Runner::default().start(|mut context| async move {
            let users: Vec<_> = (0..3).map(standard::PrivateKey::from_seed).collect();
            let key = bls12381::PrivateKey::from_seed(0);
            let fixture = commonware_cryptography::secp256r1::certificate::mocks::fixture(
                &mut context,
                NAMESPACE,
                4,
                Scheme::signer,
                Scheme::verifier,
            );
            let mut validators = Vec::new();
            for index in 0..4 {
                let validator =
                    Validator::<_, User, OperatorKey, Sha256, EightCap, Sequential, u128>::init(
                        context.child("validator").with_attribute("index", index),
                        config_for(&format!("schemes-{index}"), key.public_key()),
                        Vec::new(),
                    )
                    .await
                    .unwrap();
                validators.push(validator);
            }
            let mut ledger = Ledger::<User, OperatorKey, Scheme, Sha256, u128>::new(
                namespace(),
                key.public_key(),
                fixture.verifier.clone(),
                validators[0].summary().balances,
            );
            let mut operator =
                SchemesOperator::init(key, namespace(), LIMITS, MemoryBalances::new(), [], None)
                    .await
                    .unwrap();

            // Closes the operator's epoch, processing every queued request, and posts it.
            async fn close(
                context: &mut deterministic::Context,
                operator: &mut SchemesOperator,
                validators: &mut Vec<
                    Validator<
                        deterministic::Context,
                        User,
                        OperatorKey,
                        Sha256,
                        EightCap,
                        Sequential,
                        u128,
                    >,
                >,
                schemes: &[Scheme],
                ledger: &mut Ledger<User, OperatorKey, Scheme, Sha256, u128>,
            ) -> Summary<Digest> {
                let queue = ledger.queue();
                let close = operator
                    .close(
                        &queue,
                        queue.deposits.len() as u64,
                        queue.forced_withdrawals.len() as u64,
                    )
                    .await
                    .unwrap();
                let mut proposals = Vec::new();
                for validator in validators.iter() {
                    proposals.push(validator.verify(close.clone(), &queue).await.unwrap());
                }
                let attestations: Vec<_> = proposals
                    .iter()
                    .zip(schemes)
                    .map(|(proposal, scheme)| proposal.sign(scheme).unwrap())
                    .collect();
                let certificate = schemes[0]
                    .assemble(non_empty![@attestations], &Sequential)
                    .unwrap();
                let summary = *proposals[0].summary();
                ledger
                    .post(context, &summary, proposals[0].payouts(), &certificate)
                    .unwrap();
                for (validator, proposal) in std::mem::take(validators).into_iter().zip(proposals) {
                    validators.push(validator.apply(proposal).await.unwrap());
                }
                summary
            }

            ledger.deposit(users[0].public_key(), 5 * UNIT).unwrap();
            close(
                &mut context,
                &mut operator,
                &mut validators,
                &fixture.schemes,
                &mut ledger,
            )
            .await;

            // A user pays another and withdraws part of its balance through the operator, and the
            // receiver withdraws part of the payment through the ledger in the same epoch.
            let mut alice = Sender::<User, _, OperatorKey, Sha256, u128>::new(
                users[0].clone(),
                operator.public_key(),
                namespace(),
            );
            let mut bob = Receiver::<User, OperatorKey, Sha256, u128>::new(
                users[1].public_key(),
                operator.public_key(),
                namespace(),
                2,
            );
            let batch = Amounts::new([(users[1].public_key(), 2 * UNIT + 1)]).unwrap();
            let request = alice.send(2, batch, false).unwrap();
            let acknowledgement = operator.accept(&request).await.unwrap();
            for receipt in alice.acknowledged(&acknowledgement).unwrap() {
                assert_eq!(bob.receive(receipt).unwrap(), 2 * UNIT + 1);
            }
            assert_eq!(
                operator.live(&users[0].public_key()).await.unwrap(),
                3 * UNIT - 1
            );
            operator
                .withdraw(Withdrawal::sign(&users[0], &namespace(), 2, UNIT, 0))
                .unwrap();
            ledger.withdraw(users[1].public_key(), UNIT).unwrap();
            let summary = close(
                &mut context,
                &mut operator,
                &mut validators,
                &fixture.schemes,
                &mut ledger,
            )
            .await;

            // The receiver finds the payment in the posted matrix.
            let opening = validators[0]
                .matrix()
                .open(&users[0].public_key(), &users[1].public_key());
            assert!(
                bob.audit(2, &summary.matrix, &users[0].public_key(), &opening)
                    .unwrap()
                    .is_none()
            );
            let balances = [(0, 2 * UNIT - 1), (1, UNIT + 1)];
            for validator in &validators {
                for (index, expected) in balances {
                    let account = users[index].public_key();
                    assert_eq!(validator.balance(&account).await.unwrap(), expected);
                    assert_eq!(operator.balance(&account).await.unwrap(), expected);
                }
            }
            assert_eq!(ledger.custody(), 3 * UNIT);

            // After a halt, each user claims its balance with a proof against the last close.
            ledger.halt();
            for (index, expected) in balances {
                let account = users[index].public_key();
                let proof = validators[0].prove(&account).await.unwrap().unwrap();
                assert_eq!(BalanceProof::decode(proof.encode()).unwrap(), proof);
                assert_eq!(ledger.claim(&account, Some(&proof)).unwrap(), expected);
            }
            assert_eq!(ledger.custody(), 0);
        });
    }
}
