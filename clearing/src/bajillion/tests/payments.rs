//! Paying and receiving through the operator, without validators or a ledger.

use super::*;
use crate::bajillion::{Balances as _, Error, Opening, Outcome};
use commonware_codec::{Decode as _, Encode as _};
use commonware_runtime::Runner as _;

/// Funds users by closing the operator's epoch with a deposit of each `(index, amount)`.
async fn fund(operator: &mut TestOperator, balances: &[(u64, u64)]) -> TestClose {
    let queue = deposits(operator.epoch(), balances);
    close_epoch(operator, &queue, queue.deposits.len() as u64, 0).await
}

/// Closes the operator's epoch without processing any queued request.
async fn close(operator: &mut TestOperator) -> TestClose {
    close_epoch(operator, &deposits(operator.epoch(), &[]), 0, 0).await
}

/// Returns the close's matrix root and an opening of `sender`'s row in it.
fn open_row(close: &TestClose, sender: u64) -> (Digest, Opening<PublicKey, Digest, u64>) {
    let matrix = close.matrix::<Sha256>();
    (
        matrix.root(),
        matrix.open(&account(sender), &account(sender)),
    )
}

#[test]
fn test_payments_preconfirm_receivers() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;
        let mut alice = sender(0);
        let mut bob = receiver(1, 2);
        let mut carol = receiver(2, 2);

        // One request pays both receivers, each of which gets a receipt for its cumulative amount.
        let request = alice.send(2, amounts(&[(1, 10), (2, 5)]), false).unwrap();
        let acknowledgement = operator.accept(&request).await.unwrap();
        let receipts = alice.acknowledged(&acknowledgement).unwrap();
        assert_eq!(receipts.len(), 2);
        for receipt in receipts {
            if receipt.receiver == account(1) {
                assert_eq!(bob.receive(receipt).unwrap(), 10);
            } else {
                assert_eq!(carol.receive(receipt).unwrap(), 5);
            }
        }

        // Later payments to the same receiver accumulate.
        let request = alice.send(2, amounts(&[(1, 7)]), false).unwrap();
        let acknowledgement = operator.accept(&request).await.unwrap();
        let receipts = alice.acknowledged(&acknowledgement).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(bob.receive(receipts[0].clone()).unwrap(), 17);
        assert_eq!(bob.amount(2, &account(0)), 17);
        assert_eq!(carol.amount(2, &account(0)), 5);
        assert_eq!(alice.payments(2), Some(&amounts(&[(1, 17), (2, 5)])));
        assert_eq!(operator.payments(&account(0)), alice.payments(2));
        assert_eq!(operator.live(&account(0)).await.unwrap(), 78);
    });
}

#[test]
fn test_operator_refuses_overdrafts() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 10)]).await;
        let mut alice = sender(0);

        let request = alice.send(2, amounts(&[(1, 8)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        let request = alice.send(2, amounts(&[(1, 3)]), false).unwrap();
        assert!(matches!(
            operator.accept(&request).await,
            Err(Error::InsufficientBalance)
        ));
        alice.refused().unwrap();
        assert!(alice.pending().is_none());
        let request = alice.send(2, amounts(&[(1, 2)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        assert_eq!(operator.live(&account(0)).await.unwrap(), 0);

        // Incoming payments are not spendable until a close processes them.
        let mut bob = sender(1);
        let request = bob.send(2, amounts(&[(2, 1)]), false).unwrap();
        assert!(matches!(
            operator.accept(&request).await,
            Err(Error::InsufficientBalance)
        ));
        bob.refused().unwrap();
        close(&mut operator).await;
        assert_eq!(operator.balance(&account(1)).await.unwrap(), 10);
        let request = bob.send(3, amounts(&[(2, 10)]), false).unwrap();
        bob.acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
    });
}

#[test]
fn test_operator_refuses_states_the_sender_did_not_sign() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100), (1, 100)]).await;

        // The request must be for the current epoch.
        for epoch in [1, 3] {
            let request = sender(0).send(epoch, amounts(&[(2, 1)]), false).unwrap();
            assert!(matches!(
                operator.accept(&request).await,
                Err(Error::WrongEpoch {
                    expected: 2,
                    found
                }) if found == epoch
            ));
        }

        // The signature must cover the batch, the account, and the deployment.
        let request = sender(0).send(2, amounts(&[(2, 1)]), false).unwrap();
        let mut tampered = request.clone();
        tampered.batch = amounts(&[(2, 2)]);
        assert!(matches!(
            operator.accept(&tampered).await,
            Err(Error::InvalidSignature)
        ));
        let mut tampered = request;
        tampered.account = account(1);
        assert!(matches!(
            operator.accept(&tampered).await,
            Err(Error::InvalidSignature)
        ));
        let mut other = Sender::<_, _, _, Sha256, u64>::new(
            user(0),
            operator_key().public_key(),
            Namespace::new(b"other"),
        );
        let request = other.send(2, amounts(&[(2, 1)]), false).unwrap();
        assert!(matches!(
            operator.accept(&request).await,
            Err(Error::InvalidSignature)
        ));

        // The state must extend the map the last close settled for the sender. A sender that lost
        // track of its payments cannot pay on top of a different map.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(2, 1)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        close(&mut operator).await;
        let request = sender(0).send(3, amounts(&[(2, 1)]), false).unwrap();
        assert!(matches!(
            operator.accept(&request).await,
            Err(Error::InvalidSignature)
        ));
        let request = alice.send(3, amounts(&[(2, 1)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
    });
}

#[test]
fn test_operator_acknowledges_retried_requests_once() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;
        let mut alice = sender(0);

        // The first acknowledgement is lost, and the sender sends the same request again.
        let first = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
        operator.accept(&first).await.unwrap();
        let acknowledgement = operator.accept(alice.pending().unwrap()).await.unwrap();
        assert_eq!(alice.acknowledged(&acknowledgement).unwrap()[0].amount, 10);
        assert_eq!(operator.live(&account(0)).await.unwrap(), 90);

        // A retried request that spent the rest of the balance is acknowledged again, and its
        // receipt carries the cumulative amount.
        let second = alice.send(2, amounts(&[(1, 90)]), false).unwrap();
        operator.accept(&second).await.unwrap();
        assert_eq!(operator.live(&account(0)).await.unwrap(), 0);
        let receipts = alice
            .acknowledged(&operator.accept(&second).await.unwrap())
            .unwrap();
        assert_eq!(receipts[0].amount, 100);

        // An earlier request is neither acknowledged nor paid again once a later one extended the
        // map.
        assert!(operator.accept(&first).await.is_err());
        assert_eq!(operator.payments(&account(0)), Some(&amounts(&[(1, 100)])));
        assert_eq!(operator.live(&account(0)).await.unwrap(), 0);
    });
}

#[test]
fn test_sender_rules() {
    deterministic::Runner::default().start(|_| async move {
        let mut alice = sender(0);
        assert!(matches!(
            alice.send(0, amounts(&[(1, 1)]), false),
            Err(Error::ZeroEpoch)
        ));
        assert!(matches!(
            alice.send(1, Amounts::empty(), false),
            Err(Error::NoReceivers)
        ));
        assert!(matches!(alice.refused(), Err(Error::NotPending)));

        // One request at a time.
        let request = alice.send(1, amounts(&[(1, 1)]), false).unwrap();
        assert_eq!(alice.pending(), Some(&request));
        assert!(matches!(
            alice.send(1, amounts(&[(1, 1)]), false),
            Err(Error::Pending)
        ));

        // Never back to an epoch before one the sender has paid in.
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 10)]).await;
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 1)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        assert!(matches!(
            alice.send(1, amounts(&[(1, 1)]), false),
            Err(Error::LaterEpoch)
        ));
        assert!(matches!(
            alice.send(1, amounts(&[(1, 1)]), true),
            Err(Error::LaterEpoch)
        ));
        alice.send(2, amounts(&[(1, 1)]), true).unwrap();
    });
}

#[test]
fn test_sender_rejects_foreign_acknowledgements() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 10), (1, 10)]).await;
        let mut alice = sender(0);
        let mut bob = sender(1);
        let request = alice.send(2, amounts(&[(2, 1)]), false).unwrap();
        let bobs = operator
            .accept(&bob.send(2, amounts(&[(2, 1)]), false).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            alice.acknowledged(&bobs),
            Err(Error::InvalidAcknowledgement)
        ));

        // An acknowledgement from another operator does not count.
        let mut impostor = TestOperator::init(
            PrivateKey::from_seed(1_001),
            namespace(),
            LIMITS,
            MemoryBalances::new(),
            [],
            None,
        )
        .await
        .unwrap();
        fund(&mut impostor, &[(0, 10)]).await;
        let forged = impostor.accept(&request).await.unwrap();
        assert!(matches!(
            alice.acknowledged(&forged),
            Err(Error::InvalidAcknowledgement)
        ));
        let acknowledgement = operator.accept(&request).await.unwrap();
        assert_eq!(alice.acknowledged(&acknowledgement).unwrap().len(), 1);
        assert!(matches!(
            alice.acknowledged(&acknowledgement),
            Err(Error::NotPending)
        ));
    });
}

#[test]
fn test_pipelined_request_settles_in_the_next_epoch() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;
        let mut alice = sender(0);
        let mut bob = receiver(1, 2);

        // The request is for epoch 2, but reaches the operator after it closed epoch 2.
        let request = alice.send(2, amounts(&[(1, 10)]), true).unwrap();
        close(&mut operator).await;
        let acknowledgement = operator.accept(&request).await.unwrap();
        assert_eq!(acknowledgement.epoch, 3);
        let receipts = alice.acknowledged(&acknowledgement).unwrap();
        assert_eq!(receipts[0].state.epoch, 3);
        assert_eq!(bob.receive(receipts[0].clone()).unwrap(), 10);
        assert_eq!(alice.payments(2), None);
        assert_eq!(alice.payments(3), Some(&amounts(&[(1, 10)])));

        // After a request settles in its own epoch, its state for the next epoch does not extend
        // the settled map, so the operator cannot settle it again.
        let request = alice.send(3, amounts(&[(1, 5)]), true).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        close(&mut operator).await;
        assert!(matches!(
            operator.accept(&request).await,
            Err(Error::InvalidSignature)
        ));
    });
}

#[test]
fn test_posted_close_resolves_pending_requests() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;

        // The operator settled the request, but its acknowledgement was lost.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
        operator.accept(&request).await.unwrap();
        let posted = close(&mut operator).await;
        let (root, opening) = open_row(&posted, 0);
        assert_eq!(alice.posted(2, &root, &opening).unwrap(), Outcome::Settled);
        assert!(alice.pending().is_none());
        assert_eq!(alice.payments(2), Some(&amounts(&[(1, 10)])));

        // A request for one epoch is dropped if that epoch's close did not settle it.
        alice.send(3, amounts(&[(1, 10)]), false).unwrap();
        let posted = close(&mut operator).await;
        let (root, opening) = open_row(&posted, 0);
        assert_eq!(alice.posted(3, &root, &opening).unwrap(), Outcome::Dropped);
        assert!(alice.pending().is_none());
        assert_eq!(alice.payments(3), None);

        // A pipelined request the close did not settle may still settle in the next epoch.
        let request = alice.send(4, amounts(&[(1, 10)]), true).unwrap();
        let posted = close(&mut operator).await;
        let (root, opening) = open_row(&posted, 0);
        assert_eq!(alice.posted(4, &root, &opening).unwrap(), Outcome::Pending);
        assert_eq!(alice.pending(), Some(&request));
        operator.accept(&request).await.unwrap();
        let posted = close(&mut operator).await;
        let (root, opening) = open_row(&posted, 0);
        let (other, _) = open_row(&fund(&mut operator, &[(7, 1)]).await, 0);
        assert!(matches!(
            alice.posted(5, &other, &opening),
            Err(Error::InvalidOpening)
        ));
        assert_eq!(alice.posted(5, &root, &opening).unwrap(), Outcome::Settled);
        assert_eq!(alice.payments(5), Some(&amounts(&[(1, 10)])));
    });
}

#[test]
fn test_posted_earlier_map_does_not_settle_request() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 5)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();

        // The close settles the sender's earlier map, not the one its pending request pays.
        alice.send(2, amounts(&[(1, 5)]), false).unwrap();
        let posted = close(&mut operator).await;
        let (root, opening) = open_row(&posted, 0);
        assert_eq!(alice.posted(2, &root, &opening).unwrap(), Outcome::Dropped);
        assert_eq!(alice.payments(2), Some(&amounts(&[(1, 5)])));
    });
}

/// An operator admits no more senders, receivers in one sender's payment map, or soft withdrawals
/// in an epoch than its limits allow. Requests within them still succeed, and the close it builds
/// at the limits decodes with them.
#[test]
fn test_operator_admits_within_its_limits() {
    deterministic::Runner::default().start(|_| async move {
        let limits = Limits {
            rows: 2,
            receivers: 2,
            withdrawals: 1,
        };
        let mut operator = TestOperator::init(
            operator_key(),
            namespace(),
            limits,
            MemoryBalances::new(),
            [],
            None,
        )
        .await
        .unwrap();
        fund(&mut operator, &[(0, 100), (1, 100), (2, 100)]).await;
        let (mut alice, mut bob, mut carol) = (sender(0), sender(1), sender(2));

        // Alice pays two receivers and bob one, filling the senders and alice's map.
        let request = alice.send(2, amounts(&[(1, 5), (2, 5)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        let retried = bob.send(2, amounts(&[(0, 5)]), false).unwrap();
        bob.acknowledged(&operator.accept(&retried).await.unwrap())
            .unwrap();

        // A third sender, or a third receiver in alice's map, would not fit the close.
        let request = carol.send(2, amounts(&[(0, 5)]), false).unwrap();
        assert!(matches!(operator.accept(&request).await, Err(Error::Full)));
        carol.refused().unwrap();
        let request = alice.send(2, amounts(&[(3, 1)]), false).unwrap();
        assert!(matches!(operator.accept(&request).await, Err(Error::Full)));
        alice.refused().unwrap();

        // A request the account did not sign is refused as unsigned even when it would not fit, so
        // the refusal does not reveal which accounts pay or how many receivers they paid.
        let mut impostor = sender(9);
        for (owner, receiver) in [(2, 0), (0, 3)] {
            let mut request = impostor.send(2, amounts(&[(receiver, 1)]), false).unwrap();
            request.account = account(owner);
            assert!(matches!(
                operator.accept(&request).await,
                Err(Error::InvalidSignature)
            ));
            impostor.refused().unwrap();
        }

        // Alice still pays a receiver she paid, and a retried request is acknowledged again.
        let request = alice.send(2, amounts(&[(1, 1)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        operator.accept(&retried).await.unwrap();

        // One soft withdrawal fills the epoch's, and collecting it again has no effect. A
        // withdrawal the account did not sign is refused as unsigned, with room left or not.
        let mut forged = Withdrawal::sign(&user(9), &namespace(), 2, 10, 0);
        forged.account = account(1);
        assert!(matches!(
            operator.withdraw(forged.clone()),
            Err(Error::InvalidSignature)
        ));
        let withdrawal = Withdrawal::sign(&user(0), &namespace(), 2, 10, 0);
        operator.withdraw(withdrawal.clone()).unwrap();
        let other = Withdrawal::sign(&user(1), &namespace(), 2, 10, 0);
        assert!(matches!(operator.withdraw(other), Err(Error::Full)));
        assert!(matches!(
            operator.withdraw(forged),
            Err(Error::InvalidSignature)
        ));
        operator.withdraw(withdrawal).unwrap();

        // The close at the limits decodes with them.
        let closed = close(&mut operator).await;
        assert_eq!(closed.rows().len(), 2);
        assert_eq!(closed.withdrawals().len(), 1);
        assert_eq!(
            TestClose::decode_cfg(closed.encode(), &limits).unwrap(),
            closed
        );
    });
}

/// A request the account did not sign is refused before the operator reads the account's balance
/// or checks its payments, so the refusal is the same whatever the account holds or paid.
#[test]
fn test_unsigned_requests_are_refused_before_any_read() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 10)]).await;
        let cached = operator.cached();

        // An impostor signs requests for alice's account, for amounts she can and cannot pay.
        let mut impostor = sender(9);
        for amount in [5, 11] {
            let mut request = impostor.send(2, amounts(&[(1, amount)]), false).unwrap();
            request.account = account(0);
            assert!(matches!(
                operator.accept(&request).await,
                Err(Error::InvalidSignature)
            ));
            impostor.refused().unwrap();
        }
        assert_eq!(operator.cached(), cached);

        // Once alice has paid, a forged batch that would overflow her map is refused alike.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 3)]), false).unwrap();
        alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        let mut request = impostor.send(2, amounts(&[(1, u64::MAX)]), false).unwrap();
        request.account = account(0);
        assert!(matches!(
            operator.accept(&request).await,
            Err(Error::InvalidSignature)
        ));
    });
}

#[test]
fn test_roles_resume_from_persisted_state() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
        let receipts = alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        let posted = close(&mut operator).await;
        let pending = alice.send(3, amounts(&[(1, 5)]), true).unwrap();

        // The operator resumes from a store holding the balances its last close left, and from
        // that close's matrix.
        let mut balances = Vec::new();
        for index in [0, 1] {
            balances.push((
                account(index),
                operator.balance(&account(index)).await.unwrap(),
            ));
        }
        let store = MemoryBalances::new().put(0, 2, &balances).await.unwrap();
        let mut resumed = TestOperator::init(
            operator_key(),
            namespace(),
            LIMITS,
            store,
            posted.matrix::<Sha256>().rows().iter().cloned(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(resumed.epoch(), 3);
        assert_eq!(resumed.live(&account(0)).await.unwrap(), 90);

        // The sender resumes with its pending request, and the resumed operator accepts it.
        let mut resumed_alice = TestSender::resume(
            user(0),
            operator_key().public_key(),
            namespace(),
            [(2, amounts(&[(1, 10)]))],
            Some(pending.clone()),
        )
        .unwrap();
        assert_eq!(resumed_alice.pending(), Some(&pending));
        let receipts_3 = resumed_alice
            .acknowledged(&resumed.accept(&pending).await.unwrap())
            .unwrap();
        assert_eq!(receipts_3[0].amount, 5);

        // Replaying the epoch's requests and soft withdrawals, the resumed operator closes the
        // epoch exactly as the original would have.
        operator.accept(&pending).await.unwrap();
        let withdrawal = Withdrawal::sign(&user(1), &namespace(), 3, 4, 0);
        operator.withdraw(withdrawal.clone()).unwrap();
        resumed.withdraw(withdrawal).unwrap();
        assert_eq!(close(&mut resumed).await, close(&mut operator).await);

        // A request that does not extend the persisted maps does not resume, including one whose
        // payment map was persisted without clearing it.
        for payments in [
            vec![(2, amounts(&[(1, 11)]))],
            vec![(2, amounts(&[(1, 10)])), (3, amounts(&[(1, 5)]))],
        ] {
            assert!(matches!(
                TestSender::resume(
                    user(0),
                    operator_key().public_key(),
                    namespace(),
                    payments,
                    Some(pending.clone()),
                ),
                Err(Error::InvalidSignature)
            ));
        }
        assert!(matches!(
            TestSender::resume(
                user(0),
                operator_key().public_key(),
                namespace(),
                [(2, Amounts::empty())],
                None,
            ),
            Err(Error::NoReceivers)
        ));

        // Neither does a request of another account, though the sender signed its states.
        let mut foreign = pending.clone();
        foreign.account = account(1);
        assert!(matches!(
            TestSender::resume(
                user(0),
                operator_key().public_key(),
                namespace(),
                [(2, amounts(&[(1, 10)]))],
                Some(foreign),
            ),
            Err(Error::InvalidSignature)
        ));

        // The receiver resumes with the receipts it accepted, including those of closed epochs.
        let bob = TestReceiver::resume(
            account(1),
            operator_key().public_key(),
            namespace(),
            3,
            false,
            receipts.clone(),
        )
        .unwrap();
        assert_eq!(bob.amount(2, &account(0)), 10);
        assert!(matches!(
            TestReceiver::resume(
                account(2),
                operator_key().public_key(),
                namespace(),
                3,
                false,
                receipts
            ),
            Err(Error::WrongReceiver)
        ));
    });
}

#[test]
fn test_receiver_rejects_receipts_it_cannot_rely_on() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 10), (2, 5)]), false).unwrap();
        let receipts = alice
            .acknowledged(&operator.accept(&request).await.unwrap())
            .unwrap();
        let (for_bob, for_carol) = if receipts[0].receiver == account(1) {
            (receipts[0].clone(), receipts[1].clone())
        } else {
            (receipts[1].clone(), receipts[0].clone())
        };

        let mut bob = receiver(1, 2);
        assert!(matches!(bob.receive(for_carol), Err(Error::WrongReceiver)));
        let mut tampered = for_bob.clone();
        tampered.amount += 1;
        assert!(matches!(bob.receive(tampered), Err(Error::InvalidReceipt)));
        let mut misled = TestReceiver::new(
            account(1),
            PrivateKey::from_seed(1_001).public_key(),
            namespace(),
            2,
        );
        assert!(matches!(
            misled.receive(for_bob.clone()),
            Err(Error::InvalidReceipt)
        ));
        assert_eq!(bob.receive(for_bob.clone()).unwrap(), 10);
        assert!(matches!(
            bob.receive(for_bob.clone()),
            Err(Error::NotIncreasing)
        ));

        // A receiver rejects receipts for an epoch whose close posted, and every receipt once the
        // ledger halts.
        let mut late = receiver(1, 2);
        late.posted(2);
        assert!(matches!(late.receive(for_bob.clone()), Err(Error::Closed)));
        let mut halted = receiver(1, 2);
        halted.halt();
        assert!(matches!(halted.receive(for_bob), Err(Error::Halted)));
    });
}

#[test]
fn test_resumed_receiver_keeps_its_strongest_receipts_and_halt() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        fund(&mut operator, &[(0, 100)]).await;
        let mut alice = sender(0);
        let first = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
        let lower = alice
            .acknowledged(&operator.accept(&first).await.unwrap())
            .unwrap()
            .pop()
            .unwrap();
        let second = alice.send(2, amounts(&[(1, 5)]), false).unwrap();
        let upper = alice
            .acknowledged(&operator.accept(&second).await.unwrap())
            .unwrap()
            .pop()
            .unwrap();

        // Receipts restored in any order keep the largest amount from each sender.
        let resume = |halted, receipts: Vec<_>| {
            TestReceiver::resume(
                account(1),
                operator_key().public_key(),
                namespace(),
                2,
                halted,
                receipts,
            )
            .unwrap()
        };
        let mut bob = resume(false, vec![upper.clone(), lower.clone()]);
        assert_eq!(bob.amount(2, &account(0)), 15);
        assert!(matches!(
            bob.receive(lower.clone()),
            Err(Error::NotIncreasing)
        ));

        // A receiver that saw the ledger halt keeps refusing receipts after resuming.
        let mut halted = resume(true, vec![lower]);
        assert!(matches!(halted.receive(upper), Err(Error::Halted)));
    });
}

#[test]
fn test_posted_close_needs_a_valid_opening() {
    deterministic::Runner::default().start(|_| async move {
        let mut alice = sender(0);
        alice.send(2, amounts(&[(1, 5)]), false).unwrap();

        // Even a close of an epoch the request does not involve must come with a valid opening.
        let populated =
            Matrix::<_, Digest, u64>::new::<Sha256>([(account(0), amounts(&[(1, 7)]))]).unwrap();
        let empty = Matrix::<PublicKey, Digest, u64>::empty::<Sha256>();
        let opening = populated.open(&account(0), &account(1));
        assert!(matches!(
            alice.posted(1, &empty.root(), &opening),
            Err(Error::InvalidOpening)
        ));
        assert!(alice.pending().is_some());
    });
}
