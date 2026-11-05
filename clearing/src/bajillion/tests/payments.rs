//! Paying and receiving through the operator, without validators or a ledger.

use super::*;
use crate::bajillion::{Error, Opening, Outcome};

/// Funds users by closing the operator's epoch with a deposit of each `(index, amount)`.
fn fund(operator: &mut TestOperator, balances: &[(u64, u64)]) -> TestClose {
    let queue = deposits(operator.epoch(), balances);
    operator
        .close(&queue, queue.deposits.len() as u64, 0)
        .unwrap()
}

/// Closes the operator's epoch without processing any queued request.
fn close(operator: &mut TestOperator) -> TestClose {
    operator
        .close(&deposits(operator.epoch(), &[]), 0, 0)
        .unwrap()
}

/// Returns the close's matrix root and an opening of `sender`'s row in it.
fn open_row(close: &TestClose, sender: u64) -> (Digest, Opening<PublicKey, Digest>) {
    let matrix = close.matrix::<Sha256>();
    (
        matrix.root(),
        matrix.open(&account(sender), &account(sender)),
    )
}

#[test]
fn test_payments_preconfirm_receivers() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let mut bob = receiver(1, 2);
    let mut carol = receiver(2, 2);

    // One request pays both receivers, each of which gets a receipt for its cumulative amount.
    let request = alice.send(2, amounts(&[(1, 10), (2, 5)]), false).unwrap();
    let acknowledgement = operator.accept(&request).unwrap();
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
    let acknowledgement = operator.accept(&request).unwrap();
    let receipts = alice.acknowledged(&acknowledgement).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(bob.receive(receipts[0].clone()).unwrap(), 17);
    assert_eq!(bob.amount(2, &account(0)), 17);
    assert_eq!(carol.amount(2, &account(0)), 5);
    assert_eq!(alice.payments(2), Some(&amounts(&[(1, 17), (2, 5)])));
    assert_eq!(operator.payments(&account(0)), alice.payments(2));
    assert_eq!(operator.live(&account(0)), 78);
}

#[test]
fn test_operator_refuses_overdrafts() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 10)]);
    let mut alice = sender(0);

    let request = alice.send(2, amounts(&[(1, 8)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    let request = alice.send(2, amounts(&[(1, 3)]), false).unwrap();
    assert!(matches!(
        operator.accept(&request),
        Err(Error::InsufficientBalance)
    ));
    alice.refused().unwrap();
    assert!(alice.pending().is_none());
    let request = alice.send(2, amounts(&[(1, 2)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    assert_eq!(operator.live(&account(0)), 0);

    // Incoming payments are not spendable until a close processes them.
    let mut bob = sender(1);
    let request = bob.send(2, amounts(&[(2, 1)]), false).unwrap();
    assert!(matches!(
        operator.accept(&request),
        Err(Error::InsufficientBalance)
    ));
    bob.refused().unwrap();
    close(&mut operator);
    assert_eq!(operator.balance(&account(1)), 10);
    let request = bob.send(3, amounts(&[(2, 10)]), false).unwrap();
    bob.acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
}

#[test]
fn test_operator_refuses_states_the_sender_did_not_sign() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100), (1, 100)]);

    // The request must be for the current epoch.
    for epoch in [1, 3] {
        let request = sender(0).send(epoch, amounts(&[(2, 1)]), false).unwrap();
        assert!(matches!(
            operator.accept(&request),
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
        operator.accept(&tampered),
        Err(Error::InvalidSignature)
    ));
    let mut tampered = request;
    tampered.account = account(1);
    assert!(matches!(
        operator.accept(&tampered),
        Err(Error::InvalidSignature)
    ));
    let mut other = Sender::<_, _, _, Sha256>::new(
        user(0),
        operator_key().public_key(),
        Namespace::new(b"other"),
    );
    let request = other.send(2, amounts(&[(2, 1)]), false).unwrap();
    assert!(matches!(
        operator.accept(&request),
        Err(Error::InvalidSignature)
    ));

    // The state must extend the map the last close settled for the sender. A sender that lost
    // track of its payments cannot pay on top of a different map.
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(2, 1)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    close(&mut operator);
    let request = sender(0).send(3, amounts(&[(2, 1)]), false).unwrap();
    assert!(matches!(
        operator.accept(&request),
        Err(Error::InvalidSignature)
    ));
    let request = alice.send(3, amounts(&[(2, 1)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
}

#[test]
fn test_operator_acknowledges_retried_requests_once() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);

    // The first acknowledgement is lost, and the sender sends the same request again.
    let first = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
    operator.accept(&first).unwrap();
    let acknowledgement = operator.accept(alice.pending().unwrap()).unwrap();
    assert_eq!(alice.acknowledged(&acknowledgement).unwrap()[0].amount, 10);
    assert_eq!(operator.live(&account(0)), 90);

    // A retried request that spent the rest of the balance is acknowledged again, and its
    // receipt carries the cumulative amount.
    let second = alice.send(2, amounts(&[(1, 90)]), false).unwrap();
    operator.accept(&second).unwrap();
    assert_eq!(operator.live(&account(0)), 0);
    let receipts = alice
        .acknowledged(&operator.accept(&second).unwrap())
        .unwrap();
    assert_eq!(receipts[0].amount, 100);

    // An earlier request is neither acknowledged nor paid again once a later one extended the
    // map.
    assert!(operator.accept(&first).is_err());
    assert_eq!(operator.payments(&account(0)), Some(&amounts(&[(1, 100)])));
    assert_eq!(operator.live(&account(0)), 0);
}

#[test]
fn test_sender_rules() {
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
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 10)]);
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 1)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
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
}

#[test]
fn test_sender_rejects_foreign_acknowledgements() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 10), (1, 10)]);
    let mut alice = sender(0);
    let mut bob = sender(1);
    let request = alice.send(2, amounts(&[(2, 1)]), false).unwrap();
    let bobs = operator
        .accept(&bob.send(2, amounts(&[(2, 1)]), false).unwrap())
        .unwrap();
    assert!(matches!(
        alice.acknowledged(&bobs),
        Err(Error::InvalidAcknowledgement)
    ));

    // An acknowledgement from another operator does not count.
    let mut impostor = TestOperator::new(PrivateKey::from_seed(1_001), namespace());
    fund(&mut impostor, &[(0, 10)]);
    let forged = impostor.accept(&request).unwrap();
    assert!(matches!(
        alice.acknowledged(&forged),
        Err(Error::InvalidAcknowledgement)
    ));
    let acknowledgement = operator.accept(&request).unwrap();
    assert_eq!(alice.acknowledged(&acknowledgement).unwrap().len(), 1);
    assert!(matches!(
        alice.acknowledged(&acknowledgement),
        Err(Error::NotPending)
    ));
}

#[test]
fn test_pipelined_request_settles_in_the_next_epoch() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let mut bob = receiver(1, 2);

    // The request is for epoch 2, but reaches the operator after it closed epoch 2.
    let request = alice.send(2, amounts(&[(1, 10)]), true).unwrap();
    close(&mut operator);
    let acknowledgement = operator.accept(&request).unwrap();
    assert_eq!(acknowledgement.epoch, 3);
    let receipts = alice.acknowledged(&acknowledgement).unwrap();
    assert_eq!(receipts[0].state.epoch, 3);
    assert_eq!(bob.receive(receipts[0].clone()).unwrap(), 10);
    assert_eq!(alice.payments(2), None);
    assert_eq!(alice.payments(3), Some(&amounts(&[(1, 10)])));

    // After a request settles in its own epoch, its state for the next epoch does not extend the
    // settled map, so the operator cannot settle it again.
    let request = alice.send(3, amounts(&[(1, 5)]), true).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    close(&mut operator);
    assert!(matches!(
        operator.accept(&request),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn test_posted_close_resolves_pending_requests() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);

    // The operator settled the request, but its acknowledgement was lost.
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
    operator.accept(&request).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(alice.posted(2, &root, &opening).unwrap(), Outcome::Settled);
    assert!(alice.pending().is_none());
    assert_eq!(alice.payments(2), Some(&amounts(&[(1, 10)])));

    // A request for one epoch is dropped if that epoch's close did not settle it.
    alice.send(3, amounts(&[(1, 10)]), false).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(alice.posted(3, &root, &opening).unwrap(), Outcome::Dropped);
    assert!(alice.pending().is_none());
    assert_eq!(alice.payments(3), None);

    // A pipelined request the close did not settle may still settle in the next epoch.
    let request = alice.send(4, amounts(&[(1, 10)]), true).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(alice.posted(4, &root, &opening).unwrap(), Outcome::Pending);
    assert_eq!(alice.pending(), Some(&request));
    operator.accept(&request).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    let (other, _) = open_row(&fund(&mut operator, &[(7, 1)]), 0);
    assert!(matches!(
        alice.posted(5, &other, &opening),
        Err(Error::InvalidOpening)
    ));
    assert_eq!(alice.posted(5, &root, &opening).unwrap(), Outcome::Settled);
    assert_eq!(alice.payments(5), Some(&amounts(&[(1, 10)])));
}

#[test]
fn test_posted_earlier_map_does_not_settle_request() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 5)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();

    // The close settles the sender's earlier map, not the one its pending request pays.
    alice.send(2, amounts(&[(1, 5)]), false).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(alice.posted(2, &root, &opening).unwrap(), Outcome::Dropped);
    assert_eq!(alice.payments(2), Some(&amounts(&[(1, 5)])));
}

#[test]
fn test_roles_resume_from_persisted_state() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
    let receipts = alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    let posted = close(&mut operator);
    let pending = alice.send(3, amounts(&[(1, 5)]), true).unwrap();

    // The operator resumes from the balances and matrix of its last close.
    let balances: Vec<_> = operator
        .balances()
        .map(|(account, balance)| (account.clone(), balance))
        .collect();
    assert_eq!(balances.len(), 2);
    let mut resumed = TestOperator::resume(
        operator_key(),
        namespace(),
        3,
        balances.clone(),
        &posted.matrix::<Sha256>(),
    )
    .unwrap();
    assert_eq!(resumed.live(&account(0)), 90);

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
        .acknowledged(&resumed.accept(&pending).unwrap())
        .unwrap();
    assert_eq!(receipts_3[0].amount, 5);

    // Replaying the epoch's requests and soft withdrawals, the resumed operator closes the epoch
    // exactly as the original would have.
    operator.accept(&pending).unwrap();
    let withdrawal = Withdrawal::sign(&user(1), &namespace(), 3, 4, 0);
    operator.withdraw(withdrawal.clone()).unwrap();
    resumed.withdraw(withdrawal).unwrap();
    assert_eq!(close(&mut resumed), close(&mut operator));

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

    // The operator resumes only in a nonzero epoch from positive, distinct balances.
    let matrix = posted.matrix::<Sha256>();
    let resume = |epoch, balances: Vec<_>| {
        TestOperator::resume(operator_key(), namespace(), epoch, balances, &matrix)
    };
    assert!(matches!(resume(0, balances), Err(Error::ZeroEpoch)));
    assert!(matches!(
        resume(3, vec![(account(0), 0)]),
        Err(Error::ZeroAmount)
    ));
    assert!(matches!(
        resume(3, vec![(account(0), 1), (account(0), 2)]),
        Err(Error::DuplicateAccount)
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
}

#[test]
fn test_receiver_rejects_receipts_it_cannot_rely_on() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 10), (2, 5)]), false).unwrap();
    let receipts = alice
        .acknowledged(&operator.accept(&request).unwrap())
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
}

#[test]
fn test_resumed_receiver_keeps_its_strongest_receipts_and_halt() {
    let mut operator = TestOperator::new(operator_key(), namespace());
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let first = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
    let lower = alice
        .acknowledged(&operator.accept(&first).unwrap())
        .unwrap()
        .pop()
        .unwrap();
    let second = alice.send(2, amounts(&[(1, 5)]), false).unwrap();
    let upper = alice
        .acknowledged(&operator.accept(&second).unwrap())
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
}

#[test]
fn test_posted_close_needs_a_valid_opening() {
    let mut alice = sender(0);
    alice.send(2, amounts(&[(1, 5)]), false).unwrap();

    // Even a close of an epoch the request does not involve must come with a valid opening.
    let populated = Matrix::<_, Digest>::new::<Sha256>([(account(0), amounts(&[(1, 7)]))]).unwrap();
    let empty = Matrix::<PublicKey, Digest>::empty::<Sha256>();
    let opening = populated.open(&account(0), &account(1));
    assert!(matches!(
        alice.posted(1, &empty.root(), &opening),
        Err(Error::InvalidOpening)
    ));
    assert!(alice.pending().is_some());
}
