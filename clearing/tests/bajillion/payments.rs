//! Paying and receiving through the operator, without validators or a ledger.

use super::*;
use crate::roles::{
    operator::Refusal as Operator,
    receiver::Refusal as Receiving,
    sender::{Outcome, Refusal as Sending},
};
use commonware_clearing::bajillion::{Error, Matrix, Opening, Request};
use commonware_codec::Decode as _;

/// Returns the close's matrix root and an opening of `sender`'s row in it.
fn open_row(close: &TestClose, sender: u64) -> (Digest, Opening<PublicKey, Digest, u64>) {
    let matrix = close.matrix::<Sha256>();
    (
        matrix.root(),
        matrix.open(&account(sender), &account(sender)),
    )
}

/// One request pays several receivers, each receipt carries the cumulative amount paid, and the
/// operator's record matches the sender's.
#[test]
fn test_payments_preconfirm_receivers() {
    let mut operator = operator();
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

/// The operator admits no payment beyond what the sender can still spend, and incoming payments
/// become spendable only once a close settles them.
#[test]
fn test_operator_refuses_overdrafts() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 10)]);
    let mut alice = sender(0);

    // Alice spends her 10 in two requests. A request beyond what remains is refused, and she
    // drops it.
    let request = alice.send(2, amounts(&[(1, 8)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    let request = alice.send(2, amounts(&[(1, 3)]), false).unwrap();
    assert!(matches!(
        operator.accept(&request),
        Err(Operator::InsufficientBalance)
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
        Err(Operator::InsufficientBalance)
    ));
    bob.refused().unwrap();
    close(&mut operator);
    assert_eq!(operator.balance(&account(1)), 10);
    let request = bob.send(3, amounts(&[(2, 10)]), false).unwrap();
    bob.acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
}

/// The operator countersigns only a state its sender signed for the current epoch, on top of the
/// map the last close settled for the sender.
#[test]
fn test_operator_refuses_states_the_sender_did_not_sign() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 100), (1, 100)]);

    // The request must be for the current epoch.
    for epoch in [1, 3] {
        let request = sender(0).send(epoch, amounts(&[(2, 1)]), false).unwrap();
        assert!(matches!(
            operator.accept(&request),
            Err(Operator::Error(Error::WrongEpoch {
                expected: 2,
                found
            })) if found == epoch
        ));
    }

    // The signature must cover the batch, the account, and the deployment.
    let request = sender(0).send(2, amounts(&[(2, 1)]), false).unwrap();
    let mut tampered = request.clone();
    tampered.batch = amounts(&[(2, 2)]);
    assert!(matches!(
        operator.accept(&tampered),
        Err(Operator::Error(Error::InvalidSignature))
    ));
    let mut tampered = request;
    tampered.account = account(1);
    assert!(matches!(
        operator.accept(&tampered),
        Err(Operator::Error(Error::InvalidSignature))
    ));
    let mut other = TestSender::new(
        user(0),
        Namespace::new(b"other"),
        operator_key().public_key(),
    );
    let request = other.send(2, amounts(&[(2, 1)]), false).unwrap();
    assert!(matches!(
        operator.accept(&request),
        Err(Operator::Error(Error::InvalidSignature))
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
        Err(Operator::Error(Error::InvalidSignature))
    ));
    let request = alice.send(3, amounts(&[(2, 1)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
}

/// The operator refuses a request that pays no receiver, even one its account signed, so no close
/// holds a row that validators cannot decode.
#[test]
fn test_operator_refuses_requests_that_pay_no_receiver() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 100)]);
    let empty = Amounts::empty();
    let state = State {
        epoch: 2,
        account: account(1),
        payments: empty.root::<Sha256>(),
        previous: empty.root::<Sha256>(),
    };
    let request = Request {
        account: account(1),
        epoch: 2,
        batch: empty,
        payments: state.payments,
        previous: state.previous,
        signature: user(1).sign(&namespace().state, &state.encode()),
        pipelined: None,
    };
    assert!(matches!(
        operator.accept(&request),
        Err(Operator::Error(Error::NoReceivers))
    ));
    assert!(operator.payments(&account(1)).is_none());
}

/// A retried request is countersigned again without paying twice, and an earlier request is
/// neither countersigned nor paid once a later one extended the map.
#[test]
fn test_operator_acknowledges_retried_requests_once() {
    let mut operator = operator();
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

/// A sender keeps one request pending at a time and never signs for an epoch before one it holds
/// a countersigned map in.
#[test]
fn test_sender_rules() {
    // An empty batch is refused, and no request is pending to drop.
    let mut alice = sender(0);
    assert!(matches!(
        alice.send(1, Amounts::empty(), false),
        Err(Sending::Error(Error::NoReceivers))
    ));
    assert!(matches!(alice.refused(), Err(Sending::NotPending)));

    // One request at a time.
    let request = alice.send(1, amounts(&[(1, 1)]), false).unwrap();
    assert_eq!(alice.pending(), Some(&request));
    assert!(matches!(
        alice.send(1, amounts(&[(1, 1)]), false),
        Err(Sending::Pending)
    ));

    // Never back to an epoch before one the sender has paid in.
    let mut operator = operator();
    fund(&mut operator, &[(0, 10)]);
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 1)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    for pipelined in [false, true] {
        assert!(matches!(
            alice.send(1, amounts(&[(1, 1)]), pipelined),
            Err(Sending::LaterEpoch)
        ));
    }
    alice.send(2, amounts(&[(1, 1)]), true).unwrap();
}

/// A sender records a map only on an acknowledgement of its pending state by the deployment's
/// operator.
#[test]
fn test_sender_rejects_foreign_acknowledgements() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 10), (1, 10)]);
    let mut alice = sender(0);
    let mut bob = sender(1);

    // An acknowledgement of bob's state does not count for alice's request.
    let request = alice.send(2, amounts(&[(2, 1)]), false).unwrap();
    let bobs = operator
        .accept(&bob.send(2, amounts(&[(2, 1)]), false).unwrap())
        .unwrap();
    assert!(matches!(
        alice.acknowledged(&bobs),
        Err(Sending::InvalidAcknowledgement)
    ));

    // An acknowledgement from another operator does not count.
    let mut impostor = TestOperator::new(PrivateKey::from_seed(1_001), namespace(), LIMITS);
    fund(&mut impostor, &[(0, 10)]);
    let forged = impostor.accept(&request).unwrap();
    assert!(matches!(
        alice.acknowledged(&forged),
        Err(Sending::InvalidAcknowledgement)
    ));

    // The operator's own acknowledgement records the map once.
    let acknowledgement = operator.accept(&request).unwrap();
    assert_eq!(alice.acknowledged(&acknowledgement).unwrap().len(), 1);
    assert!(matches!(
        alice.acknowledged(&acknowledgement),
        Err(Sending::NotPending)
    ));
}

/// A pipelined request that reaches the operator after its epoch closed settles in the next, but
/// not once its own epoch settled it.
#[test]
fn test_pipelined_request_settles_in_the_next_epoch() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let mut bob = receiver(1, 2);

    // The request is for epoch 2, but reaches the operator after it closed epoch 2.
    let request = alice.send(2, amounts(&[(1, 10)]), true).unwrap();
    close(&mut operator);
    let acknowledgement = operator.accept(&request).unwrap();
    let receipts = alice.acknowledged(&acknowledgement).unwrap();
    assert_eq!(receipts[0].state.epoch, 3);
    assert_eq!(bob.receive(receipts[0].clone()).unwrap(), 10);
    assert_eq!(alice.payments(2), None);
    assert_eq!(alice.payments(3), Some(&amounts(&[(1, 10)])));

    // After a request settles in its own epoch, its state for the next epoch does not extend
    // the settled map, so the operator cannot settle it again.
    let request = alice.send(3, amounts(&[(1, 5)]), true).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    close(&mut operator);
    assert!(matches!(
        operator.accept(&request),
        Err(Operator::Error(Error::InvalidSignature))
    ));
}

/// A posted close settles, drops, or keeps pending the sender's request. The request's
/// acknowledgement may have been lost.
#[test]
fn test_posted_close_resolves_pending_requests() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 100)]);

    // The operator admitted the request and the close settles it, but its acknowledgement was
    // lost.
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
    operator.accept(&request).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(
        alice.posted(2, &root, &opening).unwrap(),
        Some(Outcome::Settled)
    );
    assert!(alice.pending().is_none());
    assert_eq!(alice.payments(2), Some(&amounts(&[(1, 10)])));

    // A request for one epoch is dropped if that epoch's close did not settle it.
    alice.send(3, amounts(&[(1, 10)]), false).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(
        alice.posted(3, &root, &opening).unwrap(),
        Some(Outcome::Dropped)
    );
    assert!(alice.pending().is_none());
    assert_eq!(alice.payments(3), None);

    // A pipelined request the close did not settle may still settle in the next epoch.
    let request = alice.send(4, amounts(&[(1, 10)]), true).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(
        alice.posted(4, &root, &opening).unwrap(),
        Some(Outcome::Pending)
    );
    assert_eq!(alice.pending(), Some(&request));

    // The operator admits it in epoch 5, and the sender takes the post only with an opening under
    // the posted root.
    operator.accept(&request).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    let (other, _) = open_row(&fund(&mut operator, &[(7, 1)]), 0);
    assert!(matches!(
        alice.posted(5, &other, &opening),
        Err(Sending::Error(Error::InvalidOpening))
    ));
    assert_eq!(
        alice.posted(5, &root, &opening).unwrap(),
        Some(Outcome::Settled)
    );
    assert_eq!(alice.payments(5), Some(&amounts(&[(1, 10)])));
}

/// A close settling an earlier countersigned map drops the request that would have extended it.
#[test]
fn test_posted_earlier_map_does_not_settle_request() {
    let mut operator = operator();
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
    assert_eq!(
        alice.posted(2, &root, &opening).unwrap(),
        Some(Outcome::Dropped)
    );
    assert_eq!(alice.payments(2), Some(&amounts(&[(1, 5)])));
}

/// A refusal of a pipelined request in its own epoch does not retire its state for the next
/// epoch (S4). Once the close settles the map that state builds on, a replayed copy is admitted
/// if the sender can afford it. A request for another batch then fails, and a request for the
/// same batch repeats the admitted state, so the batch pays once.
#[test]
fn test_replayed_pipelined_request_settles_at_most_once() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 10)]);
    let mut alice = sender(0);

    // Alice pays bob her whole balance, then asks to pay carol 5, pipelined. The operator refuses
    // the request, and alice drops it as if it had been delivered once.
    let paid = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&paid).unwrap())
        .unwrap();
    let refused = alice.send(2, amounts(&[(2, 5)]), true).unwrap();
    assert!(matches!(
        operator.accept(&refused),
        Err(Operator::InsufficientBalance)
    ));
    alice.refused().unwrap();

    // The close of epoch 2 settles her payment to bob and processes a deposit of 5 to her.
    operator.close(&deposits(2, &[(0, 5)]), 1, 0).unwrap();
    assert_eq!(operator.balance(&account(0)), 5);

    // A replayed copy reaches the operator in epoch 3. Its state for epoch 3 builds on the row
    // the close settled and its batch fits her balance, so the operator admits it. Alice has no
    // pending request, so she cannot record its acknowledgement.
    let replayed = operator.accept(&refused).unwrap();
    assert_eq!(operator.payments(&account(0)), Some(&amounts(&[(2, 5)])));
    assert!(matches!(
        alice.acknowledged(&replayed),
        Err(Sending::NotPending)
    ));

    // A request of hers for another batch does not extend the admitted state and is refused.
    let other = alice.send(3, amounts(&[(3, 1)]), false).unwrap();
    assert!(matches!(
        operator.accept(&other),
        Err(Operator::Error(Error::InvalidSignature))
    ));
    alice.refused().unwrap();

    // A request for the same batch signs the admitted state, so the operator countersigns it
    // again. Alice's record then holds the map the close of epoch 3 settles, and carol is paid
    // once.
    let again = alice.send(3, amounts(&[(2, 5)]), false).unwrap();
    let acknowledgement = operator.accept(&again).unwrap();
    assert_eq!(acknowledgement, replayed);
    alice.acknowledged(&acknowledgement).unwrap();
    assert_eq!(alice.payments(3), Some(&amounts(&[(2, 5)])));
    let closed = close(&mut operator);
    assert_eq!(closed.rows().len(), 1);
    assert_eq!(closed.rows()[0].payments, amounts(&[(2, 5)]));
    assert_eq!(operator.balance(&account(0)), 0);
    assert_eq!(operator.balance(&account(2)), 5);
}

/// A posted row settles a pipelined request only if it matches the request's state for the row's
/// epoch. The state for the next epoch pays only the batch, so a close of the request's own epoch
/// that settles an earlier map equal to the batch leaves it pending, and the next close settles it.
#[test]
fn test_pipelined_state_settles_only_in_its_own_epoch() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 10)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();

    // Her pipelined request paying bob 10 more reaches the operator after it closed epoch 2.
    // That close settles her map paying bob 10, the same map her state for epoch 3 commits to.
    let request = alice.send(2, amounts(&[(1, 10)]), true).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(
        alice.posted(2, &root, &opening).unwrap(),
        Some(Outcome::Pending)
    );
    assert_eq!(alice.pending(), Some(&request));

    // The operator admits it in epoch 3, and the close of epoch 3 settles it.
    operator.accept(&request).unwrap();
    let posted = close(&mut operator);
    let (root, opening) = open_row(&posted, 0);
    assert_eq!(
        alice.posted(3, &root, &opening).unwrap(),
        Some(Outcome::Settled)
    );
    assert_eq!(alice.payments(3), Some(&amounts(&[(1, 10)])));
}

/// An operator admits no more senders, receivers in one sender's payment map, or soft withdrawals
/// in an epoch than its limits allow. Requests within them still succeed, and the close it builds
/// at the limits decodes with them.
#[test]
fn test_operator_admits_within_its_limits() {
    let limits = Limits {
        rows: 2,
        receivers: 2,
        withdrawals: 1,
    };
    let mut operator = TestOperator::new(operator_key(), namespace(), limits);
    fund(&mut operator, &[(0, 100), (1, 100), (2, 100)]);
    let (mut alice, mut bob, mut carol) = (sender(0), sender(1), sender(2));

    // Alice pays two receivers and bob one, filling the senders and alice's map.
    let request = alice.send(2, amounts(&[(1, 5), (2, 5)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    let retried = bob.send(2, amounts(&[(0, 5)]), false).unwrap();
    bob.acknowledged(&operator.accept(&retried).unwrap())
        .unwrap();

    // A third sender, or a third receiver in alice's map, would not fit the close.
    let request = carol.send(2, amounts(&[(0, 5)]), false).unwrap();
    assert!(matches!(operator.accept(&request), Err(Operator::Full)));
    carol.refused().unwrap();
    let request = alice.send(2, amounts(&[(3, 1)]), false).unwrap();
    assert!(matches!(operator.accept(&request), Err(Operator::Full)));
    alice.refused().unwrap();

    // A request the account did not sign is refused as unsigned even when it would not fit, so
    // the refusal does not reveal which accounts pay or how many receivers they paid.
    let mut impostor = sender(9);
    for (owner, receiver) in [(2, 0), (0, 3)] {
        let mut request = impostor.send(2, amounts(&[(receiver, 1)]), false).unwrap();
        request.account = account(owner);
        assert!(matches!(
            operator.accept(&request),
            Err(Operator::Error(Error::InvalidSignature))
        ));
        impostor.refused().unwrap();
    }

    // Alice still pays a receiver she paid, and a retried request is acknowledged again.
    let request = alice.send(2, amounts(&[(1, 1)]), false).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    operator.accept(&retried).unwrap();

    // A withdrawal the account did not sign is refused as unsigned while room is left.
    let mut forged = Withdrawal::sign(&user(9), &namespace(), 2, 10, 0);
    forged.account = account(1);
    assert!(matches!(
        operator.withdraw(forged.clone()),
        Err(Operator::Error(Error::InvalidSignature))
    ));

    // A soft withdrawal of another epoch is refused with room left, so it never reaches a close
    // that validators would refuse.
    for epoch in [1, 3] {
        let stale = Withdrawal::sign(&user(0), &namespace(), epoch, 10, 0);
        assert!(matches!(
            operator.withdraw(stale),
            Err(Operator::Error(Error::WrongEpoch { expected: 2, found })) if found == epoch
        ));
    }

    // One soft withdrawal fills the epoch's, so another account's is refused as full. The forged
    // one is still refused as unsigned, and collecting the admitted one again has no effect.
    let withdrawal = Withdrawal::sign(&user(0), &namespace(), 2, 10, 0);
    operator.withdraw(withdrawal.clone()).unwrap();
    let other = Withdrawal::sign(&user(1), &namespace(), 2, 10, 0);
    assert!(matches!(operator.withdraw(other), Err(Operator::Full)));
    assert!(matches!(
        operator.withdraw(forged),
        Err(Operator::Error(Error::InvalidSignature))
    ));
    operator.withdraw(withdrawal).unwrap();

    // The close at the limits decodes with them.
    let closed = close(&mut operator);
    assert_eq!(closed.rows().len(), 2);
    assert_eq!(closed.withdrawals().len(), 1);
    assert_eq!(
        TestClose::decode_cfg(closed.encode(), &limits).unwrap(),
        closed
    );
}

/// A request the account did not sign is refused for its signature alone, before the operator
/// reads any record of the account, so the refusal is the same whatever the account holds or
/// paid. That holds for amounts the account can and cannot pay, for a pipelined state, and for a
/// batch that would overflow its map.
#[test]
fn test_unsigned_requests_are_refused_before_any_read() {
    let refused = |operator: &mut TestOperator, request| {
        let reads = operator.reads();
        assert!(matches!(
            operator.accept(&request),
            Err(Operator::Error(Error::InvalidSignature))
        ));
        assert_eq!(operator.reads(), reads);
    };
    let mut operator = operator();
    fund(&mut operator, &[(0, 10)]);

    // An impostor signs requests for alice's account, for amounts she can and cannot pay, in the
    // current epoch and as the pipelined state of a request for the epoch before.
    let mut impostor = sender(9);
    for (epoch, amount) in [(2, 5), (2, 11), (1, 5)] {
        let pipelined = epoch == 1;
        let mut request = impostor
            .send(epoch, amounts(&[(1, amount)]), pipelined)
            .unwrap();
        request.account = account(0);
        refused(&mut operator, request);
        impostor.refused().unwrap();
    }

    // Alice's own request reads her records. Once she has paid, a forged batch that would
    // overflow her map is refused alike.
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 3)]), false).unwrap();
    let reads = operator.reads();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    assert!(operator.reads() > reads);
    let mut request = impostor.send(2, amounts(&[(1, u64::MAX)]), false).unwrap();
    request.account = account(0);
    refused(&mut operator, request);
    assert_eq!(operator.payments(&account(0)), Some(&amounts(&[(1, 3)])));
}

/// A sender restarted from what it persisted still awaits its pending request. After the
/// acknowledgement, a restart issues the same receipts again from the countersigned state, both
/// signatures, and the map the sender recorded, and pays on top of that map.
#[test]
fn test_sender_restarts_from_its_records() {
    let restart = |sender: &TestSender| {
        TestSender::restart(
            user(0),
            namespace(),
            operator_key().public_key(),
            sender.persisted().clone(),
        )
    };
    let mut operator = operator();
    fund(&mut operator, &[(0, 100)]);
    let alice = sender(0);
    let mut alice = alice;

    // The request is persisted before it is sent.
    let request = alice.send(2, amounts(&[(1, 10), (2, 5)]), false).unwrap();
    let mut restarted = restart(&alice);
    assert_eq!(restarted.pending(), Some(&request));
    let receipts = restarted
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();

    // The acknowledgement is persisted with the request cleared, before any receipt is released.
    let mut again = restart(&restarted);
    assert!(again.pending().is_none());
    let receivers = receipts.iter().map(|receipt| receipt.receiver.clone());
    assert_eq!(again.receipts(2, receivers).unwrap(), receipts);
    let request = again.send(2, amounts(&[(1, 1)]), false).unwrap();
    again
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    assert_eq!(again.payments(2), Some(&amounts(&[(1, 11), (2, 5)])));
}

/// A receiver relies only on a verified receipt that pays it, in an epoch whose close has not
/// posted, before a halt, and only if it raises the amount held.
#[test]
fn test_receiver_rejects_receipts_it_cannot_rely_on() {
    // Alice pays bob 10 and carol 5 in one request.
    let mut operator = operator();
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

    // Bob refuses carol's receipt and a raised amount, and a receiver expecting another operator
    // refuses his. He relies on his own once, and refuses it again as not increasing.
    let mut bob = receiver(1, 2);
    assert!(matches!(
        bob.receive(for_carol.clone()),
        Err(Receiving::WrongReceiver)
    ));
    let mut tampered = for_bob.clone();
    tampered.amount += 1;
    assert!(matches!(
        bob.receive(tampered),
        Err(Receiving::Error(Error::InvalidReceipt))
    ));
    let mut misled = TestReceiver::new(
        account(1),
        namespace(),
        PrivateKey::from_seed(1_001).public_key(),
        2,
    );
    assert!(matches!(
        misled.receive(for_bob.clone()),
        Err(Receiving::Error(Error::InvalidReceipt))
    ));
    assert_eq!(bob.receive(for_bob.clone()).unwrap(), 10);
    assert!(matches!(
        bob.receive(for_bob.clone()),
        Err(Receiving::NotIncreasing)
    ));

    // Once bob holds 10 from alice, a receipt he cannot rely on is refused for that reason
    // alone, so the refusal reveals nothing about what he holds.
    let mut forged = for_bob.clone();
    forged.amount = 5;
    forged.signature = user(9).sign(b"forged", b"receipt");
    forged.acknowledgement = user(9).sign(b"forged", b"receipt");
    assert!(matches!(
        bob.receive(forged),
        Err(Receiving::Error(Error::InvalidReceipt))
    ));
    assert!(matches!(
        bob.receive(for_carol),
        Err(Receiving::WrongReceiver)
    ));

    // Bob audits epoch 2 only once he records that its close posted.
    let empty = Matrix::<PublicKey, Digest, u64>::empty::<Sha256>();
    let opening = empty.open(&account(0), &account(1));
    assert!(matches!(
        bob.audit(2, &empty.root(), &account(0), &opening),
        Err(Receiving::NotClosed)
    ));

    // A receiver rejects receipts for an epoch whose close posted, and every receipt once the
    // ledger halts.
    let mut late = receiver(1, 2);
    late.posted(2);
    assert!(matches!(
        late.receive(for_bob.clone()),
        Err(Receiving::Closed)
    ));
    let mut halted = receiver(1, 2);
    halted.halt();
    assert!(matches!(halted.receive(for_bob), Err(Receiving::Halted)));
}

/// A receiver resumes from its persisted receipts, in any order, keeping the largest from each
/// sender, its recorded halt, and receipts of closed epochs. It refuses receipts that pay another
/// account.
#[test]
fn test_resumed_receiver_keeps_its_strongest_receipts_and_halt() {
    let mut operator = operator();
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
    let resume = |index, next, halted, receipts: Vec<_>| {
        TestReceiver::resume(
            account(index),
            namespace(),
            operator_key().public_key(),
            next,
            halted,
            receipts,
        )
    };
    for receipts in [
        vec![upper.clone(), lower.clone()],
        vec![lower.clone(), upper.clone()],
    ] {
        let mut bob = resume(1, 2, false, receipts).unwrap();
        assert_eq!(bob.amount(2, &account(0)), 15);
        assert!(matches!(
            bob.receive(lower.clone()),
            Err(Receiving::NotIncreasing)
        ));
    }

    // A receiver that saw the ledger halt keeps refusing receipts after resuming.
    let mut halted = resume(1, 2, true, vec![lower.clone()]).unwrap();
    assert!(matches!(halted.receive(upper), Err(Receiving::Halted)));

    // Receipts of an epoch whose close posted are kept for its audit, and none pays another
    // account.
    let bob = resume(1, 3, false, vec![lower.clone()]).unwrap();
    assert_eq!(bob.amount(2, &account(0)), 10);
    assert!(matches!(
        resume(2, 3, false, vec![lower]),
        Err(Receiving::WrongReceiver)
    ));
}

/// A post updates the sender only with a valid opening of its row, even a post of an epoch its
/// pending request does not involve.
#[test]
fn test_posted_close_needs_a_valid_opening() {
    let mut alice = sender(0);
    alice.send(2, amounts(&[(1, 5)]), false).unwrap();
    let queue = deposits(1, &[]);
    let populated = forge(
        &operator_key(),
        &queue,
        vec![row(1, 0, amounts(&[(1, 7)]), &Amounts::empty())],
        Vec::new(),
        0,
        0,
    )
    .matrix::<Sha256>();
    let empty = Matrix::<PublicKey, Digest, u64>::empty::<Sha256>();
    let opening = populated.open(&account(0), &account(1));
    assert!(matches!(
        alice.posted(1, &empty.root(), &opening),
        Err(Sending::Error(Error::InvalidOpening))
    ));
    assert!(alice.pending().is_some());
}
