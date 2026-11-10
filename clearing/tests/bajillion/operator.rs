//! Sharded admission and restarts of operators built from the helpers.

use super::*;
use commonware_clearing::bajillion::{Flow, ForcedWithdrawal};
use std::collections::HashMap;

/// Two operators that restart from one operator's persisted state and each admit half the
/// accounts produce rows and soft withdrawals that assemble into the same close, byte for byte,
/// with the same flows, as one operator admitting everything.
#[test]
fn test_assembly_matches_monolithic_close() {
    // Two shards restart from the state the funded single operator persisted for epoch 2.
    const USERS: u64 = 6;
    const SHARDS: u64 = 2;
    let users: Vec<u64> = (0..USERS).collect();
    let mut replica = operator();
    let funding: Vec<_> = users.iter().map(|index| (*index, 100)).collect();
    fund(&mut replica, &funding);
    let mut shards: Vec<_> = (0..SHARDS)
        .map(|_| {
            TestOperator::restart(
                operator_key(),
                namespace(),
                LIMITS,
                replica.persisted().clone(),
            )
        })
        .collect();

    // The same requests and soft withdrawals reach the single operator and the shard serving
    // their account.
    let mut senders: HashMap<_, _> = users.iter().map(|index| (*index, sender(*index))).collect();
    for from in &users {
        for offset in [1, 3] {
            let to = (from + offset) % USERS;
            let sender = senders.get_mut(from).unwrap();
            let request = sender.send(2, amounts(&[(to, 10 + from)])).unwrap();
            let shard = usize::try_from(from % SHARDS).expect("a shard index must fit a usize");
            let acknowledgement = shards[shard].accept(&request).unwrap();
            replica.accept(&request).unwrap();
            sender.acknowledged(&acknowledgement).unwrap();
        }
    }
    let withdrawal = Withdrawal::sign(&user(2), &namespace(), 2, 15, 0);
    shards[0].withdraw(withdrawal.clone()).unwrap();
    replica.withdraw(withdrawal).unwrap();

    // Both close epoch 2 identically.
    let queue = Queue {
        forced_withdrawals: vec![ForcedWithdrawal {
            account: account(4),
            amount: 5,
        }],
        ..deposits(2, &[(5, 7)])
    };
    let (assembled, flows) = replica.close(&queue, 1, 1).unwrap();
    let (sharded, sharded_flows) = Close::assemble::<Sha256, _>(
        &operator_key(),
        &namespace(),
        &queue,
        shards.iter().flat_map(TestOperator::rows),
        shards.iter().flat_map(|shard| shard.withdrawals().cloned()),
        1,
        1,
    )
    .unwrap();
    assert_eq!(assembled.encode(), sharded.encode());
    assert_eq!(flows, sharded_flows);
}

/// Flows routed to the shard serving each account and applied there in epoch order (O8) give the
/// balances the operator holds, however the closes' flows arrive. Bob's forced withdrawal of
/// epoch 2 and his deposit of epoch 3 do not commute, so applying them out of order leaves him
/// the wrong balance.
#[test]
fn test_flows_apply_per_account_in_epoch_order() {
    let mut operator = operator();
    fund(&mut operator, &[(0, 100), (1, 100)]);
    let mut alice = sender(0);

    // In epoch 2 alice pays bob 30 and bob forces out more than he holds. In epoch 3 he deposits
    // 40. After both closes the operator holds 70 for alice and 40 for bob.
    let request = alice.send(2, amounts(&[(1, 30)])).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    let forcing = Queue {
        forced_withdrawals: vec![ForcedWithdrawal {
            account: account(1),
            amount: 150,
        }],
        ..deposits(2, &[])
    };
    let (second, second_flows) = operator.close(&forcing, 0, 1).unwrap();
    let (third, third_flows) = operator.close(&deposits(3, &[(1, 40)]), 1, 0).unwrap();
    assert_eq!((second.epoch(), third.epoch()), (2, 3));
    assert_eq!(operator.balance(&account(0)), 70);
    assert_eq!(operator.balance(&account(1)), 40);

    // Epoch 3's flows reach the shards before epoch 2's.
    let mut delivered: HashMap<_, Vec<_>> = HashMap::new();
    for (account, flow) in third_flows.into_iter().chain(second_flows) {
        delivered.entry(account).or_default().push(flow);
    }
    let apply = |flows: &[Flow<u64>], balance: u64| {
        flows
            .iter()
            .fold(balance, |balance, flow| flow.settle(balance).unwrap().0)
    };

    // Applied in epoch order, each account's flows give the operator's balance. Applied as
    // delivered, bob's withdrawal takes his deposit too, and he keeps 20 while the operator holds
    // 40 for him.
    let (alice, bob) = (account(0), account(1));
    for (holder, flows) in &delivered {
        let mut ordered = flows.clone();
        ordered.sort_by_key(Flow::epoch);
        let funded = if *holder == alice || *holder == bob {
            100
        } else {
            0
        };
        assert_eq!(apply(&ordered, funded), operator.balance(holder));
    }
    assert_eq!(apply(&delivered[&bob], 100), 20);
}

/// An operator restarted from what it persisted, its admissions and soft withdrawals of the open
/// epoch included, closes the epoch exactly as the original. A restart after the close holds the
/// close it released.
#[test]
fn test_restarted_operator_closes_like_the_original() {
    let restart = |operator: &TestOperator| {
        TestOperator::restart(
            operator_key(),
            namespace(),
            LIMITS,
            operator.persisted().clone(),
        )
    };

    // Alice pays bob 10 in epoch 2, and the operator closes it.
    let mut operator = operator();
    fund(&mut operator, &[(0, 100)]);
    let mut alice = sender(0);
    let request = alice.send(2, amounts(&[(1, 10)])).unwrap();
    alice
        .acknowledged(&operator.accept(&request).unwrap())
        .unwrap();
    close(&mut operator);

    // In epoch 3, the operator admits a request on top of the row the close of epoch 2 settled for
    // alice, and a soft withdrawal, persisting each before it answers.
    let request = alice.send(3, amounts(&[(1, 5)])).unwrap();
    let acknowledgement = operator.accept(&request).unwrap();
    assert_eq!(alice.acknowledged(&acknowledgement).unwrap()[0].amount, 5);
    let withdrawal = Withdrawal::sign(&user(1), &namespace(), 3, 4, 0);
    operator.withdraw(withdrawal).unwrap();

    // The restarted operator holds both from its records alone. It countersigns the request again
    // as a retry, paying nothing twice, and closes the epoch as the original does.
    let mut restarted = restart(&operator);
    assert_eq!(restarted.epoch(), 3);
    assert_eq!(restarted.payments(&account(0)), Some(&amounts(&[(1, 5)])));
    assert_eq!(restarted.live(&account(0)), 85);
    assert_eq!(restarted.accept(&request).unwrap(), acknowledgement);
    assert_eq!(restarted.live(&account(0)), 85);
    let released = close(&mut operator);
    assert_eq!(close(&mut restarted), released);

    // A restart after the close holds the close to release again.
    let again = restart(&operator);
    assert_eq!(again.persisted().released.as_ref(), Some(&released));
    assert_eq!(again.persisted(), restarted.persisted());
}
