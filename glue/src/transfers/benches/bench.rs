//! Benchmarks the CPU stages of [commonware_glue::transfers] over batches of payments.

use commonware_allocator::mimalloc;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_glue::transfers::{Account, Change, Transfer};
use commonware_utils::test_rng;
use criterion::criterion_main;
use rand::RngExt as _;
use std::{collections::HashMap, convert::Infallible};

mod plan;
mod select;
mod settle;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

/// Workers in the pool behind the parallel rows.
const CONCURRENCY: usize = 8;

/// Payments per benchmarked batch.
const TRANSFERS: [usize; 4] = [16, 1_024, 32_768, 131_072];

/// Numbers of distinct keys the payments draw from, ranging from few enough that a large batch
/// touches each many times to enough that most payments touch fresh keys.
const ACCOUNTS: [u64; 3] = [128, 4_096, 1_000_000];

/// Starting balance of every account, more than any key's debits in a batch.
const BALANCE: u64 = 1 << 40;

/// An account that holds only a balance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Balance(u64);

impl Account for Balance {
    type Effect = Infallible;

    fn balance(&self) -> u64 {
        self.0
    }

    fn set_balance(&mut self, balance: u64) {
        self.0 = balance;
    }

    fn apply(&mut self, effect: Infallible) -> bool {
        match effect {}
    }
}

/// An account that holds a balance and the next nonce its payments consume.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Nonced {
    balance: u64,
    nonce: u64,
}

impl Nonced {
    /// The starting account of every key.
    const START: Self = Self {
        balance: BALANCE,
        nonce: 0,
    };
}

impl Account for Nonced {
    /// The nonce a payment consumes.
    type Effect = u64;

    fn balance(&self) -> u64 {
        self.balance
    }

    fn set_balance(&mut self, balance: u64) {
        self.balance = balance;
    }

    fn apply(&mut self, nonce: u64) -> bool {
        if nonce != self.nonce {
            return false;
        }
        self.nonce += 1;
        true
    }
}

/// A payment from one key to another.
#[derive(Clone)]
struct Payment {
    from: Digest,
    to: Digest,
    amount: u64,
}

impl Transfer for Payment {
    type Key = Digest;
    type Account = Balance;

    fn changes(&self) -> impl Iterator<Item = (&Digest, Change)> {
        [
            (&self.from, Change::debit(self.amount)),
            (&self.to, Change::credit(self.amount)),
        ]
        .into_iter()
    }
}

/// A payment whose sender also consumes its next nonce.
struct Signed {
    payment: Payment,
    nonce: u64,
}

impl Transfer for Signed {
    type Key = Digest;
    type Account = Nonced;

    fn changes(&self) -> impl Iterator<Item = (&Digest, Change<u64>)> {
        let Payment { from, to, amount } = &self.payment;
        let sender = Change {
            effect: Some(self.nonce),
            ..Change::debit(*amount)
        };
        [(from, sender), (to, Change::credit(*amount))].into_iter()
    }
}

/// Returns `count` payments between random keys among the first `accounts`.
fn payments(count: usize, accounts: u64) -> Vec<Payment> {
    let mut rng = test_rng();
    (0..count)
        .map(|_| Payment {
            from: key(rng.random_range(0..accounts)),
            to: key(rng.random_range(0..accounts)),
            amount: rng.random_range(1..10),
        })
        .collect()
}

/// Returns `payments` with each sender's nonces assigned in order from zero.
fn signed(payments: &[Payment]) -> Vec<Signed> {
    let mut nonces = HashMap::new();
    payments
        .iter()
        .map(|payment| {
            let nonce = nonces.entry(payment.from).or_insert(0);
            let signed = Signed {
                payment: payment.clone(),
                nonce: *nonce,
            };
            *nonce += 1;
            signed
        })
        .collect()
}

/// The key of account `index`.
fn key(index: u64) -> Digest {
    Sha256::hash(&[&index.to_be_bytes()])
}

/// Calls `bench` with the parameters of every benchmarked batch, its payments, and the same
/// payments with nonces.
fn for_each_batch(mut bench: impl FnMut(&str, &[Payment], &[Signed])) {
    for transfers in TRANSFERS {
        for accounts in ACCOUNTS {
            let payments = payments(transfers, accounts);
            let signed = signed(&payments);
            bench(
                &format!("transfers={transfers} accounts={accounts}"),
                &payments,
                &signed,
            );
        }
    }
}

criterion_main!(plan::benches, settle::benches, select::benches);
