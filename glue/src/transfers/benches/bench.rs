//! Benchmarks the CPU stages of [commonware_glue::transfers] over batches of payments.

use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_glue::transfers::{Account, Change, Transfer};
use commonware_utils::test_rng;
use criterion::criterion_main;
use rand::RngExt as _;
use std::convert::Infallible;

mod plan;
mod select;
mod settle;

/// Workers in the pool behind the parallel rows.
const CONCURRENCY: usize = 8;

/// Payments per benchmarked batch.
const TRANSFERS: [usize; 4] = [16, 1_024, 32_768, 131_072];

/// Distinct keys the payments draw from.
const KEYS: u64 = 1_000_000;

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

/// A payment from one key to another.
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
            (&self.from, Change::Debit(self.amount)),
            (&self.to, Change::Credit(self.amount)),
        ]
        .into_iter()
    }
}

/// Returns `count` payments between random keys of [KEYS].
fn payments(count: usize) -> Vec<Payment> {
    let mut rng = test_rng();
    (0..count)
        .map(|_| Payment {
            from: key(rng.random_range(0..KEYS)),
            to: key(rng.random_range(0..KEYS)),
            amount: rng.random_range(1..10),
        })
        .collect()
}

/// The key of account `index`.
fn key(index: u64) -> Digest {
    Sha256::hash(&[&index.to_be_bytes()])
}

criterion_main!(plan::benches, settle::benches, select::benches);
