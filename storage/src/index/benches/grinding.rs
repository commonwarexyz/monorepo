//! Adversarial "grinding" benchmark for the partitioned ordered index.
//!
//! Compares a `uniform` key distribution (keys spread across partitions) against a `grinding`
//! distribution (every key sharing the partition prefix, flooding one partition with distinct
//! translated keys). The decisive cost is insert: an unguarded sorted array memmoves O(M) per
//! inserted key -- O(M^2) to flood M keys -- so the spill guard converts the flooded partition to a
//! `BTreeMap`, making each insert O(log M) (O(M log M) total). Distinct-key lookup is O(log M)
//! either way (a binary search over the sorted array vs a tree descent), so the guard bounds its
//! locality, not its asymptotics; an O(M) scan would only arise for a same-translated-key collision
//! chain, which is not the grinding vector. The grinding and uniform curves should therefore stay
//! within a small factor rather than diverging quadratically.

use super::DummyMetrics;
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::{
    index::{partitioned, Unordered},
    translator::Cap,
};
use criterion::{criterion_group, Criterion};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 3] = [10_000, 50_000, 200_000];

/// 8-byte keys. With P=2 the first two bytes select the partition. `grinding` uses the big-endian
/// index, whose top two bytes are zero, so every key lands in partition 0 with a distinct
/// translated suffix; `uniform` hashes the index so keys spread across all 65,536 partitions.
fn keys(items: usize, grinding: bool) -> Vec<[u8; 8]> {
    (0..items as u64)
        .map(|i| {
            if grinding {
                i.to_be_bytes()
            } else {
                Sha256::hash(&i.to_be_bytes()).as_ref()[..8]
                    .try_into()
                    .unwrap()
            }
        })
        .collect()
}

fn new_index() -> partitioned::ordered::Index<Cap<6>, u64, 2> {
    partitioned::ordered::Index::new(DummyMetrics, Cap::<6>::new())
}

fn run_insert(keys: &[[u8; 8]]) -> Duration {
    let mut index = new_index();
    let start = Instant::now();
    for (i, k) in keys.iter().enumerate() {
        index.insert(k, i as u64);
    }
    start.elapsed()
}

fn bench_grinding(c: &mut Criterion) {
    for items in N_ITEMS {
        for grinding in [false, true] {
            let dist = if grinding { "grinding" } else { "uniform" };
            let ks = keys(items, grinding);

            c.bench_function(
                &format!("{}/op=insert dist={dist} items={items}", module_path!()),
                |b| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += run_insert(&ks);
                        }
                        total
                    });
                },
            );

            // Build once outside the timed region; the lookup bench measures only `get`.
            let mut index = new_index();
            for (i, k) in ks.iter().enumerate() {
                index.insert(k, i as u64);
            }
            c.bench_function(
                &format!("{}/op=lookup dist={dist} items={items}", module_path!()),
                |b| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let start = Instant::now();
                            for k in &ks {
                                for v in index.get(k) {
                                    black_box(v);
                                }
                            }
                            total += start.elapsed();
                        }
                        total
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_grinding
}
