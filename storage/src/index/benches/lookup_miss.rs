use super::DummyMetrics;
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::{
    index::{unordered, Unordered},
    translator::{EightCap, FourCap, OneCap, Translator, TwoCap},
};
use criterion::{criterion_group, Criterion};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];

const N_LOOKUPS: usize = 10_000;

type Digest = <Sha256 as Hasher>::Digest;

// Match the full digest via stored positions so misses scan the entire collision
// chain without changing the index value layout.
fn contains_full_key<I: Unordered<Value = u64>>(index: &I, key: &Digest, keys: &[Digest]) -> bool {
    index
        .get(key)
        .any(|candidate| &keys[*candidate as usize] == key)
}

fn run_lookup_miss<T: Translator>(
    c: &mut Criterion,
    translator: T,
    name: &str,
    items: usize,
    inserted_keys: &[Digest],
    missing_keys: &[Digest],
) {
    // Populate the index
    let mut index = unordered::Index::new(DummyMetrics, translator);
    for (i, key) in inserted_keys.iter().enumerate().take(items) {
        index.insert(key, i as u64);
    }

    let label = format!("{}/translator={name} items={items}", module_path!());
    c.bench_function(&label, |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                for key in missing_keys.iter().take(N_LOOKUPS) {
                    black_box(contains_full_key(&index, key, inserted_keys));
                }
                total += start.elapsed();
            }
            total
        });
    });
}

fn bench_lookup_miss(c: &mut Criterion) {
    let max_items = *N_ITEMS.last().unwrap();

    // Keys inserted into the index: hash(0), hash(1), ...
    let inserted_keys: Vec<_> = (0..max_items)
        .map(|i| Sha256::hash(&i.to_be_bytes()))
        .collect();

    // Keys NOT in the index: hash(max_items), hash(max_items+1), ...
    let missing_keys: Vec<_> = (max_items..max_items + N_LOOKUPS)
        .map(|i| Sha256::hash(&i.to_be_bytes()))
        .collect();

    for items in N_ITEMS {
        run_lookup_miss(c, OneCap, "one_cap", items, &inserted_keys, &missing_keys);
        run_lookup_miss(c, TwoCap, "two_cap", items, &inserted_keys, &missing_keys);
        run_lookup_miss(c, FourCap, "four_cap", items, &inserted_keys, &missing_keys);
        run_lookup_miss(
            c,
            EightCap,
            "eight_cap",
            items,
            &inserted_keys,
            &missing_keys,
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50).warm_up_time(std::time::Duration::from_secs(5)).measurement_time(std::time::Duration::from_secs(10));
    targets = bench_lookup_miss,
}
