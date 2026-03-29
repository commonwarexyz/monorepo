use super::DummyMetrics;
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::{
    index::{unordered, Unordered},
    translator::{EightCap, FourCap, OneCap, Translator, TwoCap},
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];

type Digest = <Sha256 as Hasher>::Digest;

// Match the full digest so collisions pay the same chain scan cost as real callers.
fn contains_full_key<I: Unordered<Value = Digest>>(index: &I, key: &Digest) -> bool {
    index.get(key).any(|candidate| candidate == key)
}

fn run_lookup<T: Translator>(
    c: &mut Criterion,
    translator: T,
    name: &str,
    items: usize,
    keys: &[Digest],
) {
    // Populate the index
    let mut index = unordered::Index::new(DummyMetrics, translator);
    for key in keys.iter().take(items) {
        index.insert(key, key.clone());
    }

    // Shuffle lookup order
    let mut rng = StdRng::seed_from_u64(1);
    let mut lookup_keys: Vec<_> = keys.iter().take(items).cloned().collect();
    lookup_keys.shuffle(&mut rng);

    let label = format!("{}/translator={name} items={items}", module_path!());
    c.bench_function(&label, |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                for key in &lookup_keys {
                    black_box(contains_full_key(&index, key));
                }
                total += start.elapsed();
            }
            total
        });
    });
}

fn bench_lookup(c: &mut Criterion) {
    let max_items = *N_ITEMS.last().unwrap();
    let keys: Vec<_> = (0..max_items)
        .map(|i| Sha256::hash(&i.to_be_bytes()))
        .collect();

    for items in N_ITEMS {
        run_lookup(c, OneCap, "one_cap", items, &keys);
        run_lookup(c, TwoCap, "two_cap", items, &keys);
        run_lookup(c, FourCap, "four_cap", items, &keys);
        run_lookup(c, EightCap, "eight_cap", items, &keys);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50).warm_up_time(std::time::Duration::from_secs(5)).measurement_time(std::time::Duration::from_secs(10));
    targets = bench_lookup,
}
