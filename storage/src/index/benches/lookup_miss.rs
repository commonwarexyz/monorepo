use super::{Digest, DummyMetrics};
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::{
    index::{unordered, Unordered},
    translator::{EightCap, FourCap, Translator, TwoCap},
};
use criterion::{criterion_group, Criterion};
use std::{
    collections::HashSet,
    hint::black_box,
    time::{Duration, Instant},
};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 2] = [10_000, 50_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];

const N_LOOKUPS: usize = 10_000;

fn run_lookup_miss<T: Translator>(
    c: &mut Criterion,
    translator: T,
    name: &str,
    items: usize,
    inserted_keys: &[Digest],
) {
    let missing_keys = translated_key_misses(&translator, &inserted_keys[..items], N_LOOKUPS);

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
                for key in &missing_keys {
                    black_box(index.get(key).next().is_none());
                }
                total += start.elapsed();
            }
            total
        });
    });
}

fn translated_key_misses<T: Translator>(
    translator: &T,
    inserted_keys: &[Digest],
    count: usize,
) -> Vec<Digest> {
    let mut seen: HashSet<_> = inserted_keys
        .iter()
        .map(|key| translator.transform(key))
        .collect();

    let mut misses = Vec::with_capacity(count);
    let mut i = inserted_keys.len() as u64;
    while misses.len() < count {
        let key = Sha256::hash(&i.to_be_bytes());
        // Keep translated misses distinct so we do not benchmark repeated probes into the
        // same empty bucket.
        if seen.insert(translator.transform(&key)) {
            misses.push(key);
        }
        i += 1;
    }
    misses
}

fn bench_lookup_miss(c: &mut Criterion) {
    let max_items = *N_ITEMS.last().unwrap();

    // Keys inserted into the index: hash(0), hash(1), ...
    let inserted_keys: Vec<_> = (0..max_items)
        .map(|i| Sha256::hash(&i.to_be_bytes()))
        .collect();

    for items in N_ITEMS {
        // OneCap cannot produce translated-key misses at these benchmark sizes.
        if items <= u16::MAX as usize {
            run_lookup_miss(c, TwoCap, "two_cap", items, &inserted_keys);
        }
        run_lookup_miss(c, FourCap, "four_cap", items, &inserted_keys);
        run_lookup_miss(c, EightCap, "eight_cap", items, &inserted_keys);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_lookup_miss,
}
