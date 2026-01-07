use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const N_ITEMS: usize = 100_000;
const N_LOOKUPS: usize = 10_000;

fn binary_search(vec: &[(u64, u32)], key: u64) -> Option<u32> {
    vec.binary_search_by_key(&key, |(k, _)| *k)
        .ok()
        .map(|idx| vec[idx].1)
}

fn bench_lookup(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);

    // Generate indices (simulating non-contiguous blockchain indices)
    let mut indices: Vec<u64> = (0..N_ITEMS as u64).map(|i| i * 3 + (i % 7)).collect();
    indices.shuffle(&mut rng);

    // Build BTreeMap
    let btree: BTreeMap<u64, u32> = indices
        .iter()
        .enumerate()
        .map(|(pos, &idx)| (idx, pos as u32))
        .collect();

    // Build sorted Vec
    let mut sorted_vec: Vec<(u64, u32)> = indices
        .iter()
        .enumerate()
        .map(|(pos, &idx)| (idx, pos as u32))
        .collect();
    sorted_vec.sort_by_key(|(k, _)| *k);

    // Generate random lookup keys (all valid)
    let mut lookup_keys: Vec<u64> = indices.to_vec();
    lookup_keys.shuffle(&mut rng);
    lookup_keys.truncate(N_LOOKUPS);

    // Benchmark BTreeMap lookup
    c.bench_function(
        &format!(
            "{}/btreemap items={} lookups={}",
            module_path!(),
            N_ITEMS,
            N_LOOKUPS
        ),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    for key in &lookup_keys {
                        std::hint::black_box(btree.get(key));
                    }
                    total += start.elapsed();
                }
                total
            });
        },
    );

    // Benchmark sorted Vec binary search
    c.bench_function(
        &format!(
            "{}/sorted_vec items={} lookups={}",
            module_path!(),
            N_ITEMS,
            N_LOOKUPS
        ),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    for key in &lookup_keys {
                        std::hint::black_box(binary_search(&sorted_vec, *key));
                    }
                    total += start.elapsed();
                }
                total
            });
        },
    );
}

fn bench_insert(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);

    // Generate indices (simulating sequential blockchain indices with small gaps)
    let indices: Vec<u64> = (0..N_ITEMS as u64).map(|i| i * 3 + (i % 7)).collect();

    // Benchmark BTreeMap insert (random order)
    let mut shuffled = indices.clone();
    shuffled.shuffle(&mut rng);
    c.bench_function(
        &format!(
            "{}/btreemap_insert_random items={}",
            module_path!(),
            N_ITEMS
        ),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut btree: BTreeMap<u64, u32> = BTreeMap::new();
                    let start = Instant::now();
                    for (pos, &idx) in shuffled.iter().enumerate() {
                        btree.insert(idx, pos as u32);
                    }
                    total += start.elapsed();
                    std::hint::black_box(btree);
                }
                total
            });
        },
    );

    // Benchmark sorted Vec insert (sequential order - best case)
    c.bench_function(
        &format!(
            "{}/sorted_vec_insert_sequential items={}",
            module_path!(),
            N_ITEMS
        ),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut vec: Vec<(u64, u32)> = Vec::new();
                    let start = Instant::now();
                    for (pos, &idx) in indices.iter().enumerate() {
                        // Sequential inserts go at the end
                        vec.push((idx, pos as u32));
                    }
                    total += start.elapsed();
                    std::hint::black_box(vec);
                }
                total
            });
        },
    );

    // Benchmark sorted Vec insert (random order - worst case, needs sorting)
    c.bench_function(
        &format!(
            "{}/sorted_vec_insert_random items={}",
            module_path!(),
            N_ITEMS
        ),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut vec: Vec<(u64, u32)> = Vec::new();
                    let start = Instant::now();
                    for (pos, &idx) in shuffled.iter().enumerate() {
                        // Insert in sorted position
                        let insert_pos = vec.partition_point(|(k, _)| *k < idx);
                        vec.insert(insert_pos, (idx, pos as u32));
                    }
                    total += start.elapsed();
                    std::hint::black_box(vec);
                }
                total
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = bench_lookup, bench_insert
}
