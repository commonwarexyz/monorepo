use super::{Digest, DummyMetrics};
use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::{
    index::{ordered, partitioned, Ordered, Snapshottable, Unordered},
    translator::EightCap,
};
use criterion::{criterion_group, Criterion};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[cfg(not(full_bench))]
const N_ITEMS: [usize; 1] = [10_000];
#[cfg(full_bench)]
const N_ITEMS: [usize; 3] = [10_000, 50_000, 100_000];

fn keys(items: usize) -> Vec<Digest> {
    (0..items).map(|i| Sha256::hash(&i.to_be_bytes())).collect()
}

fn populate<I: Unordered<Value = u64>>(index: &mut I, keys: &[Digest]) {
    for (i, key) in keys.iter().enumerate() {
        index.insert(key, i as u64);
    }
}

fn bench_cheap_snapshot_dirty_head(c: &mut Criterion) {
    for items in N_ITEMS {
        let keys = keys(items);
        let mut index = ordered::Index::new(DummyMetrics, EightCap);
        populate(&mut index, &keys);

        let label = format!(
            "{}/case=cheap_snapshot dirty=true items={items}",
            module_path!()
        );
        c.bench_function(&label, |b| {
            let mut i = 0usize;
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    if index.needs_compaction() {
                        index.compact();
                    }
                    let key = keys[i % keys.len()];
                    index.insert(&key, i as u64);
                    i += 1;

                    let start = Instant::now();
                    black_box(Snapshottable::snapshot(&mut index));
                    total += start.elapsed();
                }
                total
            });
        });
    }
}

fn bench_first_write_after_snapshot(c: &mut Criterion) {
    for items in N_ITEMS {
        let keys = keys(items);
        let mut index = ordered::Index::new(DummyMetrics, EightCap);
        populate(&mut index, &keys);

        let label = format!(
            "{}/case=first_write_after_snapshot items={items}",
            module_path!()
        );
        c.bench_function(&label, |b| {
            let mut i = 0usize;
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    if index.needs_compaction() {
                        index.compact();
                    }
                    let _snapshot = Snapshottable::snapshot(&mut index);
                    let key = keys[i % keys.len()];
                    i += 1;
                    let start = Instant::now();
                    index.insert(&key, i as u64);
                    total += start.elapsed();
                }
                total
            });
        });
    }
}

fn bench_point_read_through_epochs(c: &mut Criterion) {
    for items in N_ITEMS {
        let keys = keys(items);
        let mut index = ordered::Index::new(DummyMetrics, EightCap);
        populate(&mut index, &keys);
        for (i, key) in keys.iter().enumerate().take(8) {
            index.insert(key, i as u64);
            let _snapshot = Snapshottable::snapshot(&mut index);
        }

        let label = format!(
            "{}/case=point_read_through_epochs depth=8 items={items}",
            module_path!()
        );
        c.bench_function(&label, |b| {
            let key = keys[0];
            b.iter(|| black_box(index.get(&key).next()));
        });
    }
}

fn bench_ordered_next_through_epochs(c: &mut Criterion) {
    for items in N_ITEMS {
        let keys = keys(items);
        let mut index = partitioned::ordered::Index::<_, u64, 1>::new(DummyMetrics, EightCap);
        populate(&mut index, &keys);
        for key in keys.iter().take(8).skip(1) {
            index.remove(key);
            let _snapshot = Snapshottable::snapshot(&mut index);
        }

        let label = format!(
            "{}/case=ordered_next_prev_through_tombstones depth=7 items={items}",
            module_path!()
        );
        c.bench_function(&label, |b| {
            let key = keys[0];
            b.iter(|| {
                black_box(index.next_translated_key(&key).is_some());
                black_box(index.prev_translated_key(&key).is_some());
            });
        });
    }
}

fn bench_explicit_full_compaction(c: &mut Criterion) {
    for items in N_ITEMS {
        let keys = keys(items);
        let label = format!(
            "{}/case=explicit_full_compaction depth=8 items={items}",
            module_path!()
        );
        c.bench_function(&label, |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for iter in 0..iters {
                    let mut index = ordered::Index::new(DummyMetrics, EightCap);
                    populate(&mut index, &keys);
                    for key in keys.iter().take(8) {
                        index.insert(key, iter);
                        let _snapshot = Snapshottable::snapshot(&mut index);
                    }
                    let start = Instant::now();
                    index.compact();
                    total += start.elapsed();
                    black_box(index.get(&keys[7]).next());
                }
                total
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_cheap_snapshot_dirty_head, bench_first_write_after_snapshot,
        bench_point_read_through_epochs, bench_ordered_next_through_epochs,
        bench_explicit_full_compaction,
}
