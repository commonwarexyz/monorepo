//! Standalone, opt-in characterization of the index at huge key counts.
//!
//! At P=3 (16.8M partitions) criterion is a poor fit: it reruns each benchmark for many samples,
//! and every insert sample would rebuild a multi-GB index. This binary instead builds each variant
//! once and reports insert and lookup ns/op. It is opt-in: a bare `cargo bench` prints a notice and
//! does nothing (even a tiny P=3 run allocates the ~805 MB partition header). The real run (20M/100M
//! keys, ~12+ GB RAM) is gated behind `--cfg huge_bench`, e.g.
//! `RUSTFLAGS="--cfg huge_bench" cargo bench -p commonware-storage --bench index_scale`.

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    telemetry::metrics::{Metric, Registered, Registration},
    Metrics, Name, Supervisor,
};
use commonware_storage::{
    index::{ordered, partitioned, unordered, Unordered},
    translator::{Cap, EightCap},
};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

type Digest = <Sha256 as Hasher>::Digest;

// 20M keys gives ~1.2 entries per P=3 partition, 100M gives ~6 -- enough to exercise the
// per-partition sorted runs.
const N_ITEMS: [usize; 2] = [20_000_000, 100_000_000];

/// No-op metrics context. Mirrors the criterion benches' helper; duplicated because a separate
/// `harness = false` target cannot share the criterion entry point's module.
#[derive(Clone)]
struct DummyMetrics;

impl Supervisor for DummyMetrics {
    fn child(&self, _: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _: &'static str, _: impl std::fmt::Display) -> Self {
        Self
    }

    fn name(&self) -> Name {
        Name::default()
    }
}

impl Metrics for DummyMetrics {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        _: N,
        _: H,
        metric: M,
    ) -> Registered<M> {
        Registered::with_registration(metric, Registration::from(()))
    }

    fn encode(&self) -> String {
        String::new()
    }
}

/// Insert every key (timing the build), then look every key up (timing the gets), returning the two
/// batch durations. The index is built once and reused for both phases; the orders differ so lookups
/// don't follow insertion order.
fn measure<I: Unordered<Value = u64>>(
    mut index: I,
    keys: &[Digest],
    insert_order: &[usize],
    lookup_order: &[usize],
) -> (Duration, Duration) {
    let start = Instant::now();
    for &i in insert_order {
        index.insert(&keys[i], i as u64);
    }
    let insert = start.elapsed();

    let start = Instant::now();
    for &i in lookup_order {
        black_box(index.get(&keys[i]).next().is_some());
    }
    let lookup = start.elapsed();

    (insert, lookup)
}

fn main() {
    // Empty (and a notice) unless built with `--cfg huge_bench`, so a bare `cargo bench` -- including
    // CI's full-suite run, which uses `--cfg full_bench` -- neither allocates the P=3 header nor runs
    // the multi-GB builds. The work below still compiles either way, so it is type-checked in CI.
    let sizes: &[usize] = if cfg!(huge_bench) {
        &N_ITEMS
    } else {
        eprintln!(
            "index_scale is opt-in; rerun with RUSTFLAGS=\"--cfg huge_bench\" (needs ~12+ GB RAM)"
        );
        &[]
    };

    for &items in sizes {
        let keys: Vec<Digest> = (0..items).map(|i| Sha256::hash(&i.to_be_bytes())).collect();
        let mut insert_order: Vec<usize> = (0..items).collect();
        insert_order.shuffle(&mut StdRng::seed_from_u64(0));
        let mut lookup_order: Vec<usize> = (0..items).collect();
        lookup_order.shuffle(&mut StdRng::seed_from_u64(1));

        println!("index_scale: items={items}");

        // Each variant is built once; insert is the timed build, lookup reuses the populated index.
        // P=3 ordered SoA is the structure under test; the flat BTree/hashmap and unordered shards
        // are baselines. (Ordered P=1/P=2 and unordered P=3 are omitted: pathological build, or
        // 16.8M hashmaps.)
        macro_rules! run {
            ($name:literal, $index:expr) => {{
                let (insert, lookup) = measure($index, &keys, &insert_order, &lookup_order);
                println!(
                    "  {:<24} insert={} ns/op  lookup={} ns/op",
                    $name,
                    insert.as_nanos() / items as u128,
                    lookup.as_nanos() / items as u128,
                );
            }};
        }

        run!("ordered", ordered::Index::new(DummyMetrics, EightCap));
        run!("unordered", unordered::Index::new(DummyMetrics, EightCap));
        run!(
            "partitioned_ordered_3",
            partitioned::ordered::Index::<_, _, 3>::new(DummyMetrics, Cap::<5>::new())
        );
        run!(
            "partitioned_unordered_1",
            partitioned::unordered::Index::<_, _, 1>::new(DummyMetrics, Cap::<7>::new())
        );
        run!(
            "partitioned_unordered_2",
            partitioned::unordered::Index::<_, _, 2>::new(DummyMetrics, Cap::<6>::new())
        );
    }
}
