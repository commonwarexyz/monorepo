//! Compare allocation policies through the real index during build, replacements, and growth.

use super::{
    DummyMetrics, SEED,
    packed::{PackedLocation, Window},
    packed_scale::Value,
};
use commonware_storage::{
    index::{Cursor, Unordered, partitioned::ordered::Index},
    translator::Cap,
};
use commonware_utils::TestRng;
use rand::Rng;
use std::{
    hint::black_box,
    io::{self, Read as _, Write as _},
    time::Instant,
};

fn measure<V: Value, const P: usize>(items: u64) {
    assert!((4..=(1 << 38)).contains(&items));
    let window = black_box(Window::new(0, 1 << 40).unwrap());
    let mut index = Index::<_, V, P>::new(DummyMetrics, Cap::<5>::new());
    let sample_memory = std::env::var_os("INDEX_MEMORY_CHECKPOINTS").is_some();
    let checkpoint = |phase: &str, keys: u64| {
        if sample_memory {
            println!(
                "memory_checkpoint: phase={phase} pid={} keys={keys}",
                std::process::id()
            );
            io::stdout().flush().unwrap();
            io::stdin().read_exact(&mut [0]).unwrap();
        }
    };
    let report = |operation: &str, start: Instant, operations: u64, keys: u64| {
        let elapsed = start.elapsed();
        println!(
            "{}::{operation}/items={items} p={P} value_bytes={} ns/op={:.2}",
            module_path!(),
            size_of::<V>(),
            elapsed.as_nanos() as f64 / operations as f64,
        );
        checkpoint(operation, keys);
    };
    checkpoint("empty", 0);

    let mut build_rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..items {
        index.insert(&build_rng.next_u64().to_be_bytes(), V::encode(window, i));
    }
    report("build", start, items, items);

    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..items {
        assert!(black_box(
            index
                .get(&rng.next_u64().to_be_bytes())
                .any(|&v| black_box(v.decode(window)) == i)
        ));
    }
    report("lookup", start, items, items);

    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..items {
        let key = rng.next_u64().to_be_bytes();
        let mut cursor = index.get_mut(&key).expect("inserted key exists");
        assert!(cursor.find(|&v| v.decode(window) == i));
        cursor.update(V::encode(window, items + i));
    }
    report("replace", start, items, items);

    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..items {
        assert!(black_box(
            index
                .get(&rng.next_u64().to_be_bytes())
                .any(|&v| black_box(v.decode(window)) == items + i)
        ));
    }
    report("lookup_replaced", start, items, items);

    // Continue the original key stream in four steps, moving the occupancy distribution upward.
    let mut total = items;
    for (step, operation) in ["grow_25", "grow_50", "grow_75", "grow_100"]
        .iter()
        .enumerate()
    {
        let end = items + items * (step as u64 + 1) / 4;
        let start = Instant::now();
        for i in total..end {
            index.insert(
                &build_rng.next_u64().to_be_bytes(),
                V::encode(window, items + i),
            );
        }
        report(operation, start, end - total, end);
        total = end;
    }

    // The first one percent of this seeded random stream is uniformly distributed across
    // partitions. Delete by value so translated-key collisions retain their other entries.
    let deletes = (total / 100).max(1);
    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..deletes {
        let key = rng.next_u64().to_be_bytes();
        let mut cursor = index.get_mut(&key).unwrap();
        assert!(cursor.find(|&v| v.decode(window) == items + i));
        cursor.delete();
    }
    report("delete", start, deletes, total - deletes);

    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..total {
        let found = black_box(
            index
                .get(&rng.next_u64().to_be_bytes())
                .any(|&v| black_box(v.decode(window)) == items + i),
        );
        assert_eq!(found, i >= deletes);
    }
    report("lookup_final", start, total, total - deletes);
}

pub(super) fn run(items: u64, only: &[String]) {
    for name in only {
        match name.as_str() {
            "relocate_u64_2" => measure::<u64, 2>(items),
            "relocate_packed_2" => measure::<PackedLocation, 2>(items),
            "relocate_u64_3" => measure::<u64, 3>(items),
            "relocate_packed_3" => measure::<PackedLocation, 3>(items),
            _ => {}
        }
    }
}
