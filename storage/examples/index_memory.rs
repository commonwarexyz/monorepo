//! Measures heap bytes-per-key for the index variants at 8-byte key resolution, decomposing each
//! into marginal cost (the per-key slope between 20M and 100M, which excludes fixed
//! partition/header overhead) and that fixed overhead amortized at 100M.
//!
//! Run with: `cargo run --release --example index_memory -p commonware-storage`
//!
//! A counting global allocator records the net heap bytes each index retains after inserting all
//! keys (capacity slack included, matching real usage). The key set is allocated before each
//! measurement baseline, so only the index's own allocations are counted. The counter sums the
//! requested layout sizes, so it is a lower bound on RSS: the allocator's size-class rounding and
//! per-allocation metadata are not captured, which understates the partitioned index most (it makes
//! millions of tiny per-partition allocations).

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    telemetry::metrics::{Metric, Registered, Registration},
    Metrics, Name, Supervisor,
};
use commonware_storage::{
    index::{ordered, partitioned, unordered, Unordered},
    translator::{Cap, EightCap},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

/// Global allocator that tracks net live bytes in `LIVE`.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards directly to the System allocator and only adjusts an atomic byte
// counter, so it upholds the same allocation contract as System.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            LIVE.fetch_add(new_size, Relaxed);
            LIVE.fetch_sub(layout.size(), Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// No-op metrics context so the index allocations we measure are the index's own.
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

type Digest = <Sha256 as Hasher>::Digest;

const SMALL: usize = 20_000_000;
const LARGE: usize = 100_000_000;

/// Build an index, insert the first `keys`, and return the net heap bytes it retains.
fn measure<I: Unordered<Value = u64>>(keys: &[Digest], build: impl FnOnce() -> I) -> usize {
    let base = LIVE.load(Relaxed);
    let mut index = build();
    for (i, key) in keys.iter().enumerate() {
        index.insert(key, i as u64);
    }
    let used = LIVE.load(Relaxed) - base;
    black_box(&index);
    drop(index);
    used
}

/// Measure a scheme at [`SMALL`] and [`LARGE`] keys and split the footprint into the marginal
/// bytes/key (the slope, which cancels the fixed partition/header allocation) and the fixed
/// overhead amortized at [`LARGE`].
fn bench_scheme<I: Unordered<Value = u64>>(name: &str, keys: &[Digest], build: impl Fn() -> I) {
    let small = measure(&keys[..SMALL], &build);
    let large = measure(&keys[..LARGE], &build);
    let marginal = (large - small) as f64 / (LARGE - SMALL) as f64;
    let total = large as f64 / LARGE as f64;
    let fixed = total - marginal;
    println!("{name:<24} {marginal:>8.2} {fixed:>8.2} {total:>8.2}");
}

fn main() {
    println!("generating {LARGE} keys...");
    let keys: Vec<Digest> = (0..LARGE as u64)
        .map(|i| Sha256::hash(&i.to_be_bytes()))
        .collect();

    println!("\nindex memory, 8-byte resolution, value=u64 (bytes/key):");
    println!(
        "marginal = per-key cost excluding fixed overhead; fixed = headers amortized at {LARGE}"
    );
    println!(
        "{:<24} {:>8} {:>8} {:>8}",
        "scheme", "marginal", "fixed", "total"
    );
    bench_scheme("flat_unordered", &keys, || {
        unordered::Index::new(DummyMetrics, EightCap)
    });
    bench_scheme("flat_ordered", &keys, || {
        ordered::Index::new(DummyMetrics, EightCap)
    });
    bench_scheme("partitioned_ordered_3", &keys, || {
        partitioned::ordered::Index::<_, _, 3>::new(DummyMetrics, Cap::<5>::new())
    });
    bench_scheme("partitioned_unordered_1", &keys, || {
        partitioned::unordered::Index::<_, _, 1>::new(DummyMetrics, Cap::<7>::new())
    });
    bench_scheme("partitioned_unordered_2", &keys, || {
        partitioned::unordered::Index::<_, _, 2>::new(DummyMetrics, Cap::<6>::new())
    });
}
