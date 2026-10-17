//! Allocator metrics exported by a runtime whose process runs on mimalloc.
//!
//! The `bench-mimalloc` feature installs an allocator from the library itself,
//! which would conflict with the one declared here.

#![cfg(all(feature = "mimalloc", not(feature = "bench-mimalloc")))]

use commonware_allocator::mimalloc::{ARENA_CHUNK_SIZE, Config, MiMalloc, Purge, Reserve};
use commonware_runtime::{Metrics as _, Runner as _, tokio};

const RESERVE_BYTES: usize = 2 * ARENA_CHUNK_SIZE;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc::new(Config {
    purge: Purge::Never,
    reserve: Some(Reserve::pinned(RESERVE_BYTES)),
    ..Config::DEFAULT
});

/// Returns the value of a plain (unlabeled) metric line, if present.
fn value(metrics: &str, name: &str) -> Option<u64> {
    metrics
        .lines()
        .find(|line| line.starts_with(&format!("{name} ")))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
}

#[test]
fn allocator_metrics_are_exported() {
    assert!(commonware_allocator::mimalloc::is_global_allocator());
    tokio::Runner::default().start(|context| async move {
        // The collector populates the family when the runtime starts, so the
        // reservation applied before main is already visible.
        let metrics = context.encode();
        for name in [
            "runtime_allocator_committed_bytes",
            "runtime_allocator_reserved_bytes",
            "runtime_allocator_arenas",
            "runtime_allocator_purged_bytes_total",
            "runtime_allocator_huge_allocations_total",
        ] {
            assert!(metrics.contains(name), "missing {name} in {metrics}");
        }
        let pinned = value(&metrics, "runtime_allocator_pinned_bytes").expect("pinned gauge");
        assert_eq!(pinned, RESERVE_BYTES as u64);
        assert!(value(&metrics, "runtime_allocator_committed_bytes").unwrap_or(0) > 0);
        assert_eq!(
            value(&metrics, "runtime_allocator_purged_bytes_total"),
            Some(0)
        );
    });
}
