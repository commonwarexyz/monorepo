//! Benchmarks for steady-state buffer allocation and reuse.
//!
//! Compares `BufferPool` against bare aligned allocation for the hot path we care
//! about here: allocate, touch the requested bytes at page granularity, and drop.
//!
//! # Metrics
//!
//! - **raw**: end-to-end time for allocate + page-touch + drop.
//! - **adjusted**: raw time minus the cost of repeatedly touching pages on an
//!   already-materialized buffer. This isolates allocator overhead. The baseline
//!   is always measured single-threaded because each thread writes to private
//!   memory (same per-iteration cost regardless of thread count), and this avoids
//!   wall-clock noise from thread scheduling that would swamp the signal.
//!
//! # Thread configurations
//!
//! For each buffer size, single-threaded benchmarks run first, followed by
//! multi-threaded benchmarks with two contention patterns:
//!
//! - **lockstep**: all workers enter the hot path together (worst-case contention).
//! - **staggered**: workers add a small variable spin delay between iterations to
//!   decorrelate allocation timing.
//!
//! # Why touch pages?
//!
//! Large allocations may be backed by lazily materialized virtual memory (e.g. once
//! the allocator starts using `mmap`), so timing allocation alone can undercount the
//! real cost of actually using the buffer. Touching each page forces materialization
//! and makes the comparison between direct aligned allocation and pooled reuse
//! fairer.
//!
//! For large sizes this means much of the raw benchmark measures page writes rather
//! than allocator bookkeeping. That is acceptable because both implementations pay
//! the same page-touch cost, so the relative comparison still isolates the
//! allocation strategy.
//!
//! Run with: `cargo bench --bench buffer_pool -p commonware-runtime`

use criterion::{criterion_group, criterion_main};

mod pool;

criterion_group!(benches, pool::bench);

criterion_main!(benches);
