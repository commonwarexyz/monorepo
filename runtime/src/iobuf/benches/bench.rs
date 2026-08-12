//! Benchmarks for `runtime::iobuf`.
//!
//! This entry point registers five suites:
//!
//! - [`iobuf`]: fixed-size decode benchmarks comparing `Bytes` with `IoBuf`
//!   backed by external `Bytes` or native heap storage. `Vec<u8>` modes
//!   provide the deep-clone baseline.
//! - [`allocation`]: end-to-end steady-state `BufferPool` allocation and
//!   reuse, compared against direct aligned allocation.
//! - [`reuse`]: global reuse after partial lazy growth with thread-local
//!   caching disabled.
//! - [`freelist`]: microbenchmarks of the global freelist that stores free
//!   pooled buffers shared across threads, compared against `Mutex<Vec<_>>` and
//!   `ArrayQueue`.
//! - [`summary`]: production-integrated summary-policy boundary, stale cleanup,
//!   batch publication, and settled-empty scan benchmarks.
//!
//! Shared threading and measurement helpers live in [`utils`].
//!
//! Run with: `cargo bench --bench iobuf -p commonware-runtime --features bench`

use criterion::{criterion_group, criterion_main};

mod allocation;
mod freelist;
mod iobuf;
mod reuse;
mod summary;
mod utils;

criterion_group!(
    benches,
    iobuf::bench,
    allocation::bench,
    reuse::bench,
    freelist::bench,
    summary::bench
);

criterion_main!(benches);
