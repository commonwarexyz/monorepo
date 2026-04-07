//! Benchmarks for `runtime::iobuf`.
//!
//! This entry point registers two suites:
//!
//! - [`pool`]: end-to-end steady-state `BufferPool` allocation and reuse,
//!   compared against direct aligned allocation. This primarily exercises the
//!   thread-local cache path.
//! - [`freelist`]: microbenchmarks of the global freelist that stores free
//!   pooled buffers shared across threads, compared against `Mutex<Vec<_>>` and
//!   `ArrayQueue`.
//!
//! Shared threading and measurement helpers live in [`utils`].
//!
//! Run with: `cargo bench --bench buffer_pool -p commonware-runtime --features bench`

use criterion::{criterion_group, criterion_main};

mod freelist;
mod pool;
mod utils;

criterion_group!(benches, pool::bench, freelist::bench);

criterion_main!(benches);
