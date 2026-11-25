//! Kani proof harnesses for `commonware-coding`.
//!
//! [Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. A
//! harness that passes holds for EVERY input inside its stated bounds, not for a sample.
//!
//! The harnesses call the public API only. Each `p*` module holds one proof and states it in
//! its header:
//!
//! - "Documented contract": what the documentation of `commonware-coding` (or of
//!   `commonware-codec` and `commonware-storage`, whose types it uses) promises, each item
//!   with its quote and its source: the file and the item the text belongs to. Where the
//!   documentation is silent, an item quotes a test, a code comment or the implementation code
//!   of those crates instead, and says which. These assertions are in every build. The default
//!   build is the gate: a failure there is a difference from a quoted source, which for an item
//!   that rests on implementation code can also be a change of that code.
//! - "Implementation consistency": checks that are stronger than the documentation. They are
//!   asserted only with `--features consistency` (the `consistency!` macro) and are not a gate:
//!   a valid change of the implementation may fail them.
//! - "Bounds": the input sizes and loop bounds the proof holds for.
//!
//! `kani::cover!` checks show that the paths a proof talks about are reachable.
//!
//! The name of every harness starts with `kani_`. Nothing here is compiled outside
//! `cargo kani`: under `cargo build` this crate is empty. The commands are in `README.md`.

#[cfg(kani)]
mod common;
#[cfg(kani)]
mod p1_config;
#[cfg(kani)]
mod p2_total_shards;
#[cfg(kani)]
mod p3_config_size;
#[cfg(kani)]
mod p4_chunk_size_bound;
#[cfg(kani)]
mod p6_chunk_reencode;
