//! Kani proof harnesses for `commonware-utils`.
//!
//! [Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. A
//! harness that passes holds for EVERY input inside its stated bounds, not for a sample.
//!
//! The harnesses call the public API of `commonware-utils` only. Each module holds one proof
//! and states it in its header:
//!
//! - "Documented contract": what the documentation of `commonware-utils` promises, each item
//!   with its quote and source (the file and the item, never a line number). Where
//!   the documentation is silent, for example on the order of `FixedBytes`, an item quotes a
//!   test of `commonware-utils` instead and says so. These assertions are in every build. The
//!   default build is the gate.
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
mod bitmap;
#[cfg(kani)]
mod common;
#[cfg(kani)]
mod fixed_bytes;
#[cfg(kani)]
mod prefixed_u64;
