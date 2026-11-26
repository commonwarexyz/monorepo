//! Kani proof harnesses for the CUPS record sizes of `commonware-stream`.
//!
//! [Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. A
//! harness that passes holds for EVERY input inside its stated bounds, not for a sample.
//!
//! Each module holds one proof and states it in its header:
//!
//! - "Documented contract": what the documentation of `commonware-stream` promises, each item
//!   with its quote and source (file and item). Where the
//!   documentation is silent, an item quotes a test instead and says so. These assertions are
//!   in every build. The default build is the gate.
//! - "Implementation consistency": checks that are stronger than the documentation. They are
//!   asserted only with `--features consistency` and are not a gate: a valid change of the
//!   implementation may fail them. The proofs here fix their results exactly, so they have
//!   none.
//! - "Bounds": the input sizes and loop bounds the proof holds for.
//!
//! `kani::cover!` checks show that the paths a proof talks about are reachable, and every one
//! of them must be satisfied. A harness whose name ends with `_panics` shows with Kani's
//! `should_panic` that inputs of a class panic; its `_panics_control` partner shows that the
//! class boundary returns (see `README.md`).
//!
//! The harnesses call the public API of `commonware-stream` only. The name of every harness
//! starts with `kani_`. Nothing here is compiled outside `cargo kani`: under `cargo build`
//! this crate is empty. The commands are in `README.md`.

#[cfg(kani)]
mod cups_sizes;
