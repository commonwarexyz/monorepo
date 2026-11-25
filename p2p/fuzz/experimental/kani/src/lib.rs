//! Kani proof harnesses for the subchannel prefix of `commonware_p2p::utils::mux`.
//!
//! [Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. A
//! harness that passes holds for EVERY input inside its stated bounds, not for a sample.
//!
//! Each module holds one proof and states it in its header:
//!
//! - "Documented contract": what the documentation of `commonware-p2p` (and, for the varint
//!   it names, of `commonware-codec`) promises, each item with its quote and source (file and
//!   item). Where the documentation is silent, an item quotes a test
//!   instead and says so. These assertions are in every build. The default build is the gate.
//! - "Implementation consistency": checks that are stronger than the documentation. They are
//!   asserted only with `--features consistency` (the `consistency!` macro) and are not a gate:
//!   a valid change of the implementation may fail them.
//! - "Bounds": the input sizes and loop bounds the proof holds for.
//!
//! `kani::cover!` checks show that the paths a proof talks about are reachable.
//!
//! The harnesses call the public API of `commonware-p2p` only. The name of every harness
//! starts with `kani_`. Nothing here is compiled outside `cargo kani`: under `cargo build`
//! this crate is empty. The commands are in `README.md`.

#[cfg(kani)]
mod common;
#[cfg(kani)]
mod mux_parse;
#[cfg(kani)]
mod mux_prefixed;
