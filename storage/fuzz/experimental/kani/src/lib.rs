//! Kani proof harnesses for `commonware-storage`.
//!
//! [Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. A
//! harness that passes holds for EVERY input inside its stated bounds, not for a sample.
//!
//! The harnesses call only the public API of `commonware-storage`: the position and location
//! math of the Merkle families (MMR and MMB) in `p1` to `p4`, and the synchronous public items of
//! the contiguous journal in `p5`. Each `p*` module states its proofs in its header:
//!
//! - "Documented contract": what the documentation of `commonware-storage` promises, each item
//!   with its quote and source (the file under `storage/src` and the documented item). Where the
//!   documentation is silent, an item names a test of `commonware-storage` instead and says so.
//!   These assertions are in every build. The default build is the gate.
//! - "Implementation consistency": checks that are stronger than the documentation. They are
//!   asserted only with `--features consistency` (the `consistency!` macro) and are not a gate:
//!   a valid change of the implementation may fail them.
//! - "Bounds": the input ranges and loop bounds the proof holds for.
//!
//! `kani::cover!` checks show that the paths a proof talks about are reachable.
//!
//! The name of every harness starts with `kani_`. Nothing here is compiled outside
//! `cargo kani`: under `cargo build` this crate is empty. The commands are in `README.md`.

#[cfg(kani)]
mod common;
#[cfg(kani)]
mod p1_location_position;
#[cfg(kani)]
mod p2_sizes;
#[cfg(kani)]
mod p3_peaks;
#[cfg(kani)]
mod p4_nodes;
#[cfg(kani)]
mod p5_journal;
