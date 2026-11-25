//! Kani proof harnesses for the I/O buffers of `commonware-runtime` and the page size of its
//! page cache.
//!
//! [Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. A
//! harness that passes holds for EVERY input inside its stated bounds, not for a sample. Kani
//! also checks every pointer use, allocation and deallocation of the code it runs, so the
//! `unsafe` code behind the buffer handles is checked for memory safety on every path a
//! harness reaches.
//!
//! The harnesses call the public API only. Each `p*` module holds one proof and states it in
//! its header:
//!
//! - "Documented contract": what the documentation of `commonware-runtime` (or of the `bytes`
//!   trait a type implements) promises, each item with its quote and its source: the file and
//!   the item the text belongs to (no line numbers). These assertions are in every build. The
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
mod common;
#[cfg(kani)]
mod p1_iobuf_lifecycle;
#[cfg(kani)]
mod p2_iobuf_split;
#[cfg(kani)]
mod p3_iobuf_large_spare;
#[cfg(kani)]
mod p4_iobufmut_cursor;
#[cfg(kani)]
mod p5_iobufs;
#[cfg(kani)]
mod p6_page_size;
