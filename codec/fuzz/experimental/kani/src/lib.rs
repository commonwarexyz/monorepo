//! Kani proof harnesses for `commonware-codec`.
//!
//! [Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. A
//! harness that passes holds for EVERY input inside its stated bounds, not for a sample.
//!
//! Each `p*` module holds one proof and states it in its header:
//!
//! - "Documented contract": what the documentation of `commonware-codec` promises, each item
//!   with its quote and source (file and lines of `codec/src` as of `main` at commit
//!   c2627b4132). Where the documentation is silent, for example on the byte layout of an
//!   address, an item quotes a test of `commonware-codec` instead and says so. These
//!   assertions are in every build. The default build is the gate.
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
mod p10_tags;
#[cfg(kani)]
mod p11_modes;
#[cfg(kani)]
mod p1_varint_decode;
#[cfg(kani)]
mod p2_varint_roundtrip;
#[cfg(kani)]
mod p3_stream_decoder;
#[cfg(kani)]
mod p4_range;
#[cfg(kani)]
mod p5_length_math;
#[cfg(kani)]
mod p6_varint_uint14;
#[cfg(kani)]
mod p7_net;
#[cfg(kani)]
mod p8_exact_decode;
#[cfg(kani)]
mod p9_fixed_width;
