//! A subject of the held-out harness (sandblaster/bench/heldout-harness).
//!
//! One crate source for every subject (fairness audit J11): the package's
//! feature selects the module. `source` compiles the held-out files as
//! written: H1's `src/lib.rs` byte for byte, H2's sampled functions copied
//! verbatim from their files (`gen/h2_source.rs`, written by run.sh: the
//! files themselves need their crates' dependencies). `optimized` compiles
//! the lowered copies the exec-only optimizer wrote (`gen/h1.rs`,
//! `gen/h2_opt.rs`). Held-out v2 (`h1v2`, `h2v2`) is compiled the same way
//! (the frozen `heldout-v2/h1/src/lib.rs`; `gen/v2/`). `probe` is the same
//! text in every subject.
#![allow(dead_code, unused_imports, clippy::all)]

#[cfg(all(feature = "source", not(feature = "optimized")))]
#[path = "../../heldout/h1/src/lib.rs"]
pub mod h1;
#[cfg(feature = "optimized")]
#[path = "../gen/h1.rs"]
pub mod h1;

#[cfg(all(feature = "source", not(feature = "optimized")))]
#[path = "../gen/h2_source.rs"]
pub mod h2;
#[cfg(feature = "optimized")]
#[path = "../gen/h2_opt.rs"]
pub mod h2;

// held-out v2 (sandblaster/bench/heldout-v2/): H1 is the frozen file
// itself under `source`, the lowered copy under `optimized`; H2's sampled
// functions as gen/v2/h2_source.rs and gen/v2/h2_opt.rs (run.sh --set v2)
#[cfg(all(feature = "source", not(feature = "optimized")))]
#[path = "../../heldout-v2/h1/src/lib.rs"]
pub mod h1v2;
#[cfg(feature = "optimized")]
#[path = "../gen/v2/h1.rs"]
pub mod h1v2;

#[cfg(all(feature = "source", not(feature = "optimized")))]
#[path = "../gen/v2/h2_source.rs"]
pub mod h2v2;
#[cfg(feature = "optimized")]
#[path = "../gen/v2/h2_opt.rs"]
pub mod h2v2;

pub mod probe;
