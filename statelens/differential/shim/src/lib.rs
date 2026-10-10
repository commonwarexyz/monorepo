//! Compiles the two StateLens runtime templates without editing them.
//!
//! `statelens/runtime/target_states.rs` imports
//! `commonware_consensus::simplex::statelens::{self, Seen}`, and
//! `statelens/runtime/statelens.rs` sets
//! `commonware_runtime::deterministic::STATELENS_FRESH_RUN`. The two
//! `extern crate self as ...` lines below put this crate into its own extern
//! prelude under both names, so those paths resolve to the modules declared
//! here and the templates are included by `#[path]` byte-identical.
//!
//! The `sl_probe!`, `sl_assert!` and `sl_implies!` macros expand
//! `$crate::simplex::statelens::...` only when invoked; nothing here invokes
//! them.

extern crate self as commonware_consensus;
extern crate self as commonware_runtime;

/// The stand-in for `commonware_runtime::deterministic`.
pub mod deterministic {
    /// The fresh-run hook the materialize step inserts into
    /// `runtime/src/deterministic.rs`; the test calls it where `Runner::new`
    /// would.
    pub static STATELENS_FRESH_RUN: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();
}

/// The stand-in for `commonware_consensus::simplex` (`simplex/mod.rs`).
pub mod simplex;

/// The helper template, as the fuzz package's `target_states` module.
#[path = "../../../runtime/target_states.rs"]
pub mod target_states;
