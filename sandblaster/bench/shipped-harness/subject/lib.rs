//! A subject of the measurement harness (sandblaster/bench/shipped-harness).
//!
//! One crate source for every subject: the package's dependencies select the
//! code. `subj_orig` and `subj_aa` link the crates at the base commit,
//! `subj_wt` the worktree's own crates (gen/, prepare.py), each under the
//! names `codec` and `storage`. `probe` (the probe's `probe.rs`, copied to
//! `gen/probe.rs`) is the same text in every subject.
#![allow(dead_code, unused_imports, clippy::all)]

#[path = "../gen/probe.rs"]
pub mod probe;
