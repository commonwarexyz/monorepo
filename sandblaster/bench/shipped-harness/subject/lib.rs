//! A subject of the shipped-code harness (sandblaster/bench/shipped-harness).
//!
//! One crate source for every subject: the package's dependencies select the
//! code. `subj_orig` and `subj_aa` link the original Commonware crates (the
//! merge base of the sandblaster branch), `subj_shipped` the code
//! commonware-codec and commonware-storage compile from sandblaster's
//! emitted and lowered copies (gen/, prepare.py), each under the names
//! `codec` and `storage`. `probe` is the same text in every subject.
#![allow(dead_code, unused_imports, clippy::all)]

pub mod probe;
