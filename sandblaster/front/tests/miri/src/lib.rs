//! The pointer fixtures of `tests/unsafe_simd.rs`, as written (the same
//! source files), for Miri: the positive ones must run clean under both
//! aliasing models; each aliasing or bounds twin must be reported as
//! undefined behaviour by at least one (`run.sh`). `local` holds the bases
//! that live in a local of the forming function and the window rule's
//! other siblings (stage soundness-fixes, the review's F1).
#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

#[path = "../../mir_fixtures/sd_ptr/src/a.rs"]
pub mod ptr;

#[path = "../../mir_fixtures/sd_ptr_twins/src/a.rs"]
pub mod twins;

#[path = "../../mir_fixtures/sd_ptr_local/src/a.rs"]
pub mod local;
