//! The pointer fixtures of `tests/unsafe_simd.rs`, as written (the same
//! source files), for Miri: the positive ones must run clean under both
//! aliasing models; each aliasing or bounds twin must be reported as
//! undefined behaviour by at least one (`run.sh`).
#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

#[path = "../../mir_fixtures/sd_ptr/src/a.rs"]
pub mod ptr;

#[path = "../../mir_fixtures/sd_ptr_twins/src/a.rs"]
pub mod twins;
