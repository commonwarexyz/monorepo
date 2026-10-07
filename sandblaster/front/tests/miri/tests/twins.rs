//! The twins whose refusal is about undefined behaviour, each run on its
//! own (`run.sh` runs every test separately under both models and requires
//! at least one model to report undefined behaviour).
#![cfg(target_arch = "aarch64")]

use core::arch::aarch64::*;
use sd_miri::twins;

fn v() -> uint8x16_t {
    // SAFETY: NEON.
    unsafe { vdupq_n_u8(7) }
}

/// Bytes 49..65 of a 64-byte chunk: out of bounds.
#[test]
fn ub_load_past_end() {
    let mut x = [0u8; 64];
    let _ = twins::load_past_end(&mut x);
}

/// An offset past one beyond the end.
#[test]
fn ub_offset_past_end() {
    let mut x = [0u8; 64];
    let _ = twins::offset_past_end(&mut x);
}

/// A store through a pointer formed from a shared reference.
#[test]
fn ub_store_through_shared() {
    let x = [0u8; 16];
    twins::store_through_shared(&x, v());
}

/// The reference written between two stores through its pointer (W2).
#[test]
fn ub_alias() {
    let mut x = [0u8; 64];
    let _ = twins::alias(&mut x, v());
}

/// Two formations from one `&mut`, interleaved (W0/W2).
#[test]
fn ub_two_formations() {
    let mut x = [0u8; 64];
    twins::two_formations(&mut x, v());
}
