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

// ---------------------------------------------------------------------------
// bases that live in a local of the forming function, and the window rule's
// other siblings (stage soundness-fixes, the review's F1): `sd_ptr_local`
// ---------------------------------------------------------------------------

use sd_miri::local;

/// (review) The local written between two stores through its pointer.
#[test]
fn ub_local_write() {
    let _ = local::local_write(v());
}

/// (review) A shared pointer to a local, the local written before the load.
#[test]
fn ub_local_shared() {
    let _ = local::local_shared(9);
}

/// (review) A store through a pointer to a local whose scope has ended.
#[test]
fn ub_local_scope() {
    let _ = local::local_scope(v());
}

/// (review) `ptr::from_mut(&mut a)`, the local written between two stores.
#[test]
fn ub_local_from_mut() {
    let _ = local::local_from_mut(v());
}

/// (review) `&raw mut (*r)`, `r = &mut a`, the local written between two stores.
#[test]
fn ub_local_raw_deref() {
    let _ = local::local_raw_deref(v());
}

/// (review) A by-value array parameter written before the load through it.
#[test]
fn ub_param_by_value() {
    let _ = local::param_by_value([1u8; 16], 9);
}

/// A by-value array parameter written between two stores.
#[test]
fn ub_param_by_value_mut() {
    let _ = local::param_by_value_mut([1u8; 16], v());
}

/// `&raw mut a`, the local written between two stores (Stacked Borrows).
#[test]
fn ub_local_raw_write() {
    let _ = local::local_raw_write(v());
}

/// `&raw mut a` of a local whose scope has ended.
#[test]
fn ub_raw_scope() {
    let _ = local::raw_scope(v());
}

/// A field of a local struct written between two stores.
#[test]
fn ub_struct_field() {
    let _ = local::struct_field(v());
}

/// A tuple's array written between two stores.
#[test]
fn ub_tuple_field() {
    let _ = local::tuple_field(v());
}

/// A row of a local array of rows written between two stores.
#[test]
fn ub_nested_array() {
    let _ = local::nested_array(v());
}

/// A local `Box`'s array written between two stores.
#[test]
fn ub_boxed() {
    let _ = local::boxed(v());
}

/// A local `Vec`'s slice written between two stores.
#[test]
fn ub_vec_slice() {
    let _ = local::vec_slice(v());
}

/// A pointer to a temporary, loaded after the temporary is dead.
#[test]
fn ub_temporary() {
    let _ = local::temporary(9);
}

/// A mutable pointer to a temporary, stored through after it is dead.
#[test]
fn ub_temporary_mut() {
    let _ = local::temporary_mut(v());
}

/// A closure writing the local, called between two stores.
#[test]
fn ub_closure_write() {
    let _ = local::closure_write(v());
}

/// Two mutable pointers from one local, the first used after the second.
#[test]
fn ub_two_pointers() {
    // SAFETY: NEON.
    let w = unsafe { vdupq_n_u8(8) };
    let _ = local::two_pointers(v(), w);
}

/// A shared pointer, then a mutable one from the same local written through.
#[test]
fn ub_shared_then_mut() {
    let _ = local::shared_then_mut(v());
}

/// The reference a pointer was formed through, moved and written through.
#[test]
fn ub_reborrow_moved() {
    let _ = local::reborrow_moved(v());
}

/// The local written by a loop between two stores.
#[test]
fn ub_after_loop() {
    let _ = local::after_loop(v(), 1);
}

/// The local lent `&mut` to a function between two stores.
#[test]
fn ub_after_call() {
    let _ = local::after_call(v());
}

/// A pointer formed in a loop's body, used after the loop.
#[test]
fn ub_loop_scope() {
    let _ = local::loop_scope(v());
}
