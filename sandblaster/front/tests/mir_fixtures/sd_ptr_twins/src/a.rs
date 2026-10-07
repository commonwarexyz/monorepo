//! Negative twins of `sd_ptr` (docs/DESIGN-UNSAFE-SIMD.md §7): each is
//! refused by the reading, with its reason named.
use core::arch::aarch64::*;

/// A load past the end: bytes 49..65 of a 64-byte chunk (the in-bounds
/// proof fails: the literal reading is stuck there).
pub fn load_past_end(x: &mut [u8; 64]) -> uint8x16_t {
    let p = x.as_mut_ptr();
    // SAFETY: none (out of bounds).
    unsafe { vld1q_u8(p.add(49)) }
}

/// An offset beyond one past the end (`add(65)`): undefined behaviour even
/// without an access.
pub fn offset_past_end(x: &mut [u8; 64]) -> uint8x16_t {
    let p = x.as_mut_ptr();
    // SAFETY: none (out of bounds).
    unsafe { vld1q_u8(p.add(65).sub(16)) }
}

/// A store through a pointer formed from a shared reference: undefined
/// behaviour even after `cast_mut()`.
pub fn store_through_shared(x: &[u8; 16], v: uint8x16_t) {
    // SAFETY: none (a write through a shared borrow).
    unsafe { vst1q_u8(x.as_ptr().cast_mut(), v) }
}

/// A pointer that escapes: returned to the caller (the window rule's W1).
pub fn escape(x: &mut [u8; 64]) -> *mut u8 {
    x.as_mut_ptr()
}

/// A pointer stored into an array before its use (W1).
pub fn stored(x: &mut [u8; 64]) -> uint8x16_t {
    let ps = [x.as_mut_ptr()];
    // SAFETY: in bounds, but the pointer went through memory.
    unsafe { vld1q_u8(ps[0]) }
}

/// The reference written between two stores through its pointer (W2):
/// undefined under Stacked and Tree Borrows, the write through the parent
/// reference invalidates the pointer for the byte it writes, which the
/// second store covers.
pub fn alias(x: &mut [u8; 64], v: uint8x16_t) {
    let p = x.as_mut_ptr();
    // SAFETY: none (the second store is through an invalidated pointer).
    unsafe { vst1q_u8(p, v) };
    x[16] = 1;
    unsafe { vst1q_u8(p.add(16), v) };
}

/// The reference only read between two stores through its pointer: both
/// aliasing models allow it (a read through the parent leaves a raw
/// pointer usable), the window rule refuses it all the same (W2 is the
/// conservative rule: the base is reached only through the pointer while
/// the pointer is in use, whatever the bytes).
pub fn alias_read(x: &mut [u8; 64], v: uint8x16_t) -> u8 {
    let p = x.as_mut_ptr();
    // SAFETY: allowed by both models; refused by the window rule.
    unsafe { vst1q_u8(p, v) };
    let b = x[0];
    unsafe { vst1q_u8(p.add(16), v) };
    b
}

/// Two formations from one `&mut`, interleaved (W0/W2): the second
/// formation reborrows the reference inside the first pointer's window.
pub fn two_formations(x: &mut [u8; 64], v: uint8x16_t) {
    let p = x.as_mut_ptr();
    let q = x.as_mut_ptr();
    // SAFETY: none (`p` is invalidated by the second formation).
    unsafe {
        vst1q_u8(q, v);
        vst1q_u8(p.add(16), v);
    }
}

/// A load from a table of another type: `bool` has a niche (only the
/// bytes 0 and 1 are values), so its bytes are no plain reinterpretation
/// (the admitted base types are niche-free and `UnsafeCell`-free).
pub fn bool_table(t: &[bool; 16]) -> uint8x16_t {
    // SAFETY: 16 bytes of `t` (defined in Rust, but outside the reading).
    unsafe { vld1q_u8(t.as_ptr().cast()) }
}

#[target_feature(enable = "sm4")]
fn with_sm4(x: u64) -> u64 {
    x ^ 1
}

/// A call into `#[target_feature(enable = "sm4")]` code from a body without
/// the feature: `sm4` is detected at run time on this target, and nothing
/// here establishes it.
pub fn no_fact(x: u64) -> u64 {
    // SAFETY: none (the CPU may lack SM4).
    unsafe { with_sm4(x) }
}

/// A library `unsafe fn` outside the admitted pointer operations:
/// `core::ptr::read`.
pub fn ptr_read(x: &[u8; 16]) -> u8 {
    // SAFETY: in bounds (defined in Rust, but outside the reading).
    unsafe { core::ptr::read(x.as_ptr()) }
}

/// `get_unchecked`: a library `unsafe fn` (its bound is the caller's).
pub fn unchecked(x: &[u8; 16], i: usize) -> u8 {
    // SAFETY: none (unchecked).
    unsafe { *x.get_unchecked(i) }
}

/// A raw pointer dereferenced as a place (`*p`).
pub fn deref(x: &[u8; 16]) -> u8 {
    let p = x.as_ptr();
    // SAFETY: in bounds (defined in Rust, but outside the reading).
    unsafe { *p }
}

/// A pointer moved by bytes (`byte_add`): a library `unsafe fn` next to the
/// admitted `add`, not in the table (refused by its path).
pub fn byte_offset(x: &mut [u8; 64]) -> uint8x16_t {
    let p = x.as_mut_ptr();
    // SAFETY: bytes 16..32 of the chunk.
    unsafe { vld1q_u8(p.byte_add(16)) }
}

/// A crate function named `add`, with no pointer in it: read as any
/// function of the crate, never as the pointer helper of that name.
pub fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// A call of the crate's `add`.
pub fn calls_add(a: u64) -> u64 {
    add(a, 1)
}
