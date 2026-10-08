//! Pointers whose base lives in a local of the forming function, and the
//! window rule's other siblings (docs/DESIGN-UNSAFE-SIMD.md §2.6; stage
//! soundness-fixes, the review's finding F1). The positive functions are
//! defined and read as rustc computes them; every other one has undefined
//! behaviour under Stacked and Tree Borrows (the Miri gate reports it) or is
//! outside the reading, and each is refused with its reason named.
use core::arch::aarch64::*;

// ---------------------------------------------------------------------------
// positive: defined, read
// ---------------------------------------------------------------------------

/// A local written only through its pointer, then returned.
pub fn local_ok(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = a.as_mut_ptr();
    // SAFETY: 16 bytes of `a`; nothing else touches `a` meanwhile.
    unsafe { vst1q_u8(p, v) };
    a
}

/// Two shared pointers from one local, both loaded, the local only read.
pub fn two_shared_ok(x: u8) -> [u8; 16] {
    let a = [x; 16];
    let p = a.as_ptr();
    let q = a.as_ptr();
    let mut out = [0u8; 16];
    let o = out.as_mut_ptr();
    // SAFETY: 16 bytes of `a` through each, 16 of `out`; `a` is not written.
    unsafe {
        vst1q_u8(o, vld1q_u8(p));
        vst1q_u8(o, vld1q_u8(q));
    }
    out
}

/// The table every function below reads (an immutable static: no write can
/// reach it).
pub static TABLE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// An immutable static read through a shared pointer.
pub fn static_ok() -> [u8; 16] {
    let p = TABLE.as_ptr();
    let mut out = [0u8; 16];
    let o = out.as_mut_ptr();
    // SAFETY: 16 bytes of `TABLE` and of `out`.
    unsafe { vst1q_u8(o, vld1q_u8(p)) };
    out
}

/// A constant array whose reference rustc promotes to a static: the pointer
/// stays valid after the statement.
pub fn promoted_ok() -> [u8; 16] {
    let p = [3u8; 16].as_ptr();
    let mut out = [0u8; 16];
    let o = out.as_mut_ptr();
    // SAFETY: the promoted constant's 16 bytes, and `out`'s.
    unsafe { vst1q_u8(o, vld1q_u8(p)) };
    out
}

/// Sixteen bytes from byte `k` of a pair of `u128`s (a base aligned to 16):
/// the alignment arm's fixture (amendment A-S5; the review's F5). Every
/// admitted row is unaligned, so every `k <= 16` reads; a row that needed
/// 16-byte alignment would read only at `k = 0` and `k = 16`.
pub fn rows_at(t: &[u128; 2], k: usize) -> uint8x16_t {
    let p = t.as_ptr().cast::<u8>();
    // SAFETY: bytes `k..k + 16` of `t`, in bounds for `k <= 16`.
    unsafe { vld1q_u8(p.add(k)) }
}

/// The same from a byte array (a base aligned to 1).
pub fn bytes_at(t: &[u8; 32], k: usize) -> uint8x16_t {
    let p = t.as_ptr();
    // SAFETY: bytes `k..k + 16` of `t`, in bounds for `k <= 16`.
    unsafe { vld1q_u8(p.add(k)) }
}

// ---------------------------------------------------------------------------
// the review's six programs (F1): undefined behaviour, refused
// ---------------------------------------------------------------------------

/// The local written between two stores through its pointer
/// (`as_mut_ptr`): the write invalidates the pointer for byte 0.
pub fn local_write(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = a.as_mut_ptr();
    // SAFETY: none (the second store is through an invalidated pointer).
    unsafe { vst1q_u8(p, v) };
    a[0] = 5;
    unsafe { vst1q_u8(p, v) };
    a
}

/// A shared pointer to a local (`as_ptr`), the local written before the
/// load through it.
pub fn local_shared(x: u8) -> uint8x16_t {
    let mut a = [1u8; 16];
    let p = a.as_ptr();
    a[0] = x;
    // SAFETY: none (the load is through an invalidated pointer).
    unsafe { vld1q_u8(p) }
}

/// A store through a pointer to a local whose scope has ended.
pub fn local_scope(v: uint8x16_t) -> u8 {
    let p;
    {
        let mut a = [0u8; 16];
        p = a.as_mut_ptr();
    }
    // SAFETY: none (use after the local's scope).
    unsafe { vst1q_u8(p, v) };
    0
}

/// `local_write` with the pointer formed by `ptr::from_mut(&mut a)`.
pub fn local_from_mut(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = core::ptr::from_mut(&mut a).cast::<u8>();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    a[0] = 5;
    unsafe { vst1q_u8(p, v) };
    a
}

/// `local_write` with the pointer formed by `&raw mut (*r)`, `r = &mut a`
/// (the place is behind a `Deref`).
pub fn local_raw_deref(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let r = &mut a;
    let p = &raw mut (*r) as *mut u8;
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    a[0] = 5;
    unsafe { vst1q_u8(p, v) };
    a
}

/// A by-value array parameter (a local too), written, then read through a
/// shared pointer formed before the write.
pub fn param_by_value(mut a: [u8; 16], x: u8) -> uint8x16_t {
    let p = a.as_ptr();
    a[0] = x;
    // SAFETY: none (as `local_shared`).
    unsafe { vld1q_u8(p) }
}

// ---------------------------------------------------------------------------
// the siblings: undefined behaviour, refused
// ---------------------------------------------------------------------------

/// A by-value array parameter written between two stores through its
/// pointer.
pub fn param_by_value_mut(mut a: [u8; 16], v: uint8x16_t) -> [u8; 16] {
    let p = a.as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    a[0] = 5;
    unsafe { vst1q_u8(p, v) };
    a
}

/// `&raw mut a` of the local itself (the window rule named this base before
/// the fix too).
pub fn local_raw_write(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = &raw mut a as *mut u8;
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    a[0] = 5;
    unsafe { vst1q_u8(p, v) };
    a
}

/// `&raw mut a` of a local whose scope has ended before the store.
pub fn raw_scope(v: uint8x16_t) -> u8 {
    let p;
    {
        let mut a = [0u8; 16];
        p = &raw mut a as *mut u8;
    }
    // SAFETY: none (use after the local's scope).
    unsafe { vst1q_u8(p, v) };
    0
}

/// A local struct: an array and a byte.
pub struct Pair {
    pub a: [u8; 16],
    pub b: u8,
}

/// A field of a local struct.
pub fn struct_field(v: uint8x16_t) -> [u8; 16] {
    let mut s = Pair { a: [0u8; 16], b: 1 };
    let p = s.a.as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    s.a[0] = s.b;
    unsafe { vst1q_u8(p, v) };
    s.a
}

/// A tuple's array.
pub fn tuple_field(v: uint8x16_t) -> [u8; 16] {
    let mut t = ([0u8; 16], 5u8);
    let p = t.0.as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    t.0[0] = t.1;
    unsafe { vst1q_u8(p, v) };
    t.0
}

/// One row of a local array of rows, written through the array.
pub fn nested_array(v: uint8x16_t) -> [[u8; 16]; 2] {
    let mut a = [[0u8; 16]; 2];
    let p = a[1].as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    a[1][0] = 5;
    unsafe { vst1q_u8(p, v) };
    a
}

/// A `Box` owned by a local: its array written through the box.
pub fn boxed(v: uint8x16_t) -> [u8; 16] {
    let mut b = Box::new([0u8; 16]);
    let p = b.as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    b[0] = 5;
    unsafe { vst1q_u8(p, v) };
    *b
}

/// A `Vec` owned by a local: its slice written through the vector.
pub fn vec_slice(v: uint8x16_t) -> u8 {
    let mut w = vec![0u8; 16];
    let p = w.as_mut_slice().as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    w[0] = 5;
    unsafe { vst1q_u8(p, v) };
    w[1]
}

/// A pointer to a temporary that is not promoted (it depends on `x`): the
/// array lives until the end of the `let`.
pub fn temporary(x: u8) -> uint8x16_t {
    #[allow(dangling_pointers_from_temporaries)]
    let p = [x; 16].as_ptr();
    // SAFETY: none (the temporary is dead).
    unsafe { vld1q_u8(p) }
}

/// A mutable pointer to a temporary (a mutable borrow is never promoted).
pub fn temporary_mut(v: uint8x16_t) -> u8 {
    #[allow(dangling_pointers_from_temporaries)]
    let p = [0u8; 16].as_mut_ptr();
    // SAFETY: none (the temporary is dead).
    unsafe { vst1q_u8(p, v) };
    0
}

/// A closure that writes the local, called between two stores.
pub fn closure_write(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = a.as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    let mut set = || a[0] = 5;
    set();
    unsafe { vst1q_u8(p, v) };
    a
}

/// Two mutable pointers from one local, the first used after the second.
pub fn two_pointers(v: uint8x16_t, w: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = a.as_mut_ptr();
    let q = a.as_mut_ptr();
    // SAFETY: none (`p` is invalidated by the second formation and the store through `q`).
    unsafe {
        vst1q_u8(q, w);
        vst1q_u8(p, v);
    }
    a
}

/// A shared pointer, then a mutable one from the same local, written
/// through, then the shared one loaded.
pub fn shared_then_mut(v: uint8x16_t) -> uint8x16_t {
    let mut a = [1u8; 16];
    let p = a.as_ptr();
    let q = a.as_mut_ptr();
    // SAFETY: none (the store through `q` invalidates `p`).
    unsafe {
        vst1q_u8(q, v);
        vld1q_u8(p)
    }
}

/// The reference a pointer was formed through, moved, and written through.
pub fn reborrow_moved(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let r = &mut a;
    let p = r.as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    let s = r;
    s[0] = 5;
    unsafe { vst1q_u8(p, v) };
    a
}

/// The local written by a loop between two stores.
pub fn after_loop(v: uint8x16_t, n: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = a.as_mut_ptr();
    // SAFETY: none when `n > 0` (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    let mut i = 0;
    while i < n && i < 16 {
        a[i] = 5;
        i += 1;
    }
    unsafe { vst1q_u8(p, v) };
    a
}

fn set_first(b: &mut [u8; 16]) {
    b[0] = 5;
}

/// The local lent `&mut` to a function between two stores.
pub fn after_call(v: uint8x16_t) -> [u8; 16] {
    let mut a = [0u8; 16];
    let p = a.as_mut_ptr();
    // SAFETY: none (as `local_write`).
    unsafe { vst1q_u8(p, v) };
    set_first(&mut a);
    unsafe { vst1q_u8(p, v) };
    a
}

/// A pointer formed in a loop's body and used after the loop: the local it
/// points into is the body's, dead once the loop is left.
#[allow(clippy::never_loop)]
pub fn loop_scope(v: uint8x16_t) -> u8 {
    let p;
    loop {
        let mut b = [0u8; 16];
        p = b.as_mut_ptr();
        break;
    }
    // SAFETY: none (use after the local's scope).
    unsafe { vst1q_u8(p, v) };
    0
}

/// A local that is not `Copy`, larger than two registers (passed to a
/// function by reference to the caller's own memory when moved).
pub struct Holder {
    pub a: [u8; 16],
    pub b: [u8; 16],
}

fn consume(mut h: Holder) -> u8 {
    h.a[0] = 9;
    h.a[1] ^ h.b[1]
}

/// The local a shared pointer points into, moved into a call before the
/// load: the moved-from local no longer holds its value (the callee may
/// even have written it in place).
pub fn moved_into_call(x: u8) -> uint8x16_t {
    let h = Holder { a: [x; 16], b: [x; 16] };
    let p = h.a.as_ptr();
    let _ = consume(h);
    // SAFETY: none (the local was moved).
    unsafe { vld1q_u8(p) }
}

/// A `static mut`'s array (refused: a raw pointer dereferenced as a place,
/// outside the reading).
pub static mut SCRATCH: [u8; 16] = [0u8; 16];

/// A store into a `static mut` through a pointer to it (defined, but
/// outside the reading: refused by name).
pub fn static_mut_store(v: uint8x16_t) {
    let p = (&raw mut SCRATCH).cast::<u8>();
    // SAFETY: 16 bytes of `SCRATCH`; no other reference to it exists.
    unsafe { vst1q_u8(p, v) };
}
