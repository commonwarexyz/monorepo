//! The shape of Reed–Solomon's NEON `mul_neon`, as written: an `unsafe`
//! `#[target_feature]` function that walks a slice of 64-byte chunks with
//! `iter_mut`, forms a raw pointer from each chunk, loads its four 16-byte
//! quarters through it at `add(16 * k)`, multiplies them and stores the
//! products back (`mul_neon`'s order: the loads, the multiplications, the
//! stores); the same on one chunk (`fftb_128`'s shape: a `&mut [u8; 64]`
//! parameter); an `#[inline(always)]` helper whose value intrinsics need
//! `unsafe` (NEON is static on aarch64); a safe entry point; a load through
//! a pointer formed from a shared reference (`mul_128`'s table loads).
use core::arch::aarch64::*;

/// Each byte `b` of `x` through the nibble tables: `lo[b & 15] ^ hi[b >> 4]`.
#[inline(always)]
pub fn mul_16(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) -> uint8x16_t {
    // SAFETY: NEON is enabled statically on every aarch64 target.
    unsafe {
        let mask = vdupq_n_u8(0x0f);
        let l = vqtbl1q_u8(lo, vandq_u8(x, mask));
        let h = vqtbl1q_u8(hi, vshrq_n_u8::<4>(x));
        veorq_u8(l, h)
    }
}

/// One 64-byte chunk through the nibble tables: `mul_chunks`' loop body.
///
/// # Safety
///
/// The CPU must support NEON.
#[target_feature(enable = "neon")]
pub unsafe fn chunk_mul(chunk: &mut [u8; 64], lo: uint8x16_t, hi: uint8x16_t) {
    let x_ptr: *mut u8 = chunk.as_mut_ptr();

    // SAFETY: the offsets stay within the 64-byte chunk.
    unsafe {
        let x0 = vld1q_u8(x_ptr);
        let x1 = vld1q_u8(x_ptr.add(16));
        let x2 = vld1q_u8(x_ptr.add(16 * 2));
        let x3 = vld1q_u8(x_ptr.add(16 * 3));

        vst1q_u8(x_ptr, mul_16(x0, lo, hi));
        vst1q_u8(x_ptr.add(16), mul_16(x1, lo, hi));
        vst1q_u8(x_ptr.add(16 * 2), mul_16(x2, lo, hi));
        vst1q_u8(x_ptr.add(16 * 3), mul_16(x3, lo, hi));
    }
}

/// Every byte of every chunk of `x` through the nibble tables.
///
/// # Safety
///
/// The CPU must support NEON.
#[target_feature(enable = "neon")]
pub unsafe fn mul_chunks(x: &mut [[u8; 64]], lo: uint8x16_t, hi: uint8x16_t) {
    for chunk in x.iter_mut() {
        let x_ptr: *mut u8 = chunk.as_mut_ptr();

        // SAFETY: the offsets stay within the 64-byte chunk.
        unsafe {
            let x0 = vld1q_u8(x_ptr);
            let x1 = vld1q_u8(x_ptr.add(16));
            let x2 = vld1q_u8(x_ptr.add(16 * 2));
            let x3 = vld1q_u8(x_ptr.add(16 * 3));

            let p0 = mul_16(x0, lo, hi);
            let p1 = mul_16(x1, lo, hi);
            let p2 = mul_16(x2, lo, hi);
            let p3 = mul_16(x3, lo, hi);

            vst1q_u8(x_ptr, p0);
            vst1q_u8(x_ptr.add(16), p1);
            vst1q_u8(x_ptr.add(16 * 2), p2);
            vst1q_u8(x_ptr.add(16 * 3), p3);
        }
    }
}

/// `mul_chunks` from safe code: NEON is static on aarch64.
pub fn mul(x: &mut [[u8; 64]], lo: uint8x16_t, hi: uint8x16_t) {
    // SAFETY: every aarch64 CPU has NEON.
    unsafe { mul_chunks(x, lo, hi) }
}

/// The sixteen bytes of a table row as a vector: a load through a pointer
/// formed from a shared reference (`mul_128`'s table loads).
pub fn load_row(t: &[u8; 16]) -> uint8x16_t {
    // SAFETY: 16 bytes of `t`.
    unsafe { vld1q_u8(t.as_ptr()) }
}

/// `x ^= y` on 64-byte chunks: two pointer families, one per chunk
/// (`fftb_128`'s shape: a chunk read through one pointer, a chunk written
/// through another).
pub fn xor_rows(x: &mut [u8; 64], y: &[u8; 64]) {
    let x_ptr: *mut u8 = x.as_mut_ptr();
    let y_ptr: *const u8 = y.as_ptr();

    // SAFETY: the offsets stay within the two 64-byte chunks.
    unsafe {
        let a0 = vld1q_u8(x_ptr);
        let a1 = vld1q_u8(x_ptr.add(16));
        let a2 = vld1q_u8(x_ptr.add(16 * 2));
        let a3 = vld1q_u8(x_ptr.add(16 * 3));
        let b0 = vld1q_u8(y_ptr);
        let b1 = vld1q_u8(y_ptr.add(16));
        let b2 = vld1q_u8(y_ptr.add(16 * 2));
        let b3 = vld1q_u8(y_ptr.add(16 * 3));

        vst1q_u8(x_ptr, veorq_u8(a0, b0));
        vst1q_u8(x_ptr.add(16), veorq_u8(a1, b1));
        vst1q_u8(x_ptr.add(16 * 2), veorq_u8(a2, b2));
        vst1q_u8(x_ptr.add(16 * 3), veorq_u8(a3, b3));
    }
}
