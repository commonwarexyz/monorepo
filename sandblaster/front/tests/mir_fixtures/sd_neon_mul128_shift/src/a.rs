//! A negative twin of `sd_neon_mul128`: the high nibble of the low bytes
//! taken with a shift by 3, not 4.
//!
//! The shape of Reed–Solomon's NEON `mul_128` and `muladd_128`
//! (`cryptography/src/reed_solomon/engine/engine_neon.rs`), as written but
//! for the type of the table rows.
//!
//! Sixteen field elements, held as their low bytes (`value_lo`) and high
//! bytes (`value_hi`), are multiplied by one multiplier through its split
//! nibble tables: for nibble position `i`, the row `lut.lo[i]` holds at index
//! `x` the low byte and `lut.hi[i]` the high byte of the product of
//! `x << 4i` by the multiplier. Each nibble of an element is looked up (TBL)
//! in its two rows, and the four lookups of each product byte are combined by
//! xor. The rows are loaded through raw pointers formed from shared
//! references (`ptr::from_ref`, `cast`, `vld1q_u8`), and the value
//! intrinsics need `unsafe` in an `#[inline(always)]` helper without
//! `#[target_feature]` (NEON is static on aarch64), as in the engine. The
//! engine's rows are `u128`s, whose 16 bytes these arrays hold (128-bit
//! integers are not read yet, C4).
use core::arch::aarch64::*;

/// A multiplier's split nibble tables (the engine's `Multiply128lutT`).
#[derive(Clone, Copy)]
pub struct Lut {
    /// Low product bytes for each nibble position.
    pub lo: [[u8; 16]; 4],
    /// High product bytes for each nibble position.
    pub hi: [[u8; 16]; 4],
}

/// Multiplies the elements whose low and high bytes are in `value_lo` and
/// `value_hi` by the multiplier of `lut`, and returns the low and high
/// product bytes (LEO_MUL_128).
#[inline(always)]
pub fn mul_128(value_lo: uint8x16_t, value_hi: uint8x16_t, lut: &Lut) -> (uint8x16_t, uint8x16_t) {
    let mut prod_lo: uint8x16_t;
    let mut prod_hi: uint8x16_t;

    // SAFETY: NEON is enabled statically on aarch64; each load reads the 16
    // bytes of one row.
    unsafe {
        let t0_lo = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.lo[0]).cast::<u8>());
        let t1_lo = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.lo[1]).cast::<u8>());
        let t2_lo = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.lo[2]).cast::<u8>());
        let t3_lo = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.lo[3]).cast::<u8>());

        let t0_hi = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.hi[0]).cast::<u8>());
        let t1_hi = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.hi[1]).cast::<u8>());
        let t2_hi = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.hi[2]).cast::<u8>());
        let t3_hi = vld1q_u8(core::ptr::from_ref::<[u8; 16]>(&lut.hi[3]).cast::<u8>());

        let clr_mask = vdupq_n_u8(0x0f);

        let data_0 = vandq_u8(value_lo, clr_mask);
        prod_lo = vqtbl1q_u8(t0_lo, data_0);
        prod_hi = vqtbl1q_u8(t0_hi, data_0);

        let data_1 = vshrq_n_u8(value_lo, 3);
        prod_lo = veorq_u8(prod_lo, vqtbl1q_u8(t1_lo, data_1));
        prod_hi = veorq_u8(prod_hi, vqtbl1q_u8(t1_hi, data_1));

        let data_0 = vandq_u8(value_hi, clr_mask);
        prod_lo = veorq_u8(prod_lo, vqtbl1q_u8(t2_lo, data_0));
        prod_hi = veorq_u8(prod_hi, vqtbl1q_u8(t2_hi, data_0));

        let data_1 = vshrq_n_u8(value_hi, 4);
        prod_lo = veorq_u8(prod_lo, vqtbl1q_u8(t3_lo, data_1));
        prod_hi = veorq_u8(prod_hi, vqtbl1q_u8(t3_hi, data_1));
    }

    (prod_lo, prod_hi)
}

/// Returns `{x_lo, x_hi} ^ {y_lo, y_hi} * m`, where `m` is the multiplier of
/// `lut` (LEO_MULADD_128).
#[inline(always)]
pub fn muladd_128(mut x_lo: uint8x16_t, mut x_hi: uint8x16_t, y_lo: uint8x16_t, y_hi: uint8x16_t, lut: &Lut) -> (uint8x16_t, uint8x16_t) {
    let (prod_lo, prod_hi) = mul_128(y_lo, y_hi, lut);

    // SAFETY: NEON is enabled statically on aarch64.
    unsafe {
        x_lo = veorq_u8(x_lo, prod_lo);
        x_hi = veorq_u8(x_hi, prod_hi);
    }
    (x_lo, x_hi)
}
