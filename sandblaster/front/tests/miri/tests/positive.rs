//! The positive pointer fixtures on concrete inputs, against the scalar
//! reference: clean under Miri with Stacked and Tree Borrows.
#![cfg(target_arch = "aarch64")]

use core::arch::aarch64::*;
use sd_miri::ptr;

fn mul_byte(b: u8, lo: &[u8; 16], hi: &[u8; 16]) -> u8 {
    lo[(b & 15) as usize] ^ hi[(b >> 4) as usize]
}

fn bytes(seed: &mut u64) -> u8 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (*seed >> 56) as u8
}

fn tables(seed: &mut u64) -> ([u8; 16], [u8; 16]) {
    (std::array::from_fn(|_| bytes(seed)), std::array::from_fn(|_| bytes(seed)))
}

fn vec(b: &[u8; 16]) -> uint8x16_t {
    // SAFETY: 16 bytes.
    unsafe { vld1q_u8(b.as_ptr()) }
}

#[test]
fn mul_chunks_and_mul_are_the_scalar_reference() {
    let mut seed = 1u64;
    for n in [0usize, 1, 3] {
        let x: Vec<[u8; 64]> = (0..n).map(|_| std::array::from_fn(|_| bytes(&mut seed))).collect();
        let (lo, hi) = tables(&mut seed);
        let want: Vec<[u8; 64]> = x.iter().map(|c| std::array::from_fn(|k| mul_byte(c[k], &lo, &hi))).collect();
        let mut y = x.clone();
        // SAFETY: aarch64 has NEON.
        unsafe { ptr::mul_chunks(&mut y, vec(&lo), vec(&hi)) };
        assert_eq!(y, want);
        let mut z = x.clone();
        ptr::mul(&mut z, vec(&lo), vec(&hi));
        assert_eq!(z, want);
    }
}

#[test]
fn chunk_mul_is_the_scalar_reference() {
    let mut seed = 2u64;
    let c: [u8; 64] = std::array::from_fn(|_| bytes(&mut seed));
    let (lo, hi) = tables(&mut seed);
    let mut d = c;
    // SAFETY: aarch64 has NEON.
    unsafe { ptr::chunk_mul(&mut d, vec(&lo), vec(&hi)) };
    assert_eq!(d, std::array::from_fn(|k| mul_byte(c[k], &lo, &hi)));
}

#[test]
fn xor_rows_and_load_row() {
    let mut seed = 3u64;
    let x: [u8; 64] = std::array::from_fn(|_| bytes(&mut seed));
    let y: [u8; 64] = std::array::from_fn(|_| bytes(&mut seed));
    let mut z = x;
    ptr::xor_rows(&mut z, &y);
    assert_eq!(z, std::array::from_fn(|k| x[k] ^ y[k]));
    let row: [u8; 16] = std::array::from_fn(|_| bytes(&mut seed));
    let mut out = [0u8; 16];
    // SAFETY: 16 bytes.
    unsafe { vst1q_u8(out.as_mut_ptr(), ptr::load_row(&row)) };
    assert_eq!(out, row);
}
