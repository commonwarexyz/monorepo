//! NEON / SHA2 variants.
use core::arch::aarch64::*;
use sandblaster::arch::aarch64::{load_u32x4, load_u8x16, store_u32x4, store_u8x16};
use sandblaster::prelude::*;

#[target_feature(enable = "neon")]
#[implements(super::add4_portable)]
pub fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    store_u32x4(vaddq_u32(load_u32x4(&a), load_u32x4(&b)))
}

#[target_feature(enable = "sha2")]
pub fn mix(block: &[u8; 16], w: [u32; 4]) -> ([u8; 16], u32, [u32; 4]) {
    let v = vrev32q_u8(load_u8x16(block));
    let x = vreinterpretq_u32_u8(v);
    let s = vsha256su0q_u32(x, load_u32x4(&w));
    let t = vextq_u32::<1>(s, vshlq_n_u32::<3>(x));
    let lane = vgetq_lane_u32::<2>(t);
    (store_u8x16(v), lane, store_u32x4(vsetq_lane_u32::<0>(7, t)))
}
