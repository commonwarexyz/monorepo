//! `param_write`'s shape with the write behind a Cargo feature: with
//! `alias`, the reference parameter is written between two stores through
//! its pointer, undefined behaviour; without it, the two stores alone,
//! which the window rule admits. An extraction made without the feature
//! judges a body without the write.
use core::arch::aarch64::*;

/// The write compiled in by the feature `alias` only.
pub fn feat_alias(x: &mut [u8; 16], v: uint8x16_t) {
    let p = x.as_mut_ptr();
    // SAFETY: without `alias`, `x` is not used while `p` is; with it, none
    // (the second store is through an invalidated pointer).
    unsafe { vst1q_u8(p, v) };
    #[cfg(feature = "alias")]
    {
        x[0] = 5;
    }
    unsafe { vst1q_u8(p, v) };
}
