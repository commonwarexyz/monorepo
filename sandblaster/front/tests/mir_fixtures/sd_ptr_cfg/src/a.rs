//! Each function is `param_write`'s shape — the reference parameter written
//! between two stores through its pointer, undefined behaviour — unless the
//! crate is compiled with a flag that compiles the write out: a target
//! feature (`-C target-feature=+sm4`) or a `--cfg` (`--cfg sd_twin`). A
//! window extraction made with the flag judges a body without the write.
use core::arch::aarch64::*;

/// The write compiled out by `-C target-feature=+sm4` (the review's
/// `cfg_alias`).
pub fn cfg_alias(x: &mut [u8; 16], v: uint8x16_t) {
    let p = x.as_mut_ptr();
    // SAFETY: none without `sm4` (the second store is through an invalidated pointer).
    unsafe { vst1q_u8(p, v) };
    #[cfg(not(target_feature = "sm4"))]
    {
        x[0] = 5;
    }
    unsafe { vst1q_u8(p, v) };
}

/// The write compiled out by `--cfg sd_twin` (no other record of the
/// extraction shows that flag but its rustflags).
pub fn cfg_flag_alias(x: &mut [u8; 16], v: uint8x16_t) {
    let p = x.as_mut_ptr();
    // SAFETY: none without `sd_twin` (as `cfg_alias`).
    unsafe { vst1q_u8(p, v) };
    #[cfg(not(sd_twin))]
    {
        x[0] = 5;
    }
    unsafe { vst1q_u8(p, v) };
}
