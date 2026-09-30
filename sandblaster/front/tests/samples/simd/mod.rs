//! Hardware intrinsics with the safe load/store helpers (aarch64 only).
#![forbid(unsafe_code)]

use sandblaster::prelude::*;

#[cfg(target_arch = "aarch64")]
mod hw;

#[cfg(target_arch = "aarch64")]
pub use hw::{add4, mix};

/// Portable lane-wise wrapping addition.
pub fn add4_portable(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    let mut out = [0u32; 4];
    for i in 0..4usize {
        out[i] = a[i].wrapping_add(b[i]);
    }
    out
}
