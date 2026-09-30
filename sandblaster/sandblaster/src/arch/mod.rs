//! Trusted load/store helpers for hardware kernels (DESIGN.md §9.2, TCB item 4).
//!
//! sandblaster hardware kernels (e.g. `sha256::compress_sha2`) are written in
//! the exec subset: no raw pointers and no `unsafe`. Vector intrinsics that
//! take plain values (`vaddq_u32`, `vsha256hq_u32`, `_mm_sha256rnds2_epu32`,
//! ...) are safe to call from a function whose `#[target_feature]` set covers
//! them (§9.3). Memory access intrinsics take raw pointers, so the subset
//! reaches them only through the helpers in this module, which follow the
//! §9.2 template exactly:
//!
//! ```ignore
//! #[target_feature(enable = F)]
//! #[inline]
//! pub fn load_u8x16(a: &[u8; 16]) -> uint8x16_t { unsafe { vld1q_u8(a.as_ptr()) } }
//! ```
//!
//! * The argument is a reference to a fixed-size array of exactly the
//!   vector's size, so every access is in bounds by construction.
//! * Loads and stores are **unaligned only** (`vld1q`/`vst1q` on aarch64,
//!   `_mm_loadu_si128`/`_mm_storeu_si128` on x86_64): a `&[u8; 16]` has
//!   alignment 1.
//! * `unsafe` is confined to the single pointer call inside each helper; the
//!   helper itself is safe. Because it carries `#[target_feature]`, `rustc`
//!   independently re-checks the feature rule at every call site (a caller
//!   without the feature needs `unsafe`, which DSL sources cannot write).
//! * Helpers are `#[inline]`, never `#[inline(always)]` (which `rustc`
//!   rejects together with `#[target_feature]`).
//! * Semantics (for the checker's target library): a load of `a` is the
//!   vector whose lane `i` is `a[i]` (lane 0 at the lowest address); a store
//!   is the inverse. On x86_64, `__m128i` is canonically 16 little-endian
//!   bytes, so `load_u32x4(&[w0, w1, w2, w3])` has 32-bit view `[w0, w1, w2,
//!   w3]`. Only little-endian targets are supported (variants are gated by
//!   `target_endian = "little"`).
//!
//! In the generated crate these helpers are emitted from the same templates
//! as trusted glue (§8.3); this module is what the baseline build and any
//! hand-written test code link against.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
