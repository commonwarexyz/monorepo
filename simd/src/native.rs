//! Native execution tokens obtained after checking their CPU feature requirements.
//!
//! The AArch64 backends exist only when NEON is enabled at compile time. Targets without
//! it cannot enable NEON per function or name vector registers, so they fall back to the
//! portable scalar backend instead of failing to build.

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub use neon::NativeNeon;

#[cfg(target_arch = "x86_64")]
mod x86_v4c;
#[cfg(target_arch = "x86_64")]
pub use x86_v4c::NativeX86V4C;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod arm_v9;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub use arm_v9::NativeArmV9;

#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod fuzz;
