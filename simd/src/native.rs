//! Native execution tokens obtained after checking their CPU feature requirements.
//!
//! On x86-64, `NativeX86V4C` implements the x86v4c profile. `NativeX86V3` implements only
//! the common instructions with AVX2 and executes the portable operation path.
//!
//! The AArch64 backends exist only when NEON is enabled at compile time. Targets without
//! it cannot enable NEON per function or name vector registers, so they fall back to the
//! portable scalar backend instead of failing to build.

#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_feature = "neon")
))]
mod partial;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub use neon::NativeNeon;

#[cfg(target_arch = "x86_64")]
mod x86_u32x4;

#[cfg(target_arch = "x86_64")]
mod x86_v4c;
#[cfg(target_arch = "x86_64")]
pub use x86_v4c::NativeX86V4C;

#[cfg(target_arch = "x86_64")]
mod x86_v3;
#[cfg(target_arch = "x86_64")]
pub use x86_v3::NativeX86V3;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod arm_v9;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub use arm_v9::NativeArmV9;

#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod fuzz;
