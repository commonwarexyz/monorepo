//! Native execution tokens obtained after checking their CPU feature requirements.

#[cfg(target_arch = "aarch64")]
mod neon;

#[cfg(target_arch = "aarch64")]
pub use neon::NativeNeon;

#[cfg(target_arch = "x86_64")]
mod ice_lake;
#[cfg(target_arch = "x86_64")]
pub use ice_lake::NativeIceLake;

#[cfg(target_arch = "aarch64")]
mod arm_v9;
#[cfg(target_arch = "aarch64")]
pub use arm_v9::NativeArmV9;

#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod fuzz;
