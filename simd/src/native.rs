//! Native execution tokens obtained after checking their CPU feature requirements.

#[cfg(target_arch = "aarch64")]
pub mod neon;

#[cfg(target_arch = "aarch64")]
pub use neon::NativeNeon;
