//! Array-backed execution tokens that run every instruction profile on any host.
//!
//! These tokens select their corresponding operation paths without using native SIMD
//! instructions. Vectors preserve lane order and wrapping arithmetic at each profile's
//! width.
//!
//! # Examples
//!
//! ```
//! use commonware_simd::{emulated::EmulatedIceLake, Simd};
//!
//! let s = EmulatedIceLake;
//! let sum = s.u64_add(s.u64_splat(u64::MAX), s.u64_splat(1));
//! let mut output = [0; 8];
//! s.u64_store(sum, &mut output);
//! assert_eq!(output, [0; 8]);
//! ```

mod arm_v9;
mod ice_lake;
mod neon;
mod scalar;
mod shared;

pub use arm_v9::EmulatedArmV9;
pub use ice_lake::EmulatedIceLake;
pub use neon::EmulatedNeon;
pub use scalar::EmulatedScalar;
