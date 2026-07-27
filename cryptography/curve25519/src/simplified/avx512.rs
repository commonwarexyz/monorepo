//! The AVX-512 backend: all eight lanes of an [`super::FVec`] limb row in one 512-bit register,
//! with field multiplication built on IFMA's 52-bit multiply-accumulates.
//!
//! Not yet implemented: [`super::with_backend`] currently `todo!()`s on the branch that would
//! construct it.
