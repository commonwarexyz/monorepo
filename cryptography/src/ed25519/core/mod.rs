//! Vendored version of [`ed25519_consensus`].
//!
//! # Changes vs. Upstream
//!
//! - Uses [`curve25519_dalek`] rather than [`curve25519_dalek_ng`] to support AVX2/AVX512 on x86 platforms.
//! - Reduces the clamped Ed25519 scalar with [`Scalar::from_bytes_mod_order`] before public-key
//!   derivation and scalar-scalar arithmetic (equivalent to [`ed25519_zebra`]).
//! - Zeroizes the signing key's prefix, along with the seed and scalar.
//! - Removed `serde` dependency.
//! - Swapped `hex` dependency to [`commonware_formatting::Hex`].
//! - Adapted code to `commonware`'s clippy rules.
//! - The batch verifier accepts pre-decompressed [`VerificationKey`] values and reuses their
//!   cached point decompression state.
//! - Large batches decompress signature R points through an owned batched square-root
//!   kernel (scalar-interleaved with NEON and AVX-512 IFMA variants) and check one global
//!   verification equation with an owned multiscalar multiplication (see [`fe`], [`point`],
//!   [`msm`], `neon`, and `ifma`).
//!
//! [`ed25519_consensus`]: https://crates.io/crates/ed25519-consensus
//! [`ed25519_zebra`]: https://crates.io/crates/ed25519-zebra
//! [`curve25519_dalek_ng`]: https://crates.io/crates/curve25519-dalek-ng
//! [`Scalar::from_bytes_mod_order`]: curve25519_dalek::scalar::Scalar::from_bytes_mod_order

pub mod batch;
mod error;
mod fe;
#[cfg(any(target_arch = "x86_64", test))]
mod ifma;
mod msm;
#[cfg(target_arch = "aarch64")]
mod neon;
mod point;
mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
