//! Vendored version of [`ed25519_consensus`].
//!
//! # Changes vs. Upstream
//!
//! - Uses [`curve25519_dalek`] rather than [`curve25519_dalek_ng`] to support AVX2/AVX512 on x86 platforms.
//! - Uses clamped bits for Ed25519 public-key derivation, but reduces the signing scalar with
//!   [`Scalar::from_bytes_mod_order`] before scalar-scalar arithmetic. See `Scalar::from_bits`'
//!   deprecation notice.
//! - Zeroizes the signing key's prefix, along with the seed and scalar.
//! - Removed `serde` dependency.
//! - Swapped `hex` dependency to [`commonware_utils::hex()`].
//! - Adapted code to `commonware`'s clippy rules.
//!
//! [`ed25519_consensus`]: https://crates.io/crates/ed25519-consensus
//! [`curve25519_dalek_ng`]: https://crates.io/crates/curve25519-dalek-ng
//! [`Scalar::from_bytes_mod_order`]: curve25519_dalek::scalar::Scalar::from_bytes_mod_order

pub mod batch;
mod error;
mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
