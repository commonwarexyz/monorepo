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
//!
//! [`ed25519_consensus`]: https://crates.io/crates/ed25519-consensus
//! [`ed25519_zebra`]: https://crates.io/crates/ed25519-zebra
//! [`curve25519_dalek_ng`]: https://crates.io/crates/curve25519-dalek-ng
//! [`Scalar::from_bytes_mod_order`]: curve25519_dalek::scalar::Scalar::from_bytes_mod_order

pub mod batch;
mod error;
mod signature;
mod signing_key;
mod verification_key;

use commonware_codec::{varint::MAX_U32_VARINT_SIZE, Write};
use curve25519_dalek::scalar::Scalar;
pub use error::Error;
use sha2::{digest::Update, Sha512};
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

/// Computes the Ed25519 challenge scalar `k = H(R || A || namespace_prefix || msg)`.
///
/// When `namespace` is `Some`, a varint length prefix is streamed before it,
/// matching [`commonware_utils::union_unique`] without materializing the
/// concatenation. SHA-512 is a streaming hash, so the result is byte-identical to
/// hashing the concatenated buffer.
#[allow(non_snake_case)]
pub(crate) fn challenge(
    R_bytes: &[u8; 32],
    A_bytes: &[u8; 32],
    namespace: Option<&[u8]>,
    msg: &[u8],
) -> Scalar {
    let mut h = Sha512::default();
    Update::update(&mut h, R_bytes);
    Update::update(&mut h, A_bytes);
    if let Some(namespace) = namespace {
        let mut prefix = [0u8; MAX_U32_VARINT_SIZE];
        let mut buf: &mut [u8] = &mut prefix;
        namespace.len().write(&mut buf);
        let n = MAX_U32_VARINT_SIZE - buf.len();
        Update::update(&mut h, &prefix[..n]);
        Update::update(&mut h, namespace);
    }
    Update::update(&mut h, msg);
    Scalar::from_hash(h)
}
