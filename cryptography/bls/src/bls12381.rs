//! BLS12-381 scalars, prime-order groups, pairings, and BLS signatures.
//!
//! Compressed group decoding accepts the canonical identity. The signing layer separately
//! rejects identity public keys and signatures.
//!
//! ```
//! use commonware_cryptography_bls::bls12381::signing::{SigningKey, min_pk};
//!
//! let key = SigningKey::random(commonware_utils::test_rng());
//! let public_key = min_pk::public_key(&key);
//! let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
//! let signature = min_pk::sign(&key, b"message", dst);
//! assert!(min_pk::verify(&public_key, b"message", dst, &signature));
//! ```

use commonware_cryptography_vroom::{Bls12381, Element};

mod extension;
pub mod group;
mod hash;
pub mod pairing;
pub mod recovery;
pub mod scalar;
pub mod signing;

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    target_pointer_width = "64",
    not(miri)
))]
mod word;
#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    target_pointer_width = "64",
    not(miri)
))]
mod word_pairing;

type Fp = Element<Bls12381>;
