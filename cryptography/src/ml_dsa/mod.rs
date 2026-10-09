//! ML-DSA-65 ([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)) implementation of the
//! [crate::Verifier] and [crate::Signer] traits.
//!
//! ML-DSA is a lattice-based signature scheme designed to remain secure against adversaries with
//! quantum computers. This module only exposes the ML-DSA-65 parameter set (NIST security
//! category 3).
//!
//! # Encoding
//!
//! - Private keys are encoded as the 32-byte seed `xi` from which `ML-DSA.KeyGen_internal`
//!   derives the key pair, so equal seeds always produce equal keys.
//! - Public keys are encoded with `pkEncode` (1952 bytes). Every 1952-byte string decodes to a
//!   valid public key.
//! - Signatures are encoded with `sigEncode` (3309 bytes). Decoding rejects encodings that
//!   `sigDecode` rejects (malformed hints or out-of-range responses), so every decoded signature
//!   is well-formed.
//!
//! # Signing
//!
//! Messages are signed with the deterministic variant of `ML-DSA.Sign` (`rnd` is all zeros) and
//! an empty context string, after prefixing the namespace with [commonware_utils::union_unique]
//! like every other [crate::Signer] in this crate. Signatures are therefore reproducible: signing
//! the same namespace and message with the same key always yields identical bytes. Any
//! FIPS 204 verifier accepts these signatures, and [PublicKey] accepts signatures produced with
//! the hedged (randomized) variant over the same payload.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{ml_dsa, PrivateKey, PublicKey, Signature, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use commonware_utils::test_rng;
//!
//! let mut rng = test_rng();
//!
//! // Generate a new private key
//! let signer = ml_dsa::PrivateKey::random(&mut rng);
//!
//! // Create a message to sign
//! let namespace = b"demo";
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

pub mod certificate;
mod scheme;

pub use scheme::{PrivateKey, PublicKey, Signature};
