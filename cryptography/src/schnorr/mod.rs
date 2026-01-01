//! Schnorr signature implementation over secp256k1 of the [crate::Verifier] and [crate::Signer] traits.
//!
//! This implementation uses the `k256` crate and follows [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
//! for Schnorr signatures over the secp256k1 curve. It uses x-only public keys (32 bytes) and produces
//! deterministic signatures as specified in BIP-340.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{schnorr, PrivateKey, PublicKey, Signature, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = schnorr::PrivateKey::random(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = &b"demo"[..];
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

mod scheme;

pub use scheme::{PrivateKey, PublicKey, Signature};
