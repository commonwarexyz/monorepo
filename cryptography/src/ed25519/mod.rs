//! Ed25519 implementation of the [crate::Verifier] and [crate::Signer] traits.
//!
//! # Validation Rules (ZIP-215)
//!
//! This crate follows the [ZIP-215](https://zips.z.cash/zip-0215) specification
//! for Ed25519 signature validation. You can read more about the rationale for
//! this [here](https://hdevalence.ca/blog/2020-10-04-its-25519am).
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{ed25519, PrivateKey, PublicKey, Signature, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = ed25519::PrivateKey::random(&mut OsRng);
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
pub(in crate::ed25519) mod core;
mod scheme;

pub use scheme::Batch;
pub use scheme::{PrivateKey, PublicKey, Signature};
