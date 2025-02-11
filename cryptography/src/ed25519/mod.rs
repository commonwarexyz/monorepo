//! Ed25519 implementation of the `Scheme` trait.
//!
//! This implementation uses the `ed25519-consensus` crate to adhere to a strict
//! set of validation rules for Ed25519 signatures (which is necessary for
//! stability in a consensus context). You can read more about this
//! [here](https://hdevalence.ca/blog/2020-10-04-its-25519am).
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Ed25519, Scheme};
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = Ed25519::new(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = Some(&b"demo"[..]);
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(Ed25519::verify(namespace, msg, &signer.public_key(), &signature));
//! ```

mod scheme;

pub use scheme::{Ed25519, Ed25519Batch, PrivateKey, PublicKey, Signature};
