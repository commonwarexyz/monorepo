//! Ed25519 implementation of the `Scheme` trait.
//!
//! This implementation uses the `ed25519-consensus` crate to adhere to a strict
//! set of validation rules for Ed25519 signatures (which is necessary for
//! stability in a consensus context). You can read more about this
//! [here](https://hdevalence.ca/blog/2020-10-04-its-25519am).
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{ed25519, PrivateKey, PublicKey, Signature, PrivateKeyExt as _, Verifier as _, Signer as _};
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = ed25519::PrivateKey::from_rng(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = Some(&b"demo"[..]);
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

mod scheme;

pub use scheme::{Batch, PrivateKey, PublicKey, Signature};
