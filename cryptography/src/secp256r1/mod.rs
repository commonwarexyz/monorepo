//! Secp256r1 implementation of the `Scheme` trait.
//!
//! This implementation operates over public keys in compressed form (SEC 1, Version 2.0, Section 2.3.3), generates
//! deterministic signatures as specified in [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979), and enforces
//! signatures are normalized according to [BIP 62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures).
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Scheme, Secp256r1};
//! use rand::rngs::OsRng;
//!
//! // Generate a new private key
//! let mut signer = Secp256r1::new(&mut OsRng);
//!
//! // Create a message to sign
//! let namespace = Some(&b"demo"[..]);
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(Secp256r1::verify(namespace, msg, &signer.public_key(), &signature));
//! ```

mod scheme;

pub use scheme::{PrivateKey, PublicKey, Secp256r1, Signature};
