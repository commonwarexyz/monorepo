//! Operations over the BLS12-381 scalar field.
//!
//! # Acknowledgements
//!
//! _The following crates were used as a reference when implementing this crate. If code is very similar
//! to the reference, it is accompanied by a comment and link._
//!
//! * <https://github.com/celo-org/celo-threshold-bls-rs>: Operations over the BLS12-381 scalar field, GJKR99, and Desmedt97.
//! * <https://github.com/filecoin-project/blstrs> + <https://github.com/MystenLabs/fastcrypto>: Implementing operations over
//!   the BLS12-381 scalar field with <https://github.com/supranational/blst>.
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::bls12381::{
//!     primitives::{ops::{partial_sign_message, partial_verify_message, threshold_signature_recover, verify_message}, poly::public},
//!     dkg::ops::{generate_shares},
//! };
//! use rand::rngs::OsRng;
//!
//! // Configure threshold
//! let (n, t) = (5, 4);
//!
//! // Generate commitment and shares
//! let (commitment, shares) = generate_shares(&mut OsRng, None, n, t);
//!
//! // Generate partial signatures from shares
//! let namespace = Some(&b"demo"[..]);
//! let message = b"hello world";
//! let partials: Vec<_> = shares.iter().map(|s| partial_sign_message(s, namespace, message)).collect();
//!
//! // Verify partial signatures
//! for p in &partials {
//!     partial_verify_message(&commitment, namespace, message, p).expect("signature should be valid");
//! }
//!
//! // Aggregate partial signatures
//! let threshold_sig = threshold_signature_recover(t, partials).unwrap();
//!
//! // Verify threshold signature
//! let threshold_pub = public(&commitment);
//! verify_message(&threshold_pub, namespace, message, &threshold_sig).expect("signature should be valid");
//! ```

pub mod group;
pub mod ops;
pub mod poly;

use thiserror::Error;

/// Errors that can occur when working with BLS12-381 primitives.
#[derive(Error, Debug)]
pub enum Error {
    #[error("not enough partial signatures: {0}/{1}")]
    NotEnoughPartialSignatures(u32, u32),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid recovery")]
    InvalidRecovery,
    #[error("no inverse")]
    NoInverse,
    #[error("duplicate polynomial evaluation point")]
    DuplicateEval,
}
