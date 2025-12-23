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
//!     primitives::{ops::{partial_sign_message, partial_verify_message, threshold_signature_recover, verify_message}, variant::MinSig, sharing::Mode},
//!     dkg,
//! };
//! use commonware_utils::NZU32;
//! use rand::rngs::OsRng;
//!
//! // Configure number of players
//! let n = NZU32!(5);
//!
//! // Generate commitment and shares
//! let (sharing, shares) = dkg::deal_anonymous::<MinSig>(&mut OsRng, Mode::default(), n);
//!
//! // Generate partial signatures from shares
//! let namespace = Some(&b"demo"[..]);
//! let message = b"hello world";
//! let partials: Vec<_> = shares.iter().map(|s| partial_sign_message::<MinSig>(s, namespace, message)).collect();
//!
//! // Verify partial signatures
//! for p in &partials {
//!     partial_verify_message::<MinSig>(&sharing, namespace, message, p).expect("signature should be valid");
//! }
//!
//! // Aggregate partial signatures
//! let threshold_sig = threshold_signature_recover::<MinSig, _>(&sharing, &partials).unwrap();
//!
//! // Verify threshold signature
//! let threshold_pub = sharing.public();
//! verify_message::<MinSig>(threshold_pub, namespace, message, &threshold_sig).expect("signature should be valid");
//! ```

pub mod group;
pub mod ops;
pub mod sharing;
pub mod variant;

use thiserror::Error;

/// Errors that can occur when working with BLS12-381 primitives.
#[derive(Error, Debug)]
pub enum Error {
    #[error("not enough partial signatures: {0}/{1}")]
    NotEnoughPartialSignatures(usize, usize),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid recovery")]
    InvalidRecovery,
    #[error("no inverse")]
    NoInverse,
    #[error("duplicate polynomial evaluation point")]
    DuplicateEval,
    #[error("evaluation index is invalid")]
    InvalidIndex,
}
