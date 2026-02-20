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
//! * <https://github.com/supranational/blst/blob/v0.3.13/bindings/rust/src/pippenger.rs>: Parallel MSM using tile-based Pippenger.
//!
//! # Security Notes
//!
//! ## Zero-Checks
//!
//! This module intentionally deviates from strict IETF BLS key-validation behavior by allowing
//! canonical zero scalars and identity group elements to deserialize. The IRTF CFRG BLS draft
//! specifies KeyValidate as rejecting identity public keys (Section 2.5) and explicitly discusses
//! why in Section 5.2:
//! <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-2.5>
//! <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-5.2>
//!
//! The security model is that choosing a zero public key is a weak key choice for that participant,
//! with impact similar to leaking that participant's private key: that identity can be impersonated,
//! but this does not automatically break discrete-log assumptions for other honest participants.
//!
//! In multi-party settings (aggregate signatures, batch verification, threshold protocols), security
//! must be evaluated holistically at the set level. Adversarial participants can coordinate keys
//! and signatures to produce zero values in the aggregate (e.g. choosing `X` and `-X` as keys),
//! so simply checking individual values is not sufficient, and the protocol as a whole needs
//! to be considered.
//!
//! Proof-of-possession is the primary mechanism used here to prevent rogue-key attacks, which is the
//! most common area where zero keys might pose a problem. Our PoP verification explicitly enforces non-zero inputs.
//! This aligns with the PoP requirements and rogue-key guidance in Section 3.3 and Section 3.3.4:
//! <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-3.3>
//! <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-3.3.4>
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::bls12381::{
//!     primitives::{ops::{self, threshold}, variant::MinSig, sharing::Mode},
//!     dkg,
//! };
//! use commonware_utils::{NZU32, N3f1};
//! use rand::rngs::OsRng;
//!
//! // Configure number of players
//! let n = NZU32!(5);
//!
//! // Generate commitment and shares
//! let (sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut OsRng, Mode::default(), n);
//!
//! // Generate partial signatures from shares
//! let namespace = b"demo";
//! let message = b"hello world";
//! let partials: Vec<_> = shares.iter().map(|s| threshold::sign_message::<MinSig>(s, namespace, message)).collect();
//!
//! // Verify partial signatures
//! for p in &partials {
//!     threshold::verify_message::<MinSig>(&sharing, namespace, message, p).expect("signature should be valid");
//! }
//!
//! // Aggregate partial signatures
//! let threshold_sig = threshold::recover::<MinSig, _, N3f1>(&sharing, &partials, &commonware_parallel::Sequential).unwrap();
//!
//! // Verify threshold signature
//! let threshold_pub = sharing.public();
//! ops::verify_message::<MinSig>(threshold_pub, namespace, message, &threshold_sig).expect("signature should be valid");
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
