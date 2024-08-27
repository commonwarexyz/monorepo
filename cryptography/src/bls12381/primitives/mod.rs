//! Operations over the BLS12-381 scalar field.
//!
//! # Acknowledgements
//!
//! * <https://github.com/celo-org/celo-threshold-bls-rs>: Provides a reference implementation of
//!   common operations over the BLS12-381 curve, GJKR99, and Desmedt97.
//! * <https://github.com/filecoin-project/blstrs>, <https://github.com/MystenLabs/fastcrypto>: Provide a
//!   reference implementation of how to use `blst` to implement common operations over the BLS12-381 curve.
//!
//! # Example
//!
//! ```rust
//! use vrf::bls12381::{
//!     primitives::{ops::{partial_sign, partial_verify, aggregate, verify}, poly::public},
//!     dkg::ops::{generate_shares},
//! };
//!
//! // Configure threshold
//! let (n, t) = (5, 4);
//!
//! // Generate commitment and shares
//! let (commitment, shares) = generate_shares(None, n, t);
//!
//! // Generate partial signatures from shares
//! let msg = b"hello world";
//! let partials: Vec<_> = shares.iter().map(|s| partial_sign(s, msg)).collect();
//!
//! // Verify partial signatures
//! for p in &partials {
//!     partial_verify(&commitment, msg, p).expect("signature should be valid");
//! }
//!
//! // Aggregate partial signatures
//! let threshold_sig = aggregate(t, partials).unwrap();
//!
//! // Verify threshold signature
//! let threshold_pub = public(&commitment);
//! verify(&threshold_pub, msg, &threshold_sig).expect("signature should be valid");
//! ```

pub mod group;
pub mod ops;
pub mod poly;

#[derive(Debug)]
pub enum Error {
    NotEnoughPartialSignatures,
    InvalidSignature,
    InvalidRecovery,
    NoInverse,
    DuplicateEval,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NotEnoughPartialSignatures => write!(f, "not enough partial signatures"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::InvalidRecovery => write!(f, "invalid recovery"),
            Error::NoInverse => write!(f, "no inverse"),
            Error::DuplicateEval => write!(f, "duplicate eval"),
        }
    }
}

impl std::error::Error for Error {}
