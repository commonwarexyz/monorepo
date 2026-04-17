use thiserror::Error;

/// An error related to Ed25519 signatures.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The encoding of a secret key was malformed.
    #[error("Malformed secret key encoding.")]
    MalformedSecretKey,
    /// The encoding of a public key was malformed.
    #[error("Malformed public key encoding.")]
    MalformedPublicKey,
    /// Signature verification failed.
    #[error("Invalid signature.")]
    InvalidSignature,
    /// A byte slice of the wrong length was supplied during parsing.
    #[error("Invalid length when parsing byte slice.")]
    InvalidSliceLength,
}
