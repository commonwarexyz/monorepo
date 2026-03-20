//! Error types for the commitment crate.

/// Errors that can occur during proof generation or verification.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration parameters are invalid.
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),

    /// Proof structure is incomplete or malformed.
    #[error("invalid proof")]
    InvalidProof,

    /// Merkle proof verification failed.
    #[error("merkle verification failed")]
    MerkleVerificationFailed,

    /// Sumcheck round consistency check failed.
    #[error("sumcheck mismatch")]
    SumcheckMismatch,

    /// Proof verification failed.
    #[error("verification failed")]
    VerificationFailed,
}
