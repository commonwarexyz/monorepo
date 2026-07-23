use thiserror::Error;

/// An error related to Ed25519 signature verification.
#[commonware_macros::stability(ALPHA)]
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The verification key is not a valid point encoding.
    #[error("verification key is not a valid point encoding")]
    InvalidVerificationKey,
    /// The signature's `R` component is not a valid point encoding.
    #[error("signature R is not a valid point encoding")]
    InvalidSignature,
    /// The signature's `s` component is not canonically reduced modulo the group order.
    #[error("signature s is not canonically reduced")]
    NonCanonicalScalar,
    /// The verification equation did not hold.
    #[error("signature verification failed")]
    VerificationFailed,
}
