use core::ops::Range;
use thiserror::Error;

/// Errors relating to the handshake.
#[derive(Error, Debug)]
pub enum Error {
    /// A peer's signature does not verify over the transcript.
    #[error("invalid signature")]
    InvalidSignature,
    /// A peer's ephemeral key yields a non-contributory shared secret.
    #[error("invalid ephemeral key")]
    InvalidEphemeralKey,
    /// A peer's confirmation does not match the transcript.
    #[error("invalid confirmation")]
    InvalidConfirmation,
    /// The timestamp is not in the allowable bounds
    #[error("timestamp {0} not in {1:?}")]
    InvalidTimestamp(u64, Range<u64>),
}
