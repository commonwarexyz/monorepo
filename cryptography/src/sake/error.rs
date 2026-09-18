use core::ops::Range;
use thiserror::Error;

/// Errors relating to the handshake, or to encryption.
#[derive(Error, Debug)]
pub enum Error {
    /// An error indicating that the handshake failed.
    ///
    /// We don't provide detail on why the handshake failed, following a common
    /// precautionary principle. The basis of this reasoning is that:
    ///
    /// - the application can't meaningfully respond to different failure reasons,
    /// - an adversary might gain an advantage by knowing the failure reason.
    ///
    /// In other words, there's only disadvantages and extra effort in doing so.
    #[error("handshake failed")]
    HandshakeFailed,
    /// An error indicating that no more messages can (safely) be sent.
    ///
    /// In practice, you should never see this error, because the limit takes
    /// an ultra-astronomical amount of messages to reach.
    #[error("message encryption limited reached")]
    MessageLimitReached,
    /// Encryption failed for some reason.
    ///
    /// In practice, this error shouldn't happen.
    #[error("encryption failed")]
    EncryptionFailed,
    /// Decryption failed.
    ///
    /// This can happen if the message was corrupted, for some reason.
    #[error("decryption failed")]
    DecryptionFailed,
    /// The timestamp is not in the allowable bounds
    #[error("timestamp {0} not in {1:?}")]
    InvalidTimestamp(u64, Range<u64>),
}
