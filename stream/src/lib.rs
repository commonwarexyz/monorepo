//! Exchange messages over arbitrary transport.

pub mod public_key;
pub mod utils;

use bytes::Bytes;
use commonware_codec::Error as CodecError;
use commonware_runtime::Error as RuntimeError;
use std::future::Future;
use thiserror::Error;

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    #[error("unable to decode: {0}")]
    UnableToDecode(CodecError),
    #[error("handshake not for us")]
    HandshakeNotForUs,
    #[error("handshake timeout")]
    HandshakeTimeout,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("wrong peer")]
    WrongPeer,
    #[error("recv failed")]
    RecvFailed(RuntimeError),
    #[error("recv too large: {0} bytes")]
    RecvTooLarge(usize),
    #[error("send failed")]
    SendFailed(RuntimeError),
    #[error("send zero size")]
    SendZeroSize,
    #[error("send too large: {0} bytes")]
    SendTooLarge(usize),
    #[error("connection closed")]
    StreamClosed,
    #[error("cipher creation failed")]
    CipherCreationFailed,
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("timestamp too old: {0}")]
    InvalidTimestampOld(u64),
    #[error("timestamp too future: {0}")]
    InvalidTimestampFuture(u64),
}

/// A trait for sending messages.
pub trait Sender: Sync + Send + 'static {
    /// Send a message to the stream.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
}

/// A trait for receiving messages.
pub trait Receiver: Sync + Send + 'static {
    /// Receive a message from the stream.
    fn receive(&mut self) -> impl Future<Output = Result<Bytes, Error>> + Send;
}
