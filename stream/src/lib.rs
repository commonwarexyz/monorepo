//! Exchange messages over arbitrary transport.

pub mod public_key;

use bytes::Bytes;
use prost::DecodeError;
use std::future::Future;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("unexpected message")]
    UnexpectedMessage,
    #[error("unable to decode: {0}")]
    UnableToDecode(DecodeError),
    #[error("invalid ephemeral public key")]
    InvalidEphemeralPublicKey,
    #[error("invalid channel public key")]
    InvalidChannelPublicKey,
    #[error("invalid peer public key")]
    InvalidPeerPublicKey,
    #[error("handshake not for us")]
    HandshakeNotForUs,
    #[error("handshake timeout")]
    HandshakeTimeout,
    #[error("missing signature")]
    MissingSignature,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("wrong peer")]
    WrongPeer,
    #[error("recv failed")]
    RecvFailed,
    #[error("recv too large: {0} bytes")]
    RecvTooLarge(usize),
    #[error("send failed")]
    SendFailed,
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
