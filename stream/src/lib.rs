//! Exchange messages over arbitrary transport.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

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
    // Handshake errors
    #[error("handshake timeout")]
    HandshakeTimeout,

    // Hello errors
    #[error("hello not for us")]
    HelloNotForUs,
    #[error("hello uses our public key")]
    HelloUsesOurKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("timestamp too old: {0}")]
    InvalidTimestampOld(u64),
    #[error("timestamp too future: {0}")]
    InvalidTimestampFuture(u64),

    // Confirmation errors
    #[error("shared secret was not contributory")]
    SharedSecretNotContributory,
    #[error("cipher creation failed")]
    CipherCreation,
    #[error("HKDF expansion failed")]
    HKDFExpansion,
    #[error("key confirmation failed")]
    ConfirmationFailed,
    #[error("invalid key confirmation")]
    InvalidConfirmation,

    // Connection errors
    #[error("cannot dial self")]
    DialSelf,
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

    // Encryption errors
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,

    // Codec errors
    #[error("unable to decode: {0}")]
    UnableToDecode(CodecError),
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
