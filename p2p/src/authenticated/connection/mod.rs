//! Connection

use commonware_cryptography::Scheme;
use prost::DecodeError;
use std::time::Duration;
use thiserror::Error;

mod handshake;
mod instance;
mod utils;
mod x25519;

pub use handshake::IncomingHandshake;
pub use instance::{Instance, Sender};

#[derive(Clone)]
pub struct Config<C: Scheme> {
    pub crypto: C,
    pub namespace: Vec<u8>,
    pub max_message_size: usize,
    pub synchrony_bound: Duration,
    pub max_handshake_age: Duration,
    pub handshake_timeout: Duration,
}

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
    #[error("read failed")]
    ReadFailed,
    #[error("send failed")]
    SendFailed,
    #[error("connection closed")]
    StreamClosed,
    #[error("cipher creation failed")]
    CipherCreationFailed,
    #[error("peer nonce overflow")]
    PeerNonceOverflow,
    #[error("our nonce overflow")]
    OurNonceOverflow,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid timestamp")]
    InvalidTimestamp,
}
