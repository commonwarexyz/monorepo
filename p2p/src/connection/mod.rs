//! Connection

use commonware_cryptography::Scheme;
use prost::DecodeError;
use std::time::Duration;

mod handshake;
mod stream;
mod utils;
mod x25519;

pub use handshake::IncomingHandshake;
pub use stream::{Sender, Stream};

#[derive(Clone)]
pub struct Config<C: Scheme> {
    pub crypto: C,
    pub max_frame_length: usize,
    pub handshake_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub tcp_nodelay: Option<bool>,
}

#[derive(Debug)]
pub enum Error {
    UnexpectedMessage,
    UnableToDecode(DecodeError),
    InvalidEphemeralPublicKey,
    InvalidChannelPublicKey,
    InvalidPeerPublicKey,
    HandshakeNotForUs,
    MissingSignature,
    InvalidSignature,
    HandshakeTimeout,
    ReadTimeout,
    WriteTimeout,
    WrongPeer,
    ReadFailed,
    SendFailed,
    StreamClosed,
    CipherCreationFailed,
    PeerNonceOverflow,
    OurNonceOverflow,
    EncryptionFailed,
    DecryptionFailed,
    ReadInvalidFrame,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnexpectedMessage => write!(f, "unexpected message"),
            Error::UnableToDecode(decode_error) => {
                write!(f, "unable to decode: {}", decode_error)
            }
            Error::InvalidEphemeralPublicKey => write!(f, "invalid ephemeral public key"),
            Error::InvalidChannelPublicKey => {
                write!(f, "invalid channel public key")
            }
            Error::InvalidPeerPublicKey => write!(f, "invalid peer public key"),
            Error::HandshakeNotForUs => {
                write!(f, "handshake not for us")
            }
            Error::MissingSignature => write!(f, "missing signature"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::HandshakeTimeout => write!(f, "handshake timeout"),
            Error::ReadTimeout => write!(f, "read timeout"),
            Error::WriteTimeout => write!(f, "write timeout"),
            Error::WrongPeer => write!(f, "wrong peer"),
            Error::ReadFailed => write!(f, "read failed"),
            Error::SendFailed => write!(f, "send failed"),
            Error::StreamClosed => write!(f, "connection closed"),
            Error::CipherCreationFailed => write!(f, "cipher creation failed"),
            Error::PeerNonceOverflow => write!(f, "peer nonce overflow"),
            Error::OurNonceOverflow => write!(f, "our nonce overflow"),
            Error::EncryptionFailed => write!(f, "encryption failed"),
            Error::DecryptionFailed => write!(f, "decryption failed"),
            Error::ReadInvalidFrame => write!(f, "read invalid frame"),
        }
    }
}

impl std::error::Error for Error {}
