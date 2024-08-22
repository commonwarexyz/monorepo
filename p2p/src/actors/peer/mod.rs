//! Peer

use crate::{connection, metrics};
use commonware_cryptography::PublicKey;
use governor::Quota;
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::time::Duration;
use tokio::task::JoinError;

mod actor;
pub use actor::Actor;

mod ingress;
pub use ingress::{Mailbox, Message, Relay};

pub struct Config {
    pub mailbox_size: usize,
    pub gossip_bit_vec_frequency: Duration,
    pub allowed_bit_vec_rate: Quota,
    pub allowed_peers_rate: Quota,

    pub sent_messages: Family<metrics::Message, Counter>,
    pub received_messages: Family<metrics::Message, Counter>,
}

#[derive(Debug)]
pub enum Error {
    PeerKilled(PublicKey),
    SendFailed(connection::Error),
    PeerDisconnected,
    ReceiveFailed(connection::Error),
    UnexpectedHandshake,
    UnexpectedFailure(JoinError),
    MessageDropped,
    MessageTooLarge(usize),
    InvalidChunk,
    InvalidChannel,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::PeerKilled(peer) => {
                write!(f, "peer killed: {}", hex::encode(peer))
            }
            Error::SendFailed(err) => write!(f, "send failed: {}", err),
            Error::PeerDisconnected => write!(f, "peer disconnected"),
            Error::ReceiveFailed(err) => write!(f, "receive failed: {}", err),
            Error::UnexpectedHandshake => write!(f, "unexpected handshake message"),
            Error::UnexpectedFailure(err) => write!(f, "unexpected failure: {}", err),
            Error::MessageDropped => write!(f, "message dropped"),
            Error::MessageTooLarge(size) => write!(f, "message too large: {}", size),
            Error::InvalidChunk => write!(f, "invalid chunk"),
            Error::InvalidChannel => write!(f, "invalid channel"),
        }
    }
}

impl std::error::Error for Error {}
