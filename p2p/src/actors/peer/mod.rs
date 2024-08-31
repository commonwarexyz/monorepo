//! Peer

use crate::{connection, metrics};
use governor::Quota;
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::time::Duration;
use thiserror::Error;
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

#[derive(Error, Debug)]
pub enum Error {
    #[error("peer killed: {0}")]
    PeerKilled(String),
    #[error("send failed: {0}")]
    SendFailed(connection::Error),
    #[error("peer disconnected")]
    PeerDisconnected,
    #[error("receive failed: {0}")]
    ReceiveFailed(connection::Error),
    #[error("unexpected handshake message")]
    UnexpectedHandshake,
    #[error("unexpected failure: {0}")]
    UnexpectedFailure(JoinError),
    #[error("message dropped")]
    MessageDropped,
    #[error("message too large: {0}")]
    MessageTooLarge(usize),
    #[error("invalid chunk")]
    InvalidChunk,
    #[error("invalid channel")]
    InvalidChannel,
}
