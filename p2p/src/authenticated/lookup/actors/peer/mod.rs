//! Peer

use crate::authenticated::lookup::metrics;
use commonware_codec::Error as CodecError;
use governor::Quota;
use prometheus_client::metrics::{counter::Counter, family::Family};
use thiserror::Error;

mod actor;
pub use actor::Actor;

mod ingress;
pub use ingress::Message;

pub struct Config {
    pub mailbox_size: usize,
    pub ping_frequency: std::time::Duration,
    pub allowed_ping_rate: Quota,
    pub sent_messages: Family<metrics::Message, Counter>,
    pub received_messages: Family<metrics::Message, Counter>,
    pub rate_limited: Family<metrics::Message, Counter>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("peer killed: {0}")]
    PeerKilled(String),
    #[error("send failed: {0}")]
    SendFailed(commonware_stream::Error),
    #[error("peer disconnected")]
    PeerDisconnected,
    #[error("receive failed: {0}")]
    ReceiveFailed(commonware_stream::Error),
    #[error("decode failed: {0}")]
    DecodeFailed(CodecError),
    #[error("unexpected failure: {0}")]
    UnexpectedFailure(commonware_runtime::Error),
    #[error("invalid channel")]
    InvalidChannel,
}
