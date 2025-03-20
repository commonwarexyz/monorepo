//! Peer

use commonware_codec::Error as CodecError;
use governor::Quota;
use std::time::Duration;
use thiserror::Error;

mod actor;
pub use actor::Actor;

mod ingress;
pub use ingress::{Mailbox, Message, Relay};

mod metrics;
pub(crate) use metrics::Metrics;

pub struct Config {
    pub mailbox_size: usize,
    pub gossip_bit_vec_frequency: Duration,
    pub allowed_bit_vec_rate: Quota,
    pub allowed_peers_rate: Quota,
    pub metrics: metrics::Metrics,
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
    #[error("message dropped")]
    MessageDropped,
    #[error("invalid channel")]
    InvalidChannel,
    #[error("channel closed: {0}")]
    ChannelClosed(u32),
}
