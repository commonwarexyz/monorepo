//! Peer

use crate::authenticated::lookup::metrics;
use commonware_codec::Error as CodecError;
use commonware_runtime::{
    metrics::{Counter, Family},
    Registered,
};
use std::num::NonZeroUsize;
use thiserror::Error;

mod actor;
pub use actor::Actor;

mod ingress;
pub use ingress::Message;

pub struct Config {
    pub mailbox_size: usize,
    pub send_batch_size: NonZeroUsize,
    pub ping_frequency: std::time::Duration,
    pub sent_messages: Registered<Family<metrics::Message, Counter>>,
    pub received_messages: Registered<Family<metrics::Message, Counter>>,
    pub dropped_messages: Registered<Family<metrics::Message, Counter>>,
    pub rate_limited: Registered<Family<metrics::Message, Counter>>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("peer killed: {0}")]
    PeerKilled(String),
    #[error("send failed: {0}")]
    SendFailed(commonware_stream::encrypted::Error),
    #[error("peer disconnected")]
    PeerDisconnected,
    #[error("receive failed: {0}")]
    ReceiveFailed(commonware_stream::encrypted::Error),
    #[error("decode failed: {0}")]
    DecodeFailed(CodecError),
    #[error("unexpected failure: {0}")]
    UnexpectedFailure(commonware_runtime::Error),
    #[error("invalid channel")]
    InvalidChannel,
}
