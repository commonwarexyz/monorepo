//! Peer

use crate::authenticated::discovery::{
    metrics,
    types::{self, InfoVerifier},
};
use commonware_codec::Error as CodecError;
use commonware_cryptography::PublicKey;
use commonware_runtime::Quota;
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::time::Duration;
use thiserror::Error;

mod actor;
pub use actor::Actor;

mod ingress;
pub use ingress::Message;

pub struct Config<C: PublicKey> {
    pub mailbox_size: usize,
    pub gossip_bit_vec_frequency: Duration,
    pub allowed_bit_vec_rate: Quota,
    pub max_peer_set_size: u64,
    pub allowed_peers_rate: Quota,
    pub peer_gossip_max_count: usize,
    pub info_verifier: InfoVerifier<C>,

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
    #[error("types: {0}")]
    Types(types::Error),
}
