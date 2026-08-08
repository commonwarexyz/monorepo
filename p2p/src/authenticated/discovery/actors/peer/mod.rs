//! Peer

use crate::authenticated::discovery::{
    metrics,
    types::{self, InfoVerifier},
};
use commonware_codec::Error as CodecError;
use commonware_cryptography::PublicKey;
use commonware_runtime::telemetry::metrics::CounterFamily;
use std::{num::NonZeroUsize, time::Duration};
use thiserror::Error;

mod actor;
pub use actor::Actor;

mod ingress;
pub use ingress::{Mailbox, Message};

pub struct Config<C: PublicKey> {
    pub mailbox_size: NonZeroUsize,
    pub send_batch_size: NonZeroUsize,
    pub gossip_bit_vec_frequency: Duration,
    pub max_peer_set_size: u64,
    pub peer_gossip_max_count: usize,
    pub info_verifier: InfoVerifier<C>,

    pub sent_messages: CounterFamily<metrics::Message<C>>,
    pub received_messages: CounterFamily<metrics::Message<C>>,
    pub rate_limited: CounterFamily<metrics::Message<C>>,
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
    #[error("types: {0}")]
    Types(types::Error),
    #[error("missing greeting")]
    MissingGreeting,
    #[error("duplicate greeting")]
    DuplicateGreeting,
    #[error("greeting public key mismatch")]
    GreetingMismatch,
}
