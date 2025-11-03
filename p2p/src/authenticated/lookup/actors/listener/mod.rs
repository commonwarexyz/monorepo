use commonware_cryptography::Signer;
use commonware_stream::Config as StreamConfig;
use governor::Quota;
use std::net::SocketAddr;
use std::num::NonZeroU32;

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Info;
pub(in crate::authenticated) use ingress::Message;

/// Configuration for the listener actor.
pub struct Config<C: Signer> {
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub attempt_unregistered_handshakes: bool,
    pub max_concurrent_handshakes: NonZeroU32,
    pub allowed_handshake_rate_per_ip: Quota,
    pub allowed_handshake_rate_per_subnet: Quota,
}
