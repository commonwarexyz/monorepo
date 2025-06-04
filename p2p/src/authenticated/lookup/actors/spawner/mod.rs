pub mod actor;
pub mod ingress;

pub use actor::Actor;
pub use ingress::Mailbox;

pub struct Config {
    pub mailbox_size: usize,
    pub max_peer_set_size: usize,
    pub peer_gossip_max_count: usize,
}
