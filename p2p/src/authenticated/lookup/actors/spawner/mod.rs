pub mod actor;
pub mod ingress;

pub use actor::Actor;

pub struct Config {
    pub mailbox_size: usize,
}
