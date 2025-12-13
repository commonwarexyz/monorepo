//! Chain application logic (block production and verification).

mod actor;
mod handle;
mod message;
mod store;

pub use actor::Application;
pub use handle::Handle;
pub(crate) use message::ControlMessage;

#[derive(Clone, Copy, Debug)]
pub struct BlockCodecCfg {
    pub max_txs: usize,
    pub max_calldata_bytes: usize,
}
