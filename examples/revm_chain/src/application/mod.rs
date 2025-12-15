//! Chain application logic (block production and verification).

mod actor;
mod block_sync;
mod handle;
mod message;
mod store;

pub use actor::Application;
pub use handle::Handle;
pub(crate) use message::ApplicationRequest;

#[derive(Clone, Copy, Debug)]
/// Decoding limits for blocks exchanged out-of-band.
pub struct BlockCodecCfg {
    pub max_txs: usize,
    pub max_calldata_bytes: usize,
}
