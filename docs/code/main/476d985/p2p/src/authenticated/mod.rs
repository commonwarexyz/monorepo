//! Communicate with a fixed set of authenticated peers over encrypted connections.
//!
//! [discovery] operates under the assumption that peer addresses aren't known in
//! advance, and that they need to be discovered. Bootstrappers are used to
//! connect to the network and discover peers.
//!
//! [lookup] operates under the assumption that peer addresses are known in advance,
//! and that they can be looked up by their identifiers.

mod data;
pub mod discovery;
pub mod lookup;
mod mailbox;
pub use mailbox::Mailbox;
mod relay;
