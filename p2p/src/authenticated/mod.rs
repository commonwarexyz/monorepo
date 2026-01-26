//! Communicate with a fixed set of authenticated peers over encrypted connections.
//!
//! [discovery] operates under the assumption that peer addresses aren't known in
//! advance, and that they need to be discovered. Bootstrappers are used to
//! connect to the network and discover peers.
//!
//! [lookup] operates under the assumption that peer addresses are known in advance,
//! and that they can be looked up by their identifiers.

use commonware_macros::stability_mod;

mod data;
stability_mod!(GAMMA, pub mod discovery);
stability_mod!(GAMMA, pub mod lookup);
mod mailbox;
pub use mailbox::{Mailbox, UnboundedMailbox};
mod relay;
