//! P2P implementation of the compact QMDB sync resolver.
//!
//! Implements [`commonware_storage::qmdb::sync::compact::Resolver`] over
//! [`commonware_resolver::p2p::Engine`]. Use this for compact-storage QMDBs
//! that fetch one authenticated frontier state instead of replaying operations.

mod actor;
pub use actor::{Actor, Config};

mod handler;

mod mailbox;
pub use mailbox::{Mailbox, ResponseDropped};
