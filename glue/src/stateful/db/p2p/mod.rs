//! P2P implementation of the QMDB sync resolver.
//!
//! Implements [`commonware_storage::qmdb::sync::resolver::Resolver`] over
//! [`commonware_resolver::p2p::Engine`], fetching operations from peers and
//! serving local operations in response to incoming requests.
//!
//! - [`Mailbox`]: client-facing handle that the QMDB sync engine calls to
//!   fetch operations. Each call is multiplexed through the P2P resolver
//!   engine so that duplicate requests share a single network round-trip.
//! - [`Actor`]: service loop that bridges the [`Mailbox`] with the P2P
//!   engine, dispatches fetches, fans out deliveries to waiting callers,
//!   and serves produce requests from the local database.

mod actor;
pub use actor::{Actor, Config};

mod mailbox;
pub use mailbox::{Mailbox, ResponseDropped};

mod handler;

mod metrics;
