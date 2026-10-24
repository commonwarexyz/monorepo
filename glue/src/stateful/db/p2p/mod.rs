//! P2P resolver for QMDB state sync.
//!
//! `p2p` implements [`commonware_storage::qmdb::sync::Source`] over
//! [`commonware_resolver::p2p::Engine`]: it fetches state sync data from peers and serves peers
//! from a local database.
//!
//! - [`Mailbox`]: the [`Source`](commonware_storage::qmdb::sync::Source) a QMDB sync engine
//!   fetches from. Concurrent requests for the same key share one network fetch.
//! - [`Actor`]: serves peer requests from the attached database and checks that peer responses
//!   decode and match their requests.
//!
//! A response that fails to decode, or that does not match its request, is reported invalid, and
//! the resolver blocks the sender and retries. Callers judge the validity of every other
//! response, and a rejection has the same effect. Serving is best effort: a peer request goes
//! unanswered when no database is attached, when it asks for more than
//! [`Config::max_serve_ops`] operations, when the database cannot serve it, or when the actor is
//! overloaded.
//!
//! # Message Sizes
//!
//! [`Actor`] halves the operations in a response until it fits the sender's
//! [`max_message_size`](commonware_p2p::LimitedSender::max_message_size) with resolver framing,
//! or holds one operation, and the requester fetches the rest later. A single-operation or
//! boundary response is sent whole, so the sender must admit [`boundary_size`] for the largest
//! operation. Fold it into the P2P `max_message_size`, wrapped in
//! [`Prefixed`](commonware_p2p::utils::mux::Prefixed) when the resolver runs on a
//! [`Muxer`](commonware_p2p::utils::mux::Muxer) subchannel. A larger response panics in p2p.

mod actor;
pub use actor::{Actor, Config, boundary_size};

mod mailbox;
pub use mailbox::{Mailbox, ResponseDropped};

mod handler;

mod metrics;
