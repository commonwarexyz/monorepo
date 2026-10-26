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
//! [`Actor`] fetches and serves through a resolver. The resolver frames each sync request and
//! response:
//!
//! ```text
//! On a Muxer subchannel, every message is prefixed by:
//! +---------------------------+
//! | subchannel (varint, 1-10) |
//! +---------------------------+
//!
//! Request (tag 0):
//! +--------+---------+--------------+
//! | id (8) | tag (1) | sync request |
//! +--------+---------+--------------+
//!
//! Response (tag 1):
//! +--------+---------+----------------------+---------------+
//! | id (8) | tag (1) | length (varint, 1-5) | sync response |
//! +--------+---------+----------------------+---------------+
//!
//! Error (tag 2):
//! +--------+---------+
//! | id (8) | tag (1) |
//! +--------+---------+
//!
//! Sync request for operations (tag 0):
//! +---------+--------------------+---------------------+-------------+
//! | tag (1) | size (varint, 1-9) | start (varint, 1-9) | max ops (8) |
//! +---------+--------------------+---------------------+-------------+
//!
//! Sync request for a boundary (tag 1):
//! +---------+--------------------+---------------------+
//! | tag (1) | size (varint, 1-9) | start (varint, 1-9) |
//! +---------+--------------------+---------------------+
//!
//! Sync response with operations (tag 0):
//! +---------+-------+---------------------+-------------------------+
//! | tag (1) | proof | count (varint, 1-5) | operations (count x op) |
//! +---------+-------+---------------------+-------------------------+
//!
//! Sync response with a boundary (tag 1):
//! +---------+-------+----------------+---------------------+--------------------------------+
//! | tag (1) | proof | operation (op) | count (varint, 1-5) | pinned nodes (count x D::SIZE) |
//! +---------+-------+----------------+---------------------+--------------------------------+
//!
//! Proof:
//! +----------------------+--------------------------------+
//! | leaves (varint, 1-9) | inactive peaks (varint, 1-10)  |
//! +----------------------+--------------------------------+
//! | count (varint, 1-5)  | digests (count x D::SIZE)      |
//! +----------------------+--------------------------------+
//! ```
//!
//! An operations response carries at most [`Config::max_serve_ops`] operations, and a boundary
//! response carries one. `op` is the largest encoded operation and `D` is the database digest. A
//! peer decodes at most
//! [`MAX_PROOF_DIGESTS_PER_ELEMENT`](commonware_storage::merkle::MAX_PROOF_DIGESTS_PER_ELEMENT)
//! proof digests per operation and
//! [`MAX_PINNED_NODES`](commonware_storage::merkle::MAX_PINNED_NODES) pinned nodes.
//!
//! [`response_size`] adds these terms for the wider response and the 14 bytes of resolver framing.
//! Fold it into the network's `max_message_size`, wrapped in
//! [`Prefixed`](commonware_p2p::utils::mux::Prefixed) when the resolver runs on a
//! [`Muxer`](commonware_p2p::utils::mux::Muxer) subchannel.

mod actor;
pub use actor::{Actor, Config, response_size};

mod mailbox;
pub use mailbox::{Mailbox, ResponseDropped};

mod handler;

mod metrics;
