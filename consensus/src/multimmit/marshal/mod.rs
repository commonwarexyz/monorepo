//! Durable block custody and ordered delivery for Multimmit.
//!
//! Multimmit consensus agrees on transaction-block header digests and leaves block bodies to
//! marshal. Marshal keeps the complete blocks, reconstructs the order that finalized leader
//! proofs authenticate, and reports each block to the application in that order until the
//! application acknowledges it.
//!
//! # Lifecycle
//!
//! 1. [`open`](fn@open) opens storage and returns the [`Service`] and the [`BackfillBridge`].
//! 2. The caller attaches the bridge to its network resolver.
//! 3. [`Service::start`] returns the [`Mailbox`] and the [`ServiceHandle`].
//! 4. Consensus reports activity to the [`Mailbox`]; producers stage their blocks with
//!    [`Mailbox::stage_block`]. An engine whose application also reads activity reports to both
//!    through [`Reporters::from((marshal, application))`](crate::Reporters), and
//!    [`Service::relay`] gives it a [`Relay`] that broadcasts staged blocks.
//! 5. The application receives one [`Update`] per block in [`OutputIndex`] order and
//!    acknowledges each once it has durably applied it.
//! 6. [`ServiceHandle::abort`] stops marshal; [`ServiceHandle::join`] returns its first
//!    failure.
//!
//! # Actors
//!
//! ```text
//!   consensus --hints--> router --> synchronizer --commits--> catalog --> delivery --> app
//!   producers --stage--> router -----------------------------> catalog --> promoter
//!                                         resolver <--> backfill --> catalog
//! ```
//!
//! - Router: runs staging, block subscriptions, floor installation and consensus hints for the
//!   public mailbox.
//! - Synchronizer: verifies leader proofs, reconstructs the finalized order, and commits it. It
//!   owns the scratch journals of its ancestry walks.
//! - Backfill: fetches missing L-QCs, histories and blocks from peers, and serves peers.
//! - Catalog: owns pending custody, finalized rows and the checkpoint.
//! - Delivery: owns the acknowledgement cursor and reports committed outputs to the application.
//! - Promoter: with immutable block retention, owns the immutable body archive and copies
//!   committed bodies into it.
//!
//! The catalog and delivery, and the catalog and the promoter, each need the other's mailbox, so
//! those mailboxes are created before the actors.
//!
//! # Durability
//!
//! - Custody: a staged block is recoverable after a crash once its [`Custody`] resolves.
//! - Checkpoint cut: a commit makes its finalized rows durable before it publishes the checkpoint
//!   that names them, so after a crash an output is either absent or recoverable with its body.
//! - Acknowledgement cursor: only delivery's durable cursor suppresses redelivery after a crash.
//!   Contiguous acknowledgements share one cursor sync.
//!
//! A storage failure stops the actor that owns the store, the supervisor then stops every actor,
//! and [`ServiceHandle::join`] returns the failure. No actor keeps using a store after a failed
//! mutation.
//!
//! # State sync
//!
//! - [`Start::Floor`] seeds a fresh namespace from a caller-authenticated [`Floor`].
//! - [`Mailbox::install_floor`] verifies and installs a newer floor while marshal runs, and
//!   resets delivery to it.
//! - [`Mailbox::prune`] then drops data that floor made obsolete, naming its generation in a
//!   [`Prune`].

mod actors;
mod bodies;
mod config;
mod mailbox;
mod open;
mod protocol;
mod relay;
mod service;
mod storage;
#[cfg(test)]
mod tests;
mod types;
mod verifier;
mod wire;

pub use crate::multimmit::actors::util::Completion;
pub use actors::backfill::{BackfillBridge, BackfillSubscriber};
pub use config::{
    ArchiveConfig, ArchiveMode, Capacities, Config, ConfigError, Limits, Retention, Start,
};
pub use mailbox::Mailbox;
pub use open::OpenError;
#[cfg(any(test, feature = "mocks"))]
pub(crate) use protocol::fuzz;
pub use relay::Relay;
pub use service::{Service, ServiceHandle, open};
pub use types::{
    Custody, Error, Failure, Families, Floor, LqcVerifier, MarshalProgress, OutputIndex, Prune,
    Update,
};
pub use verifier::{InvalidLqc, SchemeVerifier};
pub use wire::BackfillKey;
