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
//!    [`Mailbox::stage_block`], or run a consensus [`Application`](crate::Application) as the
//!    engine's automaton through [`Inline`]. An engine whose application also reads activity
//!    reports to both through [`Reporters::from((marshal, application))`](crate::Reporters), and
//!    [`Service::relay`] gives it a [`Relay`] that broadcasts staged blocks.
//! 5. The application receives one [`Update::Block`] per block in [`OutputIndex`] order and
//!    acknowledges each once it has durably applied it. Indices are canonical: an output's index
//!    is the sum of the producer-chain heights once it commits, so it is the same on every node.
//!    Before that, it receives an [`Update::Final`] for each block a leader finality fact made
//!    final, as soon as the block is in local custody (see [Final blocks](#final-blocks)).
//! 6. [`ServiceHandle::abort`] stops marshal; [`ServiceHandle::join`] returns its first
//!    failure.
//!
//! # Actors
//!
//! ```text
//!   consensus --hints--> router --> synchronizer --commits--> catalog --> delivery --> app
//!                          \------------finality facts-------------------> delivery
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
//! - Delivery: owns the acknowledgement cursor and reports committed outputs to the application,
//!   and reports final blocks before they are ordered.
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
//! - [`Mailbox::floor_at`] serves the newest retained floor at or below an output index, which
//!   another node can install to resume at the same indices.
//! - [`Mailbox::prune`] drops what the newest floor at or below an output index makes obsolete,
//!   keeping that floor servable.
//!
//! # Final blocks
//!
//! Finality precedes ordering: a leader finality fact names every producer chain's final tip, and
//! every block at or below it is final, but the sweep can stop at a shortfall or an unsettled
//! chain and order those blocks in a later view. So the application can start work early, such
//! as warming storage, delivery reports each final block as an [`Update::Final`]:
//!
//! - Only final blocks are reported: blocks at or below a fact's final tip on their chain, and
//!   committed outputs. Proposals and DA-certified blocks above the final tips never are.
//! - Each chain reports oldest first, from above what delivery already reported or delivered on
//!   it, once local custody holds the block. Marshal does not fetch these blocks from peers for
//!   the report; a chain whose next block is missing waits until custody admits a block on that
//!   chain, a commit, or a fact.
//! - After a restart, each chain resumes from its height at the acknowledgement cursor, so every
//!   final block not yet delivered in the new run may be reported again, including outputs
//!   redelivered from that cursor. Blocks at or below an installed floor are never reported.
//! - Each chain reads at most [`Capacities::final_lookahead`] blocks ahead at a time, its oldest
//!   unreported final blocks, and slides that window forward as they are reported or delivered.
//!   So when a fact moves a chain's final tip far ahead, every final block up to the tip is still
//!   reported in order, unless ordered delivery reaches it first.
//! - The reports read local custody in small jobs that never wait for, or hold back, ordered
//!   delivery. While marshal runs, a block is never reported after its [`Update::Block`].
//!
//! [`OutputIndex`]: crate::types::OutputIndex

mod actors;
mod bodies;
mod config;
mod inline;
mod ledger;
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
pub use inline::Inline;
pub use mailbox::Mailbox;
pub use open::OpenError;
#[cfg(any(test, feature = "mocks"))]
pub(crate) use protocol::fuzz;
pub use relay::Relay;
pub use service::{Service, ServiceHandle, open};
pub use types::{Custody, Error, Failure, Families, Floor, LqcVerifier, MarshalProgress, Update};
pub use verifier::{InvalidLqc, SchemeVerifier};
pub use wire::BackfillKey;
