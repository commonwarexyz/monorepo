//! Durable application-block custody and ordered delivery for Multimmit.
//!
//! Multimmit agrees on complete transaction-block header digests while keeping opaque application
//! bodies outside consensus. This module owns those complete blocks, reconstructs the order
//! authenticated by finalized leader proofs, and delivers them with explicit acknowledgements.
//!
//! # Data flow
//!
//! The public mailbox admits locally produced and received blocks into temporary custody and
//! accepts best-effort consensus activity. The synchronizer verifies each reported leader proof,
//! reconstructs the finalized producer-chain segments, and resolves only exact artifacts missing
//! from local custody. Producer ancestry is walked concurrently; once exact block references are
//! known, missing bodies share a globally bounded fetch pool before being merged into Multimmit's
//! canonical dense order.
//!
//! The catalog is the sole owner of mutable storage. Prunable finalized storage keeps each body in
//! its producer-chain custody archive and appends only its authenticated header and encoded length.
//! Immutable finalized storage promotes the complete block and then reclaims temporary candidates.
//! Catalog-issued custody tokens carry only authenticated headers and encoded lengths, so ordering
//! performs no body reads. Post-checkpoint delivery and immutable promotion receive bounded
//! reference-counted bodies when they remain hot and otherwise read exact bodies from custody.
//!
//! # Durability and delivery
//!
//! Staged block admission returns a custody token immediately, allowing adjacent admissions to
//! share one temporary-storage synchronization. A token completes only after its exact body is
//! crash-recoverable. Publication then synchronizes the finalized archives before publishing its
//! checkpoint. The checkpoint is therefore the only visible finalized cut: after a crash, an output
//! is either absent or recoverable with its complete body. Once that checkpoint is durable, the
//! catalog offers the same reference-counted bodies to delivery. Under mailbox pressure,
//! notifications retain a bounded hot prefix and the newest committed cursor; delivery materializes
//! any omitted bodies from the authoritative finalized layout.
//!
//! Delivery emits a dense stream beginning immediately after the durable acknowledgement cursor.
//! Several [`Update`]s may be in flight at once. Contiguous [`commonware_utils::Acknowledgement`]
//! completions share one cursor synchronization, and only that durable cursor suppresses crash
//! redelivery. Installing a verified floor replaces the durable generation, then resets the
//! pending delivery window and generation-scoped in-memory hints before returning.

mod actors;
mod config;
mod mailbox;
mod protocol;
mod storage;
#[cfg(test)]
mod tests;
mod types;
mod wire;

pub use actors::{
    resolver::Subscriber as ResolverSubscriber,
    service::{ResolverBridge, Running, Service, open},
    synchronizer::LqcVerifier,
};
pub use config::{ArchiveConfig, ArchiveMode, Config, ConfigError, Floor, Start};
pub use mailbox::{Custody, Error, FloorCheckpoint, Mailbox, Progress, Prune};
pub use types::{OutputIndex, Update};
pub use wire::Key as ResolverKey;
