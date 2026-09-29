//! Certify sparse, deterministic checkpoints of a chain, one epoch at a time.
//!
//! Each [`Engine`] aggregates the checkpoints of one immutable [`Schedule`](types::Schedule):
//! `last` and each lower height whose distance from `last` is a multiple of `interval`, down to
//! `first`. Every node must
//! derive the same schedule for an epoch, so every honest node signs the same heights. The engine
//! signs when its scheme contains a local share. A verifier-only engine can collect shares and
//! recover certificates without signing. The application must return the same digest for a
//! checkpoint across clones and restarts. Shares are not durable; after restart, a signing engine
//! requests the canonical digest and signs it again. Certificates are journaled and synced before
//! reporting.
//!
//! The engine aggregates up to `window` checkpoints concurrently, starting at the lowest
//! uncertified checkpoint at or above its floor. A node that state-syncs to a checkpoint sets the
//! floor above it and never certifies older checkpoints. The engine returns `Completed` after
//! every checkpoint at or above the floor is certified; shutdown returns `Stopped`. A durable
//! header binds the journal to its committee and schedule. The floor and window can change across
//! restarts. Replay revalidates each certificate because the header cannot fingerprint all scheme
//! verification material.
//!
//! ## Epoch-independent signatures
//!
//! An [`Item`](types::Item) signature covers only its position and digest. Acknowledgments travel
//! over an epoch-specific channel, which associates each share with the engine's epoch. The epoch
//! in an exported [`Certificate`](types::Certificate) is unsigned lookup metadata. Before
//! verification, a consumer must derive the expected schedule and signing scheme from
//! authenticated history. [`Certificate::verify_for`](types::Certificate::verify_for)
//! checks the epoch and checkpoint before verifying the signature.
//!
//! Active engines can schedule missing certificates through a shared [`RecoveryCoordinator`]. The
//! coordinator bounds and deduplicates logical resolver requests across engine scopes; it does not
//! decode, verify, archive, or route certificates. Resolver consumers deliver recovered
//! certificates through [`Mailbox`], which applies the engine's schedule and signature checks.
//! Archiving certificates and retiring the engine remain application/orchestrator
//! responsibilities. Every certificate is reported before the engine completes, so an
//! orchestrator retires a completed engine's journal by removing its configured partition.

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::{CertificateOutcome, Engine, EngineOutcome, Mailbox, Stopper};
        mod journal;
        mod metrics;
        mod recovery;
        pub use recovery::{Recoverer, Recovery, RecoveryCoordinator};
    }
}

#[cfg(test)]
mod tests;
