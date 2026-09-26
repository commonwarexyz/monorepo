//! Recover certificates for every position in a fixed per-epoch range.
//!
//! Each [`Engine`] has one immutable epoch, inclusive global position range, and signing scheme.
//! The signing scheme is the sole source of the application namespace. The engine requests every
//! position in its range and signs when its scheme contains a local share. A verifier-only engine
//! can collect shares and recover certificates without signing. The application must return the
//! same digest for a position across clones and restarts. Shares are not durable; after restart, a
//! signing engine requests the canonical digest and signs it again. Certificates are journaled and
//! synced before reporting.
//! The engine keeps a bounded window anchored at the lowest uncertified position. It returns
//! `Completed` only after the entire range is certified; shutdown returns `Stopped`. A durable
//! header binds the journal to its committee, epoch, range, and window. Replay revalidates each
//! certificate because the header cannot fingerprint all scheme verification material.
//!
//! ## Epoch-independent signatures
//!
//! An [`Item`](types::Item) signature covers only its position and digest. Acknowledgments travel
//! over an epoch-specific channel, which associates each share with the engine's epoch. The epoch
//! in an exported [`Certificate`](types::Certificate) is unsigned lookup metadata. Before
//! verification, a consumer must derive the expected epoch, inclusive position range, and signing
//! scheme from authenticated history. [`Certificate::verify_for`](types::Certificate::verify_for)
//! checks the epoch and range before verifying the signature.
//!
//! Active engines can schedule missing certificates through a shared [`RecoveryCoordinator`]. The
//! coordinator bounds and deduplicates logical resolver requests across engine scopes; it does not
//! decode, verify, archive, or route certificates. Resolver consumers deliver recovered
//! certificates through [`Mailbox`], which applies the engine's range and signature checks.
//! Archiving the complete range and retiring the engine and its journal remain
//! application/orchestrator responsibilities.

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::{CertificateOutcome, Engine, EngineOutcome, Mailbox, Stopper};
        mod journal;
        pub use journal::{Journal, JournalConfig, JournalError, JournalIdentity};
        mod metrics;
        mod recovery;
        pub use recovery::{Recoverer, Recovery, RecoveryCoordinator};

        #[cfg(test)]
        pub mod mocks;
    }
}

#[cfg(test)]
mod tests;
