//! Recover certificates for every position in a fixed per-epoch range.
//!
//! Each [`Engine`] has one immutable epoch, inclusive global position range, and signing scheme.
//! The signing scheme is the sole source of the application namespace. The engine requests every
//! position in its range and signs when its scheme contains a local share. A verifier-only engine
//! can collect shares and recover certificates without signing. The application must return the
//! same digest for a position across clones and restarts. Shares are not durable; after restart, a
//! signing engine requests the canonical digest and signs it again. Certificates are journaled and
//! synced before reporting.
//! A position is an application-defined sequence number. It need not be a block height. For
//! example, an application that checkpoints every 1000 blocks can assign position `k` to the
//! checkpoint at height `1000k + 999`. Each epoch's length is then a multiple of 1000, so the
//! epoch's last block is a checkpoint. Discovering the newest certificate is the application's
//! responsibility.
//! The engine keeps a bounded window anchored at the lowest uncertified position. It returns
//! `Completed` only after the entire range is certified; shutdown returns `Stopped`. A durable
//! header binds the journal to its committee, epoch, and range. Replay revalidates each
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
//! decode, verify, archive, or route certificates. A resolver consumer decodes each response and
//! passes it to [`Mailbox::submit`] with the requested key. The engine checks the key, range, and
//! signature. The engine does not serve certificates to peers. A resolver producer serves them
//! from the application's archive.
//!
//! ## Retirement
//!
//! `Completed` means every certificate in the range is journaled and was passed to the reporter.
//! It does not mean the application archived them, because reporter feedback is ignored. Delete
//! the journal partition or release signing keys only after the application's archive durably
//! holds the complete range. A new engine with a deleted partition starts from an empty journal,
//! so the application must track retired epochs itself. Await an engine's handle before starting
//! another engine for the same namespace and epoch.

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
