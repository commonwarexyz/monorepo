//! Recover certificates for every position in a fixed per-epoch range.
//!
//! Each [`Engine`] has a fixed epoch, signing scheme, and inclusive range of global positions.
//! The signing scheme defines the application namespace. The engine asks the application for a
//! digest for every position in its range. It signs if the scheme holds a local share. A
//! verifier-only engine collects shares and recovers certificates without signing. The application
//! must return the same digest for a position across clones and restarts. Shares are not saved.
//! After a restart, a signing engine asks for the digest and signs it again. The engine writes
//! certificates to its journal and syncs them before reporting them.
//!
//! A position is an application-defined sequence number. It need not be a block height. For
//! example, an application that checkpoints every 1000 blocks can assign position `k` to the
//! checkpoint at height `1000k + 999`. If that application also starts each epoch at a multiple
//! of 1000 and makes each epoch's length a multiple of 1000, the epoch's last block is a
//! checkpoint. Discovering the newest certificate is the application's responsibility.
//!
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
//! Epochs that share verification keys must use disjoint global position ranges. A threshold
//! key keeps the same verification identity across reshares.
//!
//! Active engines recover missing certificates through a shared [`RecoveryCoordinator`]. The
//! coordinator bounds and deduplicates logical resolver requests across engine scopes and routes
//! each response to the engine that requested it. Configure the resolver with the coordinator's
//! [`Consumer`], then start the coordinator with the resolver's mailbox. [`Engine::new`] registers
//! the engine's recovery namespace and epoch, and the registration lasts until the engine is
//! dropped. Only one engine can hold a scope at a time. Each engine decodes responses with its own
//! bounded `certificate_codec_config()` and checks the key, range, and signature. Engines do not
//! serve certificates to peers. A resolver producer serves them from the application's archive.
//!
//! ## Retirement
//!
//! `Completed` means every certificate in the range is journaled and was passed to the reporter.
//! It does not mean the application archived them, because reporter feedback is ignored. Delete
//! the journal partition or release signing keys only after the application's archive durably
//! holds the complete range. A new engine with a deleted partition starts from an empty journal,
//! so the application must track retired epochs itself. Await an engine's handle before creating
//! another engine for the same namespace and epoch.
//! If the archive is incomplete after `Completed`, keep the partition and restart the engine on
//! it to report every journaled certificate again.
//!
//! ## Example
//!
//! `consensus/examples/aggregation_lifecycle.rs` runs two finite epochs with a shared
//! [`RecoveryCoordinator`], a resolver that serves an archive, journal retirement, and a restart:
//!
//! ```text
//! cargo run -p commonware-consensus --example aggregation_lifecycle
//! ```

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
        pub use recovery::{
            Consumer, Fetcher, Recoverer, Recovery, RecoveryCoordinator, Registration,
            RegistrationError,
        };
    }
}

#[cfg(test)]
mod tests;
