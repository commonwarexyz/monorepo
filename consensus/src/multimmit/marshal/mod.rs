//! Durable block custody and ordered delivery for Multimmit.
//!
//! Multimmit consensus agrees on block references and leaves block bodies to marshal. Marshal
//! keeps the complete blocks, reconstructs the canonical order from portable proofs, and reports
//! each block to the application in that order until the application acknowledges it.
//!
//! # Lifecycle
//!
//! 1. [`open`](fn@open) opens the stores and returns the [`Service`] and the [`Bridge`].
//! 2. The caller attaches the bridge to its network resolver, as consumer and producer.
//! 3. [`Service::start`] returns the [`Mailbox`] and the [`ServiceHandle`].
//! 4. Consensus reports its activity to the [`Mailbox`] (it is a [`Reporter`](crate::Reporter));
//!    producers stage their blocks with [`Mailbox::stage_block`], and [`Service::relay`] gives the
//!    engine a [`Relay`] that broadcasts them.
//! 5. The application receives one [`Update`] per block in [`OutputIndex`] order and acknowledges
//!    each once it has durably applied it. An output's index is the sum of the producer-chain
//!    heights once it is emitted, so it is the same on every node.
//! 6. [`ServiceHandle::abort`] stops marshal; [`ServiceHandle::join`] returns its failure.
//!
//! # What authorizes delivery
//!
//! Consensus reports every L-QC it verifies with the finality it proves and the tip-history
//! records placed since its last report. Marshal stores them, connects the records into the
//! finalized history, and derives the order from durable proofs only: the openings of the records
//! from the delivered cut to the strongest durable L-QC's leader history, then that L-QC's final
//! sweep. A block is delivered only when its proof, the parent-linked path from its authenticated
//! tip down to it, and its body are all durable. Placement reports only hint at fetches, and a
//! direct finality result never authorizes delivery.
//!
//! # Structure
//!
//! One task owns all state and makes every transition synchronously; storage, reads, certificate
//! verification and serving run as jobs on other tasks. Three stores hold everything durable:
//! blocks (a custody stream and a bulk stream over one index), proofs (L-QCs, records and cut
//! entries), and one progress record. A peer request never runs on the owner, and a custody cut
//! never waits behind fetched bytes.
//!
//! # State sync and pruning
//!
//! - [`Mailbox::floor_at`] serves the newest floor at or below an output index: an L-QC, its
//!   leader's history record, and the exact last block of every chain once its order is emitted.
//! - [`Mailbox::install_floor`] verifies a newer floor and resumes delivery after it.
//! - [`Mailbox::prune`] drops what the newest floor at or below an index makes obsolete, keeping
//!   that floor servable and every block the engine may still verify.
//!
//! A storage failure stops marshal; no store is used after a failed mutation.

mod config;
mod input;
mod ledger;
mod mailbox;
mod metrics;
mod relay;
mod service;
mod store;
#[cfg(test)]
mod tests;
mod types;
mod verifier;
mod wire;

pub use crate::multimmit::actors::util::Completion;
pub use config::{Config, ConfigError, Limits};
pub use input::Bridge;
pub use mailbox::Mailbox;
pub use relay::Relay;
pub use service::{OpenError, Service, ServiceHandle, open};
pub use types::{
    Custody, Error, Failure, Floor, LqcVerifier, MarshalProgress, OutputIndex, Update,
};
pub use verifier::{InvalidLqc, SchemeVerifier};
pub use wire::Key;

/// Decodes `input` as every marshal request and response a peer may send.
#[cfg(feature = "mocks")]
pub(crate) fn fuzz_wire(input: &[u8]) {
    wire::fuzz::exercise(input);
}
