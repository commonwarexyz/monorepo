//! Ordered, reliable broadcast across reconfigurable participants.
//!
//! # Concepts
//!
//! The system has two types of network participants: `sequencers` and `validators`. Their sets may
//! overlap and are defined by the current `epoch`, a monotonically increasing integer. This module
//! can handle reconfiguration of these sets across different epochs.
//!
//! Sequencers broadcast data. The smallest unit of data is a `chunk`. Sequencers broadcast `node`s
//! that contain a chunk and a threshold signature over the previous chunk, forming a linked chain
//! of nodes from each sequencer.
//!
//! Validators verify and sign chunks using partial signatures. These can be combined to recover a
//! threshold signature, ensuring a quorum verifies each chunk. The threshold signature allows
//! external parties to confirm that the chunk was reliably broadcast.
//!
//! Network participants persist any new nodes to a journal. This enables recovery from crashes and
//! ensures that sequencers do not broadcast conflicting chunks and that validators do not sign
//! them. "Conflicting" chunks are chunks from the same sequencer at the same height with different
//! payloads.
//!
//! # Design
//!
//! The core of the module is the [`Engine`]. It is responsible for:
//! - Broadcasting nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer’s chain
//! - Recovering threshold signatures from partial signatures for each chunk
//! - Notifying other actors of new chunks and threshold signatures

pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod manager;
        use manager::Manager;
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod tip;
    }
}
