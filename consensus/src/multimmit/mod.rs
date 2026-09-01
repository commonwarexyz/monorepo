//! Multimmit consensus for independently produced application-block chains.
//!
//! Multimmit separates dissemination from ordering. An ordered subset of committee members owns
//! producer chains and disseminates new application blocks without waiting for a consensus leader.
//! Validators cast DA (data availability) votes for the blocks they hold and validated, and
//! `n - 2f` DA votes certify a chain position. One scheduled leader per view proposes a position on every
//! producer chain. A V-QC (view quorum certificate) lets the view exit and selects safe tips; an
//! L-QC (leader quorum certificate) finalizes the leader and one tip per chain. The resulting
//! leader chain authenticates the sparse facts from which a consumer derives one deterministic
//! order across all producer chains.
//!
//! ```text
//! participant 0:  genesis -> tx 1 -> tx 2 -> ... --+
//! participant 1:  genesis -> tx 1 -> tx 2 -> ... --+-- signed headers and DA facts
//! participant 2:  genesis -> tx 1 -> tx 2 -> ... --+              |
//!                                                               v
//! view 1 leader -> view 2 leader -> view 3 leader -> ... -> one global order
//!       |                 |                 |
//!       +-- votes/V-QC ---+-- votes/L-QC ---+
//! ```
//!
//! Consensus orders signed headers, not bodies, so its traffic does not grow with payload size, and
//! a slow or unavailable body delays only its own chain. The protocol follows the
//! [Multimmit specification](https://arxiv.org/abs/2607.21021v5), and
//! [Terminology](docs::state_machine#terminology) defines the terms these docs use.
//!
//! # Lifecycle
//!
//! ```text
//! Config -> Engine::open (validate, recover, build) -> Engine::start(Planes)
//!                                                             |
//!                                                             v
//!                                                      Running::ready
//!                                                             |
//!                                                 inspect / protocol work
//!                                                             |
//!                                                             v
//!                                                     abort -> Running::join
//! ```
//!
//! [`Engine::open`] validates the root [`Config`] before touching storage, recovers the node's
//! consensus store, and builds every actor; [`Engine::start`] spawns them on the four network
//! planes. The
//! [log-multimmit example](https://github.com/commonwarexyz/monorepo/blob/main/examples/log-multimmit/src/node.rs)
//! is the supported end-to-end construction: it registers the four engine planes and marshal's
//! resolver and broadcast channels, hands the engine
//! [`Reporters::from((marshal, application))`](crate::Reporters) and a [`marshal::Relay`], waits
//! for readiness, and joins the engine during shutdown.
//!
//! # Application Contract
//!
//! Multimmit uses the shared [`crate::Automaton`], [`crate::Relay`], and [`crate::Reporter`]
//! boundary. [`crate::Automaton::propose`] returns the commitment of a local payload, and
//! [`crate::Automaton::verify`] is the custody fence: returning `true` promises the payload is
//! valid, locally available, and reconstructible after a crash, while missing bytes keep it
//! pending and `false` means permanently invalid. A validator DA-votes for a block only after that
//! fence, which departs from the specification (see
//! [Deviations from the specification](docs::properties#deviations-from-the-specification)).
//! [`crate::Relay`] asks the attached application to disseminate a transaction header by its
//! complete header digest, and the [`crate::Reporter`] receives authenticated L-QCs, producer
//! headers, and history openings.
//! Certificates and leader blocks never reach `Automaton`; the resolver fetches missing view
//! proofs. There is no certification hook: the protocol has no notion of certifiability, and
//! [`crate::CertifiableAutomaton`] is deliberately incompatible with it. [`types::PathLimits`]
//! bounds how far a producer pipelines above its DA-certified anchor.
//!
//! # Fault Model and Recovery
//!
//! For a committee of `n` validators, Multimmit derives `f = floor((n - 1) / 5)` and assumes at
//! most `f` Byzantine validators, hence `n >= 5f + 1`. Beyond `f` the node makes no safety,
//! liveness, or recovery guarantees; resource limits still hold.
//!
//! Durable signing history is part of a validator's identity. A validator must never restart with
//! empty storage under the same epoch key, which could authorize a conflicting subject. Recovery
//! needs the consensus checkpoint and journal suffix together with the application's matching
//! durable state; a node that has lost them imports a trusted checkpoint holding both, or joins a
//! new epoch under a new key.
//!
//! # Deployment
//!
//! As in [`crate::simplex`], network channel quotas and backlogs are part of the synchrony model.
//! Each plane's per-peer quota must keep aggregate Byzantine ingress below the node's sustained
//! decode and verification capacity, and each backlog must absorb the permitted burst. Channels
//! drop under backpressure, so correct senders retry protocol messages until they are admitted.
//! [`config::Tuning::view_timeout`] must cover the specification's `2 * delta` deadline plus those
//! admission bounds, runtime scheduling, and verification.
//!
//! The committee is fixed for an epoch, and Multimmit defines no in-band reconfiguration. The epoch
//! in [`config::Parameters`] is a label bound into every signed subject: a deployment changes the
//! committee by stopping the engine and starting the next from new genesis facts under a new label,
//! and nothing unfinalized carries across.
//!
//! # Finality and Delivery
//!
//! Finality is chain-local: once a leader reaches `n - f` votes, the chosen prefix of each producer
//! chain is fixed. Consensus keeps no delivery cursor and exposes no ordered block stream;
//! [`marshal`] orders finalized blocks across chains, retrieves their bodies, and delivers them to
//! the application. [`Inspection`] is for diagnostics only.
//!
//! # Further Reading
//!
//! - [`docs::state_machine`]: terminology, state, transitions, recovery, invariants, and resource
//!   bounds.
//! - [`docs::properties`]: deviations from the specification, each property with its owner and
//!   evidence, and the mapping from the paper to the code.
//! - [`marshal`]: ordering, block custody, and delivery.
//! - [`scheme`]: the aggregate and threshold signatures behind votes and certificates.

pub mod config;
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
pub mod scheme;
pub mod types;

pub use types::{Artifact, ArtifactId, FinalityFact, FinalityId, PoolSummary, ViewProof};

/// Design documents.
pub mod docs {
    pub mod state_machine {
        #![doc = include_str!("docs/STATE_MACHINE.md")]
    }
    pub mod properties {
        #![doc = include_str!("docs/PROPERTIES.md")]
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod actors;
        pub(crate) mod algebra;
        mod engine;
        pub(crate) mod machine;
        pub mod marshal;
        #[cfg(any(test, feature = "mocks"))]
        pub mod mocks;
        pub(crate) mod storage;
        #[cfg(test)]
        mod tests;
        #[cfg(test)]
        pub(crate) mod testing;
        #[cfg(feature = "mocks")]
        #[doc(hidden)]
        pub mod test_utils;
        #[cfg(any(test, feature = "mocks"))]
        mod twins;
        mod wire;

        pub use actors::WAN_LATENCY;
        pub use engine::{Config, Engine, Inspector, Planes, Running, Stopped, critical_threads};
        pub use machine::{
            ChainProgress, Inspection, ProducerProgress, ReplayError, SnapshotReason,
            TransitionReason,
        };
        pub use storage::{CoreInitializationError, JournalError, OpenError, SnapshotError};
    }
}
