//! Multimmit consensus for independently produced application-block chains.
//!
//! Multimmit separates dissemination from agreement. Every producer chain belongs to one committee
//! member, which extends it at its own cadence by signing transaction-block headers. Validators
//! vote continuously: each vote names, per chain, the tip of the path it endorses, and a validator
//! sends its growing vote as compact updates. A view ends when every chain is capped or declared
//! final; `n - f` final votes form a V-QC (view quorum certificate) whose tips, the highest
//! blocks `n - 3f` of them endorse, extend the previous view's. One scheduled leader per view names
//! the previous V-QC and its tips-history commitment, and `n - f` votes for that leader block form
//! an L-QC (leader quorum certificate) that certifies the tips of every view below it.
//!
//! ```text
//! participant 0:  genesis -> tx 1 -> tx 2 -> ... --+
//! participant 1:  genesis -> tx 1 -> tx 2 -> ... --+-- signed headers, endorsed by vote updates
//! participant 2:  genesis -> tx 1 -> tx 2 -> ... --+              |
//!                                                               v
//! view 1 V-QC -> view 2 V-QC -> view 3 V-QC -> ... -> per-view tips -> one global order
//!                     |               |
//!               leader block    leader block + n - f votes = L-QC
//! ```
//!
//! Consensus agrees on signed headers, not bodies, so its traffic does not grow with payload size.
//! It reports per-view agreement facts (the resolved tips of each view and the progress of the
//! open one) and finality certificates; [`marshal`] turns them into one deterministic order across
//! chains, fetches bodies, and delivers them. The protocol follows the counted-views Multimmit
//! specification, and [Terminology](docs::state_machine#terminology) defines the terms these docs
//! use.
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
//! consensus store, and builds every actor; [`Engine::start`] spawns them on the network planes.
//! The supported end-to-end construction is the
//! [log-multimmit example](https://github.com/commonwarexyz/monorepo/blob/main/examples/log-multimmit/src/node.rs)
//! application.
//!
//! # Application Contract
//!
//! Multimmit uses the shared [`crate::Automaton`], [`crate::Relay`], and [`crate::Reporter`]
//! boundary. Every producer builds one block every `theta`, an interval the engine derives from the
//! measured delay: at each slot the engine calls [`crate::Automaton::propose`] for its chain's
//! next height, and the application answers at once with whatever it has to include, possibly an
//! empty body, which still takes the height. [`crate::Automaton::verify`] is the custody fence for
//! full acceptance: returning `true` promises the body is valid, locally available, and
//! reconstructible after a crash. A validator may also adopt a header without a verdict once
//! `alpha` validators endorse it; the body is then fetched in the background, and delivery waits
//! for it. [`crate::Relay`] asks the attached application to disseminate a transaction header by
//! its digest, and the [`crate::Reporter`] receives the agreement facts in [`types::Activity`].
//! Activities are best-effort and never gate consensus.
//!
//! # Fault Model and Recovery
//!
//! For a committee of `n` validators, Multimmit derives `f = floor((n - 1) / 5)` and assumes at
//! most `f` Byzantine validators, hence `n >= 5f + 1`. Beyond `f` the node makes no safety,
//! liveness, or recovery guarantees; resource limits still hold.
//!
//! Durable signing history is part of a validator's identity. A validator must never restart with
//! empty storage under the same epoch key, which could authorize a conflicting statement. Recovery
//! needs the consensus checkpoint and journal suffix; a node that has lost them joins a new epoch
//! under a new key.
//!
//! # Deployment
//!
//! As in [`crate::simplex`], network channel quotas and backlogs are part of the synchrony model.
//! Each plane's per-peer quota must keep aggregate Byzantine ingress below the node's sustained
//! decode and verification capacity, and each backlog must absorb the permitted burst. Channels
//! drop under backpressure, so correct senders retry protocol messages until they are admitted.
//! View timers follow the measured delay and production rate; [`config::Tuning::timer_ceiling`]
//! caps them as a backstop and must exceed the deployment's post-GST message delay by a wide
//! margin.
//!
//! The committee is fixed for an epoch, and Multimmit defines no in-band reconfiguration. The epoch
//! in [`config::Parameters`] is bound into every signed statement and every chain's genesis
//! object: a deployment changes the committee by starting the next epoch under a new label, and
//! nothing unfinalized carries across.
//!
//! # Finality and Delivery
//!
//! A block is final once every correct log must contain it: when `n - f` validators endorse it
//! within the window of a view whose base is already resolved, or when it lies at or below a
//! resolved view's tips. An L-QC
//! together with the [`types::HistoryRecord`] opening its leader block's commitment is a portable
//! certificate of that. Consensus keeps no delivery cursor; [`marshal`] orders finalized blocks
//! across chains, retrieves their bodies, and delivers them to the application. [`Inspection`] is
//! for diagnostics only.
//!
//! # Further Reading
//!
//! - [`docs::state_machine`]: terminology, state, transitions, recovery, invariants, and resource
//!   bounds.
//! - [`docs::properties`]: deviations from the specification, each property with its owner and
//!   evidence, and the mapping from the specification to the code.
//! - [`docs::decisions`]: implementation decisions and the protocol issues found while
//!   implementing the specification.
//! - [`marshal`]: ordering, block custody, and delivery.
//! - [`scheme`]: the signatures behind headers, votes, and certificates.

pub mod config;
pub mod scheme;
pub mod types;

pub use types::{Artifact, ArtifactId, ViewProof};

/// Design documents.
pub mod docs {
    pub mod state_machine {
        #![doc = include_str!("docs/STATE_MACHINE.md")]
    }
    pub mod properties {
        #![doc = include_str!("docs/PROPERTIES.md")]
    }
    pub mod decisions {
        #![doc = include_str!("docs/DECISIONS.md")]
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
        #[cfg(any(test, feature = "mocks"))]
        #[cfg_attr(
            not(test),
            allow(dead_code, reason = "the fuzz entry point uses a subset of the campaigns")
        )]
        mod twins;
        #[cfg(test)]
        pub(crate) mod testing;
        #[cfg(test)]
        mod tests;
        #[cfg(feature = "mocks")]
        #[doc(hidden)]
        pub mod test_utils;
        mod wire;

        pub use actors::WAN_LATENCY;
        pub use engine::{
            Config, Engine, Inspector, Planes, Running, Stopped, critical_threads,
        };
        pub use machine::{
            ChainProgress, DeclarationCounts, DeclarationRule, Inspection, ProducerProgress,
            ReplayError, SnapshotReason, TransitionReason, ViewEnd, ViewEnds,
        };
        pub use storage::{CoreInitializationError, JournalError, OpenError, SnapshotError};
    }
}
