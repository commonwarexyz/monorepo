//! The async boundary around the serial Multimmit core.
//!
//! The voter owns one core on one dedicated runtime task. The core is the only production
//! owner of the private synchronous reducer; it serializes bounded persistence, completion, timer,
//! resolver, and observation lanes before entering the reducer. The voter executes returned
//! capabilities through
//! thin typed ports and never derives a protocol fact, substitutes a subject, or retires a durable
//! publication on its own authority.
//!
//! ```text
//!                          dedicated task
//! batcher completion ---------+
//! timer ----------------------+-> CoreState -> reducer -> capabilities
//! resolver result ------------+       ^                    |
//! peer observation -----------+       |                    v
//! Lane::PersistenceCompletion +       |             inline egress/retry
//!                                  completions      bounded async tasks
//!
//! shared tasks: build[reserved 1], custody[pipeline depth], validate[global and per-chain caps]
//!               crypto[signing and aggregation capacity]
//! storage task: append -> one covering sync -> exact prefix acknowledgements
//! actor: resolver/serving
//! ```
//!
//! A local application build has a dedicated permit. Completed builds enter a bounded prepared
//! suffix, and their custody checks run concurrently outside remote-validation capacity. Pending
//! remote validations stay in per-producer queues under one rotating cursor; there is no actor per
//! chain. Signing and critical aggregation reserve worker and completion capacity that bulk crypto
//! cannot consume. Every exhausted core quantum explicitly reschedules through the Commonware
//! runtime.
//!
//! Journal appends may continue behind one covering sync. Acknowledgements reenter through the
//! highest-weight lane in exact prefix order; later staged work does not overtake them. Private
//! cryptographic and application work may overlap the sync, while signature-bearing effects remain
//! behind the reducer's durable exposure floor.
//!
//! Multimmit uses the shared [`crate::Automaton`] and [`crate::Relay`] application boundary. There
//! is no certification hook: the protocol has no notion of certifiability, and
//! [`crate::CertifiableAutomaton`] is deliberately incompatible with it.

mod actor;
mod egress;
mod journal;
mod metrics;
#[cfg(test)]
mod tests;

use crate::{
    multimmit::{
        machine::{CoreState, Inspection, ResolutionCompletion},
        storage::{Recovered, SafetyJournal},
    },
    types::Round,
};
pub(crate) use actor::{Actor, Config};
use commonware_actor::mailbox::{Policy, UnreliablePolicy};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::{Metrics, Storage};
use commonware_utils::channel::oneshot;
use std::{
    collections::VecDeque,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::Span;

/// Control messages accepted by the voter.
pub enum Message<V: Variant, D: Digest> {
    /// One exact resolution completion from the resolver executor.
    Resolution {
        /// The executor's tracing span.
        span: Span,
        /// The round that issued the request.
        round: Round,
        /// The exact completion for a machine-issued request.
        completion: ResolutionCompletion<V, D>,
    },
}

impl<V: Variant, D: Digest> Policy for Message<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Best-effort diagnostic queries accepted by the voter.
pub enum Query<D: Digest> {
    /// Read the machine's normalized diagnostic projection.
    Inspect {
        /// Receives the current [`Inspection`].
        responder: oneshot::Sender<Inspection<D>>,
    },
}

impl<D: Digest> UnreliablePolicy for Query<D> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Local endpoints for protocol control and best-effort diagnostics.
pub struct Mailbox<V: Variant, D: Digest> {
    /// Reliable protocol-control endpoint.
    pub control: commonware_actor::mailbox::Sender<Message<V, D>>,
    /// Bounded best-effort diagnostic endpoint.
    pub queries: commonware_actor::mailbox::UnreliableSender<Query<D>>,
}

/// How the voter starts its machine.
pub(crate) enum Startup<E: Storage + Metrics, H: Hasher, V: Variant> {
    /// Start a fresh machine for a new epoch over an empty journal.
    Fresh {
        /// The not-yet-started protocol owner.
        core: Box<CoreState<H, V>>,
        /// The epoch's empty safety journal.
        journal: Box<SafetyJournal<E, V, H::Digest>>,
    },
    /// Resume from recovered durable state.
    Recovered(Box<Recovered<E, H, V>>),
}

/// Bounded execution and retry policy for the voter.
#[derive(Copy, Clone, Debug)]
pub struct VoterLimits {
    /// Maximum concurrently executing application jobs.
    pub inflight_application: NonZeroUsize,
    /// Initial publication retry backoff.
    pub retry_initial: Duration,
    /// Maximum publication retry backoff.
    pub retry_ceiling: Duration,
    /// Interval between Relay refreshes, periodic metrics, and producer-stall checks.
    pub heartbeat: Duration,
    /// Acknowledged journal events between checkpoint snapshots.
    pub checkpoint_interval: NonZeroU64,
}
