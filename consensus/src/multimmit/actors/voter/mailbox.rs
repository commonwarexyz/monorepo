//! Inbound queues of the voter and the typed endpoints that feed them.
//!
//! The voter owns four queues, one per producer: resolution completions from the resolver,
//! observation cohorts from the ingress actor, verification completions from the verifier, and
//! diagnostic queries. Each queue is received separately so the voter can gate it by the core lane
//! it feeds, and each producer holds only its own endpoint, so a stopped producer closes its queue.

use crate::{
    multimmit::{
        actors::util::reliable_policy,
        machine::{IdentifiedArtifact, Inspection, ResolutionCompletion, VerificationCompletion},
        wire::Plane,
    },
    types::Round,
};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self, UnreliablePolicy},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::Metrics;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, num::NonZeroUsize, time::SystemTime};
use tracing::Span;

/// Resolver completions delivered to the voter.
pub(crate) enum Message<V: Variant, D: Digest> {
    /// One completion for a machine-issued resolution request.
    Resolution {
        /// The root span that owns terminal failures from this request.
        root: Span,
        /// The resolver's tracing span.
        span: Span,
        /// The round that issued the request.
        round: Round,
        /// The completion for the machine-issued request.
        completion: ResolutionCompletion<V, D>,
    },
}

reliable_policy!(impl<V: Variant, D: Digest> for Message<V, D>);

/// Best-effort diagnostic queries accepted by the voter.
pub(crate) enum Query<D: Digest> {
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

/// One bounded cohort of untrusted observations.
///
/// The ingress actor bounds these with explicit credits and stops admitting network traffic before
/// the queue can saturate, so an admitted artifact is not lost.
pub(crate) struct Observed<V: Variant, D: Digest> {
    /// Decoded, identified artifacts in observation order.
    pub(crate) artifacts: Vec<IdentifiedArtifact<V, D>>,
    /// Total canonical encoded length of the artifacts.
    pub(crate) bytes: usize,
    /// The plane every artifact in the cohort arrived on.
    pub(crate) plane: Plane,
    /// The ingress tracing span of the cohort.
    pub(crate) span: Span,
    /// When the ingress actor handed the cohort to the voter.
    pub(crate) forwarded_at: SystemTime,
}

impl<V: Variant, D: Digest> UnreliablePolicy for Observed<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        // Reject under backpressure: untrusted ingress is never buffered unboundedly.
        false
    }
}

/// One verification completion.
pub(crate) struct Completed<D: Digest> {
    /// The issuing job's tracing span.
    pub(crate) span: Span,
    /// The per-item verdicts.
    pub(crate) completion: VerificationCompletion<D>,
}

// Completions are bounded by the in-flight verification job ceiling and must not be lost.
reliable_policy!(impl<D: Digest> for Completed<D>);

/// The voter's inbound endpoints, one per producer.
///
/// Handing each producer only its own endpoint lets the voter observe that producer stopping.
pub(crate) struct Mailbox<V: Variant, D: Digest> {
    /// Resolution completions, sent by the resolver.
    pub(crate) resolutions: Resolutions<V, D>,
    /// Observation cohorts, offered by the ingress actor.
    pub(crate) observations: Observations<V, D>,
    /// Verification completions, sent by the verifier.
    pub(crate) completions: Completions<D>,
    /// Diagnostic queries.
    pub(crate) inspector: Inspector<D>,
}

/// The resolver's endpoint into the voter.
pub(crate) struct Resolutions<V: Variant, D: Digest> {
    sender: mailbox::Sender<Message<V, D>>,
}

impl<V: Variant, D: Digest> Clone for Resolutions<V, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<V: Variant, D: Digest> Resolutions<V, D> {
    /// Delivers one resolution completion.
    pub(crate) fn resolved(
        &self,
        root: Span,
        span: Span,
        round: Round,
        completion: ResolutionCompletion<V, D>,
    ) -> Feedback {
        self.sender.enqueue(Message::Resolution {
            root,
            span,
            round,
            completion,
        })
    }
}

/// The ingress actor's endpoint into the voter.
pub(crate) struct Observations<V: Variant, D: Digest> {
    sender: mailbox::UnreliableSender<Observed<V, D>>,
}

impl<V: Variant, D: Digest> Clone for Observations<V, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<V: Variant, D: Digest> Observations<V, D> {
    /// Offers one observation cohort; the voter rejects it when the queue is full.
    pub(crate) fn observed(&self, observed: Observed<V, D>) -> Unreliable<Feedback> {
        self.sender.enqueue(observed)
    }
}

/// The verifier's endpoint into the voter.
pub(crate) struct Completions<D: Digest> {
    sender: mailbox::Sender<Completed<D>>,
}

impl<D: Digest> Clone for Completions<D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<D: Digest> Completions<D> {
    /// Delivers one verification completion.
    pub(crate) fn completed(&self, completed: Completed<D>) -> Feedback {
        self.sender.enqueue(completed)
    }
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    /// Creates the voter's four inbound queues.
    ///
    /// The observation queue holds `observations` cohorts and every other queue holds `capacity`
    /// messages. `queues` labels the observation and completion queues; `context` labels the
    /// others.
    pub(crate) fn new<E: Metrics>(
        context: &E,
        queues: &E,
        capacity: NonZeroUsize,
        observations: NonZeroUsize,
    ) -> (Self, Inbox<V, D>) {
        let (resolutions, resolution_receiver) = mailbox::new(context.child("mailbox"), capacity);
        let (observations, observation_receiver) =
            mailbox::new_unreliable(queues.child("observations"), observations);
        let (completions, completion_receiver) =
            mailbox::new(queues.child("completions"), capacity);
        let (queries, query_receiver) = mailbox::new_unreliable(context.child("queries"), capacity);
        (
            Self {
                resolutions: Resolutions {
                    sender: resolutions,
                },
                observations: Observations {
                    sender: observations,
                },
                completions: Completions {
                    sender: completions,
                },
                inspector: Inspector { queries },
            },
            Inbox {
                resolutions: resolution_receiver,
                observations: observation_receiver,
                completions: completion_receiver,
                queries: query_receiver,
            },
        )
    }
}

/// A cloneable handle that reads the voter's diagnostic projection.
pub(crate) struct Inspector<D: Digest> {
    queries: mailbox::UnreliableSender<Query<D>>,
}

impl<D: Digest> Clone for Inspector<D> {
    fn clone(&self) -> Self {
        Self {
            queries: self.queries.clone(),
        }
    }
}

impl<D: Digest> Inspector<D> {
    /// Reads the machine's normalized diagnostic projection.
    ///
    /// Returns `None` when the voter is stopped or its query queue is full.
    pub(crate) async fn inspect(&self) -> Option<Inspection<D>> {
        let (responder, receiver) = oneshot::channel();
        if !self
            .queries
            .enqueue(Query::Inspect { responder })
            .accepted()
        {
            return None;
        }
        receiver.await.ok()
    }
}

/// The receiving side of the voter's inbound queues.
pub(crate) struct Inbox<V: Variant, D: Digest> {
    /// Resolution completions from the resolver.
    pub(crate) resolutions: mailbox::Receiver<Message<V, D>>,
    /// Observation cohorts from the ingress actor.
    pub(crate) observations: mailbox::UnreliableReceiver<Observed<V, D>>,
    /// Verification completions from the verifier.
    pub(crate) completions: mailbox::Receiver<Completed<D>>,
    /// Diagnostic queries.
    pub(crate) queries: mailbox::UnreliableReceiver<Query<D>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    #[test]
    fn observation_and_completion_queues_keep_their_engine_metric_names() {
        deterministic::Runner::default().start(|context| async move {
            let engine = context.child("engine");
            let voter_context = engine.child("voter");
            let (_mailbox, _inbox) = Mailbox::<MinPk, Sha256Digest>::new(
                &voter_context,
                &engine,
                NonZeroUsize::MIN,
                NonZeroUsize::MIN,
            );
            let encoded = context.encode();
            for name in [
                "engine_observations_backoff_total",
                "engine_completions_backoff_total",
                "engine_voter_mailbox_backoff_total",
                "engine_voter_queries_backoff_total",
            ] {
                assert!(
                    encoded.lines().any(|line| line.starts_with(name)),
                    "missing {name}: {encoded}"
                );
            }
            assert!(!encoded.contains("engine_voter_observations"));
            assert!(!encoded.contains("engine_voter_completions"));
        });
    }
}
