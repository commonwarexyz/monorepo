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
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
use commonware_runtime::{Metrics, Supervisor};
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
pub(crate) struct Observed<P: PublicKey, V: Variant, D: Digest> {
    /// Decoded, identified artifacts in observation order, each with its authenticated source.
    pub(crate) artifacts: Vec<(P, IdentifiedArtifact<V, D>)>,
    /// Total canonical encoded length of the artifacts.
    pub(crate) bytes: usize,
    /// The plane every artifact in the cohort arrived on.
    pub(crate) plane: Plane,
    /// The ingress tracing span of the cohort.
    pub(crate) span: Span,
    /// When the ingress actor handed the cohort to the voter.
    pub(crate) forwarded_at: SystemTime,
}

impl<P: PublicKey, V: Variant, D: Digest> UnreliablePolicy for Observed<P, V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        // Reject under backpressure: untrusted ingress is never buffered unboundedly.
        false
    }
}

/// One verification completion.
pub(crate) struct Completed<V: Variant, D: Digest> {
    /// The issuing job's tracing span.
    pub(crate) span: Span,
    /// The per-item verdicts.
    pub(crate) completion: VerificationCompletion<V, D>,
}

// Completions are bounded by the in-flight verification job ceiling and must not be lost.
reliable_policy!(impl<V: Variant, D: Digest> for Completed<V, D>);

/// Typed endpoints for every queue the voter receives.
pub(crate) struct Mailbox<P: PublicKey, V: Variant, D: Digest> {
    resolutions: Resolutions<V, D>,
    observations: Observations<P, V, D>,
    completions: Completions<V, D>,
    inspector: Inspector<D>,
}

impl<P: PublicKey, V: Variant, D: Digest> Clone for Mailbox<P, V, D> {
    fn clone(&self) -> Self {
        Self {
            resolutions: self.resolutions.clone(),
            observations: self.observations.clone(),
            completions: self.completions.clone(),
            inspector: self.inspector.clone(),
        }
    }
}

/// The voter's endpoints split by producer.
pub(crate) struct Endpoints<P: PublicKey, V: Variant, D: Digest> {
    /// Resolution completions, sent by the resolver.
    pub(crate) resolutions: Resolutions<V, D>,
    /// Observation cohorts, offered by the ingress actor.
    pub(crate) observations: Observations<P, V, D>,
    /// Verification completions, sent by the verifier.
    pub(crate) completions: Completions<V, D>,
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
pub(crate) struct Observations<P: PublicKey, V: Variant, D: Digest> {
    sender: mailbox::UnreliableSender<Observed<P, V, D>>,
}

impl<P: PublicKey, V: Variant, D: Digest> Clone for Observations<P, V, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Observations<P, V, D> {
    /// Offers one observation cohort; the voter rejects it when the queue is full.
    pub(crate) fn observed(&self, observed: Observed<P, V, D>) -> Unreliable<Feedback> {
        self.sender.enqueue(observed)
    }
}

/// The verifier's endpoint into the voter.
pub(crate) struct Completions<V: Variant, D: Digest> {
    sender: mailbox::Sender<Completed<V, D>>,
}

impl<V: Variant, D: Digest> Clone for Completions<V, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<V: Variant, D: Digest> Completions<V, D> {
    /// Delivers one verification completion.
    pub(crate) fn completed(&self, completed: Completed<V, D>) -> Feedback {
        self.sender.enqueue(completed)
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Mailbox<P, V, D> {
    /// Creates the voter's four inbound queues, each bounded by `capacity`.
    ///
    /// `queues` labels the observation and completion queues; `context` labels the others.
    pub(crate) fn new<E: Supervisor + Metrics>(
        context: &E,
        queues: &E,
        capacity: NonZeroUsize,
    ) -> (Self, Inbox<P, V, D>) {
        let (resolutions, resolution_receiver) = mailbox::new(context.child("mailbox"), capacity);
        let (observations, observation_receiver) =
            mailbox::new_unreliable(queues.child("observations"), capacity);
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

    /// Splits the mailbox into one endpoint per producer.
    ///
    /// Handing each producer only its own endpoint lets the voter observe that producer stopping.
    pub(crate) fn into_endpoints(self) -> Endpoints<P, V, D> {
        Endpoints {
            resolutions: self.resolutions,
            observations: self.observations,
            completions: self.completions,
            inspector: self.inspector,
        }
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
pub(crate) struct Inbox<P: PublicKey, V: Variant, D: Digest> {
    /// Resolution completions from the resolver.
    pub(crate) resolutions: mailbox::Receiver<Message<V, D>>,
    /// Observation cohorts from the ingress actor.
    pub(crate) observations: mailbox::UnreliableReceiver<Observed<P, V, D>>,
    /// Verification completions from the verifier.
    pub(crate) completions: mailbox::Receiver<Completed<V, D>>,
    /// Diagnostic queries.
    pub(crate) queries: mailbox::UnreliableReceiver<Query<D>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn observation_and_completion_queues_keep_their_engine_metric_names() {
        deterministic::Runner::default().start(|context| async move {
            let engine = context.child("engine");
            let voter_context = engine.child("voter");
            let (_mailbox, _inbox) = Mailbox::<ed25519::PublicKey, MinPk, Sha256Digest>::new(
                &voter_context,
                &engine,
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
