//! A recording marshal resolver with a scripted-delivery injection path.
//!
//! The source standard-marshal tests script backfill responses: their private
//! `RecordingResolver` holds the actor's resolver receiver, records every
//! fetch, and delivers a pre-armed payload to the next fetch, letting a test
//! hand the marshal exactly the notarized or finalized bytes it asked for.
//! That helper is `cfg(test)` inside `consensus/src`, but its mechanism is
//! public: [`handler::init`] builds the receiver/handler pair, and the
//! [`Handler`](handler::Handler) is the
//! [`Consumer`](commonware_resolver::Consumer) whose `deliver` enqueues the same
//! delivery message.
//!
//! This is the fuzz-crate equivalent, in three wirings:
//! - [`RecordingResolver::holding`]: no network, the source-faithful shape for
//!   unit tests.
//! - [`RecordingResolver::observing`]: forwards every request to the real P2P
//!   resolver mailbox and records what was accepted, so a prefix can assert
//!   the exact backfill requests while the node stays fully network-capable.
//! - [`RecordingResolver::injectable`] over [`init_injectable`]: the real P2P
//!   resolver is built around a handler pair the caller holds, so armed
//!   deliveries can be injected while the fetch, deliver, and serve paths all
//!   stay live for the fuzzing phase.
//!
//! A scenario arms a payload with
//! [`RecordingResolver::respond_to_next_fetch`] and awaits the actor's
//! validation verdict with [`RecordingResolver::wait_for_delivery_response`].

use crate::{marshal::end_to_end::twins::PublicKeyOf, simplex::Simplex};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_consensus::marshal::{
    mocks::harness::TEST_QUOTA,
    resolver::{
        handler::{self, Annotation, Key},
        p2p as resolver,
    },
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_p2p::simulated::Oracle;
use commonware_resolver::{Consumer as _, Delivery, Fetch, Resolver, TargetedResolver, p2p};
use commonware_runtime::{Metrics, Supervisor as _, deterministic};
use commonware_utils::{NZUsize, channel::oneshot, sync::Mutex, vec::NonEmptyVec};
use std::{sync::Arc, time::Duration};

/// A recorded backfill request: its peer-visible key and local annotation.
pub(crate) type FetchRecord = (Key<Sha256Digest>, Annotation);

/// A recorded targeted backfill request with its target peer set.
pub(crate) type TargetedRecord<P> = (Key<Sha256Digest>, Vec<PublicKeyOf<P>>);

/// A targeted fetch paired with its target peers, as the inner resolver takes it.
type TargetedFetch<P> = (
    Fetch<Key<Sha256Digest>, Annotation>,
    NonEmptyVec<PublicKeyOf<P>>,
);

/// Records fetches, optionally forwards them to the real P2P resolver, and
/// answers the next one with a pre-armed payload delivered through the held
/// handler as if a peer had responded.
pub(crate) struct RecordingResolver<P: Simplex> {
    fetches: Arc<Mutex<Vec<FetchRecord>>>,
    active: Arc<Mutex<Vec<FetchRecord>>>,
    targeted: Arc<Mutex<Vec<TargetedRecord<P>>>>,
    retains: Arc<Mutex<usize>>,
    auto_delivery: Arc<Mutex<Option<Bytes>>>,
    delivery_responses: Arc<Mutex<Vec<oneshot::Receiver<bool>>>>,
    handler: Option<handler::Handler<Sha256Digest>>,
    inner: Option<resolver::Mailbox<Sha256Digest, PublicKeyOf<P>>>,
}

impl<P: Simplex> Clone for RecordingResolver<P> {
    fn clone(&self) -> Self {
        Self {
            fetches: self.fetches.clone(),
            active: self.active.clone(),
            targeted: self.targeted.clone(),
            retains: self.retains.clone(),
            auto_delivery: self.auto_delivery.clone(),
            delivery_responses: self.delivery_responses.clone(),
            handler: self.handler.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<P: Simplex> RecordingResolver<P> {
    fn new(
        handler: Option<handler::Handler<Sha256Digest>>,
        inner: Option<resolver::Mailbox<Sha256Digest, PublicKeyOf<P>>>,
    ) -> Self {
        Self {
            fetches: Arc::new(Mutex::new(Vec::new())),
            active: Arc::new(Mutex::new(Vec::new())),
            targeted: Arc::new(Mutex::new(Vec::new())),
            retains: Arc::new(Mutex::new(0)),
            auto_delivery: Arc::new(Mutex::new(None)),
            delivery_responses: Arc::new(Mutex::new(Vec::new())),
            handler,
            inner,
        }
    }

    /// Build a network-less resolver and the receiver half the marshal actor
    /// consumes, mirroring the source helper's `holding` constructor. Exercised
    /// by unit tests; production nodes use the network-capable wirings.
    #[allow(dead_code)]
    pub(crate) fn holding(metrics: impl Metrics) -> (handler::Receiver<Sha256Digest>, Self) {
        let (receiver, handler) = handler::init(metrics, NZUsize!(100));
        (receiver, Self::new(Some(handler), None))
    }

    /// Wrap the real P2P resolver mailbox, recording accepted requests while
    /// forwarding them. No injection path.
    pub(crate) fn observing(inner: resolver::Mailbox<Sha256Digest, PublicKeyOf<P>>) -> Self {
        Self::new(None, inner.into())
    }

    /// Wrap the real P2P resolver mailbox built by [`init_injectable`],
    /// keeping its handler so armed deliveries can be injected.
    pub(crate) fn injectable(
        handler: handler::Handler<Sha256Digest>,
        inner: resolver::Mailbox<Sha256Digest, PublicKeyOf<P>>,
    ) -> Self {
        Self::new(Some(handler), inner.into())
    }

    fn record_fetch(&self, key: Key<Sha256Digest>, subscriber: Annotation, span: tracing::Span) {
        self.fetches.lock().push((key, subscriber));
        self.active.lock().push((key, subscriber));
        let Some(value) = self.auto_delivery.lock().take() else {
            return;
        };
        let mut handler = self
            .handler
            .clone()
            .expect("armed delivery requires an injection handler");
        let response = handler.deliver(
            Delivery {
                key,
                subscribers: NonEmptyVec::new((subscriber, span)),
            },
            value,
        );
        self.delivery_responses.lock().push(response);
    }

    /// Arm a payload for the next fetch, which is delivered through the held
    /// handler as if a peer had responded.
    pub(crate) fn respond_to_next_fetch(&self, value: Bytes) {
        assert!(
            self.handler.is_some(),
            "recording resolver has no injection handler"
        );
        let replaced = self.auto_delivery.lock().replace(value);
        assert!(
            replaced.is_none(),
            "recording resolver already has an automatic delivery"
        );
    }

    /// Await the actor's validation verdict for the most recent armed delivery.
    pub(crate) async fn wait_for_delivery_response(&self) -> bool {
        let response = self
            .delivery_responses
            .lock()
            .pop()
            .expect("delivery response missing");
        response.await.expect("delivery response sender dropped")
    }

    /// Every fetch ever issued, in order.
    pub(crate) fn fetches(&self) -> Vec<FetchRecord> {
        self.fetches.lock().clone()
    }

    /// Fetches still active after the latest retention.
    pub(crate) fn active_fetches(&self) -> Vec<FetchRecord> {
        self.active.lock().clone()
    }

    /// Targeted fetches with their target peer sets.
    #[allow(dead_code)]
    pub(crate) fn targeted(&self) -> Vec<TargetedRecord<P>> {
        self.targeted.lock().clone()
    }

    /// Whether no targeted fetch was ever issued.
    pub(crate) fn targeted_is_empty(&self) -> bool {
        self.targeted.lock().is_empty()
    }

    /// Number of retain calls observed.
    #[allow(dead_code)]
    pub(crate) fn retain_count(&self) -> usize {
        *self.retains.lock()
    }
}

impl<P: Simplex> Resolver for RecordingResolver<P> {
    type Key = Key<Sha256Digest>;
    type Subscriber = Annotation;

    fn fetch<F>(&mut self, fetch: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let fetch = fetch.into();
        let (key, subscriber, span) = (fetch.key, fetch.subscriber, fetch.span.clone());
        let feedback = match &mut self.inner {
            Some(inner) => inner.fetch(fetch),
            None => Feedback::Ok,
        };
        // Record only accepted requests, so the observed set reflects accepted
        // (not merely attempted) fetches.
        if feedback.accepted() {
            self.record_fetch(key, subscriber, span);
        }
        feedback
    }

    fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let fetches: Vec<Fetch<Self::Key, Self::Subscriber>> =
            fetches.into_iter().map(Into::into).collect();
        let observed: Vec<_> = fetches
            .iter()
            .map(|fetch| (fetch.key, fetch.subscriber, fetch.span.clone()))
            .collect();
        let feedback = match &mut self.inner {
            Some(inner) => inner.fetch_all(fetches),
            None => Feedback::Ok,
        };
        if feedback.accepted() {
            for (key, subscriber, span) in observed {
                self.record_fetch(key, subscriber, span);
            }
        }
        feedback
    }

    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        {
            let mut active = self.active.lock();
            active.retain(|(key, annotation)| predicate(key, annotation));
            *self.retains.lock() += 1;
        }
        match &mut self.inner {
            Some(inner) => inner.retain(predicate),
            None => Feedback::Ok,
        }
    }
}

impl<P: Simplex> TargetedResolver for RecordingResolver<P> {
    type PublicKey = PublicKeyOf<P>;

    fn fetch_targeted(
        &mut self,
        fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        let fetch = fetch.into();
        let record = (fetch.key, targets.iter().cloned().collect());
        let feedback = match &mut self.inner {
            Some(inner) => inner.fetch_targeted(fetch, targets),
            None => Feedback::Ok,
        };
        if feedback.accepted() {
            self.targeted.lock().push(record);
        }
        feedback
    }

    fn fetch_all_targeted<F>(&mut self, fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let fetches: Vec<TargetedFetch<P>> = fetches
            .into_iter()
            .map(|(fetch, targets)| (fetch.into(), targets))
            .collect();
        let observed: Vec<TargetedRecord<P>> = fetches
            .iter()
            .map(|(fetch, targets)| (fetch.key, targets.iter().cloned().collect()))
            .collect();
        let feedback = match &mut self.inner {
            Some(inner) => inner.fetch_all_targeted(fetches),
            None => Feedback::Ok,
        };
        if feedback.accepted() {
            self.targeted.lock().extend(observed);
        }
        feedback
    }
}

/// Replicate the marshal P2P resolver wiring
/// (`marshal::resolver::p2p::init`) around a handler pair the caller holds:
/// the returned receiver/mailbox go to the marshal actor as usual, while the
/// returned handler is the resolver-side
/// [`Consumer`](commonware_resolver::Consumer) whose `deliver` injects an armed
/// payload into the same receiver the actor consumes. Registers the marshal
/// backfill channel for `validator`.
pub(crate) async fn init_injectable<P: Simplex>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: PublicKeyOf<P>,
) -> (
    (
        handler::Receiver<Sha256Digest>,
        resolver::Mailbox<Sha256Digest, PublicKeyOf<P>>,
    ),
    handler::Handler<Sha256Digest>,
) {
    let control = oracle.control(validator.clone());
    let backfill = control.register(1, TEST_QUOTA).await.unwrap();
    let (receiver, handler) = handler::init(context.child("handler"), NZUsize!(100));
    let (engine, mailbox) = p2p::Engine::new(
        context.child("resolver"),
        p2p::Config {
            peer_provider: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            consumer: handler.clone(),
            producer: handler.clone(),
            mailbox_size: NZUsize!(100),
            me: Some(validator),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
    );
    engine.start(backfill);
    ((receiver, mailbox), handler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SimplexCertificateMock,
        marshal::end_to_end::twins::stack::{
            DEFAULT_MAX_PENDING_ACKS, genesis_block, setup_network, setup_validator,
        },
        scenarios::harness::{build_block, build_notarization},
    };
    use commonware_codec::Encode as _;
    use commonware_consensus::{
        marshal::Start,
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digestible as _, Hasher as _, Sha256, certificate::ConstantProvider,
    };
    use commonware_runtime::{Runner, deterministic};

    type P = SimplexCertificateMock;

    #[test]
    fn records_fetches_and_prunes_active_on_retain() {
        deterministic::Runner::default().start(|mut context| async move {
            let (participants, _schemes) = P::setup(&mut context, crate::NAMESPACE, 4);
            let (_receiver, mut resolver) =
                RecordingResolver::<P>::holding(context.child("recording"));

            let notarized_round = Round::new(Epoch::zero(), View::new(1));
            resolver.fetch(Fetch {
                key: Key::Block(Sha256::hash(&[b"block"])),
                subscriber: Annotation::Certified {
                    height: Height::new(2),
                },
                span: tracing::Span::none(),
            });
            resolver.fetch(Fetch {
                key: Key::Notarized {
                    round: notarized_round,
                },
                subscriber: Annotation::Notarization {
                    round: notarized_round,
                },
                span: tracing::Span::none(),
            });
            resolver.fetch_targeted(
                Fetch {
                    key: Key::Block(Sha256::hash(&[b"targeted"])),
                    subscriber: Annotation::Certified {
                        height: Height::new(3),
                    },
                    span: tracing::Span::none(),
                },
                NonEmptyVec::new(participants[1].clone()),
            );
            assert_eq!(resolver.fetches().len(), 2);
            assert_eq!(resolver.active_fetches().len(), 2);
            assert_eq!(resolver.targeted().len(), 1);
            assert!(!resolver.targeted_is_empty());
            assert_eq!(resolver.retain_count(), 0);

            // Retain only the notarized request; the block fetch is pruned from
            // active but the full history is retained.
            resolver.retain(|key, _| matches!(key, Key::Notarized { .. }));
            assert_eq!(resolver.retain_count(), 1);
            assert_eq!(resolver.fetches().len(), 2);
            let active = resolver.active_fetches();
            assert_eq!(active.len(), 1);
            assert!(matches!(active[0].0, Key::Notarized { .. }));
        });
    }

    /// The full injection loop against a real marshal actor: an armed payload
    /// answers the round-bound fetch a `hint_notarized` issues, the actor
    /// validates it (true for a quorum notarization over the fetched block,
    /// false for garbage), and the verdict reaches the scenario.
    #[test]
    fn armed_delivery_round_trips_through_actor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let (participants, schemes) = P::setup(&mut context, crate::NAMESPACE, 4);
            let mut oracle =
                setup_network::<P>(context.child("network"), participants.clone()).await;
            let me = participants[0].clone();
            let genesis = genesis_block::<P>(me.clone());
            let mut validator = setup_validator::<P>(
                context.child("marshal"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
                Start::Genesis(genesis.clone()),
                None,
                DEFAULT_MAX_PENDING_ACKS,
                None,
            )
            .await;
            // Discard the real P2P resolver pair; this node's backfill is
            // fully scripted.
            drop(validator.take_resolver());
            let (receiver, resolver) = RecordingResolver::<P>::holding(context.child("recording"));
            let reporter = validator.application.clone();
            let buffer = validator.buffer.clone();
            validator.start_with_buffer(reporter, (receiver, resolver.clone()), buffer);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = build_block::<P>(
                &participants,
                genesis.digest(),
                View::zero(),
                round,
                0,
                Height::new(1),
                100,
            );
            let notarization =
                build_notarization::<P>(&schemes, round, View::zero(), block.digest(), &[0, 1, 2]);
            resolver.respond_to_next_fetch((notarization, block.clone()).encode());
            validator.mailbox.hint_notarized(round, block.digest());
            // FIFO barrier: the hint, and so the fetch and the armed delivery,
            // has been processed once this round-trip returns.
            let _ = validator.mailbox.get_processed_height().await;
            assert!(
                resolver.fetches().iter().any(|(key, annotation)| matches!(
                    (key, annotation),
                    (
                        Key::Notarized { round: fetched },
                        Annotation::Notarization { round: subscribed },
                    ) if *fetched == round && *subscribed == round
                )),
                "hint must issue a round-bound notarized fetch"
            );
            assert!(
                resolver.wait_for_delivery_response().await,
                "notarized delivery must validate"
            );

            // A payload that fails validation resolves false, not silence.
            let round_two = Round::new(Epoch::zero(), View::new(2));
            resolver.respond_to_next_fetch(Bytes::from_static(b"garbage"));
            validator
                .mailbox
                .hint_notarized(round_two, Sha256::hash(&[b"missing"]));
            let _ = validator.mailbox.get_processed_height().await;
            assert!(
                !resolver.wait_for_delivery_response().await,
                "garbage delivery must be rejected"
            );
        });
    }
}
