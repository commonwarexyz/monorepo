use super::{
    Config,
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
    state::{Effect, FetchReason},
};
use crate::{
    Epochable, Viewable,
    simplex::{
        actors::{resolver::state::State, voter},
        scheme::Scheme,
        types::Certificate,
    },
    types::{Epoch, View},
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::StaticProvider};
use commonware_parallel::Strategy;
use commonware_resolver::{Fetch, Resolver, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    ordered::Quorum,
    sequence::U64,
};
use rand_core::CryptoRng;
use std::{collections::BTreeMap, num::NonZeroUsize, time::Duration};
use tracing::{debug, info_span};

/// Requests are made concurrently to multiple peers.
pub struct Actor<
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
> {
    context: ContextCell<E>,
    scheme: S,
    blocker: Option<B>,
    strategy: T,

    epoch: Epoch,
    mailbox_size: NonZeroUsize,
    fetch_timeout: Duration,

    /// Certificates known between the floor and the current view. Serves
    /// [HandlerMessage::Produce] requests and emits the [Effect]s the actor
    /// applies to the resolver (see [Self::apply_effects]).
    state: State<S, D>,

    /// Responses to notarization deliveries, keyed by notarization view and
    /// answered with the view's certification verdict (see [Self::certified])
    /// or accepted when a floor raise makes them obsolete (see
    /// [Self::apply_effects]).
    ///
    /// A view maps to multiple responses when copies of its notarization
    /// answer several outstanding requests, which is common when lagging:
    /// peers serve their floor certificate for any request at or below it,
    /// so one verdict resolves every request that notarization answered.
    /// A single request can never hold two responses under one view: the
    /// engine delivers at most one response per key at a time, and a key is
    /// only redelivered after a failure verdict, which marks the view failed
    /// and makes [Self::validate] reject further copies of its notarization.
    held: BTreeMap<View, Vec<oneshot::Sender<bool>>>,

    mailbox_receiver: mailbox::Receiver<MailboxMessage<S, D>>,
}

impl<
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
> Actor<E, S, B, D, T>
{
    pub fn new(context: E, cfg: Config<S, B, T>) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,
                blocker: Some(cfg.blocker),
                strategy: cfg.strategy,

                epoch: cfg.epoch,
                mailbox_size: cfg.mailbox_size,
                fetch_timeout: cfg.fetch_timeout,

                state: State::new(cfg.fetch_concurrent),

                held: BTreeMap::new(),

                mailbox_receiver: receiver,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, sender, receiver))
    }

    async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        let participants = self.scheme.participants().clone();
        let me = self
            .scheme
            .me()
            .and_then(|index| participants.key(index))
            .cloned();

        let (handler_tx, mut handler_rx) =
            mailbox::new(self.context.as_ref().child("handler"), self.mailbox_size);
        let handler = Handler::new(handler_tx);

        let (resolver_engine, mut resolver) = p2p::Engine::new(
            self.context.child("resolver"),
            p2p::Config {
                peer_provider: StaticProvider::new(self.epoch.get(), participants),
                blocker: self.blocker.take().expect("blocker must be set"),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                me,
                initial: self.fetch_timeout / 2,
                timeout: self.fetch_timeout,
                fetch_retry_timeout: self.fetch_timeout,
                priority_requests: true,
                priority_responses: false,
            },
        );
        let mut resolver_task = resolver_engine.start((sender, receiver));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping resolver");
            },
            _ = &mut resolver_task => {
                break;
            },
            Some(message) = self.mailbox_receiver.recv() else break => {
                let span = info_span!(
                    parent: message.span(),
                    "simplex.resolver.process",
                    operation = message.name(),
                    epoch = self.epoch.traced(),
                    view = message.view().traced()
                );
                let _guard = span.entered();
                match message {
                    MailboxMessage::Certificate { certificate, .. } => {
                        let effects = self.state.handle(certificate);
                        self.apply_effects(&mut resolver, effects);
                    }
                    MailboxMessage::Certified { round, success, .. } => {
                        self.certified(&mut resolver, round.view(), success);
                    }
                }
            },
            Some(message) = handler_rx.recv() else break => {
                if message.response_closed() {
                    continue;
                }
                self.handle_resolver(message, &mut voter, &mut resolver);
            },
        }
    }

    /// Handles a certification outcome from the voter.
    fn certified<R: Resolver<Key = U64, Subscriber = ()>>(
        &mut self,
        resolver: &mut R,
        view: View,
        success: bool,
    ) {
        // Answer the responses held for the view's notarization deliveries.
        // Success completes those fetches. Failure blocks the peers that
        // served the uncertifiable notarization and the resolver retries the
        // still-pending requests, mirroring how [Self::validate] treats peers
        // that serve a notarization for a view already marked failed. No copy
        // of that notarization can certify anywhere, so the view cannot
        // finalize and honest participants nullify it: the retried request is
        // eventually answered by that covering nullification (or by a
        // certificate at a higher view).
        if let Some(responses) = self.held.remove(&view) {
            for response in responses {
                response.send_lossy(success);
            }
        }
        let effects = self.state.handle_certified(view, success);
        self.apply_effects(resolver, effects);
    }

    /// Applies the side effects requested by [super::state::State] to the resolver.
    fn apply_effects<R: Resolver<Key = U64, Subscriber = ()>>(
        &mut self,
        resolver: &mut R,
        effects: Vec<Effect>,
    ) {
        for effect in effects {
            match effect {
                Effect::Fetch {
                    view,
                    cause,
                    reason,
                } => self.fetch(resolver, view, cause, reason),
                Effect::Remove(view) => {
                    let key = U64::from(view);
                    let _ = resolver.retain(move |candidate, _| *candidate != key);
                }
                Effect::RetainAbove(floor) => {
                    // A certification at or below the floor may be aborted
                    // rather than reported, so a response held for it would
                    // wait forever. The requests it answered are obsolete
                    // (retained out below): accept them so their fetches
                    // complete without blocking the serving peers.
                    let retained = self.held.split_off(&floor.next());
                    for (_, responses) in std::mem::replace(&mut self.held, retained) {
                        for response in responses {
                            response.send_lossy(true);
                        }
                    }
                    let floor = U64::from(floor);
                    let _ = resolver.retain(move |candidate, _| *candidate > floor);
                }
            }
        }
    }

    /// Issues a resolver fetch for `view`, attaching a span that records why the
    /// fetch was needed and which view's processing caused it.
    fn fetch<R: Resolver<Key = U64, Subscriber = ()>>(
        &self,
        resolver: &mut R,
        view: View,
        cause: View,
        reason: FetchReason,
    ) {
        let span = info_span!(
            "simplex.resolver.fetch",
            epoch = self.epoch.traced(),
            cause = cause.traced(),
            view = view.traced(),
            reason = reason.as_str()
        );
        let _ = resolver.fetch(Fetch {
            key: U64::from(view),
            subscriber: (),
            span,
        });
    }

    /// Validates an incoming message, returning the parsed message if valid.
    fn validate(&mut self, view: View, data: Bytes) -> Option<Certificate<S, D>> {
        // Decode message
        let incoming =
            Certificate::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config()).ok()?;

        // Validate message
        match incoming {
            Certificate::Notarization(notarization) => {
                let notarization_view = notarization.view();
                if notarization.view() < view {
                    debug!(%view, received = %notarization.view(), "notarization below view");
                    return None;
                }
                if notarization.epoch() != self.epoch {
                    debug!(
                        epoch = %notarization.epoch(),
                        expected = %self.epoch,
                        "rejecting notarization from different epoch"
                    );
                    return None;
                }
                if self.state.is_failed(notarization_view) {
                    debug!(
                        %notarization_view,
                        "rejecting notarization for view with failed certification"
                    );
                    return None;
                }
                if !notarization.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
                    debug!(%view, "notarization failed verification");
                    return None;
                }
                debug!(%view, received = %notarization_view, "received notarization for request");
                Some(Certificate::Notarization(notarization))
            }
            Certificate::Finalization(finalization) => {
                if finalization.view() < view {
                    debug!(%view, received = %finalization.view(), "finalization below view");
                    return None;
                }
                if finalization.epoch() != self.epoch {
                    debug!(
                        epoch = %finalization.epoch(),
                        expected = %self.epoch,
                        "rejecting finalization from different epoch"
                    );
                    return None;
                }
                if !finalization.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
                    debug!(%view, "finalization failed verification");
                    return None;
                }
                debug!(%view, received = %finalization.view(), "received finalization for request");
                Some(Certificate::Finalization(finalization))
            }
            Certificate::Nullification(nullification) => {
                if nullification.view() != view {
                    debug!(%view, received = %nullification.view(), "nullification view mismatch");
                    return None;
                }
                if nullification.epoch() != self.epoch {
                    debug!(
                        epoch = %nullification.epoch(),
                        expected = %self.epoch,
                        "rejecting nullification from different epoch"
                    );
                    return None;
                }
                if !nullification.verify::<_, D>(
                    self.context.as_mut(),
                    &self.scheme,
                    &self.strategy,
                ) {
                    debug!(%view, "nullification failed verification");
                    return None;
                }
                debug!(%view, received = %nullification.view(), "received nullification for request");
                Some(Certificate::Nullification(nullification))
            }
        }
    }

    /// Handles a message from the [p2p::Engine].
    fn handle_resolver<R: Resolver<Key = U64, Subscriber = ()>>(
        &mut self,
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut R,
    ) {
        match message {
            HandlerMessage::Deliver {
                span,
                view,
                data,
                response,
            } => {
                let span = info_span!(
                    parent: span,
                    "simplex.resolver.deliver",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Validate incoming message
                let validate = info_span!(
                    "simplex.resolver.validate",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let Some(parsed) = validate.in_scope(|| self.validate(view, data)) else {
                    // Resolver will block any peers that send invalid responses, so
                    // we don't need to do again here
                    response.send_lossy(false);
                    return;
                };

                // A notarization only answers the request if its proposal
                // certifies, so hold the response and answer it with the
                // certification verdict (see [Self::certified]). Other
                // certificates are complete answers on their own.
                match &parsed {
                    Certificate::Notarization(notarization) => {
                        self.held
                            .entry(notarization.view())
                            .or_default()
                            .push(response);
                    }
                    Certificate::Finalization(_) | Certificate::Nullification(_) => {
                        response.send_lossy(true);
                    }
                }

                // Notify voter as soon as possible
                let resolved = info_span!(
                    "simplex.resolver.resolved",
                    epoch = self.epoch.traced(),
                    view = view.traced(),
                    certificate_view = parsed.view().traced()
                );
                resolved.in_scope(|| voter.resolved(parsed.clone()));

                // Recording the notarization makes it a floor candidate, so the
                // certification verdict (see [Self::certified]) can act on it.
                let effects = self.state.handle(parsed);
                self.apply_effects(resolver, effects);
            }
            HandlerMessage::Produce { view, response } => {
                let span = info_span!(
                    "simplex.resolver.produce",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Produce message for view
                let Some(certificate) = self.state.get(view) else {
                    // If we drop the response channel, the resolver will automatically
                    // send an error response to the caller (so they don't need to wait
                    // the full timeout)
                    return;
                };
                response.send_lossy(certificate.encode());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_helpers::*, *};
    use crate::simplex::scheme::ed25519;
    use commonware_actor::Feedback;
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_async;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor, deterministic};
    use commonware_utils::{NZUsize, sync::Mutex};
    use std::{collections::BTreeSet, sync::Arc};

    const NAMESPACE: &[u8] = b"resolver-actor";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;
    type TestActor =
        Actor<deterministic::Context, TestScheme, NoopBlocker, Sha256Digest, Sequential>;

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }
    }

    /// Tracks the set of pending requests the way the resolver engine would.
    #[derive(Clone, Default)]
    struct RecordingResolver {
        outstanding: Arc<Mutex<BTreeSet<U64>>>,
    }

    impl RecordingResolver {
        fn outstanding(&self) -> Vec<u64> {
            self.outstanding.lock().iter().map(u64::from).collect()
        }
    }

    impl Resolver for RecordingResolver {
        type Key = U64;
        type Subscriber = ();

        fn fetch<F>(&mut self, key: F) -> Feedback
        where
            F: Into<Fetch<U64, ()>> + Send,
        {
            self.outstanding.lock().insert(key.into().key);
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
        where
            F: Into<Fetch<U64, ()>> + Send,
        {
            for key in keys {
                self.fetch(key);
            }
            Feedback::Ok
        }

        fn retain(&mut self, predicate: impl Fn(&U64, &()) -> bool + Send + 'static) -> Feedback {
            self.outstanding.lock().retain(|key| predicate(key, &()));
            Feedback::Ok
        }
    }

    fn build_actor(context: deterministic::Context, scheme: TestScheme) -> TestActor {
        let (actor, _) = Actor::new(
            context,
            Config {
                scheme,
                blocker: NoopBlocker,
                strategy: Sequential,
                epoch: EPOCH,
                mailbox_size: NZUsize!(8),
                fetch_concurrent: NZUsize!(4),
                fetch_timeout: Duration::from_secs(1),
            },
        );
        actor
    }

    #[test_async]
    async fn apply_effects_maintains_resolver_pending_set() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            // The first certificate opens the fetch window below it.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(5));
            let effects = actor
                .state
                .handle(Certificate::Nullification(nullification));
            actor.apply_effects(&mut resolver, effects);
            assert_eq!(resolver.outstanding(), vec![1, 2, 3, 4]);

            // A nullification removes exactly its own request.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
            let effects = actor
                .state
                .handle(Certificate::Nullification(nullification));
            actor.apply_effects(&mut resolver, effects);
            assert_eq!(resolver.outstanding(), vec![1, 3, 4]);

            // A floor raise drops the requests at and below it.
            let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(3));
            let effects = actor.state.handle(Certificate::Finalization(finalization));
            actor.apply_effects(&mut resolver, effects);
            assert_eq!(resolver.outstanding(), vec![4]);

            // The request at the floor view itself must not survive.
            let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(4));
            let effects = actor.state.handle(Certificate::Finalization(finalization));
            actor.apply_effects(&mut resolver, effects);
            assert!(resolver.outstanding().is_empty());
        });
    }

    #[test_async]
    async fn notarization_response_answered_with_certification_verdict() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            // The response to a notarization delivery is withheld until the
            // voter reports the certification outcome.
            let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(6));
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: View::new(6),
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(notarization)
                        .encode(),
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert!(actor.held.contains_key(&View::new(6)));

            // A failed certification rejects the response, so the resolver
            // blocks the serving peer and retries the request itself.
            actor.certified(&mut resolver, View::new(6), false);
            assert!(actor.held.is_empty());
            assert!(!receiver.await.unwrap());
        });
    }

    #[test_async]
    async fn certified_notarization_response_accepted() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(6));
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: View::new(6),
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(notarization)
                        .encode(),
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            actor.certified(&mut resolver, View::new(6), true);
            assert!(actor.held.is_empty());
            assert!(receiver.await.unwrap());
        });
    }

    #[test_async]
    async fn held_responses_accepted_when_floor_passes_them() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(6));
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: View::new(6),
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(notarization)
                        .encode(),
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert!(actor.held.contains_key(&View::new(6)));

            // A floor raise past the notarization may abort its certification
            // without a report, so the held response is accepted (the request
            // it answered is retained out in the same batch).
            let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(8));
            let effects = actor.state.handle(Certificate::Finalization(finalization));
            actor.apply_effects(&mut resolver, effects);
            assert!(actor.held.is_empty());
            assert!(receiver.await.unwrap());
        });
    }
}
