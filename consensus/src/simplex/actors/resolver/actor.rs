use super::{
    super::Purpose,
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
use commonware_resolver::{Fetch, Resolver, TargetedResolver, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    ordered::Quorum,
    sequence::U64,
    vec::NonEmptyVec,
};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    time::Duration,
};
use tracing::{debug, info_span};

/// A resolver delivery awaiting an exact certification verdict or covering finalization.
///
/// The requested view may be lower than the delivered notarization that keys `Actor::held`,
/// so it must remain attached to the response.
struct HeldResponse {
    requested: View,
    response: oneshot::Sender<bool>,
}

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

    /// Highest finalized view observed. Targeted ancestry at or below this
    /// view can no longer be required by a valid proposal.
    last_finalized: View,

    /// Nullifications that still cover views above finalization. These are
    /// retained as compact lifecycle tombstones even when resolver state no
    /// longer stores their certificates below a certified floor.
    known_nullifications: BTreeSet<View>,

    /// Terminal certification outcomes retained until covering finalization.
    certification_outcomes: BTreeMap<View, bool>,

    /// Responses to notarization deliveries, keyed by notarization view and
    /// answered with the view's certification verdict (see [Self::certified])
    /// or when finalization covers the requested key (see [Self::updated]).
    ///
    /// A view maps to multiple responses when copies of its notarization
    /// answer several outstanding requests, which is common when lagging:
    /// peers serve their floor certificate for any request at or below it,
    /// so one verdict resolves every request that notarization answered.
    /// A single request can never hold two responses under one view: the
    /// engine delivers at most one response per key at a time, and a key is
    /// only redelivered after a failure verdict, which marks the view failed
    /// and makes [Self::validate] reject further copies of its notarization.
    held: BTreeMap<View, Vec<HeldResponse>>,

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

                state: State::new(cfg.fetch_concurrent, cfg.term_length),
                last_finalized: View::zero(),
                known_nullifications: BTreeSet::new(),
                certification_outcomes: BTreeMap::new(),

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
                        self.updated(&mut resolver, certificate);
                    }
                    MailboxMessage::Certified { round, success, .. } => {
                        self.certified(&mut resolver, round.view(), success);
                    }
                    MailboxMessage::Resolve {
                        proposal_view,
                        view,
                        purpose,
                        target,
                        ..
                    } => {
                        self.resolve(&mut resolver, proposal_view, view, purpose, target);
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

    /// Records a certificate and applies its resolver lifecycle effects.
    fn updated<R: Resolver<Key = U64, Subscriber = Purpose>>(
        &mut self,
        resolver: &mut R,
        certificate: Certificate<S, D>,
    ) {
        let (finalized, nullified) = match &certificate {
            Certificate::Finalization(finalization) => (Some(finalization.view()), None),
            Certificate::Nullification(nullification) => (None, Some(nullification.view())),
            Certificate::Notarization(_) => (None, None),
        };

        // Finalization satisfies every request key it covers, including a
        // lower key whose peer answered with a higher-view notarization.
        if let Some(finalized) = finalized {
            let finalized = self.last_finalized.max(finalized);
            self.accept_held(|held| held.requested <= finalized);
        }

        // A nullification retires background and targeted nullification demand across the rest of
        // its term. Retain a tombstone above finalization so delayed requests cannot recreate it.
        if let Some(nullified) = nullified {
            let term_end = nullified.term_end(self.state.term_length());
            if term_end > self.last_finalized {
                self.known_nullifications.insert(nullified);
            }
            self.retire(resolver, Purpose::Nullification, nullified, term_end);
        }

        // Certificate state owns floor selection and background repair.
        let effects = self.state.handle(certificate);
        self.apply_effects(resolver, effects);

        // Finalization is the global retirement boundary. Remove covered tombstones and resolver
        // requests so delayed work cannot recreate demand below the finalized view.
        let Some(finalized) = finalized else {
            return;
        };
        self.last_finalized = self.last_finalized.max(finalized);
        let term_length = self.state.term_length();
        self.known_nullifications
            .retain(|view| view.term_end(term_length) > self.last_finalized);
        self.certification_outcomes
            .retain(|view, _| *view > self.last_finalized);
        let floor = U64::from(self.last_finalized);
        let _ = resolver.retain(move |candidate, _| *candidate > floor);
    }

    /// Handles a certification outcome from the voter.
    fn certified<R: Resolver<Key = U64, Subscriber = Purpose>>(
        &mut self,
        resolver: &mut R,
        view: View,
        success: bool,
    ) {
        if view > self.last_finalized {
            self.certification_outcomes.insert(view, success);
        }

        // Answer the responses held for the view's notarization deliveries.
        // Success completes those fetches. Failure blocks the peers that
        // served the uncertifiable notarization and the resolver retries the
        // still-pending requests, mirroring how [Self::validate] treats peers
        // that serve a notarization for a view already marked failed. The
        // notarization cannot certify at an honest participant, so honest
        // participants continue with nullification. Once an eligible honest
        // peer is available, its covering nullification (or a certificate at
        // a higher view) can satisfy the re-queued request.
        if let Some(responses) = self.held.remove(&view) {
            for held in responses {
                held.response.send_lossy(success);
            }
        }
        self.retire(resolver, Purpose::Parent, view, view);
        let effects = self.state.handle_certified(view, success);
        self.apply_effects(resolver, effects);
    }

    /// Applies the side effects requested by [super::state::State] to the resolver.
    fn apply_effects<R: Resolver<Key = U64, Subscriber = Purpose>>(
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
                Effect::RetainAbove(floor) => {
                    // Resolver retention cancels background-only delivery.
                    // Any targeted subscriber attached before or during
                    // validation keeps the response pending for the exact
                    // verdict or finalization.
                    let floor = U64::from(floor);
                    let _ = resolver.retain(move |candidate, purpose| {
                        purpose.is_targeted() || *candidate > floor
                    });
                    self.prune_held();
                }
            }
        }
    }

    /// Removes demand made unnecessary by matching terminal evidence.
    fn retire<R: Resolver<Key = U64, Subscriber = Purpose>>(
        &self,
        resolver: &mut R,
        resolved: Purpose,
        start: View,
        end: View,
    ) {
        let start = U64::from(start);
        let end = U64::from(end);
        let _ = resolver.retain(move |candidate, purpose| {
            *candidate < start || *candidate > end || !purpose.is_retired_by(resolved)
        });
    }

    /// Issues a resolver fetch for `view`, attaching a span that records why the
    /// fetch was needed and which view's processing caused it.
    fn fetch<R: Resolver<Key = U64, Subscriber = Purpose>>(
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
            subscriber: Purpose::Backfill,
            span,
        });
    }

    /// Fetches ancestry from the leader whose proposal requires it.
    fn resolve<R>(
        &self,
        resolver: &mut R,
        proposal_view: View,
        view: View,
        purpose: Purpose,
        target: S::PublicKey,
    ) where
        R: TargetedResolver<Key = U64, Subscriber = Purpose, PublicKey = S::PublicKey>,
    {
        if view >= proposal_view
            || view <= self.last_finalized
            || self.purpose_resolved(view, purpose)
        {
            return;
        }
        let span = info_span!(
            "simplex.resolver.fetch",
            epoch = self.epoch.traced(),
            cause = proposal_view.traced(),
            view = view.traced(),
            reason = "proposal_ancestry",
            purpose = purpose.as_str()
        );
        let _ = resolver.fetch_targeted(
            Fetch {
                key: U64::from(view),
                subscriber: purpose,
                span,
            },
            NonEmptyVec::new(target),
        );
    }

    /// Returns whether local evidence has already made this targeted demand
    /// unnecessary. Keeping this knowledge separately from resolver storage
    /// prevents an older queued request from resurrecting retired work.
    fn purpose_resolved(&self, view: View, purpose: Purpose) -> bool {
        match purpose {
            Purpose::Nullification => self
                .known_nullifications
                .range(view.covering_range(self.state.term_length()))
                .next_back()
                .is_some(),
            Purpose::Parent => self.certification_outcomes.contains_key(&view),
            Purpose::Backfill => false,
        }
    }

    /// Returns the terminal verdict for a notarization delivery, if known.
    fn notarization_verdict(&self, requested: View, notarization_view: View) -> Option<bool> {
        if requested <= self.last_finalized {
            return Some(true);
        }
        self.certification_outcomes.get(&notarization_view).copied()
    }

    /// Removes responses whose resolver delivery has already been canceled.
    fn prune_held(&mut self) {
        self.held.retain(|_, responses| {
            responses.retain(|held| !held.response.is_closed());
            !responses.is_empty()
        });
    }

    /// Accepts and removes held responses selected by `predicate`.
    fn accept_held(&mut self, mut predicate: impl FnMut(&HeldResponse) -> bool) {
        self.held.retain(|_, responses| {
            let mut retained = Vec::with_capacity(responses.len());
            for held in std::mem::take(responses) {
                if predicate(&held) {
                    held.response.send_lossy(true);
                } else {
                    retained.push(held);
                }
            }
            *responses = retained;
            !responses.is_empty()
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
                if self.state.is_failed(notarization_view)
                    || self.certification_outcomes.get(&notarization_view) == Some(&false)
                {
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
                let nullified_view = nullification.view();
                if !nullified_view.covers(view, self.state.term_length()) {
                    debug!(%view, received = %nullified_view, "nullification view mismatch");
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
    fn handle_resolver<R: Resolver<Key = U64, Subscriber = Purpose>>(
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
                targeted,
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
                // certifies, so hold the response and answer it with the exact
                // certification verdict (see [Self::certified]). Finalization
                // may instead satisfy the requested key. Other certificates
                // are complete answers on their own.
                match &parsed {
                    Certificate::Notarization(notarization) => {
                        match self.notarization_verdict(view, notarization.view()) {
                            Some(verdict) => {
                                response.send_lossy(verdict);
                            }
                            None => {
                                self.held.entry(notarization.view()).or_default().push(
                                    HeldResponse {
                                        requested: view,
                                        response,
                                    },
                                );
                            }
                        }
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
                    certificate_view = parsed.view().traced(),
                    targeted
                );
                resolved.in_scope(|| {
                    if targeted {
                        voter.resolved_targeted(parsed.clone());
                    } else {
                        voter.resolved(parsed.clone());
                    }
                });

                // Recording the notarization makes it a floor candidate, so the
                // certification verdict (see [Self::certified]) can act on it.
                self.updated(resolver, parsed);
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
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{Notarization, Notarize},
        },
        types::TermLength,
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_async};
    use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Quota, Runner, Supervisor, deterministic};
    use commonware_utils::{NZU32, NZUsize, sync::Mutex};
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
        outstanding: Arc<Mutex<BTreeSet<(U64, Purpose)>>>,
        targeted: Arc<Mutex<Vec<(U64, Purpose, PublicKey)>>>,
    }

    impl RecordingResolver {
        fn outstanding(&self) -> Vec<u64> {
            self.outstanding
                .lock()
                .iter()
                .map(|(key, _)| u64::from(key))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        }

        fn targeted(&self) -> Vec<(u64, Purpose, PublicKey)> {
            self.targeted
                .lock()
                .iter()
                .map(|(key, subscription, target)| (u64::from(key), *subscription, target.clone()))
                .collect()
        }

        fn subscriptions(&self, view: u64) -> Vec<Purpose> {
            self.outstanding
                .lock()
                .iter()
                .filter_map(|(key, subscription)| (u64::from(key) == view).then_some(*subscription))
                .collect()
        }
    }

    impl Resolver for RecordingResolver {
        type Key = U64;
        type Subscriber = Purpose;

        fn fetch<F>(&mut self, key: F) -> Feedback
        where
            F: Into<Fetch<U64, Purpose>> + Send,
        {
            let fetch = key.into();
            self.outstanding
                .lock()
                .insert((fetch.key, fetch.subscriber));
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
        where
            F: Into<Fetch<U64, Purpose>> + Send,
        {
            for key in keys {
                self.fetch(key);
            }
            Feedback::Ok
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&U64, &Purpose) -> bool + Send + 'static,
        ) -> Feedback {
            self.outstanding
                .lock()
                .retain(|(key, subscription)| predicate(key, subscription));
            Feedback::Ok
        }
    }

    impl TargetedResolver for RecordingResolver {
        type PublicKey = PublicKey;

        fn fetch_targeted(
            &mut self,
            fetch: impl Into<Fetch<U64, Purpose>> + Send,
            targets: NonEmptyVec<PublicKey>,
        ) -> Feedback {
            let fetch = fetch.into();
            self.targeted.lock().push((
                fetch.key.clone(),
                fetch.subscriber,
                targets.first().clone(),
            ));
            self.outstanding
                .lock()
                .insert((fetch.key, fetch.subscriber));
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(&mut self, fetches: Vec<(F, NonEmptyVec<PublicKey>)>) -> Feedback
        where
            F: Into<Fetch<U64, Purpose>> + Send,
        {
            for (fetch, targets) in fetches {
                self.fetch_targeted(fetch, targets);
            }
            Feedback::Ok
        }
    }

    fn build_actor(context: deterministic::Context, scheme: TestScheme) -> TestActor {
        build_actor_with_term_length(context, scheme, TermLength::new(NZU32!(5)))
    }

    fn build_actor_with_term_length(
        context: deterministic::Context,
        scheme: TestScheme,
        term_length: TermLength,
    ) -> TestActor {
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
                term_length,
            },
        );
        actor
    }

    #[test_async]
    async fn targeted_fetch_does_not_restrict_existing_backfill() {
        let runtime = deterministic::Runner::timed(Duration::from_secs(10));
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            network.start();

            let mut connections = Vec::new();
            for participant in &participants {
                connections.push(
                    oracle
                        .control(participant.clone())
                        .register(2, Quota::per_second(NZU32!(1_000)))
                        .await
                        .unwrap(),
                );
            }
            let mut connections = connections.into_iter();
            let requester_connection = connections.next().unwrap();
            let (_target_sender, mut target_receiver) = connections.next().unwrap();
            let responder_connection = connections.next().unwrap();
            let _unused_connection = connections.next().unwrap();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            oracle
                .add_link(
                    participants[0].clone(),
                    participants[1].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    participants[1].clone(),
                    participants[0].clone(),
                    link.clone(),
                )
                .await
                .unwrap();

            let (requester_voter_sender, mut requester_voter_receiver) =
                mailbox::new(context.child("requester_voter"), NZUsize!(8));
            let (requester, mut requester_mailbox) = TestActor::new(
                context.child("requester"),
                Config {
                    scheme: schemes[0].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_concurrent: NZUsize!(4),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _requester = requester.start(
                voter::Mailbox::new(requester_voter_sender),
                requester_connection.0,
                requester_connection.1,
            );

            let (responder_voter_sender, _responder_voter_receiver) =
                mailbox::new(context.child("responder_voter"), NZUsize!(8));
            let (responder, mut responder_mailbox) = TestActor::new(
                context.child("responder"),
                Config {
                    scheme: schemes[2].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_concurrent: NZUsize!(4),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _responder = responder.start(
                voter::Mailbox::new(responder_voter_sender),
                responder_connection.0,
                responder_connection.1,
            );

            let requested = View::new(1);
            let available = build_nullification(&schemes, &verifier, EPOCH, requested);
            responder_mailbox.updated(Certificate::Nullification(available.clone()));
            context.sleep(Duration::from_millis(10)).await;

            // Advancing to view 2 creates unrestricted background demand for
            // view 1. The only connected peer is the silent target, so seeing
            // its request proves the background fetch is already in flight.
            requester_mailbox.updated(Certificate::Nullification(build_nullification(
                &schemes,
                &verifier,
                EPOCH,
                View::new(2),
            )));
            let (requester_key, _) = select! {
                request = target_receiver.recv() => request.expect("target channel closed"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("background request did not reach silent target");
                },
            };
            assert_eq!(requester_key, participants[0]);

            // Add targeted ancestry demand for the same key and silent peer.
            // It must attach a subscriber without narrowing the in-flight
            // unrestricted fetch.
            requester_mailbox.resolve(
                View::new(3),
                requested,
                Purpose::Nullification,
                participants[1].clone(),
            );
            context.sleep(Duration::from_millis(10)).await;

            // Remove the silent target and expose a different responder. If
            // the targeted demand narrowed the fetch, recovery cannot finish.
            oracle
                .remove_link(participants[0].clone(), participants[1].clone())
                .await
                .unwrap();
            oracle
                .remove_link(participants[1].clone(), participants[0].clone())
                .await
                .unwrap();
            oracle
                .add_link(
                    participants[0].clone(),
                    participants[2].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(participants[2].clone(), participants[0].clone(), link)
                .await
                .unwrap();

            let recovered = select! {
                message = requester_voter_receiver.recv() => message.expect("voter mailbox closed"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("unrestricted fetch was narrowed to the silent target");
                },
            };
            assert!(matches!(
                recovered,
                voter::Message::Verified {
                    certificate: Certificate::Nullification(nullification),
                    ..
                } if nullification == available
            ));
        });
    }

    /// A terminal certification verdict releases a response while background
    /// repair and a later ancestry objection share the parked view.
    #[test_async]
    async fn certification_failure_unparks_attached_ancestry_fetch() {
        let runtime = deterministic::Runner::timed(Duration::from_secs(10));
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            network.start();

            let mut connections = Vec::new();
            for participant in &participants {
                connections.push(
                    oracle
                        .control(participant.clone())
                        .register(2, Quota::per_second(NZU32!(1_000)))
                        .await
                        .unwrap(),
                );
            }
            let mut connections = connections.into_iter();
            let requester_connection = connections.next().unwrap();
            let first_responder_connection = connections.next().unwrap();
            let nullification_holder_connection = connections.next().unwrap();
            let _unused_connection = connections.next().unwrap();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            oracle
                .add_link(
                    participants[0].clone(),
                    participants[1].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    participants[1].clone(),
                    participants[0].clone(),
                    link.clone(),
                )
                .await
                .unwrap();

            let (requester_voter_sender, mut requester_voter_receiver) =
                mailbox::new(context.child("requester_voter"), NZUsize!(8));
            let (requester, mut requester_mailbox) = TestActor::new(
                context.child("requester"),
                Config {
                    scheme: schemes[0].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_concurrent: NZUsize!(4),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _requester = requester.start(
                voter::Mailbox::new(requester_voter_sender),
                requester_connection.0,
                requester_connection.1,
            );

            let (first_voter_sender, _first_voter_receiver) =
                mailbox::new(context.child("first_voter"), NZUsize!(8));
            let (first_responder, mut first_responder_mailbox) = TestActor::new(
                context.child("first_responder"),
                Config {
                    scheme: schemes[1].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_concurrent: NZUsize!(4),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _first_responder = first_responder.start(
                voter::Mailbox::new(first_voter_sender),
                first_responder_connection.0,
                first_responder_connection.1,
            );

            let (holder_voter_sender, _holder_voter_receiver) =
                mailbox::new(context.child("holder_voter"), NZUsize!(8));
            let (nullification_holder, mut nullification_holder_mailbox) = TestActor::new(
                context.child("nullification_holder"),
                Config {
                    scheme: schemes[2].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_concurrent: NZUsize!(4),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _nullification_holder = nullification_holder.start(
                voter::Mailbox::new(holder_voter_sender),
                nullification_holder_connection.0,
                nullification_holder_connection.1,
            );

            let requested = View::new(1);
            let notarized = requested.next();
            let notarization = build_notarization(&schemes, &verifier, EPOCH, notarized);
            first_responder_mailbox.updated(Certificate::Notarization(notarization.clone()));
            // Model the Byzantine peer as willing to serve this notarization.
            // Honest certification at the requester may still reject it.
            first_responder_mailbox.certified(notarization.round(), true);
            let nullification = build_nullification(&schemes, &verifier, EPOCH, requested);
            nullification_holder_mailbox.updated(Certificate::Nullification(nullification.clone()));
            context.sleep(Duration::from_millis(10)).await;

            // A later nullification exposes a gap and starts an unrestricted
            // background fetch. The only connected peer answers with a valid
            // notarization, whose resolver verdict waits for certification.
            requester_mailbox.updated(Certificate::Nullification(build_nullification(
                &schemes, &verifier, EPOCH, notarized,
            )));
            let first = select! {
                message = requester_voter_receiver.recv() => {
                    message.expect("voter mailbox closed")
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("notarization was not fetched");
                },
            };
            assert!(matches!(
                first,
                voter::Message::Verified {
                    certificate: Certificate::Notarization(ref fetched),
                    ..
                } if fetched == &notarization
            ));

            oracle
                .add_link(
                    participants[0].clone(),
                    participants[2].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(participants[2].clone(), participants[0].clone(), link)
                .await
                .unwrap();

            // A proposal objection for the same view attaches another
            // subscriber. The existing fetch remains unrestricted, so the
            // leader hint neither narrows it nor bypasses the response whose
            // certification is still pending.
            requester_mailbox.resolve(
                View::new(3),
                requested,
                Purpose::Nullification,
                participants[2].clone(),
            );
            select! {
                _ = requester_voter_receiver.recv() => {
                    panic!("pending certification unexpectedly allowed another delivery");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Raising an unrelated certified floor removes the background
            // subscriber, but must not accept and cache the parked response:
            // the attached targeted subscriber still needs the exact verdict.
            let higher = build_notarization(&schemes, &verifier, EPOCH, View::new(4));
            requester_mailbox.updated(Certificate::Notarization(higher.clone()));
            requester_mailbox.certified(higher.round(), true);
            select! {
                _ = requester_voter_receiver.recv() => {
                    panic!("certified floor redelivered a cached response to targeted demand");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // The nullification at `notarized` leaves the lower request as the
            // only unsatisfied key. Rejecting the parked response must retry
            // that key. The honest holder then supplies its nullification.
            requester_mailbox.certified(notarization.round(), false);
            let recovered = select! {
                message = requester_voter_receiver.recv() => {
                    message.expect("voter mailbox closed")
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("certification failure did not unpark ancestry repair");
                },
            };
            assert!(matches!(
                recovered,
                voter::Message::Verified {
                    certificate: Certificate::Nullification(fetched),
                    ..
                } if fetched == nullification
            ));
        });
    }

    #[test_async]
    async fn updates_maintain_resolver_pending_set() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            // The first certificate opens the fetch window at the term anchors.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(20));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![1, 6, 11, 16]);

            // A covering nullification retains out only its own term's requests
            // (here, the request at its own view): views below its start and
            // above its term end stay pending.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(6));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![1, 11, 16]);

            // A mid-term floor raise drops the requests below it and re-scans
            // the stranded term tail (view 5).
            let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(4));
            actor.updated(&mut resolver, Certificate::Finalization(finalization));
            assert_eq!(resolver.outstanding(), vec![5, 11, 16]);

            // A below-floor nullification covering the floor's term retains
            // out the request at its term end (view 5), not just the request
            // at its own view.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![11, 16]);

            // A floor raise drops the request at the floor view itself and
            // re-scans the stranded term tail (view 12).
            let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(11));
            actor.updated(&mut resolver, Certificate::Finalization(finalization));
            assert_eq!(resolver.outstanding(), vec![12, 16]);

            // A nullification at the floor covering the floor's term retains
            // out mid-term requests strictly inside its range.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(11));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![16]);
        });
    }

    #[test_async]
    async fn targeted_fetches_drop_only_when_purpose_is_satisfied() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();
            let requested = View::new(3);

            actor.resolve(
                &mut resolver,
                View::new(10),
                requested,
                Purpose::Nullification,
                participants[0].clone(),
            );
            actor.resolve(
                &mut resolver,
                View::new(11),
                requested,
                Purpose::Parent,
                participants[1].clone(),
            );
            resolver.fetch(Fetch {
                key: U64::from(requested),
                subscriber: Purpose::Backfill,
                span: tracing::Span::none(),
            });
            assert_eq!(
                resolver.targeted(),
                vec![
                    (3, Purpose::Nullification, participants[0].clone()),
                    (3, Purpose::Parent, participants[1].clone()),
                ]
            );
            assert_eq!(
                resolver.subscriptions(3),
                vec![Purpose::Backfill, Purpose::Nullification, Purpose::Parent,]
            );

            // A covering nullification completes both background repair and
            // the targeted nullification request. It must preserve the
            // targeted parent request. That opposite evidence is the reason
            // the parent certificate is still needed.
            actor.updated(
                &mut resolver,
                Certificate::Nullification(build_nullification(
                    &schemes, &verifier, EPOCH, requested,
                )),
            );
            assert_eq!(resolver.subscriptions(3), vec![Purpose::Parent]);
            actor.resolve(
                &mut resolver,
                View::new(14),
                requested,
                Purpose::Nullification,
                participants[2].clone(),
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                requested.next(),
                Purpose::Nullification,
                participants[2].clone(),
            );
            assert_eq!(resolver.targeted().len(), 2);

            // Exercise the mirror case at another key. Successful
            // certification completes only the exact parent request. It does
            // not provide the nullification needed to skip that view.
            let second_requested = requested.next_term_start(actor.state.term_length());
            actor.resolve(
                &mut resolver,
                View::new(12),
                second_requested,
                Purpose::Nullification,
                participants[2].clone(),
            );
            actor.resolve(
                &mut resolver,
                View::new(13),
                second_requested,
                Purpose::Parent,
                participants[3].clone(),
            );
            resolver.fetch(Fetch {
                key: U64::from(second_requested),
                subscriber: Purpose::Backfill,
                span: tracing::Span::none(),
            });
            actor.certified(&mut resolver, second_requested, true);
            assert_eq!(
                resolver.subscriptions(6),
                vec![Purpose::Backfill, Purpose::Nullification,]
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                second_requested,
                Purpose::Parent,
                participants[0].clone(),
            );
            assert_eq!(resolver.targeted().len(), 4);

            // A numeric floor raise alone does not identify which ancestry
            // requirement it satisfies. Both remaining targeted requests
            // survive until matching evidence or finalization arrives.
            actor.apply_effects(&mut resolver, vec![Effect::RetainAbove(second_requested)]);
            assert_eq!(resolver.outstanding(), vec![3, 6]);

            // Finalization is the universal boundary. No valid proposal can
            // require ancestry at or below it. It removes every such key and
            // prevents a delayed mailbox request from recreating stale work.
            let finalized = second_requested;
            actor.updated(
                &mut resolver,
                Certificate::Finalization(build_finalization(
                    &schemes, &verifier, EPOCH, finalized,
                )),
            );
            assert!(resolver.outstanding().is_empty());
            assert!(actor.known_nullifications.is_empty());
            assert!(actor.certification_outcomes.is_empty());
            actor.resolve(
                &mut resolver,
                finalized.next(),
                requested,
                Purpose::Parent,
                participants[0].clone(),
            );
            assert!(resolver.outstanding().is_empty());
            assert_eq!(resolver.targeted().len(), 4);
        });
    }

    #[test_async]
    async fn nullification_satisfies_target_at_certified_floor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor_with_term_length(
                context,
                verifier.clone(),
                TermLength::ONE,
            );
            let mut resolver = RecordingResolver::default();
            let view = View::new(3);

            // Certify the view first, then request its coexisting
            // nullification as ancestry for a proposal that skips it.
            let notarization = build_notarization(&schemes, &verifier, EPOCH, view);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(notarization),
            );
            actor.certified(&mut resolver, view, true);
            let floor = View::new(8);
            let certified_floor = build_notarization(&schemes, &verifier, EPOCH, floor);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(certified_floor.clone()),
            );
            actor.certified(&mut resolver, floor, true);
            actor.resolve(
                &mut resolver,
                View::new(10),
                view,
                Purpose::Nullification,
                participants[0].clone(),
            );
            assert_eq!(
                resolver.subscriptions(3),
                vec![Purpose::Nullification]
            );

            // The resolver still prefers the certified floor when producing
            // a kindless response, but locally observing the nullification
            // must retire the exact targeted demand it satisfies.
            actor.updated(
                &mut resolver,
                Certificate::Nullification(build_nullification(
                    &schemes, &verifier, EPOCH, view,
                )),
            );
            assert!(resolver.outstanding().is_empty());
            assert!(
                matches!(actor.state.get(view), Some(Certificate::Notarization(n)) if n == &certified_floor)
            );
            actor.resolve(
                &mut resolver,
                View::new(11),
                view,
                Purpose::Nullification,
                participants[1].clone(),
            );
            assert_eq!(resolver.targeted().len(), 1);
        });
    }

    #[test_async]
    async fn certification_failure_retires_parent_target() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();
            let view = View::new(5);

            actor.resolve(
                &mut resolver,
                View::new(10),
                view,
                Purpose::Parent,
                participants[0].clone(),
            );
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, view)),
            );
            actor.certified(&mut resolver, view, false);

            // A false certification verdict is permanent. Parent repair is
            // retired, while ordinary repair asks for the nullification that
            // can now cover the failed view.
            assert_eq!(resolver.subscriptions(5), vec![Purpose::Backfill]);
            actor.resolve(
                &mut resolver,
                View::new(11),
                view,
                Purpose::Parent,
                participants[1].clone(),
            );
            assert_eq!(resolver.targeted().len(), 1);
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
                    targeted: false,
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
    async fn valid_nullification_completes_kindless_targeted_delivery() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            // The local requirement is intentionally absent from a delivery.
            // A covering nullification is a valid answer for the U64 key even
            // if the triggering proposal wanted a certified parent.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(3));
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: View::new(4),
                    data: Certificate::<TestScheme, Sha256Digest>::Nullification(nullification)
                        .encode(),
                    targeted: true,
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert!(receiver.await.unwrap());
        });
    }

    #[test_async]
    async fn valid_notarization_completes_kindless_targeted_delivery_after_certification() {
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
                    // The local requirement is intentionally absent from a
                    // delivery. A notarization is a valid answer for the U64
                    // key even if the triggering proposal wanted a
                    // nullification, but it completes only after application
                    // certification succeeds.
                    targeted: true,
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
    async fn already_certified_notarization_response_accepted() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            let view = View::new(6);
            let notarization = build_notarization(&schemes, &verifier, EPOCH, view);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(notarization.clone()),
            );
            actor.certified(&mut resolver, view, true);

            // Build a second valid aggregate for the same proposal from a
            // different signer subset. Certification belongs to the proposal,
            // not to one encoding of its aggregate certificate.
            let votes: Vec<_> = schemes
                .iter()
                .take(3)
                .map(|scheme| Notarize::sign(scheme, notarization.proposal.clone()).unwrap())
                .collect();
            let alternate = Notarization::from_notarizes(&verifier, &votes, &Sequential).unwrap();
            assert_ne!(notarization, alternate);

            // A targeted request can receive the leader's preferred
            // certificate even when the requester already certified it. The
            // duplicate will not produce a second certification callback, so
            // the resolver response must be completed immediately.
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view,
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(alternate).encode(),
                    targeted: true,
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert!(actor.held.is_empty());
            assert!(receiver.await.unwrap());
        });
    }

    #[test_async]
    async fn finalization_releases_held_response_by_requested_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context.child("actor"), verifier.clone());
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            let notarized = View::new(8);
            let (response, receiver) = oneshot::channel();
            actor.held.insert(
                notarized,
                vec![HeldResponse {
                    requested,
                    response,
                }],
            );

            let finalized = View::new(6);
            actor.updated(
                &mut resolver,
                Certificate::Finalization(build_finalization(
                    &schemes, &verifier, EPOCH, finalized,
                )),
            );
            assert!(actor.held.is_empty());
            assert!(receiver.await.unwrap());
        });
    }

    #[test_async]
    async fn validate_accepts_nullification_covering_requested_view_in_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(6));
            assert!(View::new(6).same_term(View::new(10), TermLength::new(NZU32!(5))));
            let mut actor = build_actor(context, verifier);

            let validated = actor.validate(
                View::new(10),
                Certificate::<TestScheme, Sha256Digest>::Nullification(nullification.clone())
                    .encode(),
            );

            assert!(matches!(
                validated,
                Some(Certificate::Nullification(parsed)) if parsed.view() == nullification.view()
            ));
        });
    }

    #[test_async]
    async fn validate_rejects_nullification_from_different_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(10));

            let validated = actor.validate(
                View::new(11),
                Certificate::<TestScheme, Sha256Digest>::Nullification(nullification).encode(),
            );

            assert!(validated.is_none());
        });
    }

    #[test_async]
    async fn validate_rejects_nullification_above_requested_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(9));

            let validated = actor.validate(
                View::new(8),
                Certificate::<TestScheme, Sha256Digest>::Nullification(nullification).encode(),
            );

            assert!(validated.is_none());
        });
    }

    #[test_async]
    async fn failed_verdict_survives_higher_certified_floor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();
            let failed = View::new(7);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, failed)),
            );
            actor.certified(&mut resolver, failed, false);

            let floor = View::new(9);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, floor)),
            );
            actor.certified(&mut resolver, floor, true);

            let notarization = build_notarization(&schemes, &verifier, EPOCH, failed);
            assert!(
                actor
                    .validate(failed, Certificate::Notarization(notarization).encode())
                    .is_none()
            );
        });
    }

    #[test_async]
    async fn validate_rejects_finalization_from_different_epoch() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let finalization =
                build_finalization(&schemes, &verifier, Epoch::new(10), View::new(7));

            let validated = actor.validate(
                View::new(7),
                Certificate::Finalization(finalization).encode(),
            );

            assert!(validated.is_none());
        });
    }
}
