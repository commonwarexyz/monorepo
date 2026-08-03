use super::{
    super::{Demand, Kind, Until},
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
use commonware_resolver::{Fetch, Outcome, Resolver, TargetedResolver, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    channel::fallible::OneshotExt, ordered::Quorum, sequence::U64, vec::NonEmptyVec,
};
use rand::RngExt as _;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    time::Duration,
};
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

    /// Highest finalized view observed. Targeted ancestry at or below this
    /// view can no longer be required by a valid proposal.
    last_finalized: View,

    /// Nullifications cached in the encoded form expected by [p2p::Producer].
    /// These response payloads remain available while they cover views above
    /// finalization so a demand below the floor can still be served.
    nullification_responses: BTreeMap<View, Bytes>,

    /// Notarizations cached in the encoded form expected by [p2p::Producer].
    /// These response payloads remain available until finalization so exact
    /// parents survive later floor raises. A view whose certification fails is
    /// removed: no copy of that notarization can certify anywhere.
    notarization_responses: BTreeMap<View, Bytes>,

    /// Views whose certification failed, retained until covering finalization.
    ///
    /// This is the sole record of a failed verdict. [State] prunes at the floor,
    /// which rises above a failed view while a delayed request for it can still
    /// arrive, so the tombstone is kept here against the finalization boundary.
    failed_certifications: BTreeSet<View>,

    /// Certificates still wanted from peers, paired with what retires each.
    ///
    /// This mirrors the resolver's outstanding fetches. Owning them here keeps
    /// retirement in one place: [Self::settled] decides it from local evidence,
    /// and [Self::sync_demands] publishes the survivors to the resolver.
    demands: BTreeSet<(View, Demand)>,

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
                nullification_responses: BTreeMap::new(),
                notarization_responses: BTreeMap::new(),
                failed_certifications: BTreeSet::new(),
                demands: BTreeSet::new(),

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
                        kind,
                        target,
                        ..
                    } => {
                        self.resolve(&mut resolver, proposal_view, view, kind, target);
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
    fn updated<R: Resolver<Key = U64, Subscriber = Demand>>(
        &mut self,
        resolver: &mut R,
        certificate: Certificate<S, D>,
    ) {
        let (finalized, nullified, notarized) = match &certificate {
            Certificate::Finalization(finalization) => (Some(finalization.view()), None, None),
            Certificate::Nullification(nullification) => (None, Some(nullification.view()), None),
            Certificate::Notarization(notarization) => (None, None, Some(notarization.view())),
        };

        // Cache response payloads for as long as a peer can still ask for them.
        // [State] prunes at the floor, which rises sooner than finalization and
        // would hide this evidence from a peer still repairing the view.
        if let Some(nullified) = nullified
            && nullified.term_end(self.state.term_length()) > self.last_finalized
        {
            self.nullification_responses
                .insert(nullified, certificate.encode());
        }
        if let Some(notarized) = notarized
            && notarized > self.last_finalized
            && !self.failed_certifications.contains(&notarized)
        {
            self.notarization_responses
                .insert(notarized, certificate.encode());
        }

        // Finalization is the global retirement boundary: a valid proposal can no
        // longer name ancestry at or below it, so nothing here can still be asked
        // for. Demands below it are dropped by [Self::sync_demands], which treats
        // a finalized view as settled.
        if let Some(finalized) = finalized {
            self.last_finalized = self.last_finalized.max(finalized);
            let term_length = self.state.term_length();
            self.nullification_responses
                .retain(|view, _| view.term_end(term_length) > self.last_finalized);
            self.notarization_responses
                .retain(|view, _| *view > self.last_finalized);
            self.failed_certifications
                .retain(|view| *view > self.last_finalized);
        }

        // Certificate state owns floor selection and background repair.
        let effects = self.state.handle(certificate);
        self.apply_effects(resolver, effects);
    }

    /// Handles a certification outcome from the voter.
    fn certified<R: Resolver<Key = U64, Subscriber = Demand>>(
        &mut self,
        resolver: &mut R,
        view: View,
        success: bool,
    ) {
        // No copy of an uncertifiable notarization can certify anywhere, so it
        // is not an answer to an exact-parent request.
        if !success {
            self.notarization_responses.remove(&view);
            if view > self.last_finalized {
                self.failed_certifications.insert(view);
            }
        }

        let effects = self.state.handle_certified(view, success);
        self.apply_effects(resolver, effects);
    }

    /// Applies the side effects requested by [super::state::State] to the resolver.
    ///
    /// Call this after recording new evidence: it ends by syncing the resolver to
    /// the surviving demands, which is what publishes both the effects below and
    /// the evidence recorded by the caller.
    fn apply_effects<R: Resolver<Key = U64, Subscriber = Demand>>(
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
                    // Resolver state does not repair below its floor, so a
                    // background demand there has nothing left to do. This is
                    // the only retirement that depends on the floor:
                    // [Self::settled] cannot use it, because a proposal may name
                    // ancestry below the floor and only finalization rules that
                    // out.
                    self.demands
                        .retain(|(view, demand)| demand.until != Until::Floor || *view > floor);
                }
            }
        }

        self.sync_demands(resolver);
    }

    /// Drops settled demands and mirrors the survivors into the resolver.
    ///
    /// [Resolver::retain] takes a `'static` predicate and so cannot consult
    /// [Self::settled] directly, which is why the survivors are snapshotted into
    /// it.
    fn sync_demands<R: Resolver<Key = U64, Subscriber = Demand>>(&mut self, resolver: &mut R) {
        let live: BTreeSet<_> = self
            .demands
            .iter()
            .copied()
            .filter(|(view, demand)| !self.settled(*view, demand.kind))
            .collect();
        self.demands = live.clone();
        let _ = resolver
            .retain(move |key, demand| live.contains(&(View::new(u64::from(key)), *demand)));
    }

    /// Issues a background fetch for the nullification covering `view`.
    ///
    /// Both [FetchReason]s want the same certificate: [State] only ever reports
    /// a view whose covering nullification is missing, whether the gap was found
    /// by scanning below the current view or opened by a failed certification.
    fn fetch<R: Resolver<Key = U64, Subscriber = Demand>>(
        &mut self,
        resolver: &mut R,
        view: View,
        cause: View,
        reason: FetchReason,
    ) {
        let demand = Demand::backfill();
        self.demands.insert((view, demand));
        let span = info_span!(
            "simplex.resolver.fetch",
            epoch = self.epoch.traced(),
            cause = cause.traced(),
            view = view.traced(),
            reason = reason.as_str(),
            kind = demand.kind.as_str()
        );
        let _ = resolver.fetch(Fetch {
            key: U64::from(view),
            subscriber: demand,
            span,
        });
    }

    /// Fetches ancestry from the leader whose proposal requires it.
    fn resolve<R>(
        &mut self,
        resolver: &mut R,
        proposal_view: View,
        view: View,
        kind: Kind,
        target: S::PublicKey,
    ) where
        R: TargetedResolver<Key = U64, Subscriber = Demand, PublicKey = S::PublicKey>,
    {
        if view >= proposal_view || self.settled(view, kind) {
            return;
        }
        let demand = Demand::ancestry(kind);
        self.demands.insert((view, demand));
        let span = info_span!(
            "simplex.resolver.fetch",
            epoch = self.epoch.traced(),
            cause = proposal_view.traced(),
            view = view.traced(),
            reason = "proposal_ancestry",
            kind = demand.kind.as_str()
        );
        let _ = resolver.fetch_targeted(
            Fetch {
                key: U64::from(view),
                subscriber: demand,
                span,
            },
            NonEmptyVec::new(target),
        );
    }

    /// Returns whether local evidence has settled a demand for `kind` at `view`.
    ///
    /// Settled means there is nothing left to fetch: either the evidence is in
    /// hand, or no response could ever serve the demand. This decides whether to
    /// open a fetch, whether a delivery completed one, and which demands survive
    /// [Self::sync_demands].
    ///
    /// A valid response does not imply this. The wire key names only a view, so a
    /// peer may answer a notarization request with a covering nullification: valid
    /// evidence, worth recording, but not what was asked for.
    fn settled(&self, view: View, kind: Kind) -> bool {
        // Finalization rules out any further need for the view. This is also
        // what settles a demand answered by a finalization, since recording one
        // raises [Self::last_finalized].
        if view <= self.last_finalized {
            return true;
        }
        match kind {
            Kind::Nullification => self.covering_nullification(view).is_some(),
            // Holding the notarization settles this, and so does a failed
            // verdict: certification is an application judgement on the
            // evidence itself, so no other copy of it could pass either.
            Kind::Notarization => {
                self.notarization_responses.contains_key(&view)
                    || self.failed_certifications.contains(&view)
            }
        }
    }

    /// Returns the cached nullification covering `view`, if any.
    ///
    /// A nullification covers the rest of its term, so it may be keyed at an
    /// earlier view than the one being served.
    fn covering_nullification(&self, view: View) -> Option<&Bytes> {
        self.nullification_responses
            .range(view.covering_range(self.state.term_length()))
            .next_back()
            .map(|(_, nullification)| nullification)
    }

    /// Selects a certificate to serve for `view`.
    ///
    /// The request does not say which certificate it wants, so when both a
    /// notarization and a covering nullification are held either may be the one
    /// the requester needs. The choice is random: a fixed preference
    /// would answer every retry from a requester wanting the other
    /// kind with the same useless certificate.
    fn produce_certificate(&mut self, view: View) -> Option<Bytes> {
        // A finalization settles either kind, so weaker evidence would only
        // delay the requester.
        if let Some(certificate @ Certificate::Finalization(_)) = self.state.get(view) {
            return Some(certificate.encode());
        }

        let notarization = self.notarization_responses.get(&view).cloned();
        let nullification = self.covering_nullification(view).cloned();
        match (notarization, nullification) {
            (Some(notarization), Some(nullification)) => {
                Some(if self.context.random_range(0..2) == 0 {
                    notarization
                } else {
                    nullification
                })
            }
            (Some(certificate), None) | (None, Some(certificate)) => Some(certificate),
            // Either cached response also serves ordinary backfill, so the floor
            // adds no response the requester could not already have.
            (None, None) => self.state.get(view).map(|certificate| certificate.encode()),
        }
    }

    /// Validates an incoming message, returning the parsed message if valid.
    ///
    /// Validity is judged against `view` alone, because that is all the request
    /// named. Any certificate an honest peer could serve for the view is accepted,
    /// including one that answers the other kind: rejecting it would fault a peer
    /// that answered the only question the wire key asked. Whether it
    /// settles the demand is a separate judgement (see [Self::settled]).
    fn validate(&mut self, view: View, data: Bytes) -> Option<Certificate<S, D>> {
        let incoming =
            Certificate::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config()).ok()?;

        // A nullification covers the rest of its term. A notarization or
        // finalization is servable from a peer's floor, which may sit above the
        // requested view.
        let servable = match &incoming {
            Certificate::Nullification(nullification) => {
                nullification.view().covers(view, self.state.term_length())
            }
            Certificate::Notarization(notarization) => notarization.view() >= view,
            Certificate::Finalization(finalization) => finalization.view() >= view,
        };
        if !servable {
            debug!(%view, received = %incoming.view(), "certificate below requested view");
            return None;
        }

        if incoming.epoch() != self.epoch {
            debug!(
                %view,
                epoch = %incoming.epoch(),
                expected = %self.epoch,
                "rejecting certificate from different epoch"
            );
            return None;
        }

        let verified = match &incoming {
            Certificate::Notarization(notarization) => {
                notarization.verify(self.context.as_mut(), &self.scheme, &self.strategy)
            }
            Certificate::Nullification(nullification) => {
                nullification.verify::<_, D>(self.context.as_mut(), &self.scheme, &self.strategy)
            }
            Certificate::Finalization(finalization) => {
                finalization.verify(self.context.as_mut(), &self.scheme, &self.strategy)
            }
        };
        if !verified {
            debug!(%view, "certificate failed verification");
            return None;
        }

        debug!(%view, received = %incoming.view(), "received certificate for request");
        Some(incoming)
    }

    /// Handles a message from the [p2p::Engine].
    fn handle_resolver<R: Resolver<Key = U64, Subscriber = Demand>>(
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
                demands,
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
                    response.send_lossy(Outcome::Invalid);
                    return;
                };

                // A failed notarization remains valid protocol evidence, but
                // replaying it cannot satisfy any outstanding repair demand.
                let obsolete = matches!(
                    &parsed,
                    Certificate::Notarization(notarization)
                        if self.failed_certifications.contains(&notarization.view())
                );
                if !obsolete {
                    // Notify voter as soon as possible.
                    let resolved = info_span!(
                        "simplex.resolver.resolved",
                        epoch = self.epoch.traced(),
                        view = view.traced(),
                        certificate_view = parsed.view().traced()
                    );
                    resolved.in_scope(|| voter.resolved(parsed.clone()));

                    // Record the certificate, which settles whichever demands it
                    // answered and retires their fetches.
                    self.updated(resolver, parsed);
                }

                // The peer answered the view it was asked about, so it is never
                // faulted here. Whether that answer was the certificate anyone
                // wanted is a separate question: if a demand for this view is
                // still open, the response was valid but ambiguous, and the
                // resolver retries without penalizing the peer.
                let outcome = if demands.iter().all(|demand| self.settled(view, demand.kind)) {
                    Outcome::Complete
                } else {
                    Outcome::Ambiguous
                };
                response.send_lossy(outcome);
            }
            HandlerMessage::Produce { view, response } => {
                let span = info_span!(
                    "simplex.resolver.produce",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Produce message for view
                let Some(certificate) = self.produce_certificate(view) else {
                    // If we drop the response channel, the resolver will automatically
                    // send an error response to the caller (so they don't need to wait
                    // the full timeout)
                    return;
                };
                response.send_lossy(certificate);
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
    use commonware_utils::{NZU32, NZUsize, channel::oneshot, non_empty_vec, sync::Mutex};
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
        outstanding: Arc<Mutex<BTreeSet<(U64, Demand)>>>,
        targeted: Arc<Mutex<Vec<(U64, Demand, PublicKey)>>>,
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

        fn targeted(&self) -> Vec<(u64, Demand, PublicKey)> {
            self.targeted
                .lock()
                .iter()
                .map(|(key, subscription, target)| (u64::from(key), *subscription, target.clone()))
                .collect()
        }

        fn subscriptions(&self, view: u64) -> Vec<Demand> {
            self.outstanding
                .lock()
                .iter()
                .filter_map(|(key, subscription)| (u64::from(key) == view).then_some(*subscription))
                .collect()
        }
    }

    impl Resolver for RecordingResolver {
        type Key = U64;
        type Subscriber = Demand;

        fn fetch<F>(&mut self, key: F) -> Feedback
        where
            F: Into<Fetch<U64, Demand>> + Send,
        {
            let fetch = key.into();
            self.outstanding
                .lock()
                .insert((fetch.key, fetch.subscriber));
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
        where
            F: Into<Fetch<U64, Demand>> + Send,
        {
            for key in keys {
                self.fetch(key);
            }
            Feedback::Ok
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&U64, &Demand) -> bool + Send + 'static,
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
            fetch: impl Into<Fetch<U64, Demand>> + Send,
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
            F: Into<Fetch<U64, Demand>> + Send,
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
                Kind::Nullification,
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

    /// A valid notarization with pending certification does not prevent a
    /// different peer from supplying the requested nullification.
    #[test_async]
    async fn pending_certification_does_not_block_nullification_fetch() {
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
            oracle
                .remove_link(participants[0].clone(), participants[1].clone())
                .await
                .unwrap();
            oracle
                .remove_link(participants[1].clone(), participants[0].clone())
                .await
                .unwrap();
            context.sleep(Duration::from_millis(10)).await;

            // A proposal objection for the same view attaches another
            // subscriber. Certification remains pending, but the valid
            // notarization must release the network slot so another peer can
            // supply the nullification that this proposal actually needs.
            requester_mailbox.resolve(
                View::new(3),
                requested,
                Kind::Nullification,
                participants[2].clone(),
            );
            let recovered = select! {
                message = requester_voter_receiver.recv() => {
                    message.expect("voter mailbox closed")
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("pending certification blocked ancestry repair");
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
    async fn targeted_fetches_drop_only_when_demand_is_satisfied() {
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
                Kind::Nullification,
                participants[0].clone(),
            );
            actor.resolve(
                &mut resolver,
                View::new(11),
                requested,
                Kind::Notarization,
                participants[1].clone(),
            );
            resolver.fetch(Fetch {
                key: U64::from(requested),
                subscriber: Demand::backfill(),
                span: tracing::Span::none(),
            });
            assert_eq!(
                resolver.targeted(),
                vec![
                    (
                        3,
                        Demand::ancestry(Kind::Nullification),
                        participants[0].clone()
                    ),
                    (
                        3,
                        Demand::ancestry(Kind::Notarization),
                        participants[1].clone()
                    ),
                ]
            );
            assert_eq!(
                resolver.subscriptions(3),
                vec![
                    Demand::backfill(),
                    Demand::ancestry(Kind::Nullification),
                    Demand::ancestry(Kind::Notarization),
                ]
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
            assert_eq!(
                resolver.subscriptions(3),
                vec![Demand::ancestry(Kind::Notarization)]
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                requested,
                Kind::Nullification,
                participants[2].clone(),
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                requested.next(),
                Kind::Nullification,
                participants[2].clone(),
            );
            assert_eq!(resolver.targeted().len(), 2);

            // Exercise the mirror case at another key. Holding the exact
            // parent completes only the targeted parent request. It does not
            // provide the nullification needed to skip that view.
            let second_requested = requested.next_term_start(actor.state.term_length());
            actor.resolve(
                &mut resolver,
                View::new(12),
                second_requested,
                Kind::Nullification,
                participants[2].clone(),
            );
            actor.resolve(
                &mut resolver,
                View::new(13),
                second_requested,
                Kind::Notarization,
                participants[3].clone(),
            );
            resolver.fetch(Fetch {
                key: U64::from(second_requested),
                subscriber: Demand::backfill(),
                span: tracing::Span::none(),
            });
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(
                    &schemes,
                    &verifier,
                    EPOCH,
                    second_requested,
                )),
            );
            actor.certified(&mut resolver, second_requested, true);

            // The certified notarization is now the floor, which satisfies
            // background repair at that view. Targeted nullification demand
            // survives: a notarization is not a nullification covering it.
            assert_eq!(
                resolver.subscriptions(6),
                vec![Demand::ancestry(Kind::Nullification)]
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                second_requested,
                Kind::Notarization,
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
            assert!(actor.nullification_responses.is_empty());
            assert!(actor.notarization_responses.is_empty());
            assert!(actor.failed_certifications.is_empty());
            actor.resolve(
                &mut resolver,
                finalized.next(),
                requested,
                Kind::Notarization,
                participants[0].clone(),
            );
            assert!(resolver.outstanding().is_empty());
            assert_eq!(resolver.targeted().len(), 4);
        });
    }

    #[test_async]
    async fn concurrent_kindless_retries_serve_required_ancestry() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let term_length = TermLength::new(NZU32!(5));
            let mut responder = build_actor_with_term_length(
                context.child("responder"),
                verifier.clone(),
                term_length,
            );
            let mut responder_resolver = RecordingResolver::default();

            let requested = View::new(3);
            let nullification = Certificate::Nullification(build_nullification(
                &schemes, &verifier, EPOCH, requested,
            ));
            let expected_nullification = nullification.encode();
            responder.updated(&mut responder_resolver, nullification);
            let parent = build_notarization(&schemes, &verifier, EPOCH, requested);
            let expected_parent = Certificate::Notarization(parent.clone()).encode();
            responder.updated(&mut responder_resolver, Certificate::Notarization(parent));
            responder.certified(&mut responder_resolver, requested, true);
            let floor = View::new(4);
            let floor_notarization = build_notarization(&schemes, &verifier, EPOCH, floor);
            responder.updated(
                &mut responder_resolver,
                Certificate::Notarization(floor_notarization),
            );
            responder.certified(&mut responder_resolver, floor, true);

            let mut first_saw_nullification = false;
            let mut second_saw_parent = false;
            for _ in 0..32 {
                // Interleave two requesters so a shared two-class rotation
                // would pin each one to the evidence needed by the other.
                first_saw_nullification |= responder
                    .produce_certificate(requested)
                    .expect("responder has ancestry")
                    == expected_nullification;
                second_saw_parent |= responder
                    .produce_certificate(requested)
                    .expect("responder has ancestry")
                    == expected_parent;
            }

            assert!(
                first_saw_nullification,
                "first requester stayed pinned to the exact parent"
            );
            assert!(
                second_saw_parent,
                "second requester stayed pinned to the nullification"
            );
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
                Kind::Nullification,
                participants[0].clone(),
            );
            assert_eq!(
                resolver.subscriptions(3),
                vec![Demand::ancestry(Kind::Nullification)]
            );

            // Certificate state still prefers the certified floor for
            // background bookkeeping, but locally observing the nullification
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
                Kind::Nullification,
                participants[1].clone(),
            );
            assert_eq!(resolver.targeted().len(), 1);
        });
    }

    #[test_async]
    async fn higher_certified_floor_does_not_suppress_exact_parent_fetch() {
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
            let floor = View::new(6);

            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, floor)),
            );
            actor.certified(&mut resolver, floor, true);

            actor.resolve(
                &mut resolver,
                View::new(8),
                View::new(4),
                Kind::Notarization,
                participants[0].clone(),
            );
            assert_eq!(
                resolver.targeted(),
                vec![(
                    4,
                    Demand::ancestry(Kind::Notarization),
                    participants[0].clone()
                )]
            );
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
                Kind::Notarization,
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
            assert_eq!(resolver.subscriptions(5), vec![Demand::backfill()]);
            actor.resolve(
                &mut resolver,
                View::new(11),
                view,
                Kind::Notarization,
                participants[1].clone(),
            );
            assert_eq!(resolver.targeted().len(), 1);
        });
    }

    #[test_async]
    async fn parent_delivery_completes_on_possession_not_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone());
            let mut resolver = RecordingResolver::default();
            let view = View::new(6);

            // The exact parent was asked for and arrived. Certification is an
            // application verdict on evidence already in hand, so the fetch has
            // nothing left to retrieve and must not stay open waiting for it.
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view,
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(
                        build_notarization(&schemes, &verifier, EPOCH, view),
                    )
                    .encode(),
                    demands: non_empty_vec![Demand::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
            assert!(actor.notarization_responses.contains_key(&view));
        });
    }

    #[test_async]
    async fn failed_certification_retires_parent_demand_until_finalization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes,
                verifier,
                participants,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();
            let view = View::new(6);

            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, view)),
            );
            actor.certified(&mut resolver, view, false);

            // The payload is no longer an answer, and the tombstone keeps a
            // delayed request from recreating demand. A floor raise above the
            // view must not resurrect it (state prunes its own failed views).
            assert!(!actor.notarization_responses.contains_key(&view));
            let floor = View::new(9);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, floor)),
            );
            actor.certified(&mut resolver, floor, true);

            let targeted = resolver.targeted().len();
            actor.resolve(
                &mut resolver,
                View::new(11),
                view,
                Kind::Notarization,
                participants[0].clone(),
            );
            assert_eq!(resolver.targeted().len(), targeted);
        });
    }

    #[test_async]
    async fn valid_nullification_does_not_complete_parent_delivery() {
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
                    demands: non_empty_vec![Demand::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert_eq!(receiver.await.unwrap(), Outcome::Ambiguous);
        });
    }

    #[test_async]
    async fn unrelated_higher_certified_notarization_does_not_complete_parent_delivery() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone());
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(6));
            actor.updated(
                &mut resolver,
                Certificate::Notarization(notarization.clone()),
            );
            actor.certified(&mut resolver, View::new(6), true);
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(notarization)
                        .encode(),
                    demands: non_empty_vec![Demand::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Ambiguous);
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
                    demands: non_empty_vec![Demand::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
        });
    }

    #[test_async]
    async fn finalization_completes_every_delivery_demand() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone());
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data: Certificate::<TestScheme, Sha256Digest>::Finalization(
                        build_finalization(&schemes, &verifier, EPOCH, View::new(6)),
                    )
                    .encode(),
                    demands: non_empty_vec![
                        Demand::backfill(),
                        Demand::ancestry(Kind::Nullification),
                        Demand::ancestry(Kind::Notarization),
                    ],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
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
            assert!(actor.failed_certifications.contains(&failed));
            assert!(!actor.notarization_responses.contains_key(&failed));
            assert!(
                actor
                    .validate(failed, Certificate::Notarization(notarization).encode())
                    .is_some(),
                "failed certification does not make signed protocol evidence invalid",
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
