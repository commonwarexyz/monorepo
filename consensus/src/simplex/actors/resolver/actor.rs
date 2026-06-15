use super::{
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
    request::{FetchReason, FetchRequest},
    state::Effect,
    Config,
};
use crate::{
    simplex::{
        actors::{resolver::state::State, voter},
        scheme::Scheme,
        types::Certificate,
    },
    types::{Epoch, View},
    Epochable, Viewable,
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::StaticProvider, Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_resolver::{p2p, Fetch, Resolver as _};
use commonware_runtime::{spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{
    channel::fallible::OneshotExt, ordered::Quorum, sequence::U64, vec::NonEmptyVec,
};
use rand_core::CryptoRngCore;
use std::{collections::HashMap, num::NonZeroUsize, time::Duration};
use tracing::{debug, info_span, Span};

/// Requests are made concurrently to multiple peers.
pub struct Actor<
    E: BufferPooler + Clock + CryptoRngCore + Metrics + Spawner,
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

    state: State<S, D>,
    next_fetch_id: u64,
    fetch_spans: HashMap<FetchRequest, Span>,

    mailbox_receiver: mailbox::Receiver<MailboxMessage<S, D>>,
}

impl<
        E: BufferPooler + Clock + CryptoRngCore + Metrics + Spawner,
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
                next_fetch_id: 0,
                fetch_spans: HashMap::new(),

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
                    epoch = %self.epoch,
                    view = %message.view()
                );
                let _guard = span.entered();
                match message {
                    MailboxMessage::Certificate { certificate, .. } => {
                        // Certificates from mailbox have no associated request view
                        let effects = self.state.handle(certificate, None);
                        self.apply_effects(&mut resolver, effects);
                    }
                    MailboxMessage::Certified { round, success, .. } => {
                        let effects = self.state.handle_certified(round.view(), success);
                        self.apply_effects(&mut resolver, effects);
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

    const fn next_fetch_request(
        &mut self,
        view: View,
        cause: View,
        reason: FetchReason,
    ) -> FetchRequest {
        let request = FetchRequest::new(self.next_fetch_id, view, cause, reason);
        self.next_fetch_id = self.next_fetch_id.wrapping_add(1);
        request
    }

    fn apply_effects(
        &mut self,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey, FetchRequest>,
        effects: Vec<Effect>,
    ) {
        for effect in effects {
            match effect {
                Effect::Fetch {
                    view,
                    cause,
                    reason,
                } => self.fetch(resolver, view, cause, reason),
                Effect::Remove(view) => self.remove(resolver, view),
                Effect::RetainAbove(floor) => self.retain_above(resolver, floor),
            }
        }
    }

    fn retain_fetches(
        &mut self,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey, FetchRequest>,
        predicate: impl Fn(&FetchRequest) -> bool + Copy + Send + 'static,
    ) {
        self.fetch_spans.retain(|request, _| predicate(request));
        let _ = resolver.retain(move |_, request| predicate(request));
    }

    fn remove(&mut self, resolver: &mut p2p::Mailbox<U64, S::PublicKey, FetchRequest>, view: View) {
        self.retain_fetches(resolver, move |request| request.view != view);
    }

    fn retain_above(
        &mut self,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey, FetchRequest>,
        floor: View,
    ) {
        self.retain_fetches(resolver, move |request| request.view > floor);
    }

    fn fetch(
        &mut self,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey, FetchRequest>,
        view: View,
        cause: View,
        reason: FetchReason,
    ) {
        let request = self.next_fetch_request(view, cause, reason);
        let span = info_span!(
            "simplex.resolver.fetch",
            id = request.id,
            epoch = %self.epoch,
            cause = %cause,
            view = %view,
            reason = reason.as_str()
        );
        let feedback = span.in_scope(|| {
            resolver.fetch(Fetch {
                key: U64::from(view),
                subscriber: request,
            })
        });
        if feedback.accepted() {
            self.fetch_spans.insert(request, span);
        }
    }

    fn request_span(
        &self,
        subscribers: &NonEmptyVec<FetchRequest>,
    ) -> Option<(FetchRequest, Span)> {
        subscribers.iter().find_map(|request| {
            self.fetch_spans
                .get(request)
                .map(|span| (*request, span.clone()))
        })
    }

    fn close_fetches(&mut self, subscribers: &NonEmptyVec<FetchRequest>) {
        for request in subscribers {
            self.fetch_spans.remove(request);
        }
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
    fn handle_resolver(
        &mut self,
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey, FetchRequest>,
    ) {
        match message {
            HandlerMessage::Deliver {
                view,
                subscribers,
                data,
                response,
            } => {
                let request = self.request_span(&subscribers);
                let parent = request
                    .as_ref()
                    .map(|(_, span)| span.clone())
                    .unwrap_or_else(Span::none);
                let cause = request.as_ref().map_or(view, |(request, _)| request.cause);
                let reason = request
                    .as_ref()
                    .map(|(request, _)| request.reason.as_str())
                    .unwrap_or("unknown");
                let span = info_span!(
                    parent: parent,
                    "simplex.resolver.deliver",
                    epoch = %self.epoch,
                    cause = %cause,
                    view = %view,
                    reason,
                    subscribers = subscribers.len()
                );
                let _guard = span.entered();

                // Validate incoming message
                let validate = info_span!(
                    "simplex.resolver.validate",
                    epoch = %self.epoch,
                    view = %view
                );
                let Some(parsed) = validate.in_scope(|| self.validate(view, data)) else {
                    // Resolver will block any peers that send invalid responses, so
                    // we don't need to do again here
                    response.send_lossy(false);
                    return;
                };
                response.send_lossy(true);

                // Notify voter as soon as possible
                let resolved = info_span!(
                    "simplex.resolver.resolve",
                    epoch = %self.epoch,
                    view = %view,
                    certificate_view = %parsed.view()
                );
                resolved.in_scope(|| voter.resolved(parsed.clone()));

                // Process message with the request view for tracking
                let effects = self.state.handle(parsed, Some(view));
                self.apply_effects(resolver, effects);
                self.close_fetches(&subscribers);
            }
            HandlerMessage::Produce { view, response } => {
                let span = info_span!(
                    "simplex.resolver.produce",
                    epoch = %self.epoch,
                    view = %view
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
