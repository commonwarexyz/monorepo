use super::{
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
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
use commonware_resolver::p2p;
use commonware_runtime::{spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{channel::fallible::OneshotExt, ordered::Quorum, sequence::U64};
use rand_core::CryptoRngCore;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::debug;

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
    term_length: NonZeroU64,
    fetch_timeout: Duration,

    state: State<S, D>,

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
        let (sender, receiver) = mailbox::new(cfg.mailbox_size);
        let fetch_concurrent = NonZeroU64::new(
            cfg.fetch_concurrent
                .get()
                .try_into()
                .expect("fetch_concurrent must fit in u64"),
        )
        .expect("fetch_concurrent is non-zero");
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,
                blocker: Some(cfg.blocker),
                strategy: cfg.strategy,

                epoch: cfg.epoch,
                term_length: cfg.term_length,
                mailbox_size: cfg.mailbox_size,
                fetch_timeout: cfg.fetch_timeout,

                state: State::new(fetch_concurrent, cfg.term_length),

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

        let (handler_tx, mut handler_rx) = mailbox::new(self.mailbox_size);
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
                match message {
                    MailboxMessage::Certificate(certificate) => {
                        // Certificates from mailbox have no associated request view
                        self.state.handle(certificate, None, &mut resolver);
                    }
                    MailboxMessage::Certified { view, success } => {
                        self.state
                            .handle_certified(view, success, &mut resolver)
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
                let nullified_view = nullification.view();
                if view < nullified_view || !nullified_view.same_term(view, self.term_length) {
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
    fn handle_resolver(
        &mut self,
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey>,
    ) {
        match message {
            HandlerMessage::Deliver {
                view,
                data,
                response,
            } => {
                // Validate incoming message
                let Some(parsed) = self.validate(view, data) else {
                    // Resolver will block any peers that send invalid responses, so
                    // we don't need to do again here
                    response.send_lossy(false);
                    return;
                };
                response.send_lossy(true);

                // Notify voter as soon as possible
                voter.resolved(parsed.clone());

                // Process message with the request view for tracking
                self.state.handle(parsed, Some(view), resolver);
            }
            HandlerMessage::Produce { view, response } => {
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
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
            },
        },
        types::Round,
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_async;
    use commonware_parallel::Sequential;
    use commonware_resolver::Resolver;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::{NZUsize, NZU64};

    const NAMESPACE: &[u8] = b"resolver-actor";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;
    type TestActor =
        Actor<deterministic::Context, TestScheme, NoopBlocker, Sha256Digest, Sequential>;

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = PublicKey;

        async fn block(&mut self, _peer: Self::PublicKey) {}
    }

    #[derive(Clone, Default)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        type Key = U64;
        type PublicKey = PublicKey;

        fn fetch(&mut self, _key: U64) -> Feedback {
            Feedback::Ok
        }

        fn fetch_all(&mut self, _keys: Vec<U64>) -> Feedback {
            Feedback::Ok
        }

        fn fetch_targeted(
            &mut self,
            _key: U64,
            _targets: commonware_utils::vec::NonEmptyVec<PublicKey>,
        ) -> Feedback {
            Feedback::Ok
        }

        fn fetch_all_targeted(
            &mut self,
            _requests: Vec<(U64, commonware_utils::vec::NonEmptyVec<PublicKey>)>,
        ) -> Feedback {
            Feedback::Ok
        }

        fn cancel(&mut self, _key: U64) -> Feedback {
            Feedback::Ok
        }

        fn clear(&mut self) -> Feedback {
            Feedback::Ok
        }

        fn retain(&mut self, _predicate: impl Fn(&Self::Key) -> bool + Send + 'static) -> Feedback {
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
                term_length: NZU64!(5),
            },
        );
        actor
    }

    fn build_nullification(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Nullification<TestScheme> {
        let round = Round::new(epoch, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(verifier, &votes, &Sequential).expect("nullification quorum")
    }

    fn build_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Notarization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(verifier, &votes, &Sequential).expect("notarization quorum")
    }

    fn build_finalization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(verifier, &votes, &Sequential).expect("finalization quorum")
    }

    #[test_async]
    async fn validate_accepts_nullification_covering_requested_view_in_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(6));
            assert!(View::new(6).same_term(View::new(10), NZU64!(5)));
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
    async fn validate_rejects_notarization_for_failed_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone());
            let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(7));
            actor
                .state
                .handle_certified(View::new(7), false, &mut NoopResolver);

            let validated = actor.validate(
                View::new(7),
                Certificate::Notarization(notarization).encode(),
            );

            assert!(validated.is_none());
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
