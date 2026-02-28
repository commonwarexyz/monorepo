//! Resolver actor implementation.

use super::{
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
    state::State,
    Config,
};
use crate::{
    minimmit::{actors::voter, scheme::Scheme, types::Certificate},
    types::{Epoch, View},
    Epochable, Viewable,
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::StaticProvider, Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_resolver::{p2p, Resolver};
use commonware_runtime::{spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc},
    ordered::Quorum,
    sequence::U64,
};
use rand_core::CryptoRngCore;
use std::{collections::BTreeSet, time::Duration};
use tracing::debug;

/// Resolver actor for Minimmit consensus.
///
/// The resolver fetches missing certificates from peers to enable view progression.
/// Unlike simplex, minimmit has no certification phase - MNotarizations and
/// Finalizations can be used directly without additional verification.
pub struct Actor<E, S, B, D, T>
where
    E: Clock + CryptoRngCore + Spawner + Metrics,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
{
    context: ContextCell<E>,
    scheme: S,
    blocker: Option<B>,
    strategy: T,

    epoch: Epoch,
    mailbox_size: usize,
    fetch_timeout: Duration,

    state: State<S, D>,
    pending_refetch: BTreeSet<View>,

    mailbox_receiver: mpsc::Receiver<MailboxMessage<S, D>>,
}

impl<E, S, B, D, T> Actor<E, S, B, D, T>
where
    E: BufferPooler + Clock + CryptoRngCore + Spawner + Metrics,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
{
    /// Create a new resolver actor.
    pub fn new(context: E, cfg: Config<S, B, T>) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
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
                pending_refetch: BTreeSet::new(),

                mailbox_receiver: receiver,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the resolver actor.
    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, sender, receiver).await)
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

        let (handler_tx, mut handler_rx) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler_tx);

        let (resolver_engine, mut resolver) = p2p::Engine::new(
            self.context.with_label("resolver"),
            p2p::Config {
                provider: StaticProvider::new(self.epoch.get(), participants),
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
                        self.pending_refetch.remove(&certificate.view());
                        self.state.handle(certificate, &mut resolver).await;
                    }
                }
            },
            Some(message) = handler_rx.recv() else break => {
                self.handle_resolver(message, &mut voter, &mut resolver).await;
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
            Certificate::MNotarization(m_notarization) => {
                let m_notarization_view = m_notarization.view();
                if m_notarization_view < view {
                    debug!(%view, received = %m_notarization_view, "m-notarization below view");
                    return None;
                }
                if m_notarization.epoch() != self.epoch {
                    debug!(
                        epoch = %m_notarization.epoch(),
                        expected = %self.epoch,
                        "rejecting m-notarization from different epoch"
                    );
                    return None;
                }
                if !m_notarization.verify(&mut self.context, &self.scheme, &self.strategy) {
                    debug!(%view, "m-notarization failed verification");
                    return None;
                }
                debug!(%view, received = %m_notarization_view, "received m-notarization for request");
                Some(Certificate::MNotarization(m_notarization))
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
                if !finalization.verify(&mut self.context, &self.scheme, &self.strategy) {
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
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.strategy) {
                    debug!(%view, "nullification failed verification");
                    return None;
                }
                debug!(%view, received = %nullification.view(), "received nullification for request");
                Some(Certificate::Nullification(nullification))
            }
        }
    }

    /// Handles a message from the [p2p::Engine].
    async fn handle_resolver(
        &mut self,
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut impl Resolver<Key = U64, PublicKey = S::PublicKey>,
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
                // Keep resolver semantics: valid certificate means successful delivery.
                // If the voter mailbox is full, re-fetch so we can retry local handoff.
                if !voter.resolved_certificate(parsed.clone()) {
                    debug!(%view, "voter mailbox full, re-fetching resolved certificate");
                    response.send_lossy(true);
                    if self.pending_refetch.insert(view) {
                        resolver.fetch(view.into()).await;
                    }
                    return;
                }

                self.pending_refetch.remove(&view);

                // Process message
                response.send_lossy(true);
                self.state.handle(parsed, resolver).await;
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
        minimmit::{
            actors::resolver::Config,
            scheme::ed25519,
            types::{Certificate, MNotarization, Notarize, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey as Ed25519PublicKey,
        sha256::Digest as Sha256Digest,
    };
    use commonware_p2p::Blocker;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::{
        channel::{mpsc, oneshot},
        sync::Mutex,
        test_rng,
        vec::NonEmptyVec,
    };
    use std::{collections::BTreeSet, sync::Arc, time::Duration};

    const NAMESPACE: &[u8] = b"minimmit-resolver-actor";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = Ed25519PublicKey;

        async fn block(&mut self, _peer: Self::PublicKey) {}
    }

    #[derive(Clone, Default)]
    struct MockResolver {
        fetched: Arc<Mutex<BTreeSet<U64>>>,
    }

    impl MockResolver {
        fn fetched(&self) -> Vec<u64> {
            self.fetched
                .lock()
                .iter()
                .map(|key| key.clone().into())
                .collect()
        }
    }

    impl Resolver for MockResolver {
        type Key = U64;
        type PublicKey = Ed25519PublicKey;

        async fn fetch(&mut self, key: U64) {
            self.fetched.lock().insert(key);
        }

        async fn fetch_all(&mut self, keys: Vec<U64>) {
            for key in keys {
                self.fetched.lock().insert(key);
            }
        }

        async fn fetch_targeted(&mut self, key: U64, _targets: NonEmptyVec<Self::PublicKey>) {
            self.fetched.lock().insert(key);
        }

        async fn fetch_all_targeted(&mut self, requests: Vec<(U64, NonEmptyVec<Self::PublicKey>)>) {
            for (key, _targets) in requests {
                self.fetched.lock().insert(key);
            }
        }

        async fn cancel(&mut self, key: U64) {
            self.fetched.lock().remove(&key);
        }

        async fn clear(&mut self) {
            self.fetched.lock().clear();
        }

        async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
            self.fetched.lock().retain(|key| predicate(key));
        }
    }

    #[derive(Clone, Default)]
    struct CountingResolver {
        fetched: Arc<Mutex<Vec<U64>>>,
    }

    impl CountingResolver {
        fn fetch_count(&self, key: U64) -> usize {
            self.fetched.lock().iter().filter(|k| *k == &key).count()
        }
    }

    impl Resolver for CountingResolver {
        type Key = U64;
        type PublicKey = Ed25519PublicKey;

        async fn fetch(&mut self, key: U64) {
            self.fetched.lock().push(key);
        }

        async fn fetch_all(&mut self, keys: Vec<U64>) {
            self.fetched.lock().extend(keys);
        }

        async fn fetch_targeted(&mut self, key: U64, _targets: NonEmptyVec<Self::PublicKey>) {
            self.fetched.lock().push(key);
        }

        async fn fetch_all_targeted(&mut self, requests: Vec<(U64, NonEmptyVec<Self::PublicKey>)>) {
            self.fetched
                .lock()
                .extend(requests.into_iter().map(|(key, _)| key));
        }

        async fn cancel(&mut self, _key: U64) {}

        async fn clear(&mut self) {
            self.fetched.lock().clear();
        }

        async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
            self.fetched.lock().retain(predicate);
        }
    }

    fn ed25519_fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, NAMESPACE, 6);
        (schemes, verifier)
    }

    fn build_proposal(view: View) -> Proposal<Sha256Digest> {
        let parent_view = view.previous().unwrap_or(View::zero());
        let parent_payload = Sha256Digest::from([parent_view.get() as u8; 32]);
        Proposal::new(
            Round::new(EPOCH, view),
            parent_view,
            parent_payload,
            Sha256Digest::from([view.get() as u8; 32]),
        )
    }

    fn build_m_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> MNotarization<TestScheme, Sha256Digest> {
        let proposal = build_proposal(view);
        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
            .collect();
        MNotarization::from_notarizes(verifier, votes.iter(), &Sequential)
            .expect("m-notarization quorum")
    }

    #[test]
    fn retries_when_voter_mailbox_is_full() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (schemes, verifier) = ed25519_fixture();
            let certificate =
                Certificate::MNotarization(build_m_notarization(&schemes, &verifier, View::new(2)));
            let view = certificate.view();
            let data = certificate.encode();

            let cfg = Config {
                scheme: verifier.clone(),
                blocker: NoopBlocker,
                strategy: Sequential,
                epoch: EPOCH,
                mailbox_size: 8,
                fetch_concurrent: 2,
                fetch_timeout: Duration::from_millis(10),
            };
            let (mut actor, _mailbox) = Actor::new(context.with_label("resolver_actor"), cfg);

            let (voter_tx, mut voter_rx) = mpsc::channel(1);
            let mut voter = voter::Mailbox::new(voter_tx);
            voter.proposal(build_proposal(View::new(1))).await;

            let mut resolver = MockResolver::default();
            let (response, receiver) = oneshot::channel();

            actor
                .handle_resolver(
                    HandlerMessage::Deliver {
                        view,
                        data,
                        response,
                    },
                    &mut voter,
                    &mut resolver,
                )
                .await;

            assert!(receiver.await.expect("deliver response"));
            assert!(voter_rx.try_recv().is_ok(), "expected pre-filled proposal");
            assert!(
                voter_rx.try_recv().is_err(),
                "resolved certificate must not be enqueued when mailbox is full"
            );
            assert!(
                actor.state.get(view).is_none(),
                "resolver state must not advance on dropped voter delivery"
            );
            assert_eq!(
                resolver.fetched(),
                vec![view.get()],
                "resolver must retry fetching the dropped certificate view"
            );
        });
    }

    #[test]
    fn does_not_refetch_same_view_repeatedly_while_voter_full() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (schemes, verifier) = ed25519_fixture();
            let certificate =
                Certificate::MNotarization(build_m_notarization(&schemes, &verifier, View::new(3)));
            let view = certificate.view();
            let data = certificate.encode();

            let cfg = Config {
                scheme: verifier.clone(),
                blocker: NoopBlocker,
                strategy: Sequential,
                epoch: EPOCH,
                mailbox_size: 8,
                fetch_concurrent: 2,
                fetch_timeout: Duration::from_millis(10),
            };
            let (mut actor, _mailbox) = Actor::new(context.with_label("resolver_actor"), cfg);

            let (voter_tx, _voter_rx) = mpsc::channel(1);
            let mut voter = voter::Mailbox::new(voter_tx);
            voter.proposal(build_proposal(View::new(1))).await;

            let mut resolver = CountingResolver::default();

            for _ in 0..2 {
                let (response, receiver) = oneshot::channel();
                actor
                    .handle_resolver(
                        HandlerMessage::Deliver {
                            view,
                            data: data.clone(),
                            response,
                        },
                        &mut voter,
                        &mut resolver,
                    )
                    .await;
                assert!(receiver.await.expect("deliver response"));
            }

            let key = view.into();
            assert_eq!(
                resolver.fetch_count(key),
                1,
                "resolver should fetch a full mailbox view at most once until handoff succeeds"
            );
        });
    }
}
