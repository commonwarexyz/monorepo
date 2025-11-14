use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    simplex::{
        actors::voter,
        signing_scheme::Scheme,
        types::{Nullification, OrderedExt, Voter},
    },
    types::{Epoch, View},
    Epochable, Viewable,
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{utils::requester, Blocker, Manager, Receiver, Sender};
use commonware_resolver::{
    p2p::{
        Config as ResolverConfig, Engine as ResolverEngine, Mailbox as ResolverMailbox,
        Producer as ResolverProducer,
    },
    Consumer, Resolver,
};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{sequence::U64, set::Ordered};
use futures::{
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    SinkExt, StreamExt,
};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::counter::Counter;
use rand::{CryptoRng, Rng};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tracing::{error, warn};

#[derive(Clone)]
struct Handler {
    sender: mpsc::Sender<ResolverMessage>,
}

impl Handler {
    fn new(sender: mpsc::Sender<ResolverMessage>) -> Self {
        Self { sender }
    }
}

#[derive(Debug)]
enum ResolverMessage {
    Deliver {
        view: View,
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

#[derive(Clone, Debug)]
struct ParticipantsManager<P: PublicKey> {
    peers: Ordered<P>,
}

impl<P: PublicKey> ParticipantsManager<P> {
    fn new(peers: Ordered<P>) -> Self {
        Self { peers }
    }
}

impl<P: PublicKey> Manager for ParticipantsManager<P> {
    type PublicKey = P;
    type Peers = Ordered<P>;

    async fn update(&mut self, _: u64, peers: Self::Peers) {
        self.peers = peers;
    }

    async fn peer_set(&mut self, _: u64) -> Option<Ordered<P>> {
        Some(self.peers.clone())
    }

    async fn subscribe(&mut self) -> UnboundedReceiver<(u64, Ordered<P>, Ordered<P>)> {
        let (sender, receiver) = mpsc::unbounded();
        let _ = sender.unbounded_send((0, self.peers.clone(), self.peers.clone()));
        receiver
    }
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(ResolverMessage::Deliver {
                view: key.into(),
                data: value,
                response,
            })
            .await
            .is_err()
        {
            error!("failed to deliver resolver message to actor");
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {}
}

impl ResolverProducer for Handler {
    type Key = U64;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(ResolverMessage::Produce {
                view: key.into(),
                response,
            })
            .await
            .is_err()
        {
            error!("failed to send produce request to actor");
        }
        receiver
    }
}

/// Requests are made concurrently to multiple peers.
pub struct Actor<
    E: Clock + GClock + Rng + CryptoRng + Metrics + Spawner,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
> {
    context: ContextCell<E>,
    scheme: S,

    #[allow(dead_code)]
    blocker: B,

    epoch: Epoch,
    namespace: Vec<u8>,
    mailbox_size: usize,
    fetch_timeout: Duration,
    fetch_rate_per_peer: Quota,

    nullifications: BTreeMap<View, Nullification<S>>,
    pending: BTreeSet<View>,
    current_view: View,
    last_finalized: View,
    activity_timeout: u64,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    served: Counter,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Metrics + Spawner,
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
    > Actor<E, P, S, B, D>
{
    pub fn new(context: E, cfg: Config<S, B>) -> (Self, Mailbox<S, D>) {
        let served = Counter::default();
        context.register("served", "served nullifications", served.clone());

        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,

                blocker: cfg.blocker,

                epoch: cfg.epoch,
                namespace: cfg.namespace,
                mailbox_size: cfg.mailbox_size,
                fetch_timeout: cfg.fetch_timeout,
                fetch_rate_per_peer: cfg.fetch_rate_per_peer,

                nullifications: BTreeMap::new(),
                pending: BTreeSet::new(),
                current_view: 0,
                last_finalized: 0,
                activity_timeout: cfg.activity_timeout,

                mailbox_receiver: receiver,

                served,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = P>,
        receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, sender, receiver).await)
    }

    async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = P>,
        receiver: impl Receiver<PublicKey = P>,
    ) {
        let participants = self.scheme.participants();
        let manager_peers = participants.clone();
        let me = self
            .scheme
            .me()
            .and_then(|index| participants.key(index))
            .cloned();

        let (handler_tx, mut handler_rx) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler_tx);

        let (resolver_engine, mut resolver) = ResolverEngine::new(
            self.context.with_label("resolver"),
            ResolverConfig {
                manager: ParticipantsManager::new(manager_peers),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                requester_config: requester::Config {
                    me,
                    rate_limit: self.fetch_rate_per_peer,
                    initial: self.fetch_timeout / 2,
                    timeout: self.fetch_timeout,
                },
                fetch_retry_timeout: self.fetch_timeout,
                priority_requests: false,
                priority_responses: false,
            },
        );
        let mut resolver_task = resolver_engine.start((sender, receiver));

        loop {
            select! {
                resolver_result = &mut resolver_task => {
                    panic!("resolver engine stopped unexpectedly: {resolver_result:?}");
                },
                mailbox = self.mailbox_receiver.next() => {
                    let Some(message) = mailbox else {
                        break;
                    };
                    self.handle_mailbox_message(message, &mut voter, &mut resolver).await;
                },
                message = handler_rx.next() => {
                    let Some(message) = message else {
                        break;
                    };
                    self.handle_resolver_message(message, &mut voter).await;
                },
            }
        }
    }

    async fn handle_mailbox_message(
        &mut self,
        message: Message<S, D>,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut ResolverMailbox<U64>,
    ) {
        match message {
            Message::Notarized { notarization } => {
                self.update_current_view(notarization.view());
                self.request_missing(resolver).await;
            }
            Message::Nullified { nullification } => {
                let view = nullification.view();
                self.update_current_view(view);
                if !self.validate_nullification(view, &nullification) {
                    warn!(view, "rejected invalid local nullification");
                    return;
                }
                let was_pending = self.pending.remove(&view);
                self.store_nullification(view, nullification, voter).await;
                if was_pending {
                    resolver.cancel(U64::new(view)).await;
                }
                self.request_missing(resolver).await;
            }
            Message::Finalized { view } => {
                self.update_current_view(view);
                if view > self.last_finalized {
                    self.last_finalized = view;
                }
                if view >= self.activity_timeout {
                    let min_view = view.saturating_sub(self.activity_timeout);
                    self.prune(min_view, resolver).await;
                }
                self.request_missing(resolver).await;
            }
        }
    }

    async fn handle_resolver_message(
        &mut self,
        message: ResolverMessage,
        voter: &mut voter::Mailbox<S, D>,
    ) {
        match message {
            ResolverMessage::Deliver {
                view,
                data,
                response,
            } => {
                let success = match self.decode_nullification(&data) {
                    Some(nullification) if self.validate_nullification(view, &nullification) => {
                        self.update_current_view(view);
                        let _ = self.pending.remove(&view);
                        let _ = self.store_nullification(view, nullification, voter).await;
                        true
                    }
                    _ => false,
                };
                let _ = response.send(success);
            }
            ResolverMessage::Produce { view, response } => {
                if let Some(nullification) = self.nullifications.get(&view) {
                    if response.send(nullification.encode().into()).is_ok() {
                        self.served.inc();
                    }
                    return;
                }
                drop(response);
            }
        }
    }

    fn decode_nullification(&self, data: &Bytes) -> Option<Nullification<S>> {
        Nullification::decode_cfg(data.clone(), &self.scheme.certificate_codec_config())
            .map_err(|err| {
                warn!(?err, "failed to decode nullification");
            })
            .ok()
    }

    fn validate_nullification(&mut self, view: View, nullification: &Nullification<S>) -> bool {
        if nullification.view() != view {
            warn!(view, "nullification view mismatch");
            return false;
        }
        if nullification.epoch() != self.epoch {
            warn!(
                view,
                epoch = nullification.epoch(),
                expected = self.epoch,
                "rejecting nullification from different epoch"
            );
            return false;
        }
        if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
            warn!(view, "nullification failed verification");
            return false;
        }
        true
    }

    async fn store_nullification(
        &mut self,
        view: View,
        nullification: Nullification<S>,
        voter: &mut voter::Mailbox<S, D>,
    ) -> bool {
        let inserted = self
            .nullifications
            .insert(view, nullification.clone())
            .is_none();
        if inserted {
            voter
                .verified(vec![Voter::Nullification(nullification)])
                .await;
        }
        inserted
    }

    async fn request_missing(&mut self, resolver: &mut ResolverMailbox<U64>) {
        if self.current_view <= self.last_finalized || self.last_finalized == View::MAX {
            return;
        }

        let mut view = self.last_finalized.saturating_add(1);
        while view <= self.current_view {
            if self.nullifications.contains_key(&view) || !self.pending.insert(view) {
                view = match view.checked_add(1) {
                    Some(next) => next,
                    None => break,
                };
                continue;
            }
            resolver.fetch(U64::new(view)).await;
            view = match view.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
    }

    async fn prune(&mut self, min_view: View, resolver: &mut ResolverMailbox<U64>) {
        self.nullifications.retain(|view, _| *view >= min_view);
        self.pending.retain(|view| *view >= min_view);

        resolver
            .retain(move |key| {
                let view: View = key.clone().into();
                view >= min_view
            })
            .await;
    }

    fn update_current_view(&mut self, view: View) {
        if view > self.current_view {
            self.current_view = view;
        }
    }
}
