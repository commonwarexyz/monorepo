use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    simplex::{
        actors::voter,
        signing_scheme::Scheme,
        types::{Notarization, Nullification, OrderedExt, Voter},
    },
    types::{Epoch, View},
    Epochable, Viewable,
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    utils::{requester, StaticManager},
    Blocker, Receiver, Sender,
};
use commonware_resolver::{
    p2p::{
        Config as ResolverConfig, Engine as ResolverEngine, Mailbox as ResolverMailbox,
        Producer as ResolverProducer,
    },
    Consumer, Resolver,
};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::sequence::U64;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use governor::{clock::Clock as GClock, Quota};
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
    last_notarized: Option<Notarization<S, D>>,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,
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
                last_notarized: None,

                mailbox_receiver: receiver,
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
        let participants = self.scheme.participants().clone();
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
                manager: StaticManager::new(self.epoch, participants),
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
                resolver = &mut resolver_task => {
                    warn!(?resolver, "inner resolver engine stopped");
                    break;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let Some(message) = mailbox else {
                        break;
                    };
                    self.handle_mailbox_message(message, &mut resolver).await;
                },
                message = handler_rx.next() => {
                    let Some(message) = message else {
                        break;
                    };
                    self.handle_resolver_message(message, &mut voter, &mut resolver).await;
                },
            }
        }
    }

    async fn handle_mailbox_message(
        &mut self,
        message: Message<S, D>,
        resolver: &mut ResolverMailbox<U64>,
    ) {
        match message {
            Message::Nullified { nullification } => {
                // Update current view
                let view = nullification.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // If lower than last notarized, drop
                if let Some(last_notarized) = &self.last_notarized {
                    if view < last_notarized.view() {
                        return;
                    }
                }

                // Store nullification (and cancel outstanding)
                self.pending.remove(&view);
                self.nullifications.insert(view, nullification);
                resolver.cancel(U64::new(view)).await;
            }
            Message::Notarized { notarization } => {
                // Update current view
                let view = notarization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last notarized
                if let Some(last_notarized) = &self.last_notarized {
                    if view > last_notarized.view() {
                        self.last_notarized = Some(notarization);
                    }
                } else {
                    self.last_notarized = Some(notarization);
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
        }

        // Request missing nullifications
        self.request_missing(resolver).await;
    }

    async fn handle_resolver_message(
        &mut self,
        message: ResolverMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut ResolverMailbox<U64>,
    ) {
        match message {
            ResolverMessage::Deliver {
                view,
                data,
                response,
            } => {
                // Verify message
                let Ok(raw) =
                    Voter::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config())
                else {
                    let _ = response.send(false);
                    return;
                };
                let Some(parsed) = self.validate_incoming(view, &raw) else {
                    let _ = response.send(false);
                    return;
                };

                // Process message
                let _ = response.send(true);
                voter.verified(vec![raw]).await;
                self.handle_mailbox_message(parsed, resolver).await;
            }
            ResolverMessage::Produce { view, response } => {
                // If view is <= last notarized, return the last notarized
                if let Some(last_notarized) = &self.last_notarized {
                    if view <= last_notarized.view() {
                        let _ = response
                            .send(Voter::Notarization(last_notarized.clone()).encode().into());
                        return;
                    }
                }

                // Otherwise, return the nullification for the view
                let Some(nullification) = self.nullifications.get(&view) else {
                    return;
                };
                let _ = response.send(
                    Voter::Nullification::<S, D>(nullification.clone())
                        .encode()
                        .into(),
                );
            }
        }
    }

    fn validate_incoming(&mut self, view: View, incoming: &Voter<S, D>) -> Option<Message<S, D>> {
        match incoming {
            Voter::Notarization(notarization) => {
                if notarization.view() < view {
                    warn!(view, "notarization below view");
                    return None;
                }
                if notarization.epoch() != self.epoch {
                    warn!(
                        view,
                        epoch = notarization.epoch(),
                        expected = self.epoch,
                        "rejecting notarization from different epoch"
                    );
                    return None;
                }
                if !notarization.verify(&mut self.context, &self.scheme, &self.namespace) {
                    warn!(view, "notarization failed verification");
                    return None;
                }
                Some(Message::Notarized {
                    notarization: notarization.clone(),
                })
            }
            Voter::Nullification(nullification) => {
                if nullification.view() != view {
                    warn!(view, "nullification view mismatch");
                    return None;
                }
                if nullification.epoch() != self.epoch {
                    warn!(
                        view,
                        epoch = nullification.epoch(),
                        expected = self.epoch,
                        "rejecting nullification from different epoch"
                    );
                    return None;
                }
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
                    warn!(view, "nullification failed verification");
                    return None;
                }
                Some(Message::Nullified {
                    nullification: nullification.clone(),
                })
            }
            _ => None,
        }
    }

    async fn request_missing(&mut self, resolver: &mut ResolverMailbox<U64>) {
        let mut cursor = self
            .last_notarized
            .as_ref()
            .unwrap()
            .view()
            .saturating_add(1);
        while cursor <= self.current_view {
            if self.nullifications.contains_key(&cursor) || !self.pending.insert(cursor) {
                cursor = cursor.checked_add(1).expect("view overflow");
                continue;
            }
            resolver.fetch(U64::new(cursor)).await;
            cursor = cursor.checked_add(1).expect("view overflow");
        }
    }

    async fn prune(&mut self, resolver: &mut ResolverMailbox<U64>) {
        let min = self.last_notarized.as_ref().unwrap().view();
        self.nullifications.retain(|view, _| *view > min);
        self.pending.retain(|view| *view > min);

        let min = U64::from(min);
        resolver.retain(move |key| key >= &min).await;
    }
}
