use super::{
    ingress::{Handler, Mailbox, Message},
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
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    utils::{requester, StaticManager},
    Blocker, Receiver, Sender,
};
use commonware_resolver::{
    p2p::{Config as ResolverConfig, Engine as ResolverEngine, Mailbox as ResolverMailbox},
    Resolver,
};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::sequence::U64;
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use rand::{CryptoRng, Rng};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tracing::{debug, info, warn};

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
    fetch_concurrent: usize,

    nullifications: BTreeMap<View, Nullification<S>>,
    pending: BTreeSet<View>,
    current_view: View,
    floor: Option<Voter<S, D>>,

    mailbox_receiver: mpsc::Receiver<Voter<S, D>>,
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
                fetch_concurrent: cfg.fetch_concurrent,

                nullifications: BTreeMap::new(),
                pending: BTreeSet::new(),
                current_view: 0,
                floor: None,

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
        message: Voter<S, D>,
        resolver: &mut ResolverMailbox<U64>,
    ) {
        match message {
            Voter::Nullification(nullification) => {
                // Update current view
                let view = nullification.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // If greater than the floor, store
                self.pending.remove(&view);
                resolver.cancel(U64::new(view)).await;
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.nullifications.insert(view, nullification);
                    }
                } else {
                    self.nullifications.insert(view, nullification);
                }
            }
            Voter::Notarization(notarization) => {
                // Update current view
                let view = notarization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last notarized
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.floor = Some(Voter::Notarization(notarization));
                    }
                } else {
                    self.floor = Some(Voter::Notarization(notarization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
            Voter::Finalization(finalization) => {
                // Update current view
                let view = finalization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last finalized
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.floor = Some(Voter::Finalization(finalization));
                    }
                } else {
                    self.floor = Some(Voter::Finalization(finalization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
            _ => unreachable!("unexpected message type"),
        }

        // Request missing nullifications
        self.request_missing(resolver).await;
    }

    async fn handle_resolver_message(
        &mut self,
        message: Message,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut ResolverMailbox<U64>,
    ) {
        match message {
            Message::Deliver {
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
                info!(view, "validated incoming message");

                // Process message
                let _ = response.send(true);
                voter.verified(raw).await;
                self.handle_mailbox_message(parsed, resolver).await;
            }
            Message::Produce { view, response } => {
                // If view is <= floor, return the floor
                if let Some(floor) = &self.floor {
                    if view <= floor.view() {
                        let _ = response.send(floor.clone().encode().into());
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

    fn validate_incoming(&mut self, view: View, incoming: &Voter<S, D>) -> Option<Voter<S, D>> {
        match incoming {
            Voter::Notarization(notarization) => {
                if notarization.view() < view {
                    debug!(view, "notarization below view");
                    return None;
                }
                if notarization.epoch() != self.epoch {
                    debug!(
                        view,
                        epoch = notarization.epoch(),
                        expected = self.epoch,
                        "rejecting notarization from different epoch"
                    );
                    return None;
                }
                if !notarization.verify(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(view, "notarization failed verification");
                    return None;
                }
                debug!(current = self.current_view, view, received = ?notarization.view(), "received notarization for request");
                Some(Voter::Notarization(notarization.clone()))
            }
            Voter::Finalization(finalization) => {
                if finalization.view() < view {
                    debug!(view, "finalization below view");
                    return None;
                }
                if finalization.epoch() != self.epoch {
                    debug!(view, "finalization from different epoch");
                    return None;
                }
                if !finalization.verify(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(view, "finalization failed verification");
                    return None;
                }
                debug!(current = self.current_view, view, received = ?finalization.view(), "received finalization for request");
                Some(Voter::Finalization(finalization.clone()))
            }
            Voter::Nullification(nullification) => {
                if nullification.view() != view {
                    debug!(view, "nullification view mismatch");
                    return None;
                }
                if nullification.epoch() != self.epoch {
                    debug!(
                        view,
                        epoch = nullification.epoch(),
                        expected = self.epoch,
                        "rejecting nullification from different epoch"
                    );
                    return None;
                }
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(view, "nullification failed verification");
                    return None;
                }
                Some(Voter::Nullification(nullification.clone()))
            }
            _ => None,
        }
    }

    async fn request_missing(&mut self, resolver: &mut ResolverMailbox<U64>) {
        let mut cursor = self
            .floor
            .as_ref()
            .map(|floor| floor.view().saturating_add(1))
            .unwrap_or(1);

        // We must either receive a nullification or a notarization (at the view or higher),
        // so we don't need to worry about getting stuck because we've only made requests for the
        // next FETCH_BATCH views (which none of which may be resolvable). All will be resolved.
        while cursor < self.current_view && self.pending.len() < self.fetch_concurrent {
            if self.nullifications.contains_key(&cursor) || !self.pending.insert(cursor) {
                cursor = cursor.checked_add(1).expect("view overflow");
                continue;
            }
            self.pending.insert(cursor);
            resolver.fetch(U64::new(cursor)).await;
            debug!(cursor, "requested missing nullification");

            // Increment cursor
            cursor = cursor.checked_add(1).expect("view overflow");
        }
    }

    async fn prune(&mut self, resolver: &mut ResolverMailbox<U64>) {
        let min = self.floor.as_ref().unwrap().view();
        self.nullifications.retain(|view, _| *view > min);
        self.pending.retain(|view| *view > min);

        let min = U64::from(min);
        resolver.retain(move |key| key > &min).await;
    }
}
