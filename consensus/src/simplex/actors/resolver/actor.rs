use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    simplex::{
        actors::voter,
        signing_scheme::Scheme,
        types::{Backfiller, Notarization, Nullification, OrderedExt, Request, Response, Voter},
    },
    types::{Epoch, View},
    Epochable, Viewable,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    utils::{
        codec::{wrap, WrappedSender},
        requester,
    },
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    spawn_cell, telemetry::metrics::status::GaugeExt, Clock, ContextCell, Handle, Metrics, Spawner,
};
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::clock::Clock as GClock;
use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{counter::Counter, family::Family, gauge::Gauge},
};
use rand::{seq::IteratorRandom, CryptoRng, Rng};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

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

    blocker: B,

    epoch: Epoch,
    namespace: Vec<u8>,

    nullifications: BTreeMap<View, Nullification<S>>,
    activity_timeout: u64,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    served: Counter,
    requester: requester::Requester<E, P>,
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
        // Initialize requester
        let participants = cfg.scheme.participants();
        let me = cfg
            .scheme
            .me()
            .and_then(|index| participants.key(index))
            .cloned();

        let config = requester::Config {
            me,
            rate_limit: cfg.fetch_rate_per_peer,
            initial: cfg.fetch_timeout / 2,
            timeout: cfg.fetch_timeout,
        };
        let mut requester = requester::Requester::new(context.with_label("requester"), config);
        requester.reconcile(participants.as_ref());

        // Initialize metrics
        let served = Counter::default();
        context.register("served", "served nullifications", served.clone());

        // Initialize mailbox
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,

                blocker: cfg.blocker,

                epoch: cfg.epoch,
                namespace: cfg.namespace,

                nullifications: BTreeMap::new(),
                activity_timeout: cfg.activity_timeout,

                mailbox_receiver: receiver,

                requester,
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
        // Wrap channel
        let (mut sender, mut receiver) =
            wrap(self.scheme.certificate_codec_config(), sender, receiver);

        // Wait for an event
        let mut current_view = 0;
        let mut finalized_view = 0;
        loop {
            // Wait for an event
            select! {
                mailbox = self.mailbox_receiver.next() => {
                    let msg = match mailbox {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::Notarized { notarization } => {
                            // Update current view
                            let view = notarization.view();
                            if view > current_view {
                                current_view = view;
                            } else {
                                continue;
                            }

                            // If waiting for this notarization, remove it
                            self.required.remove(Task::Notarization, view);

                            // Add notarization to cache
                            self.notarizations.insert(view, notarization);
                        }
                        Message::Nullified { nullification } => {
                            // Update current view
                            let view = nullification.view();
                            if view > current_view {
                                current_view = view;
                            } else {
                                continue;
                            }

                            // If waiting for this nullification, remove it
                            self.required.remove(Task::Nullification, view);

                            // Add nullification to cache
                            self.nullifications.insert(view, nullification);
                        }
                        Message::Finalized { view } => {
                            // Update current view
                            if view > current_view {
                                current_view = view;
                            }
                            if view > finalized_view {
                                finalized_view = view;
                            } else {
                                continue;
                            }

                            // Remove outstanding
                            self.required.prune(view);

                            // Set prune depth
                            if view < self.activity_timeout {
                                continue;
                            }
                            let min_view = view - self.activity_timeout;

                            // Remove unneeded cache
                            //
                            // We keep some buffer of old messages around in case it helps other
                            // peers.
                            self.notarizations.retain(|k, _| *k >= min_view);
                            self.nullifications.retain(|k, _| *k >= min_view);
                        }
                    }
                },
                network = receiver.recv() => {
                    // Break if there is an internal error
                    let Ok((s, msg)) = network else {
                        break;
                    };

                    // Block if there is a decoding error
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, sender = ?s, "blocking peer for decoding error");
                            self.requester.block(s.clone());
                            self.blocker.block(s).await;
                            continue;
                        },
                    };

                    match msg {
                        Backfiller::Request(request) => {
                            let mut notarizations = Vec::new();
                            let mut missing_notarizations = Vec::new();
                            let mut notarizations_found = Vec::new();
                            let mut nullifications = Vec::new();
                            let mut missing_nullifications = Vec::new();
                            let mut nullifications_found = Vec::new();

                            // Populate notarizations first
                            for view in request.notarizations {
                                if let Some(notarization) = self.notarizations.get(&view) {
                                    notarizations.push(view);
                                    notarizations_found.push(notarization.clone());
                                    self.served.get_or_create(TaskLabel::notarization()).inc();
                                } else {
                                    missing_notarizations.push(view);
                                }
                            }

                            // Populate nullifications next
                            for view in request.nullifications {
                                if let Some(nullification) = self.nullifications.get(&view) {
                                    nullifications.push(view);
                                    nullifications_found.push(nullification.clone());
                                    self.served.get_or_create(TaskLabel::nullification()).inc();
                                } else {
                                    missing_nullifications.push(view);
                                }
                            }

                            // Send response
                            debug!(sender = ?s, ?notarizations, ?missing_notarizations, ?nullifications, ?missing_nullifications, "sending response");
                            let response = Response::new(request.id, notarizations_found, nullifications_found);
                            let response = Backfiller::Response(response);
                            sender
                                .send(Recipients::One(s), response, false)
                                .await
                                .unwrap();
                        },
                        Backfiller::Response(response) => {
                            // Ensure we were waiting for this response
                            let Some(request) = self.requester.handle(&s, response.id) else {
                                debug!(sender = ?s, "unexpected message");
                                continue;
                            };
                            self.inflight.clear(request.id);

                            // Verify message
                            if !response.verify(&mut self.context, &self.scheme, &self.namespace) {
                                warn!(sender = ?s, "blocking peer");
                                self.requester.block(s.clone());
                                self.blocker.block(s).await;
                                continue;
                            }

                            // Validate that all notarizations and nullifications are from the current epoch
                            if response.notarizations.iter().any(|n| n.epoch() != self.epoch) || response.nullifications.iter().any(|n| n.epoch() != self.epoch) {
                                warn!(sender = ?s, "blocking peer for epoch mismatch");
                                self.requester.block(s.clone());
                                self.blocker.block(s).await;
                                continue;
                            }

                            // Update cache
                            let mut voters = Vec::with_capacity(response.notarizations.len() + response.nullifications.len());
                            let mut notarizations_found = BTreeSet::new();
                            for notarization in response.notarizations {
                                let view = notarization.view();
                                if !self.required.remove(Task::Notarization, view) {
                                    debug!(view, sender = ?s, "unnecessary notarization");
                                    continue;
                                }
                                self.notarizations.insert(view, notarization.clone());
                                voters.push(Voter::Notarization(notarization));
                                notarizations_found.insert(view);
                            }
                            let mut nullifications_found = BTreeSet::new();
                            for nullification in response.nullifications {
                                let view = nullification.view();
                                if !self.required.remove(Task::Nullification, view) {
                                    debug!(view, sender = ?s, "unnecessary nullification");
                                    continue;
                                }
                                self.nullifications.insert(view, nullification.clone());
                                voters.push(Voter::Nullification(nullification));
                                nullifications_found.insert(view);
                            }

                            // Send voters
                            voter.verified(voters).await;

                            // Update performance
                            let mut shuffle = false;
                            if !notarizations_found.is_empty() || !nullifications_found.is_empty() {
                                self.requester.resolve(request);
                                debug!(
                                    sender = ?s,
                                    notarizations = ?notarizations_found,
                                    nullifications = ?nullifications_found,
                                    "response useful",
                                );
                            } else {
                                // We don't reward a peer for sending us a response that doesn't help us
                                shuffle = true;
                                debug!(sender = ?s, "response not useful");
                            }

                            // If still work to do, send another request
                            self.send(shuffle, &mut sender).await;
                        },
                    }
                },
            }
        }
    }
}
