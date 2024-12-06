use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    authority::{
        actors::voter,
        encoder::{notarize_namespace, nullify_namespace},
        verifier::{verify_notarization, verify_nullification},
        wire, View,
    },
    Supervisor,
};
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};
use commonware_macros::select;
use commonware_p2p::{utils::requester, Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prost::Message as _;
use rand::Rng;
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    time::Duration,
};
use tracing::{debug, warn};

enum Source<'a> {
    All,
    New(&'a Vec<u64>, &'a Vec<u64>),
}

pub struct Actor<E: Clock + GClock + Rng, C: Scheme, H: Hasher, S: Supervisor<Index = View>> {
    runtime: E,
    supervisor: S,
    _hasher: PhantomData<H>,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,

    notarizations: BTreeMap<View, wire::Notarization>,
    nullifications: BTreeMap<View, wire::Nullification>,
    activity_timeout: u64,

    // Unfulfilled notarization requests
    required_notarizations: BTreeSet<View>,
    // Unfulfilled nullification requests
    required_nullifications: BTreeSet<View>,

    mailbox_receiver: mpsc::Receiver<Message>,

    fetch_timeout: Duration,
    max_fetch_count: usize,
    max_fetch_size: usize,
    fetch_concurrent: usize,
    requester: requester::Requester<E, C>,

    outstanding_notarizations: Gauge,
    outstanding_nullifications: Gauge,
    outstanding_requests: Gauge,
    served_notarizations: Counter,
    served_nullifications: Counter,
}

impl<E: Clock + GClock + Rng, C: Scheme, H: Hasher, S: Supervisor<Index = View>> Actor<E, C, H, S> {
    pub fn new(runtime: E, cfg: Config<C, S>) -> (Self, Mailbox) {
        // Initialize requester
        let config = requester::Config {
            crypto: cfg.crypto.clone(),
            rate_limit: cfg.fetch_rate_per_peer,
            initial: cfg.fetch_timeout / 2,
            timeout: cfg.fetch_timeout,
        };
        let requester = requester::Requester::new(runtime.clone(), config);

        // Initialize metrics
        let outstanding_notarizations = Gauge::default();
        let outstanding_nullifications = Gauge::default();
        let outstanding_requests = Gauge::default();
        let served_notarizations = Counter::default();
        let served_nullifications = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "outstanding_notarizations",
                "outstanding notarizations",
                outstanding_notarizations.clone(),
            );
            registry.register(
                "outstanding_nullifications",
                "outstanding nullifications",
                outstanding_nullifications.clone(),
            );
            registry.register(
                "outstanding_requests",
                "outstanding requests",
                outstanding_requests.clone(),
            );
            registry.register(
                "served_notarizations",
                "served notarizations",
                served_notarizations.clone(),
            );
            registry.register(
                "served_nullifications",
                "served nullifications",
                served_nullifications.clone(),
            );
        }

        // Initialize mailbox
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                runtime,
                supervisor: cfg.supervisor,
                _hasher: PhantomData,

                notarize_namespace: notarize_namespace(&cfg.namespace),
                nullify_namespace: nullify_namespace(&cfg.namespace),

                notarizations: BTreeMap::new(),
                nullifications: BTreeMap::new(),
                activity_timeout: cfg.activity_timeout,

                required_notarizations: BTreeSet::new(),
                required_nullifications: BTreeSet::new(),

                mailbox_receiver: receiver,

                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_concurrent: cfg.fetch_concurrent,
                requester,

                outstanding_notarizations,
                outstanding_nullifications,
                outstanding_requests,
                served_notarizations,
                served_nullifications,
            },
            Mailbox::new(sender),
        )
    }

    async fn send(&mut self, source: Source<'_>, shuffle: bool, sender: &mut impl Sender) {
        // If too many concurrent requests, do nothing
        if self.requester.len() >= self.fetch_concurrent {
            return;
        }

        // Select best notarization and nullifications requests
        let (notarizations, nullifications) = match source {
            Source::All => {
                let notarizations = self
                    .required_notarizations
                    .iter()
                    .take(self.max_fetch_count)
                    .cloned()
                    .collect::<Vec<_>>();
                let remaining = self.max_fetch_count - notarizations.len();
                let nullifications = self
                    .required_nullifications
                    .iter()
                    .take(remaining)
                    .cloned()
                    .collect::<Vec<_>>();
                (notarizations, nullifications)
            }
            Source::New(notarizations, nullifications) => {
                let notarizations = notarizations
                    .iter()
                    .take(self.max_fetch_count)
                    .cloned()
                    .collect::<Vec<_>>();
                let remaining = self.max_fetch_count - notarizations.len();
                let nullifications = nullifications
                    .iter()
                    .take(remaining)
                    .cloned()
                    .collect::<Vec<_>>();
                (notarizations, nullifications)
            }
        };

        // If nothing to do, return
        if notarizations.is_empty() && nullifications.is_empty() {
            return;
        }

        // Select next recipient
        loop {
            // Get next best
            let Some((recipient, request)) = self.requester.request(shuffle) else {
                warn!("failed to send request to any validator");
                self.runtime.sleep(self.fetch_timeout).await;
                continue;
            };

            // Create new message
            let msg: Bytes = wire::Backfiller {
                id: request,
                payload: Some(wire::backfiller::Payload::Request(wire::Request {
                    notarizations: notarizations.clone(),
                    nullifications: nullifications.clone(),
                })),
            }
            .encode_to_vec()
            .into();

            // Try to send
            if sender
                .send(Recipients::One(recipient.clone()), msg.clone(), false)
                .await
                .unwrap()
                .is_empty()
            {
                // Try again
                self.requester.cancel(request);
                debug!(peer = hex(&recipient), "failed to send request");
                continue;
            }

            // Exit if sent
            debug!(peer = hex(&recipient), "sent request");
            break;
        }
    }

    pub async fn run(
        mut self,
        mut voter: voter::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Wait for an event
        let mut current_view = 0;
        let mut finalized_view = 0;
        loop {
            // Record outstanding metric
            self.outstanding_notarizations
                .set(self.required_notarizations.len() as i64);
            self.outstanding_nullifications
                .set(self.required_nullifications.len() as i64);
            self.outstanding_requests.set(self.requester.len() as i64);

            // Set timeout for next request
            let (request, timeout) = if let Some((request, timeout)) = self.requester.next() {
                (request, Either::Left(self.runtime.sleep_until(timeout)))
            } else {
                (0, Either::Right(futures::future::pending()))
            };

            // Wait for an event
            select! {
                _ = timeout => {
                    // Penalize requester for timeout
                    let request = self.requester.cancel(request).expect("request not found");
                    self.requester.timeout(request);

                    // Send message
                    self.send(Source::All, true, &mut sender).await;
                    continue;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = match mailbox {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::Fetch { notarizations, nullifications } => {
                            // Fetch new notarizations and nullifications
                            self.send(Source::New(&notarizations, &nullifications), false, &mut sender).await;

                            // Add to all outstanding required
                            self.required_notarizations.extend(notarizations);
                            self.required_nullifications.extend(nullifications);
                        }
                        Message::Notarized { notarization } => {
                            // Update current view
                            let view = notarization.proposal.as_ref().unwrap().view;
                            if view > current_view {
                                current_view = view;
                            } else {
                                continue;
                            }

                            // Update stored validators
                            let validators = self.supervisor.participants(view).unwrap();
                            self.requester.reconcile(validators);

                            // If waiting for this notarization, remove it
                            self.required_notarizations.remove(&view);

                            // Add notarization to cache
                            self.notarizations.insert(view, notarization);
                        }
                        Message::Nullified { nullification } => {
                            // Update current view
                            let view = nullification.view;
                            if view > current_view {
                                current_view = view;
                            } else {
                                continue;
                            }

                            // Update stored validators
                            let validators = self.supervisor.participants(view).unwrap();
                            self.requester.reconcile(validators);

                            // If waiting for this nullification, remove it
                            self.required_nullifications.remove(&view);

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
                            self.required_notarizations.retain(|v| *v >= view);
                            self.required_nullifications.retain(|v| *v >= view);

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
                    let (s, msg) = network.unwrap();
                    let msg = match wire::Backfiller::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, sender = hex(&s), "failed to decode message");
                            continue;
                        },
                    };
                    let payload = match msg.payload {
                        Some(payload) => payload,
                        None => {
                            warn!(sender = hex(&s), "missing payload");
                            continue;
                        },
                    };
                    match payload {
                        wire::backfiller::Payload::Request(request) => {
                            let mut populated_bytes = 0;
                            let mut notarizations_found = Vec::new();
                            let mut nullifications_found = Vec::new();

                            // Populate notarizations first
                            for view in request.notarizations {
                                if let Some(notarization) = self.notarizations.get(&view) {
                                    let size = notarization.encoded_len();
                                    if populated_bytes + size > self.max_fetch_size {
                                        break;
                                    }
                                    if notarizations_found.len() + 1 > self.max_fetch_count {
                                        break;
                                    }
                                    populated_bytes += size;
                                    notarizations_found.push(notarization.clone());
                                    self.served_notarizations.inc();
                                }
                            }

                            // Populate nullifications next
                            for view in request.nullifications {
                                if let Some(nullification) = self.nullifications.get(&view) {
                                    let size = nullification.encoded_len();
                                    if populated_bytes + size > self.max_fetch_size {
                                        break;
                                    }
                                    if notarizations_found.len() + nullifications_found.len() + 1 > self.max_fetch_count {
                                        break;
                                    }
                                    populated_bytes += size;
                                    nullifications_found.push(nullification.clone());
                                    self.served_nullifications.inc();
                                }
                            }

                            // Send response
                            debug!(notarizations_found = notarizations_found.len(), nullifications_found = nullifications_found.len(), sender = hex(&s), "sending response");
                            let response = wire::Backfiller {
                                id: msg.id,
                                payload: Some(wire::backfiller::Payload::Response(wire::Response {
                                    notarizations: notarizations_found,
                                    nullifications: nullifications_found,
                                })),
                            }
                            .encode_to_vec()
                            .into();
                            sender
                                .send(Recipients::One(s.clone()), response, false)
                                .await
                                .unwrap();
                        },
                        wire::backfiller::Payload::Response(response) => {
                            // Ensure we were waiting for this response
                            let Some(request) = self.requester.handle(&s, msg.id) else {
                                debug!(sender = hex(&s), "unexpected message");
                                continue;
                            };

                            // Ensure response isn't too big
                            if response.notarizations.len() + response.nullifications.len() > self.max_fetch_count {
                                // Block responder
                                warn!(sender = hex(&s), "response too large");
                                self.requester.block(s);

                                // Pick new recipient
                                self.send(Source::All, true, &mut sender).await;
                                continue;
                            }

                            // Parse notarizations
                            let mut notarizations_found = BTreeSet::new();
                            let mut nullifications_found = BTreeSet::new();
                            for notarization in response.notarizations {
                                let view = match notarization.proposal.as_ref() {
                                    Some(proposal) => proposal.view,
                                    None => {
                                        warn!(sender = hex(&s), "missing proposal");
                                        self.requester.block(s.clone());
                                        continue;
                                    },
                                };
                                if !self.required_notarizations.contains(&view) {
                                    debug!(view, sender = hex(&s), "unnecessary notarization");
                                    continue;
                                }
                                if !verify_notarization::<S,C>(&self.supervisor, &self.notarize_namespace, &notarization) {
                                    warn!(view, sender = hex(&s), "invalid notarization");
                                    self.requester.block(s.clone());
                                    continue;
                                }
                                self.required_notarizations.remove(&view);
                                self.notarizations.insert(view, notarization.clone());
                                voter.notarization(notarization).await;
                                notarizations_found.insert(view);
                            }

                            // Parse nullifications
                            for nullification in response.nullifications {
                                let view = nullification.view;
                                if !self.required_nullifications.contains(&view) {
                                    debug!(view, sender = hex(&s), "unnecessary nullification");
                                    continue;
                                }
                                if !verify_nullification::<S,C>(&self.supervisor, &self.nullify_namespace, &nullification) {
                                    warn!(view, sender = hex(&s), "invalid nullification");
                                    self.requester.block(s.clone());
                                    continue;
                                }
                                self.required_nullifications.remove(&view);
                                self.nullifications.insert(view, nullification.clone());
                                voter.nullification(nullification).await;
                                nullifications_found.insert(view);
                            }

                            // Update performance
                            if !notarizations_found.is_empty() || !nullifications_found.is_empty() {
                                self.requester.resolve(request);
                                debug!(
                                    notarizations_found = ?notarizations_found.into_iter().collect::<Vec<_>>(),
                                    nullifications_found = ?nullifications_found.into_iter().collect::<Vec<_>>(),
                                    sender = hex(&s),
                                    "request successful",
                                );
                            } else {
                                debug!(sender = hex(&s), "request not useful");
                            }

                            // If still work to do, send another request
                            self.send(Source::All, false, &mut sender).await;
                        },
                    }
                },
            }
        }
    }
}
