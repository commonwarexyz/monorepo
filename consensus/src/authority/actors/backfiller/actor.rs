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
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    time::Duration,
};
use tracing::{debug, warn};

/// Entry in the required set.
#[derive(Clone, Eq, PartialEq)]
struct Entry {
    notarization: bool,
    view: View,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.view.cmp(&other.view) {
            Ordering::Equal => self.notarization.cmp(&other.notarization),
            ordering => ordering,
        }
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Requests are made concurrently to multiple peers.
pub struct Actor<E: Clock + GClock + Rng, C: Scheme, H: Hasher, S: Supervisor<Index = View>> {
    runtime: E,
    supervisor: S,
    _hasher: PhantomData<H>,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,

    notarizations: BTreeMap<View, wire::Notarization>,
    nullifications: BTreeMap<View, wire::Nullification>,
    activity_timeout: u64,

    required: BTreeSet<Entry>,
    inflight: BTreeSet<Entry>,
    inflight_by_request: BTreeMap<requester::ID, Vec<Entry>>,

    mailbox_receiver: mpsc::Receiver<Message>,

    fetch_timeout: Duration,
    max_fetch_count: usize,
    max_fetch_size: usize,
    fetch_concurrent: usize,
    requester: requester::Requester<E, C>,

    unfulfilled: Gauge,
    outstanding: Gauge,
    served: Counter,
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
        let unfulfilled = Gauge::default();
        let outstanding = Gauge::default();
        let served = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "unfulfilled",
                "unfulfilled notarizations/nullifications",
                unfulfilled.clone(),
            );
            registry.register("outstanding", "outstanding requests", outstanding.clone());
            registry.register(
                "served",
                "served notarizations/nullifications",
                served.clone(),
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

                required: BTreeSet::new(),
                inflight: BTreeSet::new(),
                inflight_by_request: BTreeMap::new(),

                mailbox_receiver: receiver,

                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_concurrent: cfg.fetch_concurrent,
                requester,

                unfulfilled,
                outstanding,
                served,
            },
            Mailbox::new(sender),
        )
    }

    /// Concurrent indicates whether we should send a new request (only if we see a request for the first time)
    async fn send(&mut self, shuffle: bool, sender: &mut impl Sender) {
        // We try to send as many requests as possible at the same time for unfulfilled notarizations and nullifications.
        let mut sent = false;
        loop {
            // If we have too many requests outstanding, return
            if self.requester.len() >= self.fetch_concurrent {
                return;
            }

            // Select notarizations by ascending height rather than preferring all notarizations or all nullifications
            //
            // It is possible we may have requested notarizations and nullifications for the same view (and only one may
            // exist). We should try to fetch both before trying to fetch the next view, or we may never ask for an existing
            // notarization or nullification.
            let mut notarizations = Vec::new();
            let mut nullifications = Vec::new();
            let mut inflight = Vec::new();
            for entry in self.required.iter() {
                // Check if we already have a request outstanding for this
                if self.inflight.contains(entry) {
                    continue;
                }
                self.inflight.insert(entry.clone());
                inflight.push(entry.clone());

                // Add to inflight
                if entry.notarization {
                    notarizations.push(entry.view);
                } else {
                    nullifications.push(entry.view);
                }
                if notarizations.len() + nullifications.len() >= self.max_fetch_count {
                    break;
                }
            }

            // If nothing to do, return
            if notarizations.is_empty() && nullifications.is_empty() {
                return;
            }

            // Select next recipient
            loop {
                // Get next best
                let Some((recipient, request)) = self.requester.request(shuffle) else {
                    // If we are rate limited and already sent at least one request, return
                    if sent {
                        return;
                    }

                    // If we have not yet sent a request and have outstanding items, wait
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
                    .send(Recipients::One(recipient.clone()), msg, false)
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
                self.inflight_by_request.insert(request, inflight);
                debug!(
                    peer = hex(&recipient),
                    ?notarizations,
                    ?nullifications,
                    "sent request"
                );
                sent = true;
                break;
            }
        }
    }

    /// Clear entries for a given request.
    fn clear_inflight(&mut self, request: requester::ID) {
        if let Some(inflight) = self.inflight_by_request.remove(&request) {
            for entry in inflight {
                self.inflight.remove(&entry);
            }
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
            self.unfulfilled.set(self.required.len() as i64);
            self.outstanding.set(self.requester.len() as i64);

            // Set timeout for next request
            let (request, timeout) = if let Some((request, timeout)) = self.requester.next() {
                (request, Either::Left(self.runtime.sleep_until(timeout)))
            } else {
                (0, Either::Right(futures::future::pending()))
            };

            // Wait for an event
            select! {
                _ = timeout => {
                    // Penalize peer for timeout
                    let request = self.requester.cancel(request).expect("request not found");
                    self.clear_inflight(request.id);
                    self.requester.timeout(request);

                    // Send message
                    self.send(true, &mut sender).await;
                    continue;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = match mailbox {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::Fetch { notarizations, nullifications } => {
                            // Add to all outstanding required
                            for view in notarizations {
                                self.required.insert(Entry { notarization: true, view });
                            }
                            for view in nullifications {
                                self.required.insert(Entry { notarization: false, view });
                            }

                            // Trigger fetch of new notarizations and nullifications as soon as possible
                            self.send(false, &mut sender).await;
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
                            self.required.remove(&Entry { notarization: true, view });

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
                            self.required.remove(&Entry { notarization: false, view });

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
                            self.required.retain(|entry| entry.view >= view);

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
                            let mut notarization_views_found = Vec::new();
                            let mut notarizations_found = Vec::new();
                            let mut nullification_views_found = Vec::new();
                            let mut nullifications_found = Vec::new();

                            // Ensure too many notarizations/nullifications aren't requested
                            if request.notarizations.len() + request.nullifications.len() > self.max_fetch_count {
                                warn!(sender = hex(&s), "request too large");
                                self.requester.block(s.clone());
                                continue;
                            }

                            // Populate notarizations first
                            for view in request.notarizations {
                                if let Some(notarization) = self.notarizations.get(&view) {
                                    let size = notarization.encoded_len();
                                    if populated_bytes + size > self.max_fetch_size {
                                        break;
                                    }
                                    populated_bytes += size;
                                    notarization_views_found.push(view);
                                    notarizations_found.push(notarization.clone());
                                    self.served.inc();
                                }
                            }

                            // Populate nullifications next
                            for view in request.nullifications {
                                if let Some(nullification) = self.nullifications.get(&view) {
                                    let size = nullification.encoded_len();
                                    if populated_bytes + size > self.max_fetch_size {
                                        break;
                                    }
                                    populated_bytes += size;
                                    nullification_views_found.push(view);
                                    nullifications_found.push(nullification.clone());
                                    self.served.inc();
                                }
                            }

                            // Send response
                            debug!(sender = hex(&s), ?notarization_views_found, ?nullification_views_found,  "sending response");
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
                            self.clear_inflight(request.id);

                            // Ensure response isn't too big
                            if response.notarizations.len() + response.nullifications.len() > self.max_fetch_count {
                                // Block responder
                                warn!(sender = hex(&s), "response too large");
                                self.requester.block(s);

                                // Pick new recipient
                                self.send(true, &mut sender).await;
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
                                let entry = Entry { notarization: true, view };
                                if !self.required.contains(&entry) {
                                    debug!(view, sender = hex(&s), "unnecessary notarization");
                                    continue;
                                }
                                if !verify_notarization::<S,C>(&self.supervisor, &self.notarize_namespace, &notarization) {
                                    warn!(view, sender = hex(&s), "invalid notarization");
                                    self.requester.block(s.clone());
                                    continue;
                                }
                                self.required.remove(&entry);
                                self.notarizations.insert(view, notarization.clone());
                                voter.notarization(notarization).await;
                                notarizations_found.insert(view);
                            }

                            // Parse nullifications
                            for nullification in response.nullifications {
                                let view = nullification.view;
                                let entry = Entry { notarization: false, view };
                                if !self.required.contains(&entry) {
                                    debug!(view, sender = hex(&s), "unnecessary nullification");
                                    continue;
                                }
                                if !verify_nullification::<S,C>(&self.supervisor, &self.nullify_namespace, &nullification) {
                                    warn!(view, sender = hex(&s), "invalid nullification");
                                    self.requester.block(s.clone());
                                    continue;
                                }
                                self.required.remove(&entry);
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
                                debug!(sender = hex(&s), "response not useful");
                            }

                            // If still work to do, send another request
                            self.send(false, &mut sender).await;
                        },
                    }
                },
            }
        }
    }
}
