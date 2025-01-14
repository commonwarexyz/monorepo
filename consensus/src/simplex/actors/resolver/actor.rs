use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    simplex::{
        actors::voter,
        encoder::{notarize_namespace, nullify_namespace},
        verifier::{verify_notarization, verify_nullification},
        wire, View,
    },
    Supervisor,
};
use commonware_cryptography::{Hasher, Scheme};
use commonware_macros::select;
use commonware_p2p::{utils::requester, Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prost::Message as _;
use rand::{prelude::SliceRandom, Rng};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// Task in the required set.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
enum Task {
    Notarization,
    Nullification,
}

/// Entry in the required set.
#[derive(Clone, Eq, PartialEq)]
struct Entry {
    task: Task,
    view: View,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.view.cmp(&other.view) {
            Ordering::Equal => self.task.cmp(&other.task),
            ordering => ordering,
        }
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Tracks the contents of inflight requests to avoid duplicate work.
struct Inflight {
    all: BTreeSet<Entry>,
    requests: BTreeMap<requester::ID, Vec<Entry>>,
}

impl Inflight {
    fn new() -> Self {
        Self {
            all: BTreeSet::new(),
            requests: BTreeMap::new(),
        }
    }

    /// Check if the entry is already inflight.
    fn contains(&self, entry: &Entry) -> bool {
        self.all.contains(entry)
    }

    /// Add a new request to the inflight set.
    fn add(&mut self, request: requester::ID, entries: Vec<Entry>) {
        for entry in entries.iter() {
            self.all.insert(entry.clone());
        }
        self.requests.insert(request, entries);
    }

    /// Clear a request from the inflight set.
    fn clear(&mut self, request: requester::ID) {
        if let Some(entries) = self.requests.remove(&request) {
            for entry in entries {
                self.all.remove(&entry);
            }
        }
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
    inflight: Inflight,
    retry: Option<SystemTime>,

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
                inflight: Inflight::new(),
                retry: None,

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
        // Clear retry
        self.retry = None;

        // We try to send as many requests as possible at the same time for unfulfilled notarizations and nullifications.
        loop {
            // If we have too many requests outstanding, return
            if self.requester.len() >= self.fetch_concurrent {
                return;
            }

            // We assume nothing about the usefulness (or existence) of any given entry, so we shuffle
            // the iterator to ensure we eventually try to fetch everything requested.
            let mut entries = self
                .required
                .iter()
                .filter(|entry| !self.inflight.contains(entry))
                .collect::<Vec<_>>();
            if entries.is_empty() {
                return;
            }
            entries.shuffle(&mut self.runtime);

            // Select entries up to configured limits
            let mut notarizations = Vec::new();
            let mut nullifications = Vec::new();
            let mut inflight = Vec::new();
            for entry in self.required.iter() {
                inflight.push(entry.clone());
                match entry.task {
                    Task::Notarization => notarizations.push(entry.view),
                    Task::Nullification => nullifications.push(entry.view),
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
            let notarization_count = notarizations.len();
            let nullification_count = nullifications.len();
            let mut msg = wire::Backfiller {
                id: 0, // set once we have a request ID
                payload: Some(wire::backfiller::Payload::Request(wire::Request {
                    notarizations,
                    nullifications,
                })),
            };
            loop {
                // Get next best
                let Some((recipient, request)) = self.requester.request(shuffle) else {
                    // If we have outstanding items but there are no recipients available, set
                    // a deadline to retry and return.
                    //
                    // We return instead of waiting to continue serving requests and in case we
                    // learn of new notarizations or nullifications in the meantime.
                    warn!("failed to send request to any validator");
                    let deadline = self
                        .runtime
                        .current()
                        .checked_add(self.fetch_timeout)
                        .expect("time overflowed");
                    self.retry = Some(deadline);
                    return;
                };

                // Create new message
                msg.id = request;
                let encoded = msg.encode_to_vec().into();

                // Try to send
                if sender
                    .send(Recipients::One(recipient.clone()), encoded, false)
                    .await
                    .unwrap()
                    .is_empty()
                {
                    // Try again (treating past request as timeout)
                    let request = self.requester.cancel(request).unwrap();
                    self.requester.timeout(request);
                    debug!(peer = hex(&recipient), "failed to send request");
                    continue;
                }

                // Exit if sent
                self.inflight.add(request, inflight);
                debug!(
                    peer = hex(&recipient),
                    notarization_count, nullification_count, "sent request"
                );
                break;
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

            // Set timeout for retry
            let retry = match self.retry {
                Some(retry) => Either::Left(self.runtime.sleep_until(retry)),
                None => Either::Right(futures::future::pending()),
            };

            // Set timeout for next request
            let (request, timeout) = if let Some((request, timeout)) = self.requester.next() {
                (request, Either::Left(self.runtime.sleep_until(timeout)))
            } else {
                (0, Either::Right(futures::future::pending()))
            };

            // Wait for an event
            select! {
                _ = retry => {
                    // Retry sending after rate limiting
                    self.send(false, &mut sender).await;
                },
                _ = timeout => {
                    // Penalize peer for timeout
                    let request = self.requester.cancel(request).expect("request not found");
                    self.inflight.clear(request.id);
                    self.requester.timeout(request);

                    // Send message
                    self.send(true, &mut sender).await;
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
                                self.required.insert(Entry { task: Task::Notarization, view });
                            }
                            for view in nullifications {
                                self.required.insert(Entry { task: Task::Nullification, view });
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
                            self.required.remove(&Entry { task: Task::Notarization, view });

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
                            self.required.remove(&Entry { task: Task::Nullification, view });

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
                            let mut notarizations_found = Vec::new();
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
                                    nullifications_found.push(nullification.clone());
                                    self.served.inc();
                                }
                            }

                            // Send response
                            debug!(sender = hex(&s), notarization_count = notarizations_found.len(), nullification_count = nullifications_found.len(),  "sending response");
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
                            self.inflight.clear(request.id);

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
                                let entry = Entry { task: Task::Notarization, view };
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
                                let entry = Entry { task: Task::Nullification, view };
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
                            let mut shuffle = false;
                            if !notarizations_found.is_empty() || !nullifications_found.is_empty() {
                                self.requester.resolve(request);
                                debug!(
                                    sender = hex(&s),
                                    notarization_count = notarizations_found.len(),
                                    nullification_count = ?nullifications_found.len(),
                                    "response useful",
                                );
                            } else {
                                // We don't reward a peer for sending us a response that doesn't help us
                                shuffle = true;
                                debug!(sender = hex(&s), "response not useful");
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
