use super::{
    ingress::{Mailbox, Message},
    Config,
};
use crate::{
    threshold_simplex::{
        actors::voter,
        types::{Backfiller, Notarization, Nullification, Request, Response, View, Viewable},
    },
    ThresholdSupervisor,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{bls12381::primitives::poly, Digest, Scheme};
use commonware_macros::select;
use commonware_p2p::{utils::requester, Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand::{seq::IteratorRandom, Rng};
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
pub struct Actor<
    E: Clock + GClock + Rng + Metrics + Spawner,
    C: Scheme,
    D: Digest,
    S: ThresholdSupervisor<Index = View, Identity = poly::Public, PublicKey = C::PublicKey>,
> {
    context: E,
    supervisor: S,
    _digest: PhantomData<D>,

    namespace: Vec<u8>,

    notarizations: BTreeMap<View, Notarization<D>>,
    nullifications: BTreeMap<View, Nullification>,
    activity_timeout: u64,

    required: BTreeSet<Entry>,
    inflight: Inflight,
    retry: Option<SystemTime>,

    mailbox_receiver: mpsc::Receiver<Message<D>>,

    fetch_timeout: Duration,
    max_fetch_count: usize,
    fetch_concurrent: usize,
    requester: requester::Requester<E, C::PublicKey>,

    unfulfilled: Gauge,
    outstanding: Gauge,
    served: Counter,
}

impl<
        E: Clock + GClock + Rng + Metrics + Spawner,
        C: Scheme,
        D: Digest,
        S: ThresholdSupervisor<Index = View, Identity = poly::Public, PublicKey = C::PublicKey>,
    > Actor<E, C, D, S>
{
    pub fn new(context: E, cfg: Config<C, S>) -> (Self, Mailbox<D>) {
        // Initialize requester
        let config = requester::Config {
            public_key: cfg.crypto.public_key(),
            rate_limit: cfg.fetch_rate_per_peer,
            initial: cfg.fetch_timeout / 2,
            timeout: cfg.fetch_timeout,
        };
        let requester = requester::Requester::new(context.clone(), config);

        // Initialize metrics
        let unfulfilled = Gauge::default();
        let outstanding = Gauge::default();
        let served = Counter::default();
        context.register(
            "unfulfilled",
            "unfulfilled notarizations/nullifications",
            unfulfilled.clone(),
        );
        context.register("outstanding", "outstanding requests", outstanding.clone());
        context.register(
            "served",
            "served notarizations/nullifications",
            served.clone(),
        );

        // Initialize mailbox
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                supervisor: cfg.supervisor,
                _digest: PhantomData,

                namespace: cfg.namespace,

                notarizations: BTreeMap::new(),
                nullifications: BTreeMap::new(),
                activity_timeout: cfg.activity_timeout,

                required: BTreeSet::new(),
                inflight: Inflight::new(),
                retry: None,

                mailbox_receiver: receiver,

                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
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
    async fn send(&mut self, shuffle: bool, sender: &mut impl Sender<PublicKey = C::PublicKey>) {
        // Clear retry
        self.retry = None;

        // We try to send as many requests as possible at the same time for unfulfilled notarizations and nullifications.
        loop {
            // If we have too many requests outstanding, return
            if self.requester.len() >= self.fetch_concurrent {
                return;
            }

            // We assume nothing about the usefulness (or existence) of any given entry, so we sample
            // the iterator to ensure we eventually try to fetch everything requested.
            let entries = self
                .required
                .iter()
                .filter(|entry| !self.inflight.contains(entry))
                .choose_multiple(&mut self.context, self.max_fetch_count);
            if entries.is_empty() {
                return;
            }

            // Select entries up to configured limits
            let mut notarizations = Vec::new();
            let mut nullifications = Vec::new();
            let mut inflight = Vec::new();
            for entry in entries {
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
            let mut msg = Request::new(0, notarizations.clone(), nullifications.clone());
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
                        .context
                        .current()
                        .checked_add(self.fetch_timeout)
                        .expect("time overflowed");
                    self.retry = Some(deadline);
                    return;
                };

                // Create new message
                msg.id = request;
                let encoded = Backfiller::<D>::Request(msg.clone()).encode();

                // Try to send
                if sender
                    .send(Recipients::One(recipient.clone()), encoded.into(), false)
                    .await
                    .unwrap()
                    .is_empty()
                {
                    // Try again (treating past request as timeout)
                    let request = self.requester.cancel(request).unwrap();
                    self.requester.timeout(request);
                    debug!(peer = ?recipient, "failed to send request");
                    continue;
                }

                // Exit if sent
                self.inflight.add(request, inflight);
                debug!(
                    peer = ?recipient,
                    ?notarizations,
                    ?nullifications,
                    "sent request"
                );
                break;
            }
        }
    }

    pub fn start(
        self,
        voter: voter::Mailbox<D>,
        sender: impl Sender<PublicKey = C::PublicKey>,
        receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(voter, sender, receiver))
    }

    async fn run(
        mut self,
        mut voter: voter::Mailbox<D>,
        mut sender: impl Sender<PublicKey = C::PublicKey>,
        mut receiver: impl Receiver<PublicKey = C::PublicKey>,
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
                Some(retry) => Either::Left(self.context.sleep_until(retry)),
                None => Either::Right(futures::future::pending()),
            };

            // Set timeout for next request
            let (request, timeout) = if let Some((request, timeout)) = self.requester.next() {
                (request, Either::Left(self.context.sleep_until(timeout)))
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
                                debug!(?view, "notarization required");
                            }
                            for view in nullifications {
                                self.required.insert(Entry { task: Task::Nullification, view });
                                debug!(?view, "nullification required");
                            }

                            // Trigger fetch of new notarizations and nullifications as soon as possible
                            self.send(false, &mut sender).await;
                        }
                        Message::Notarized { notarization } => {
                            // Update current view
                            let view = notarization.view();
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
                    let msg = match Backfiller::decode_cfg(msg, &self.max_fetch_count) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, sender = ?s, "failed to decode message");
                            self.requester.block(s);
                            continue;
                        },
                    };
                    match msg{
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
                                    self.served.inc();
                                } else {
                                    missing_notarizations.push(view);
                                }
                            }

                            // Populate nullifications next
                            for view in request.nullifications {
                                if let Some(nullification) = self.nullifications.get(&view) {
                                    nullifications.push(view);
                                    nullifications_found.push(nullification.clone());
                                    self.served.inc();
                                } else {
                                    missing_nullifications.push(view);
                                }
                            }

                            // Send response
                            debug!(sender = ?s, ?notarizations, ?missing_notarizations, ?nullifications, ?missing_nullifications, "sending response");
                            let response = Response::new(request.id, notarizations_found, nullifications_found);
                            let response = Backfiller::Response(response).encode().into();
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

                            // Parse notarizations
                            let mut notarizations_found = BTreeSet::new();
                            let mut nullifications_found = BTreeSet::new();
                            for notarization in response.notarizations {
                                let view = notarization.view();
                                let entry = Entry { task: Task::Notarization, view };
                                if !self.required.contains(&entry) {
                                    debug!(view, sender = ?s, "unnecessary notarization");
                                    continue;
                                }
                                let Some(identity) = self.supervisor.identity(view) else {
                                    warn!(view, sender = ?s, "missing identity");
                                    continue;
                                };
                                let public_key = poly::public(identity);
                                if !notarization.verify(&self.namespace, public_key) {
                                    warn!(view, sender = ?s, "invalid notarization");
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
                                    debug!(view, sender = ?s, "unnecessary nullification");
                                    continue;
                                }
                                let Some(identity) = self.supervisor.identity(view) else {
                                    warn!(view, sender = ?s, "missing identity");
                                    continue;
                                };
                                let public_key = poly::public(identity);
                                if !nullification.verify(&self.namespace, public_key) {
                                    warn!(view, sender = ?s, "invalid nullification");
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
