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
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
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

/// Task in the required set.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord, EncodeLabelValue)]
enum Task {
    Notarization,
    Nullification,
}

/// Metric label that indicates the type of task.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TaskLabel {
    task: Task,
}

impl TaskLabel {
    fn notarization() -> &'static Self {
        &Self {
            task: Task::Notarization,
        }
    }

    fn nullification() -> &'static Self {
        &Self {
            task: Task::Nullification,
        }
    }
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

/// Tracks required entries with metrics by task type.
struct Required {
    entries: BTreeSet<Entry>,
    unfulfilled: Family<TaskLabel, Gauge>,
}

impl Required {
    fn new(metrics: &impl Metrics) -> Self {
        let unfulfilled = Family::default();
        metrics.register(
            "unfulfilled",
            "unfulfilled notarizations/nullifications",
            unfulfilled.clone(),
        );

        Self {
            entries: BTreeSet::new(),
            unfulfilled,
        }
    }

    fn insert(&mut self, task: Task, view: View) -> bool {
        let inserted = self.entries.insert(Entry { task, view });
        if inserted {
            let label = match task {
                Task::Notarization => TaskLabel::notarization(),
                Task::Nullification => TaskLabel::nullification(),
            };
            self.unfulfilled.get_or_create(label).inc();
        }
        inserted
    }

    fn remove(&mut self, task: Task, view: View) -> bool {
        let removed = self.entries.remove(&Entry { task, view });
        if removed {
            let label = match task {
                Task::Notarization => TaskLabel::notarization(),
                Task::Nullification => TaskLabel::nullification(),
            };
            self.unfulfilled.get_or_create(label).dec();
        }
        removed
    }

    fn prune(&mut self, min_view: View) {
        let mut removed_notarizations = 0;
        let mut removed_nullifications = 0;

        self.entries.retain(|entry| {
            let retain = entry.view >= min_view;
            if !retain {
                match entry.task {
                    Task::Notarization => removed_notarizations += 1,
                    Task::Nullification => removed_nullifications += 1,
                }
            }
            retain
        });

        if removed_notarizations > 0 {
            self.unfulfilled
                .get_or_create(TaskLabel::notarization())
                .dec_by(removed_notarizations);
        }
        if removed_nullifications > 0 {
            self.unfulfilled
                .get_or_create(TaskLabel::nullification())
                .dec_by(removed_nullifications);
        }
    }

    fn sample<R: Rng>(&self, inflight: &Inflight, rng: &mut R, count: usize) -> Vec<Entry> {
        // We assume nothing about the usefulness (or existence) of any given entry, so we sample
        // the iterator to ensure we eventually try to fetch everything requested.
        self.entries
            .iter()
            .filter(|entry| !inflight.contains(entry))
            .cloned()
            .choose_multiple(rng, count)
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

    notarizations: BTreeMap<View, Notarization<S, D>>,
    nullifications: BTreeMap<View, Nullification<S>>,
    activity_timeout: u64,

    required: Required,
    inflight: Inflight,
    retry: Option<SystemTime>,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    fetch_timeout: Duration,
    max_fetch_count: usize,
    fetch_concurrent: usize,
    requester: requester::Requester<E, P>,

    outstanding: Gauge,
    served: Family<TaskLabel, Counter>,
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
        let outstanding = Gauge::default();
        let served = Family::default();
        context.register("outstanding", "outstanding requests", outstanding.clone());
        context.register(
            "served",
            "served notarizations/nullifications",
            served.clone(),
        );

        let required = Required::new(&context);

        // Initialize mailbox
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,

                blocker: cfg.blocker,

                epoch: cfg.epoch,
                namespace: cfg.namespace,

                notarizations: BTreeMap::new(),
                nullifications: BTreeMap::new(),
                activity_timeout: cfg.activity_timeout,

                required,
                inflight: Inflight::new(),
                retry: None,

                mailbox_receiver: receiver,

                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                fetch_concurrent: cfg.fetch_concurrent,
                requester,

                outstanding,
                served,
            },
            Mailbox::new(sender),
        )
    }

    /// Concurrent indicates whether we should send a new request (only if we see a request for the first time)
    async fn send<Sr: Sender<PublicKey = P>>(
        &mut self,
        shuffle: bool,
        sender: &mut WrappedSender<Sr, Backfiller<S, D>>,
    ) {
        // Clear retry
        self.retry = None;

        // We try to send as many requests as possible at the same time for unfulfilled notarizations and nullifications.
        loop {
            // If we have too many requests outstanding, return
            if self.requester.len() >= self.fetch_concurrent {
                return;
            }

            // Randomly sample entries to request
            let entries =
                self.required
                    .sample(&self.inflight, &mut self.context, self.max_fetch_count);
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
                let encoded = Backfiller::<S, D>::Request(msg.clone());

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
        let (mut sender, mut receiver) = wrap(
            (self.max_fetch_count, self.scheme.certificate_codec_config()),
            sender,
            receiver,
        );

        // Wait for an event
        let mut current_view = 0;
        let mut finalized_view = 0;
        loop {
            // Record outstanding metric
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
                                self.required.insert(Task::Notarization, view);
                                debug!(?view, "notarization required");
                            }
                            for view in nullifications {
                                self.required.insert(Task::Nullification, view);
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
