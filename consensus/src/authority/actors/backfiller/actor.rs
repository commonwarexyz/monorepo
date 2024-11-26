use super::{
    ingress::{Mailbox, Message},
    priority_queue::PriorityQueue,
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
use commonware_cryptography::{Hasher, PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use prost::Message as _;
use rand::Rng;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

type Status = (PublicKey, SystemTime, SystemTime);

pub struct Actor<E: Clock + GClock + Rng, C: Scheme, H: Hasher, S: Supervisor<Index = View>> {
    runtime: E,
    crypto: C,
    hasher: H,
    supervisor: S,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,

    notarizations: BTreeMap<View, wire::Notarization>,
    nullifications: BTreeMap<View, wire::Nullification>,

    mailbox_receiver: mpsc::Receiver<Message>,

    fetch_timeout: Duration,
    max_fetch_count: u64,
    max_fetch_size: usize,
    fetch_rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    fetch_performance: PriorityQueue,

    incorrect: HashSet<PublicKey>,
}

impl<E: Clock + GClock + Rng, C: Scheme, H: Hasher, S: Supervisor<Index = View>> Actor<E, C, H, S> {
    pub fn new(runtime: E, cfg: Config<C, H, S>) -> (Self, Mailbox) {
        // Initialize rate limiter
        //
        // This ensures we don't exceed the inbound rate limit on any peer we are communicating with (which
        // would halt their processing of all our messages).
        let fetch_rate_limiter = RateLimiter::hashmap_with_clock(cfg.fetch_rate_per_peer, &runtime);

        // Initialize mailbox
        let (sender, receiver) = mpsc::channel(1024);
        (
            Self {
                runtime,
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                supervisor: cfg.supervisor,

                notarize_namespace: notarize_namespace(&cfg.namespace),
                nullify_namespace: nullify_namespace(&cfg.namespace),

                notarizations: BTreeMap::new(),
                nullifications: BTreeMap::new(),

                mailbox_receiver: receiver,

                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_rate_limiter,
                fetch_performance: PriorityQueue::new(),

                incorrect: HashSet::new(),
            },
            Mailbox::new(sender),
        )
    }

    async fn send(
        &mut self,
        msg: Bytes,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> Status {
        // Loop until we find a recipient
        loop {
            let iter = self.fetch_performance.iter();
            for next in iter {
                // Check if self
                if next.public_key == self.crypto.public_key() {
                    continue;
                }

                // Check if peer is invalid
                if self.incorrect.contains(&next.public_key) {
                    debug!(
                        peer = hex(&next.public_key),
                        "skipping request because peer is incorrect"
                    );
                    continue;
                }

                // Check if already sent this request
                if sent.contains(&next.public_key) {
                    debug!(
                        peer = hex(&next.public_key),
                        "skipping request because already sent"
                    );
                    continue;
                }

                // Check if rate limit is exceeded
                let validator = &next.public_key;
                if self.fetch_rate_limiter.check_key(validator).is_err() {
                    debug!(
                        peer = hex(validator),
                        "skipping request because rate limited"
                    );
                    continue;
                }

                // Send message
                if sender
                    .send(Recipients::One(validator.clone()), msg.clone(), false)
                    .await
                    .unwrap()
                    .is_empty()
                {
                    // Try again
                    debug!(peer = hex(validator), "failed to send request");
                    continue;
                }
                debug!(peer = hex(validator), "sent request");
                sent.insert(validator.clone());
                let start = self.runtime.current();
                let deadline = start + self.fetch_timeout;

                // Minimize footprint of rate limiter
                self.fetch_rate_limiter.shrink_to_fit();
                return (validator.clone(), start, deadline);
            }

            // Avoid busy looping when disconnected
            warn!("failed to send request to any validator");
            self.runtime.sleep(self.fetch_timeout).await;

            // Clear sent
            sent.clear();
        }
    }

    async fn send_request(
        &mut self,
        notarizations: &BTreeSet<View>,
        nullifications: &BTreeSet<View>,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> Status {
        // Create new message
        let msg = wire::Backfiller {
            payload: Some(wire::backfiller::Payload::Request(wire::Request {
                notarizations: notarizations.iter().cloned().collect(),
                nullifications: nullifications.iter().cloned().collect(),
            })),
        }
        .encode_to_vec()
        .into();

        // Send message
        self.send(msg, sent, sender).await
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
        let mut outstanding: Option<(BTreeSet<View>, BTreeSet<View>, HashSet<PublicKey>, Status)> =
            None;
        loop {
            // Set timeout for next request
            let timeout = if let Some((_, _, _, status)) = &outstanding {
                Either::Left(self.runtime.sleep_until(status.2))
            } else {
                Either::Right(futures::future::pending())
            };

            // Wait for an event
            select! {
                _ = timeout => {
                    // Penalize requester for timeout
                    let (notarizations, nullifications, mut sent, status) = outstanding.take().unwrap();
                    self.fetch_performance.put(status.0, self.fetch_timeout);

                    // Send message
                    let status = self.send_request(&notarizations, &nullifications, &mut sent,  &mut sender).await;
                    outstanding = Some((notarizations, nullifications, sent, status));
                    continue;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = match mailbox {
                        Some(msg) => msg,
                        None => break,
                    };
                    match msg {
                        Message::Fetch { notarizations, nullifications } => {
                            // If request already exists, just add to it
                            if outstanding.is_some() {
                                let (existing_notarizations, existing_nullifications, _, _) = outstanding.as_mut().unwrap();
                                existing_notarizations.extend(notarizations);
                                existing_nullifications.extend(nullifications);
                                continue;
                            }

                            // If request does not exist, create it
                            let mut sent = HashSet::new();
                            let notarizations = notarizations.into_iter().collect();
                            let nullifications = nullifications.into_iter().collect();
                            let status = self.send_request(&notarizations, &nullifications, &mut sent, &mut sender).await;
                            outstanding = Some((notarizations, nullifications, sent, status));
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
                            self.fetch_performance.retain(self.fetch_timeout, validators);

                            // If waiting for this notarization, remove it
                            if let Some((notarizations, _, _, _)) = &mut outstanding {
                                notarizations.remove(&view);
                            }

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
                            self.fetch_performance.retain(self.fetch_timeout, validators);

                            // If waiting for this nullification, remove it
                            if let Some((_, nullifications, _, _)) = &mut outstanding {
                                nullifications.remove(&view);
                            }

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

                            // Remove unneeded cache
                            self.notarizations.retain(|k, _| *k >= view);
                            self.nullifications.retain(|k, _| *k >= view);

                            // Remove outstanding
                            if let Some((notarizations, nullifications, _, _)) = &mut outstanding {
                                notarizations.retain(|v| *v >= view);
                                nullifications.retain(|v| *v >= view);
                            }
                        }
                    }

                    // Check if outstanding request is no longer required
                    if let Some((notarizations, nullifications, _, _)) = &outstanding {
                        if notarizations.is_empty() && nullifications.is_empty() {
                            debug!("outstanding request no longer required");
                            outstanding = None;
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
                                    if notarizations_found.len() + 1 > self.max_fetch_count as usize {
                                        break;
                                    }
                                    populated_bytes += size;
                                    notarizations_found.push(notarization.clone());
                                }
                            }

                            // Populate nullifications next
                            for view in request.nullifications {
                                if let Some(nullification) = self.nullifications.get(&view) {
                                    let size = nullification.encoded_len();
                                    if populated_bytes + size > self.max_fetch_size {
                                        break;
                                    }
                                    if notarizations_found.len() + nullifications_found.len() + 1 > self.max_fetch_count as usize {
                                        break;
                                    }
                                    populated_bytes += size;
                                    nullifications_found.push(nullification.clone());
                                }
                            }

                            // Send response
                            debug!(notarizations_found = notarizations_found.len(), nullifications_found = nullifications_found.len(), sender = hex(&s), "sending response");
                            let response = wire::Backfiller {
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
                            // If we weren't waiting for anything, ignore
                            let received = self.runtime.current();
                            let (notarizations, nullifications, status) = match &mut outstanding {
                                Some((notarizations, nullifications, _, status)) => {
                                    if s != status.0 {
                                        debug!(sender = hex(&s), "received unexpected response");
                                        continue;
                                    }
                                    if response.notarizations.is_empty() && response.nullifications.is_empty() {
                                        debug!(sender = hex(&s), "received empty response");

                                        // Pick new recipient
                                        let (notarizations, nullifications, mut sent, _) = outstanding.take().unwrap();
                                        let status = self.send_request(&notarizations, &nullifications, &mut sent, &mut sender).await;
                                        outstanding = Some((notarizations, nullifications, sent, status));
                                        continue;
                                    }
                                    (notarizations, nullifications, status)
                                },
                                None => {
                                    warn!(sender = hex(&s), "received unexpected response");
                                    continue;
                                },
                            };

                            // Ensure response isn't too big
                            if response.notarizations.len() + response.nullifications.len() > self.max_fetch_count as usize {
                                warn!(sender = hex(&s), "response too large");

                                // Pick new recipient
                                let (notarizations, nullifications, mut sent, _) = outstanding.take().unwrap();
                                let status = self.send_request(&notarizations, &nullifications, &mut sent, &mut sender).await;
                                outstanding = Some((notarizations, nullifications, sent, status));
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
                                        continue;
                                    },
                                };
                                if !notarizations.contains(&view) {
                                    debug!(view, sender = hex(&s), "unnecessry notarization");
                                    continue;
                                }
                                if !verify_notarization::<S,C>(&self.supervisor, &self.notarize_namespace, &notarization) {
                                    warn!(view, sender = hex(&s), "invalid notarization");
                                    continue;
                                }
                                notarizations.remove(&view);
                                self.notarizations.insert(view, notarization.clone());
                                voter.notarization(notarization).await;
                                notarizations_found.insert(view);
                            }

                            // Parse nullifications
                            for nullification in response.nullifications {
                                let view = nullification.view;
                                if !nullifications.contains(&view) {
                                    debug!(view, sender = hex(&s), "unnecessry nullification");
                                    continue;
                                }
                                if !verify_nullification::<S,C>(&self.supervisor, &self.nullify_namespace, &nullification) {
                                    warn!(view, sender = hex(&s), "invalid nullification");
                                    continue;
                                }
                                nullifications.remove(&view);
                                self.nullifications.insert(view, nullification.clone());
                                voter.nullification(nullification).await;
                                nullifications_found.insert(view);
                            }

                            // Update performance
                            if !notarizations_found.is_empty() || !nullifications_found.is_empty() {
                                let duration = received.duration_since(status.1).unwrap();
                                self.fetch_performance.put(s.clone(), duration);
                                debug!(
                                    notarizations_found = ?notarizations_found.into_iter().collect::<Vec<_>>(),
                                    nullifications_found = ?nullifications_found.into_iter().collect::<Vec<_>>(),
                                    sender = hex(&s),
                                    "request successful",
                                );
                            }

                            // If still work to do, send another request
                            if !notarizations.is_empty() || !nullifications.is_empty() {
                                let (notarizations, nullifications, mut sent, _) = outstanding.take().unwrap();
                                let status = self.send_request(&notarizations, &nullifications, &mut sent, &mut sender).await;
                                outstanding = Some((notarizations, nullifications, sent, status));
                            } else {
                                outstanding = None;
                            }
                        },
                    }
                },
            }
        }
    }
}
