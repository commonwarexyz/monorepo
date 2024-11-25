use super::{
    ingress::{Mailbox, Message},
    priority_queue::PriorityQueue,
    Config,
};
use crate::{
    authority::{
        actors::voter,
        encoder::{notarize_namespace, nullify_namespace},
        wire, Context, View,
    },
    Automaton, Supervisor,
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
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
        voter: &mut voter::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Wait for an event
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
                    let msg = mailbox.unwrap();
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
                            // Update stored validators
                            let view = notarization.proposal.as_ref().unwrap().view;
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
                            // Update stored validators
                            let view = nullification.view;
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
                        },
                        wire::backfiller::Payload::Response(response) => {
                        },
                    }
                },
            }
        }
    }
}
