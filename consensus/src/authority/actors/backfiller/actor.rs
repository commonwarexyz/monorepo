use super::{
    ingress::{Mailbox, Message},
    priority_queue::PriorityQueue,
    Config,
};
use crate::{
    authority::{
        actors::{resolver, voter},
        encoder::{proposal_message, proposal_namespace, vote_message, vote_namespace},
        wire, Context, View,
    },
    Automaton, Supervisor,
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Clock;
use commonware_utils::{hex, quorum};
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use prost::Message as _;
use rand::Rng;
use std::{
    collections::{BTreeMap, HashSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

struct Notarizations {
    digest: Option<wire::Notarization>,
    null: Option<wire::Notarization>,
}

impl Default for Notarizations {
    fn default() -> Self {
        Self {
            digest: None,
            null: None,
        }
    }
}

type Status = (PublicKey, SystemTime, SystemTime);

pub struct Actor<
    E: Clock + GClock + Rng,
    C: Scheme,
    H: Hasher,
    A: Automaton<Context = Context> + Supervisor<Index = View>,
> {
    runtime: E,
    crypto: C,
    hasher: H,
    application: A,

    proposal_namespace: Vec<u8>,
    vote_namespace: Vec<u8>,

    notarizations: BTreeMap<View, Notarizations>,

    mailbox_receiver: mpsc::Receiver<Message>,

    fetch_timeout: Duration,
    max_fetch_count: u32,
    max_fetch_size: usize,
    fetch_rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    fetch_performance: PriorityQueue,

    incorrect: HashSet<PublicKey>,
}

impl<
        E: Clock + GClock + Rng,
        C: Scheme,
        H: Hasher,
        A: Automaton<Context = Context> + Supervisor<Index = View>,
    > Actor<E, C, H, A>
{
    pub fn new(runtime: E, cfg: Config<C, H, A>) -> (Self, Mailbox) {
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
                application: cfg.application,

                proposal_namespace: proposal_namespace(&cfg.namespace),
                vote_namespace: vote_namespace(&cfg.namespace),

                notarizations: BTreeMap::new(),

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

    // TODO: remove duplicated code
    fn leader(&self, view: View) -> Option<PublicKey> {
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => return None,
        };
        Some(validators[view as usize % validators.len()].clone())
    }

    // TODO: remove duplicated code
    fn threshold(&self, view: View) -> Option<(u32, u32)> {
        let validators = match self.application.participants(view) {
            Some(validators) => validators,
            None => return None,
        };
        let len = validators.len() as u32;
        let threshold = quorum(len).expect("not enough validators for a quorum");
        Some((threshold, len))
    }

    async fn send(
        &mut self,
        msg: Bytes,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> Status {
        // Loop until we find a recipient
        loop {
            let mut iter = self.fetch_performance.iter();
            while let Some(next) = iter.next() {
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
                        peer = hex(&validator),
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
                    debug!(peer = hex(&validator), "failed to send request");
                    continue;
                }
                debug!(peer = hex(&validator), "sent request");
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

    async fn send_block_request(
        &mut self,
        digest: Digest,
        parents: u32,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> Status {
        // Create new message
        let msg = wire::Backfiller {
            payload: Some(wire::backfiller::Payload::ProposalRequest(
                wire::ProposalRequest { digest, parents },
            )),
        }
        .encode_to_vec()
        .into();

        // Send message
        self.send(msg, sent, sender).await
    }

    async fn send_notarization_request(
        &mut self,
        view: View,
        children: u32,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> Status {
        // Create new message
        let msg = wire::Backfiller {
            payload: Some(wire::backfiller::Payload::NotarizationRequest(
                wire::NotarizationRequest { view, children },
            )),
        }
        .encode_to_vec()
        .into();

        // Send message
        self.send(msg, sent, sender).await
    }

    pub async fn run(
        mut self,
        last_notarized: View,
        resolver: &mut resolver::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Instantiate priority queue
        let validators = self.application.participants(last_notarized).unwrap();
        self.fetch_performance
            .retain(self.fetch_timeout, validators);

        // Wait for an event
        let mut outstanding_proposal: Option<(Digest, u32, HashSet<PublicKey>, Status)> = None;
        let mut outstanding_notarization: Option<(View, u32, HashSet<PublicKey>, Status)> = None;
        loop {
            // Set timeout for next proposal
            let proposal_timeout = if let Some((_, _, _, status)) = &outstanding_proposal {
                Either::Left(self.runtime.sleep_until(status.2))
            } else {
                Either::Right(futures::future::pending())
            };

            // Set timeout for next notarization
            let notarization_timeout = if let Some((_, _, _, status)) = &outstanding_notarization {
                Either::Left(self.runtime.sleep_until(status.2))
            } else {
                Either::Right(futures::future::pending())
            };

            // Wait for an event
            select! {
                _ = proposal_timeout => {
                    // Penalize requester for timeout
                    let (digest, parents, mut sent, status) = outstanding_proposal.take().unwrap();
                    self.fetch_performance.put(status.0, self.fetch_timeout);

                    // Send message
                    let status = self.send_block_request(digest.clone(), parents, &mut sent, &mut sender).await;
                    outstanding_proposal = Some((digest, parents, sent, status));
                    continue;
                },
                _ = notarization_timeout => {
                    // Penalize requester for timeout
                    let (view, children, mut sent, status) = outstanding_notarization.take().unwrap();
                    self.fetch_performance.put(status.0, self.fetch_timeout);

                    // Send message
                    let status = self.send_notarization_request(view, children, &mut sent,  &mut sender).await;
                    outstanding_notarization = Some((view, children, sent, status));
                    continue;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Notarized {view, notarization, last_finalized} => {
                            // Update stored validators
                            let validators = self.application.participants(view).unwrap();
                            self.fetch_performance.retain(self.fetch_timeout, validators);

                            // Add notarization to cache
                            let notarizations = self.notarizations.entry(view).or_default();
                            if notarization.digest.is_none() {
                                notarizations.null = Some(notarization);
                            } else {
                                notarizations.digest = Some(notarization);
                            }

                            // Remove notarization from cache less than last finalized
                            self.notarizations.retain(|view, _| {
                                if *view < last_finalized {
                                    false
                                } else {
                                    true
                                }
                            });
                        }
                        Message::Proposals {digest, parents} => {
                            // Send message
                            let mut sent = HashSet::new();
                            let status = self.send_block_request(digest.clone(), parents, &mut sent, &mut sender).await;
                            outstanding_proposal = Some((digest, parents, sent, status));
                        },
                        Message::Notarizations { view, children } => {
                            // Send message
                            let mut sent = HashSet::new();
                            let status = self.send_notarization_request(view, children, &mut sent, &mut sender).await;
                            outstanding_notarization = Some((view, children, sent, status));
                        },
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
                    unimplemented!();
                },
            }
        }
    }
}
