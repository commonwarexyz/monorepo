use super::{ingress::Mailbox, priority_queue::PriorityQueue, Config, Message};
use crate::{
    authority::{
        actors::{resolver, voter},
        wire, Context, Height, View,
    },
    Automaton, Supervisor,
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Storage};
use commonware_storage::archive::{Archive, Translator};
use commonware_utils::hex;
use futures::{
    channel::mpsc,
    future::Either,
    lock::{Mutex, MutexGuard},
    StreamExt,
};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use prost::Message as _;
use rand::{prelude::SliceRandom, Rng};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet, HashSet},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

const STARTING_DURATION: Duration = Duration::from_secs(0);

type Status = (PublicKey, SystemTime);

pub struct Actor<
    T: Translator,
    B: Blob,
    E: Clock + GClock + Rng + Storage<B>,
    C: Scheme,
    H: Hasher,
    A: Automaton<Context = Context> + Supervisor<Index = View>,
> {
    runtime: E,
    crypto: C,
    hasher: H,
    application: A,

    proposals: Arc<Mutex<Archive<T, B, E>>>,
    notarizations: Arc<Mutex<Archive<T, B, E>>>,

    mailbox_receiver: mpsc::Receiver<Message>,

    fetch_timeout: Duration,
    max_fetch_count: u32,
    max_fetch_size: usize,
    fetch_rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    fetch_performance: PriorityQueue,
}

impl<
        T: Translator,
        B: Blob,
        E: Clock + GClock + Rng + Storage<B>,
        C: Scheme,
        H: Hasher,
        A: Automaton<Context = Context> + Supervisor<Index = View>,
    > Actor<T, B, E, C, H, A>
{
    pub fn new(
        runtime: E,
        proposals: Arc<Mutex<Archive<T, B, E>>>,
        notarizations: Arc<Mutex<Archive<T, B, E>>>,
        cfg: Config<C, H, A>,
    ) -> (Self, Mailbox) {
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

                proposals,
                notarizations,

                mailbox_receiver: receiver,

                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_rate_limiter,
                fetch_performance: PriorityQueue::new(),
            },
            Mailbox::new(sender),
        )
    }

    async fn send(
        &mut self,
        msg: Bytes,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> (PublicKey, SystemTime) {
        // Loop until we find a recipient
        loop {
            let mut iter = self.fetch_performance.iter();
            while let Some(next) = iter.next() {
                // Check if self
                if next.public_key == self.crypto.public_key() {
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
                let deadline = self.runtime.current() + self.fetch_timeout;

                // Minimize footprint of rate limiter
                self.fetch_rate_limiter.shrink_to_fit();
                return (validator.clone(), deadline);
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
        let (public_key, deadline) = self.send(msg, sent, sender).await;
        (public_key, deadline)
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
        let (public_key, deadline) = self.send(msg, sent, sender).await;
        (public_key, deadline)
    }

    pub async fn run(
        mut self,
        last_notarized: View,
        voter: &mut voter::Mailbox,
        resolver: &mut resolver::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Instantiate priority queue
        let validators = self.application.participants(last_notarized).unwrap();
        self.fetch_performance
            .retain(self.fetch_timeout / 2, validators);

        // Wait for an event
        let mut outstanding_block: Option<(Digest, u32, HashSet<PublicKey>, Status)> = None;
        let mut outstanding_notarization: Option<(View, u32, HashSet<PublicKey>, Status)> = None;
        loop {
            // Set timeout for next block
            let block_timeout = if let Some((_, _, _, status)) = &outstanding_block {
                Either::Left(self.runtime.sleep_until(status.1))
            } else {
                Either::Right(futures::future::pending())
            };

            // Set timeout for next notarization
            let notarization_timeout = if let Some((_, _, _, status)) = &outstanding_notarization {
                Either::Left(self.runtime.sleep_until(status.1))
            } else {
                Either::Right(futures::future::pending())
            };

            // Wait for an event
            select! {
                _ = block_timeout => {
                    // Penalize requester for timeout
                    let (digest, parents, mut sent, status) = outstanding_block.take().unwrap();
                    self.fetch_performance.put(status.0, self.fetch_timeout);

                    // Send message
                    let status = self.send_block_request(digest.clone(), parents, &mut sent, &mut sender).await;
                    outstanding_block = Some((digest, parents, sent, status));
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
                        Message::Notarized { view } => {
                            // Update stored validators
                            let validators = self.application.participants(view).unwrap();
                            self.fetch_performance.retain(self.fetch_timeout/2, validators);
                            continue;
                        },
                        Message::Proposals { digest, parents } => {
                            // Send message
                            let mut sent = HashSet::new();
                            let status = self.send_block_request(digest.clone(), parents, &mut sent, &mut sender).await;
                            outstanding_block = Some((digest, parents, sent, status));
                            continue;
                        },
                        Message::Notarizations { view, children } => {
                            // Send message
                            let mut sent = HashSet::new();
                            let status = self.send_notarization_request(view, children, &mut sent, &mut sender).await;
                            outstanding_notarization = Some((view, children, sent, status));
                            continue;
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
                    match payload {
                        wire::backfiller::Payload::ProposalRequest(request) => {
                            // Confirm request is valid
                            if !H::validate(&request.digest) {
                                warn!(sender = hex(&s), "invalid digest");
                                continue;
                            }

                            // Populate as many proposals as possible
                            let mut proposal_bytes = 0;
                            let mut proposals_found = Vec::new();
                            let mut cursor = request.digest.clone();
                            {
                                let proposals = self.proposals.lock().await;
                                loop {
                                    // Check to see if we have proposal
                                    let proposal = match proposals.get(&cursor).await {
                                        Ok(proposal) => proposal,
                                        Err(err) => {
                                            debug!(
                                                sender = hex(&s),
                                                proposal = hex(&cursor),
                                                ?err,
                                                "unable to load proposal",
                                            );
                                            break;
                                        }
                                    };
                                    let proposal = match proposal {
                                        Some(proposal) => proposal,
                                        None => {
                                            debug!(
                                                sender = hex(&s),
                                                proposal = hex(&cursor),
                                                "missing proposal",
                                            );
                                            break;
                                        }
                                    };
                                    let proposal = wire::Proposal::decode(proposal).expect("unable to decode persisted proposal");

                                    // If we don't have any more space, stop
                                    proposal_bytes += proposal.encoded_len();
                                    if proposal_bytes > self.max_fetch_size {
                                        debug!(
                                            requested = request.parents + 1,
                                            found = proposals_found.len(),
                                            peer = hex(&s),
                                            "reached max response size",
                                        );
                                        break;
                                    }

                                    // If we do have space, add to proposals
                                    cursor = proposal.parent.clone();
                                    proposals_found.push(proposal);

                                    // If we have all parents requested, stop gathering more
                                    let fetched = proposals_found.len() as u32;
                                    if fetched == request.parents + 1 || fetched == self.max_fetch_count {
                                        break;
                                    }
                                }
                            }

                            // Send response
                            debug!(digest = hex(&request.digest), requested = request.parents + 1, found = proposals_found.len(), peer = hex(&s), "responding to backfill request");
                            let msg =  wire::Backfiller {
                                payload: Some(wire::backfiller::Payload::ProposalResponse(wire::ProposalResponse {
                                    proposals: proposals_found,
                                })),
                            }
                            .encode_to_vec()
                            .into();
                            sender.send(Recipients::One(s), msg, false).await.unwrap();
                        },
                        wire::backfiller::Payload::ProposalResponse(response) => {
                            // TODO: skip duration update if response is empty
                        },
                        wire::backfiller::Payload::NotarizationRequest(request) => {},
                        wire::backfiller::Payload::NotarizationResponse(response) => {
                            // TODO: skip duration update if response is empty
                        },
                    }
                }
            }
        }
    }
}
