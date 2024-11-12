use super::{
    ingress::{Mailbox, Message},
    priority_queue::PriorityQueue,
    Config,
};
use crate::{
    authority::{
        actors::resolver,
        encoder::{proposal_message, proposal_namespace, vote_message, vote_namespace},
        wire, Context, Height, View,
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

#[derive(Default)]
struct Notarizations {
    digest: Option<wire::Notarization>,
    null: Option<wire::Notarization>,
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
    max_fetch_count: u64,
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
        parents: Height,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> Status {
        // Compute deadline
        let deadline = self.runtime.current() + self.fetch_timeout;
        let deadline = deadline
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create new message
        let msg = wire::Backfiller {
            payload: Some(wire::backfiller::Payload::ProposalRequest(
                wire::ProposalRequest {
                    deadline,
                    digest,
                    parents,
                },
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
        children: View,
        sent: &mut HashSet<PublicKey>,
        sender: &mut impl Sender,
    ) -> Status {
        // Compute deadline
        let deadline = self.runtime.current() + self.fetch_timeout;
        let deadline = deadline
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create new message
        let msg = wire::Backfiller {
            payload: Some(wire::backfiller::Payload::NotarizationRequest(
                wire::NotarizationRequest {
                    deadline,
                    view,
                    children,
                },
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
        mut resolver: resolver::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        // Instantiate priority queue
        let validators = self.application.participants(last_notarized).unwrap();
        self.fetch_performance
            .retain(self.fetch_timeout, validators);

        // Wait for an event
        let mut outstanding_proposal: Option<(Digest, Height, HashSet<PublicKey>, Status)> = None;
        let mut outstanding_notarization: Option<(View, View, HashSet<PublicKey>, Status)> = None;
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
                        Message::FilledProposals {recipient, proposals} => {
                            // Send message
                            let msg = wire::Backfiller {
                                payload: Some(wire::backfiller::Payload::ProposalResponse(wire::ProposalResponse {
                                    proposals,
                                })),
                            }
                            .encode_to_vec()
                            .into();
                            sender.send(Recipients::One(recipient), msg, false).await.unwrap();
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
                    match payload {
                        wire::backfiller::Payload::ProposalRequest(request) => {
                            // Confirm request is valid
                            if !H::validate(&request.digest) {
                                warn!(sender = hex(&s), "invalid digest");
                                continue;
                            }

                            // Confirm deadline is valid
                            let request_deadline = SystemTime::UNIX_EPOCH + Duration::from_secs(request.deadline);
                            let min_deadline = self.runtime.current();
                            let max_deadline = min_deadline + self.fetch_timeout;
                            if request_deadline < min_deadline || request_deadline > max_deadline {
                                warn!(sender = hex(&s), "invalid deadline");
                                continue;
                            }

                            // Request proposals from resolver
                            resolver.proposals(request.digest.clone(), request.parents, s, request_deadline).await;
                        },
                        wire::backfiller::Payload::ProposalResponse(response) => {
                            // Ensure this proposal is expected
                            //
                            // If we don't do this check, it is trivial to DoS us.
                            let mut next = match outstanding_proposal {
                                Some((ref digest, _, _, ref status)) => {
                                    if s != status.0 {
                                        debug!(sender = hex(&s), "received unexpected proposal response");
                                        continue;
                                    }

                                    // Check if this is an empty response (go to next recipient)
                                    if response.proposals.is_empty() {
                                        debug!(digest = hex(&digest), peer = hex(&s), "received empty proposal response");

                                        // Pick new recipient
                                        let (digest, parents, mut sent, _) = outstanding_proposal.take().unwrap();
                                        let status = self.send_block_request(digest.clone(), parents, &mut sent, &mut sender).await;
                                        outstanding_proposal = Some((digest, parents, sent, status));
                                        continue;
                                    }
                                    digest.clone()
                                },
                                None => {
                                    debug!(sender = hex(&s), "received unexpected batch proposal");
                                    continue;
                                },
                            };


                            // Parse proposals
                            let received = self.runtime.current();
                            let mut resolved = false;
                            let mut proposals_found = Vec::new();
                            let len = response.proposals.len();
                            for proposal in response.proposals {
                                // Ensure this is the container we want
                                if !H::validate(&proposal.parent) {
                                    debug!(sender = hex(&s), "invalid proposal parent digest size");
                                    break;
                                }
                                let payload_digest = match self.application.parse(proposal.payload.clone()).await {
                                    Some(payload_digest) => payload_digest,
                                    None => {
                                        debug!(sender = hex(&s), "unable to parse notarized/finalized payload");
                                        break;
                                    }
                                };
                                let proposal_message = proposal_message(
                                    proposal.view,
                                    proposal.height,
                                    &proposal.parent,
                                    &payload_digest,
                                );
                                self.hasher.update(&proposal_message);
                                let proposal_digest = self.hasher.finalize();
                                if proposal_digest != next {
                                    debug!(sender = hex(&s), "received invalid batch proposal");
                                    break;
                                }

                                // Verify leader signature
                                let signature = match &proposal.signature {
                                    Some(signature) => signature,
                                    None => {
                                        debug!(sender = hex(&s), "missing proposal signature");
                                        break;
                                    }
                                };
                                if !C::validate(&signature.public_key) {
                                    debug!(sender = hex(&s), "invalid proposal public key");
                                    break;
                                }
                                let expected_leader = match self.leader(proposal.view) {
                                    Some(leader) => leader,
                                    None => {
                                        debug!(
                                            proposal_leader = hex(&signature.public_key),
                                            reason = "unable to compute leader",
                                            "dropping proposal"
                                        );
                                        break;
                                    }
                                };
                                if expected_leader != signature.public_key {
                                    debug!(
                                        proposal_leader = hex(&signature.public_key),
                                        view_leader = hex(&expected_leader),
                                        reason = "leader mismatch",
                                        "dropping proposal"
                                    );
                                    break;
                                }
                                if !C::verify(
                                    &self.proposal_namespace,
                                    &proposal_message,
                                    &signature.public_key,
                                    &signature.signature,
                                ) {
                                    warn!(sender = hex(&s), "invalid proposal signature");
                                    break;
                                }
                                let height = proposal.height;
                                let parent = proposal.parent.clone();
                                proposals_found.push((proposal_digest.clone(), proposal));
                                debug!(height, digest = hex(&proposal_digest), peer = hex(&s), "received batch proposal");

                                // Remove outstanding task if we were waiting on this
                                //
                                // Note, we don't care if we are sent the proposal from someone unexpected (although
                                // this is unexpected).
                                if let Some(ref outstanding) = outstanding_proposal{
                                    if outstanding.0 == proposal_digest {
                                        resolved = true;
                                    }
                                }

                                // Setup next processing
                                if height <= 1 {
                                    break;
                                }
                                next = parent;
                            }

                            // If invalid, pick new recipient
                            if proposals_found.len() != len {
                                self.incorrect.insert(s);
                                let (digest, parents, mut sent, _) = outstanding_proposal.take().unwrap();
                                let status = self.send_block_request(digest.clone(), parents, &mut sent, &mut sender).await;
                                outstanding_proposal = Some((digest, parents, sent, status));
                                continue;
                            }

                            // Send resolution
                            if resolved {
                                let outstanding = outstanding_proposal.take().unwrap();
                                debug!(height = outstanding.1, digest = hex(&outstanding.0), peer = hex(&s), "resolved missing proposal via backfill");
                                resolver.backfilled_proposals(proposals_found).await;

                                // Update performance
                                let duration = received.duration_since(outstanding.3.1).unwrap();
                                self.fetch_performance.put(s, duration);
                            }
                        },
                        wire::backfiller::Payload::NotarizationRequest(request) => {
                            // Confirm deadline is valid
                            let request_deadline = SystemTime::UNIX_EPOCH + Duration::from_secs(request.deadline);
                            let min_deadline = self.runtime.current();
                            let max_deadline = min_deadline + self.fetch_timeout;
                            if request_deadline < min_deadline || request_deadline > max_deadline {
                                warn!(sender = hex(&s), "invalid deadline");
                                continue;
                            }

                            // Populate as many notarizations as we can
                            let mut notarization_bytes = 0; // TODO: add a buffer
                            let mut notarizations_found = Vec::new();
                            let mut cursor = request.view;
                            {
                                loop {
                                    // Attempt to fetch notarization
                                    let notarizations = match self.notarizations.get(&cursor) {
                                        Some(notarizations) => notarizations,
                                        None => {
                                            debug!(
                                                sender = hex(&s),
                                                view = cursor,
                                                "unable to load notarization",
                                            );
                                            break;
                                        }
                                    };

                                    // Prefer return a digest notarization (if it exists)
                                    let notarization = match &notarizations.digest {
                                        Some(notarization) => notarization.clone(),
                                        None => notarizations.null.as_ref().unwrap().clone(), // if exists, one must be a valid notarization
                                    };

                                    // If we don't have any more space, stop
                                    notarization_bytes += notarization.encoded_len();
                                    if notarization_bytes > self.max_fetch_size{
                                        debug!(
                                            requested = request.children + 1,
                                            fetched = notarizations_found.len(),
                                            peer = hex(&s),
                                            "reached max fetch size"
                                        );
                                        break;
                                    }
                                    notarizations_found.push(notarization.clone());

                                    // If we have all children or we hit our limit, stop
                                    let fetched = notarizations_found.len() as u64;
                                    if fetched == request.children +1 || fetched == self.max_fetch_count {
                                        break;
                                    }
                                    cursor +=1;
                                }
                            }

                            // Send back notarizations
                            debug!(view = cursor, fetched = notarizations_found.len(), peer = hex(&s), "responding to notarization request");
                            let msg = wire::Backfiller {
                                payload: Some(wire::backfiller::Payload::NotarizationResponse(
                                    wire::NotarizationResponse {
                                        notarizations: notarizations_found,
                                    },
                                )),
                            }
                            .encode_to_vec()
                            .into();
                            sender.send(Recipients::One(s), msg, false).await.unwrap();
                        },
                        wire::backfiller::Payload::NotarizationResponse(response) => {
                            // Ensure this notarization is expected
                            //
                            // If we don't do this check, it is trivial to DoS us.
                            let mut next = match outstanding_notarization {
                                Some((view, _, _, ref status)) => {
                                    if s != status.0 {
                                        debug!(sender = hex(&s), "received unexpected notarization response");
                                        continue;
                                    }

                                    // Check if this is an empty response (go to next recipient)
                                    if response.notarizations.is_empty() {
                                        debug!(view, peer = hex(&s), "received empty notarization response");

                                        // Pick new recipient
                                        let (view, children, mut sent, _) = outstanding_notarization.take().unwrap();
                                        let status = self.send_notarization_request(view, children, &mut sent, &mut sender).await;
                                        outstanding_notarization = Some((view, children, sent, status));
                                        continue;
                                    }
                                    view
                                },
                                None => {
                                    debug!(sender = hex(&s), "received unexpected batch notarization");
                                    continue;
                                },
                            };

                            // Parse notarizations
                            let received = self.runtime.current();
                            let mut resolved = false;
                            let mut notarizations_found = Vec::new();
                            let len = response.notarizations.len();
                            for notarization in response.notarizations {
                                // Ensure notarization is valid
                                if notarization.view != next {
                                    debug!(sender = hex(&s), "received invalid batch notarization");
                                    break;
                                }
                                if let Some(notarization_digest) = notarization.digest.as_ref() {
                                    if !H::validate(notarization_digest) {
                                        debug!(sender = hex(&s), "invalid notarization digest size");
                                        break;
                                    }
                                    if notarization.height.is_none() {
                                        debug!(sender = hex(&s), "missing notarization height");
                                        break;
                                    }
                                } else if notarization.height.is_some() {
                                    debug!(sender = hex(&s), "invalid notarization height for null container");
                                    break;
                                }

                                // Ensure notarization has valid number of signatures
                                let (threshold, count) = match self.threshold(notarization.view) {
                                    Some(participation) => participation,
                                    None => {
                                        debug!(
                                            view = notarization.view,
                                            reason = "unable to compute participants for view",
                                            "dropping notarization"
                                        );
                                        break;
                                    }
                                };
                                if notarization.signatures.len() < threshold as usize {
                                    debug!(
                                        threshold,
                                        signatures = notarization.signatures.len(),
                                        reason = "insufficient signatures",
                                        "dropping notarization"
                                    );
                                    break;
                                }
                                if notarization.signatures.len() > count as usize {
                                    debug!(
                                        threshold,
                                        signatures = notarization.signatures.len(),
                                        reason = "too many signatures",
                                        "dropping notarization"
                                    );
                                    break;
                                }

                                // Verify threshold notarization
                                let mut seen = HashSet::new();
                                for signature in notarization.signatures.iter() {
                                    // Verify signature
                                    if !C::validate(&signature.public_key) {
                                        debug!(
                                            signer = hex(&signature.public_key),
                                            reason = "invalid validator",
                                            "dropping notarization"
                                        );
                                        break;
                                    }

                                    // Ensure we haven't seen this signature before
                                    if seen.contains(&signature.public_key) {
                                        debug!(
                                            signer = hex(&signature.public_key),
                                            reason = "duplicate signature",
                                            "dropping notarization"
                                        );
                                        break;
                                    }
                                    seen.insert(signature.public_key.clone());

                                    // Verify signature
                                    if !C::verify(
                                        &self.vote_namespace,
                                        &vote_message(
                                            notarization.view,
                                            notarization.height,
                                            notarization.digest.as_ref(),
                                        ),
                                        &signature.public_key,
                                        &signature.signature,
                                    ) {
                                        debug!(reason = "invalid signature", "dropping notarization");
                                        break;
                                    }
                                }
                                let view = notarization.view;
                                notarizations_found.push(notarization);
                                debug!(view, "received batch notarization");

                                // Remove outstanding task if we were waiting on this
                                if let Some(ref outstanding) = outstanding_notarization {
                                    if outstanding.0 == view {
                                        resolved = true;
                                    }
                                }

                                // Setup next processing
                                if view == u64::MAX {
                                    break;
                                }
                                next = view + 1;
                            }

                            // If invalid, pick new
                            if notarizations_found.len() != len {
                                self.incorrect.insert(s);
                                let (view, children, mut sent, _) = outstanding_notarization.take().unwrap();
                                let status = self.send_notarization_request(view, children, &mut sent, &mut sender).await;
                                outstanding_notarization = Some((view, children, sent, status));
                                continue;
                            }

                            // Persist notarizations
                            for notarization in &notarizations_found {
                                let view = notarization.view;
                                let null = notarization.digest.is_none();
                                let entry = self.notarizations.entry(view).or_default();
                                if null && entry.null.is_none() {
                                    entry.null = Some(notarization.clone());
                                } else if !null && entry.digest.is_none() {
                                    entry.digest = Some(notarization.clone());
                                } else {
                                    debug!(view, null, "received unnecessary notarization");
                                }
                            }

                            // Send resolution
                            if resolved {
                                let outstanding = outstanding_notarization.take().unwrap();
                                debug!(view = outstanding.0, peer = hex(&s), "resolved missing notarization via backfill");
                                resolver.backfilled_notarizations(notarizations_found).await;

                                // Update performance
                                let duration = received.duration_since(outstanding.3.1).unwrap();
                                self.fetch_performance.put(s, duration);
                            }
                        },
                    }
                },
            }
        }
    }
}
