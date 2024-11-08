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
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{channel::mpsc, future::Either, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use prost::Message as _;
use rand::{prelude::SliceRandom, Rng};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet, HashSet},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

const STARTING_DURATION: Duration = Duration::from_secs(0);

enum Status {
    Stalled,
    Outstanding(PublicKey, SystemTime),
}

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

    mailbox_receiver: mpsc::Receiver<Message>,

    fetch_timeout: Duration,
    max_fetch_count: u32,
    max_fetch_size: usize,
    fetch_rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    fetch_performance: PriorityQueue,
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

    async fn send(&mut self, view: View, msg: Bytes, sender: &mut impl Sender) -> PublicKey {
        // Loop until we find a recipient
        loop {
            let mut iter = self.fetch_performance.iter();
            while let Some(next) = iter.next() {
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

                // Minimize footprint of rate limiter
                self.fetch_rate_limiter.shrink_to_fit();
                return validator.clone();
            }

            // Avoid busy looping when disconnected
            warn!(view, "failed to send request to any validator");
            self.runtime.sleep(self.fetch_timeout).await;
        }
    }

    pub async fn run(
        mut self,
        mut last_notarized: View,
        voter: &mut voter::Mailbox,
        resolver: &mut resolver::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
        let mut outstanding_block: Option<(Digest, u32, Status)> = None;
        let mut outstanding_notarization: Option<(View, u32, Status)> = None;
        loop {
            // Set timeout for next block
            let block_timeout = if let Some((_, _, status)) = &outstanding_block {
                Either::Left(match status {
                    Status::Stalled => Either::Left(futures::future::ready(())),
                    Status::Outstanding(_, deadline) => {
                        Either::Right(self.runtime.sleep_until(*deadline))
                    }
                })
            } else {
                Either::Right(futures::future::pending())
            };

            // Set timeout for next notarization
            let notarization_timeout = if let Some((_, _, status)) = &outstanding_notarization {
                Either::Left(match status {
                    Status::Stalled => Either::Left(futures::future::ready(())),
                    Status::Outstanding(_, deadline) => {
                        Either::Right(self.runtime.sleep_until(*deadline))
                    }
                })
            } else {
                Either::Right(futures::future::pending())
            };

            // Wait for an event
            select! {
                _ = block_timeout => {
                    // Send request to a different peer
                },
                _ = notarization_timeout => {
                    // Send request to a different peer
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Notarized { view } => {
                            // Update stored validators
                            let validators = self.application.participants(view).unwrap();
                            self.fetch_performance.retain(validators);
                            continue;
                        },
                        Message::Proposals { digest, parents } => {
                            // Handle proposals
                        },
                        Message::Notarizations { view, children } => {
                            // Handle notarizations
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
                        wire::backfiller::Payload::ProposalRequest(request) => {},
                        wire::backfiller::Payload::ProposalResponse(response) => {},
                        wire::backfiller::Payload::NotarizationRequest(request) => {},
                        wire::backfiller::Payload::NotarizationResponse(response) => {},
                    }
                }
            }
        }
    }
}
