use super::{ingress::Mailbox, Config, Message};
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
    fetch_performance: BTreeMap<Duration, Vec<PublicKey>>,
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
                fetch_performance: BTreeMap::new(),
            },
            Mailbox::new(sender),
        )
    }

    async fn send(&mut self, view: View, msg: Bytes, sender: &mut impl Sender) -> PublicKey {
        // Loop until we find a recipient
        let mut index = 0;
        let validator = loop {
            // Check if we have exhausted all validators
            if index == validators.len() {
                warn!(view, "failed to send request to any validator");

                // Avoid busy looping when disconnected
                self.runtime.sleep(self.fetch_timeout).await;
                index = 0;
                continue;
            }

            // Select random validator to fetch from
            let validator = validators[validator_indices[index]].clone();
            if validator == self.crypto.public_key() {
                index += 1;
                continue;
            }

            // Check if rate limit is exceeded
            if self.fetch_rate_limiter.check_key(&validator).is_err() {
                debug!(
                    peer = hex(&validator),
                    "skipping request because rate limited"
                );
                index += 1;
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
                index += 1;
                continue;
            }
            debug!(peer = hex(&validator), "sent request");
            break validator;
        };

        // Minimize footprint of rate limiter
        self.fetch_rate_limiter.shrink_to_fit();
        validator
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
                            // Remove any old validators
                            let mut validators_set = self.application.participants(view).unwrap().iter().collect::<BTreeSet<_>>();
                            for (_, validators) in self.fetch_performance.iter_mut() {
                                validators.iter().filter(|v| {
                                    if validators_set.contains(v){
                                        true
                                    } else {
                                        validators_set.remove(v);
                                        false
                                    }
                                });
                            }

                            // Add new validators with minimum duration to explore
                            let new_validators = validators_set.into_iter().cloned().collect::<Vec<_>>();
                            match self.fetch_performance.entry(STARTING_DURATION) {
                                Entry::Vacant(entry) => {
                                    entry.insert(new_validators);
                                },
                                Entry::Occupied(mut entry) => {
                                    entry.get_mut().extend(new_validators);
                                },
                            }
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
