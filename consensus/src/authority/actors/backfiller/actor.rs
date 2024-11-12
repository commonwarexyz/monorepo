use std::{
    collections::{BTreeMap, HashSet},
    time::Duration,
};

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
use commonware_cryptography::{Hasher, PublicKey, Scheme};
use commonware_runtime::Clock;
use futures::channel::mpsc;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use rand::Rng;

struct Notarizations {
    digest: Option<wire::Notarization>,
    null: Option<wire::Notarization>,
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
}
