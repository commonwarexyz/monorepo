use super::{ingress::Mailbox, Config, Message};
use crate::{
    authority::{
        actors::{resolver, voter},
        Context, View,
    },
    Automaton, Supervisor,
};
use commonware_cryptography::{Hasher, PublicKey, Scheme};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Clock;
use futures::channel::mpsc;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use rand::Rng;
use std::time::Duration;

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

    timeout: Duration,
    max_fetch_count: u32,
    max_fetch_size: usize,
    rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
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

                timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                rate_limiter: fetch_rate_limiter,
            },
            Mailbox::new(sender),
        )
    }

    pub async fn run(
        mut self,
        voter: &mut voter::Mailbox,
        resolver: &mut resolver::Mailbox,
        mut sender: impl Sender,
        mut receiver: impl Receiver,
    ) {
    }
}
