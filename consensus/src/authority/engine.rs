use super::{
    actors::{resolver, voter},
    config::Config,
};
use crate::{Application, Finalizer, Hasher, Supervisor};
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Spawner};
use governor::clock::Clock as GClock;
use rand::Rng;
use tracing::debug;

pub struct Engine<
    E: Clock + GClock + Rng + Spawner,
    C: Scheme,
    H: Hasher,
    A: Application + Supervisor + Finalizer,
> {
    runtime: E,

    resolver: resolver::Actor<E, C, H, A>,
    resolver_mailbox: resolver::Mailbox,

    voter: voter::Actor<E, C, H, A>,
    voter_mailbox: voter::Mailbox,
}

impl<
        E: Clock + GClock + Rng + Spawner,
        C: Scheme,
        H: Hasher,
        A: Application + Supervisor + Finalizer,
    > Engine<E, C, H, A>
{
    pub fn new(runtime: E, mut cfg: Config<C, H, A>) -> Self {
        // Sort the validators at each view
        if cfg.validators.is_empty() {
            panic!("no validators specified");
        }
        for (_, validators) in cfg.validators.iter_mut() {
            if validators.is_empty() {
                panic!("no validators specified");
            }
            validators.sort();
        }

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            runtime.clone(),
            resolver::Config {
                crypto: cfg.crypto.clone(),
                hasher: cfg.hasher.clone(),
                application: cfg.application.clone(),
                namespace: cfg.namespace.clone(),
                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_rate_per_peer: cfg.fetch_rate_per_peer,
            },
        );

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            runtime.clone(),
            voter::Config {
                crypto: cfg.crypto,
                hasher: cfg.hasher,
                application: cfg.application,
                registry: cfg.registry,
                namespace: cfg.namespace,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                null_vote_retry: cfg.null_vote_retry,
                activity_timeout: cfg.activity_timeout,
            },
        );

        // Return the engine
        Self {
            runtime,

            resolver,
            resolver_mailbox,

            voter,
            voter_mailbox,
        }
    }

    pub async fn run(
        mut self,
        resolver_network: (impl Sender, impl Receiver),
        voter_network: (impl Sender, impl Receiver),
    ) {
        // Start the resolver
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver = self.runtime.spawn("resolver", async move {
            self.resolver
                .run(&mut self.voter_mailbox, resolver_sender, resolver_receiver)
                .await;
        });

        // Start the voter
        let (voter_sender, voter_receiver) = voter_network;
        let mut voter = self.runtime.spawn("voter", async move {
            self.voter
                .run(&mut self.resolver_mailbox, voter_sender, voter_receiver)
                .await;
        });

        // Wait for the resolver or voter to finish
        select! {
            _ = &mut resolver => {
                debug!("resolver finished");
                voter.abort();
            },
            _ = &mut voter => {
                debug!("voter finished");
                resolver.abort();
            },
        }
    }
}
