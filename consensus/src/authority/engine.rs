use super::{
    actors::{resolver, voter},
    config::Config,
};
use crate::{Application, Hasher};
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Spawner};
use rand::Rng;
use tracing::debug;

pub struct Engine<E: Clock + Rng + Spawner, C: Scheme, H: Hasher, A: Application> {
    runtime: E,

    resolver: resolver::Actor<E, H, A>,
    resolver_mailbox: resolver::Mailbox,

    voter: voter::Actor<E, C, H, A>,
    voter_mailbox: voter::Mailbox,
}

impl<E: Clock + Rng + Spawner, C: Scheme, H: Hasher, A: Application> Engine<E, C, H, A> {
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
            cfg.hasher.clone(),
            cfg.application.clone(),
            cfg.fetch_timeout,
            cfg.max_fetch_count,
            cfg.max_fetch_size,
        );

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            runtime.clone(),
            cfg.crypto,
            cfg.hasher,
            cfg.application,
            voter::Config {
                registry: cfg.registry,
                namespace: cfg.namespace,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                null_vote_retry: cfg.null_vote_retry,
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
