use super::{
    actors::{resolver, voter},
    config::Config,
    Context, View,
};
use crate::{Automaton, Committer, Relay, Supervisor};
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Blob, Clock, Spawner, Storage};
use commonware_storage::journal::variable::Journal;
use commonware_utils::Array;
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use tracing::debug;

/// Instance of `simplex` consensus engine.
pub struct Engine<
    B: Blob,
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage<B>,
    C: Scheme,
    D: Array,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Committer<Digest = D>,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    runtime: E,

    voter: voter::Actor<B, E, C, D, A, R, F, S>,
    voter_mailbox: voter::Mailbox<D>,
    resolver: resolver::Actor<E, C, D, S>,
    resolver_mailbox: resolver::Mailbox,
}

impl<
        B: Blob,
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage<B>,
        C: Scheme,
        D: Array,
        A: Automaton<Context = Context<D>, Digest = D>,
        R: Relay<Digest = D>,
        F: Committer<Digest = D>,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Engine<B, E, C, D, A, R, F, S>
{
    /// Create a new `simplex` consensus engine.
    pub fn new(runtime: E, journal: Journal<B, E>, cfg: Config<C, D, A, R, F, S>) -> Self {
        // Ensure configuration is valid
        cfg.assert();

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            runtime.clone(),
            journal,
            voter::Config {
                crypto: cfg.crypto.clone(),
                automaton: cfg.automaton,
                relay: cfg.relay,
                committer: cfg.committer,
                supervisor: cfg.supervisor.clone(),
                registry: cfg.registry.clone(),
                mailbox_size: cfg.mailbox_size,
                namespace: cfg.namespace.clone(),
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
                replay_concurrency: cfg.replay_concurrency,
            },
        );

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            runtime.clone(),
            resolver::Config {
                crypto: cfg.crypto,
                supervisor: cfg.supervisor,
                registry: cfg.registry,
                mailbox_size: cfg.mailbox_size,
                namespace: cfg.namespace,
                activity_timeout: cfg.activity_timeout,
                fetch_timeout: cfg.fetch_timeout,
                fetch_concurrent: cfg.fetch_concurrent,
                max_fetch_count: cfg.max_fetch_count,
                max_fetch_size: cfg.max_fetch_size,
                fetch_rate_per_peer: cfg.fetch_rate_per_peer,
            },
        );

        // Return the engine
        Self {
            runtime,

            voter,
            voter_mailbox,
            resolver,
            resolver_mailbox,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub async fn run(
        self,
        voter_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        // Start the voter
        let (voter_sender, voter_receiver) = voter_network;
        let mut voter = self.runtime.spawn("voter", async move {
            self.voter
                .run(self.resolver_mailbox, voter_sender, voter_receiver)
                .await;
        });

        // Start the resolver
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver = self.runtime.spawn("resolver", async move {
            self.resolver
                .run(self.voter_mailbox, resolver_sender, resolver_receiver)
                .await;
        });

        // Wait for the resolver or voter to finish
        select! {
            _ = &mut voter => {
                debug!("voter finished");
                resolver.abort();
            },
            _ = &mut resolver => {
                debug!("resolver finished");
                voter.abort();
            },
        }
    }
}
