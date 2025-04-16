use super::{
    actors::{resolver, voter},
    config::Config,
    types::{Activity, Context, View},
};
use crate::{Automaton, Relay, Reporter, Supervisor};
use commonware_cryptography::{Digest, Scheme, Verifier};
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Blob, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::journal::variable::Journal;
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use tracing::debug;

/// Instance of `simplex` consensus engine.
pub struct Engine<
    B: Blob,
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage<B> + Metrics,
    C: Scheme,
    V: Verifier<PublicKey = C::PublicKey, Signature = C::Signature>,
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<V, D>>,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: E,

    voter: voter::Actor<B, E, C, D, A, R, F, S>,
    voter_mailbox: voter::Mailbox<D>,
    resolver: resolver::Actor<E, C, D, S>,
    resolver_mailbox: resolver::Mailbox,
}

impl<
        B: Blob,
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage<B> + Metrics,
        C: Scheme,
        V: Verifier<PublicKey = C::PublicKey, Signature = C::Signature>,
        D: Digest,
        A: Automaton<Context = Context<D>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<V, D>>,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Engine<B, E, C, V, D, A, R, F, S>
{
    /// Create a new `simplex` consensus engine.
    pub fn new(context: E, journal: Journal<B, E>, cfg: Config<C, V, D, A, R, F, S>) -> Self {
        // Ensure configuration is valid
        cfg.assert();

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            context.with_label("voter"),
            journal,
            voter::Config {
                crypto: cfg.crypto.clone(),
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                supervisor: cfg.supervisor.clone(),
                mailbox_size: cfg.mailbox_size,
                namespace: cfg.namespace.clone(),
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                replay_concurrency: cfg.replay_concurrency,
            },
        );

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            context.with_label("resolver"),
            resolver::Config {
                crypto: cfg.crypto,
                supervisor: cfg.supervisor,
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
            context,

            voter,
            voter_mailbox,
            resolver,
            resolver_mailbox,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub fn start(
        self,
        voter_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(voter_network, resolver_network))
    }

    async fn run(
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
        let mut voter_task = self
            .voter
            .start(self.resolver_mailbox, voter_sender, voter_receiver);

        // Start the resolver
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver_task =
            self.resolver
                .start(self.voter_mailbox, resolver_sender, resolver_receiver);

        // Wait for the resolver or voter to finish
        select! {
            _ = &mut voter_task => {
                debug!("voter finished");
                resolver_task.abort();
            },
            _ = &mut resolver_task => {
                debug!("resolver finished");
                voter_task.abort();
            },
        }
    }
}
