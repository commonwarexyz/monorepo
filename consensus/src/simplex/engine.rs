use super::{
    actors::{batcher, resolver, voter},
    config::Config,
    types::{Activity, Context},
};
use crate::{simplex::signing_scheme::Scheme, Automaton, Relay, Reporter};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use tracing::debug;

/// Instance of `simplex` consensus engine.
pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    A: Automaton<Context = Context<D, P>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,

    voter: voter::Actor<E, P, S, B, D, A, R, F>,
    voter_mailbox: voter::Mailbox<S, D>,

    batcher: batcher::Actor<E, P, S, B, D, F>,
    batcher_mailbox: batcher::Mailbox<S, D>,

    resolver: resolver::Actor<E, P, S, B, D>,
    resolver_mailbox: resolver::Mailbox<S, D>,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
        A: Automaton<Context = Context<D, P>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<S, D>>,
    > Engine<E, P, S, B, D, A, R, F>
{
    /// Create a new `simplex` consensus engine.
    pub fn new(context: E, cfg: Config<P, S, B, D, A, R, F>) -> Self {
        // Ensure configuration is valid
        cfg.assert();

        // Create batcher
        let (batcher, batcher_mailbox) = batcher::Actor::new(
            context.with_label("batcher"),
            batcher::Config {
                scheme: cfg.scheme.clone(),
                blocker: cfg.blocker.clone(),
                reporter: cfg.reporter.clone(),
                epoch: cfg.epoch,
                namespace: cfg.namespace.clone(),
                mailbox_size: cfg.mailbox_size,
                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
            },
        );

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            context.with_label("voter"),
            voter::Config {
                scheme: cfg.scheme.clone(),
                blocker: cfg.blocker.clone(),
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                partition: cfg.partition,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                namespace: cfg.namespace.clone(),
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        );

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            context.with_label("resolver"),
            resolver::Config {
                blocker: cfg.blocker,
                scheme: cfg.scheme,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                namespace: cfg.namespace,
                activity_timeout: cfg.activity_timeout,
                fetch_timeout: cfg.fetch_timeout,
                fetch_concurrent: cfg.fetch_concurrent,
                max_fetch_count: cfg.max_fetch_count,
                fetch_rate_per_peer: cfg.fetch_rate_per_peer,
            },
        );

        // Return the engine
        Self {
            context: ContextCell::new(context),

            voter,
            voter_mailbox,

            batcher,
            batcher_mailbox,

            resolver,
            resolver_mailbox,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub fn start(
        mut self,
        pending_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        recovered_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        resolver_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(pending_network, recovered_network, resolver_network)
                .await
        )
    }

    async fn run(
        self,
        pending_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        recovered_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        resolver_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        // Start the batcher
        let (pending_sender, pending_receiver) = pending_network;
        let mut batcher_task = self
            .batcher
            .start(self.voter_mailbox.clone(), pending_receiver);

        // Start the resolver
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver_task =
            self.resolver
                .start(self.voter_mailbox, resolver_sender, resolver_receiver);

        // Start the voter
        let (recovered_sender, recovered_receiver) = recovered_network;
        let mut voter_task = self.voter.start(
            self.batcher_mailbox,
            self.resolver_mailbox,
            pending_sender,
            recovered_sender,
            recovered_receiver,
        );

        // Wait for the resolver or voter to finish
        let mut shutdown = self.context.stopped();
        select! {
            _ = &mut shutdown => {
                debug!("shutdown");
            },
            _ = &mut voter_task => {
                panic!("voter should not finish");
            },
            _ = &mut batcher_task => {
                panic!("batcher should not finish");
            },
            _ = &mut resolver_task => {
                panic!("resolver should not finish");
            },
        }
    }
}
