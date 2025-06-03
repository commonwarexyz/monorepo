use super::{
    actors::{batcher, resolver, voter},
    config::Config,
    types::{Activity, Context, View},
};
use crate::{Automaton, Relay, Reporter, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{group, variant::Variant},
    Digest, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use tracing::debug;

/// Instance of `threshold-simplex` consensus engine.
pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    C: Scheme,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<V, D>>,
    S: ThresholdSupervisor<
        Index = View,
        PublicKey = C::PublicKey,
        Identity = V::Public,
        Seed = V::Signature,
        Polynomial = Vec<V::Public>,
        Share = group::Share,
    >,
> {
    context: E,

    voter: voter::Actor<E, C, B, V, D, A, R, F, S>,
    voter_mailbox: voter::Mailbox<V, D>,

    batcher: batcher::Actor<E, C, B, V, D, F, S>,
    batcher_mailbox: batcher::Mailbox<C::PublicKey, V, D>,

    resolver: resolver::Actor<E, C, B, V, D, S>,
    resolver_mailbox: resolver::Mailbox<V, D>,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
        C: Scheme,
        B: Blocker<PublicKey = C::PublicKey>,
        V: Variant,
        D: Digest,
        A: Automaton<Context = Context<D>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<V, D>>,
        S: ThresholdSupervisor<
            Seed = V::Signature,
            Index = View,
            Share = group::Share,
            Polynomial = Vec<V::Public>,
            Identity = V::Public,
            PublicKey = C::PublicKey,
        >,
    > Engine<E, C, B, V, D, A, R, F, S>
{
    /// Create a new `threshold-simplex` consensus engine.
    pub fn new(context: E, cfg: Config<C, B, V, D, A, R, F, S>) -> Self {
        // Ensure configuration is valid
        cfg.assert();

        // Create batcher
        let (batcher, batcher_mailbox) = batcher::Actor::new(
            context.with_label("batcher"),
            batcher::Config {
                blocker: cfg.blocker.clone(),
                reporter: cfg.reporter.clone(),
                supervisor: cfg.supervisor.clone(),
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
                crypto: cfg.crypto.clone(),
                blocker: cfg.blocker.clone(),
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                supervisor: cfg.supervisor.clone(),
                partition: cfg.partition,
                compression: cfg.compression,
                mailbox_size: cfg.mailbox_size,
                namespace: cfg.namespace.clone(),
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
                replay_concurrency: cfg.replay_concurrency,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
            },
        );

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            context.with_label("resolver"),
            resolver::Config {
                blocker: cfg.blocker,
                crypto: cfg.crypto,
                supervisor: cfg.supervisor,
                mailbox_size: cfg.mailbox_size,
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
            context,

            voter,
            voter_mailbox,

            batcher,
            batcher_mailbox,

            resolver,
            resolver_mailbox,
        }
    }

    /// Start the `threshold-simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub fn start(
        self,
        pending_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        recovered_network: (
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
            .spawn(|_| self.run(pending_network, recovered_network, resolver_network))
    }

    async fn run(
        self,
        pending_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        recovered_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
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
        select! {
            _ = &mut voter_task => {
                debug!("voter finished");
                resolver_task.abort();
                batcher_task.abort();
            },
            _ = &mut batcher_task => {
                debug!("batcher finished");
                voter_task.abort();
                resolver_task.abort();
            },
            _ = &mut resolver_task => {
                debug!("resolver finished");
                voter_task.abort();
                batcher_task.abort();
            },
        }
    }
}
