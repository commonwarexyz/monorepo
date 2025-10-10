use super::{
    actors::{resolver, voter},
    config::Config,
    types::{Activity, Context},
};
use crate::{types::View, Automaton, Relay, Reporter, Supervisor};
use commonware_cryptography::{Digest, Signer};
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use tracing::debug;

/// Instance of `simplex` consensus engine.
pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    C: Signer,
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<C::Signature, D>>,
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
> {
    context: ContextCell<E>,

    voter: voter::Actor<E, C, D, A, R, F, S>,
    voter_mailbox: voter::Mailbox<C::Signature, D>,
    resolver: resolver::Actor<E, C::PublicKey, D, S>,
    resolver_mailbox: resolver::Mailbox<C::Signature, D>,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
        C: Signer,
        D: Digest,
        A: Automaton<Context = Context<D>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<C::Signature, D>>,
        S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    > Engine<E, C, D, A, R, F, S>
{
    /// Create a new `simplex` consensus engine.
    pub fn new(context: E, cfg: Config<C, D, A, R, F, S>) -> Self {
        // Ensure configuration is valid
        cfg.assert();

        // Create voter
        let public_key = cfg.crypto.public_key();
        let (voter, voter_mailbox) = voter::Actor::new(
            context.with_label("voter"),
            voter::Config {
                crypto: cfg.crypto,
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                supervisor: cfg.supervisor.clone(),
                partition: cfg.partition,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                namespace: cfg.namespace.clone(),
                max_participants: cfg.max_participants,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        );

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            context.with_label("resolver"),
            resolver::Config {
                crypto: public_key,
                supervisor: cfg.supervisor,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                namespace: cfg.namespace,
                max_participants: cfg.max_participants,
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
            resolver,
            resolver_mailbox,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub fn start(
        mut self,
        voter_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter_network, resolver_network).await
        )
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
