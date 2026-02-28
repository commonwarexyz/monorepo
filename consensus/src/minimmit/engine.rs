//! Minimmit consensus engine.
//!
//! The engine composes the voter, batcher, and resolver actors into a single entry point.

use super::{
    actors::{batcher, resolver, voter},
    config::Config,
    types::{Activity, Context},
};
use crate::{elector::Config as Elector, minimmit::scheme::Scheme, Automaton, Relay, Reporter};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use rand_core::CryptoRngCore;
use tracing::debug;

/// Instance of the Minimmit consensus engine.
pub struct Engine<E, S, L, B, D, A, R, F, T>
where
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    context: ContextCell<E>,

    voter: voter::Actor<E, S, L, B, D, A, R, F, T>,
    voter_mailbox: voter::Mailbox<S, D>,

    batcher: batcher::Actor<E, S, B, D, F, T>,
    batcher_mailbox: batcher::Mailbox<S, D>,

    resolver: resolver::Actor<E, S, B, D, T>,
    resolver_mailbox: resolver::Mailbox<S, D>,
}

impl<E, S, L, B, D, A, R, F, T> Engine<E, S, L, B, D, A, R, F, T>
where
    E: BufferPooler + Clock + CryptoRngCore + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    /// Create a new Minimmit consensus engine.
    pub fn new(context: E, cfg: Config<S, L, B, D, A, R, F, T>) -> Self {
        // Ensure configuration is valid
        cfg.validate().expect("invalid configuration");

        // Create batcher
        let (batcher, batcher_mailbox) = batcher::Actor::new(
            context.with_label("batcher"),
            batcher::Config {
                scheme: cfg.scheme.clone(),
                blocker: cfg.blocker.clone(),
                reporter: cfg.reporter.clone(),
                strategy: cfg.strategy.clone(),
                epoch: cfg.epoch,
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
                elector: cfg.elector,
                blocker: cfg.blocker.clone(),
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter.clone(),
                strategy: cfg.strategy.clone(),
                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                page_cache: cfg.page_cache,
                epoch: cfg.epoch,
                mailbox_size: cfg.mailbox_size,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
            },
        );

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            context.with_label("resolver"),
            resolver::Config {
                blocker: cfg.blocker,
                scheme: cfg.scheme,
                strategy: cfg.strategy,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                fetch_concurrent: cfg.fetch_concurrent,
                fetch_timeout: cfg.fetch_timeout,
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

    /// Start the Minimmit consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided storage.
    ///
    /// # Network Channels
    ///
    /// The engine requires three separate network channels:
    ///
    /// ## `vote_network`
    ///
    /// Carries individual votes (Notarize, Nullify).
    ///
    /// ## `certificate_network`
    ///
    /// Carries certificates (MNotarization, Nullification, Finalization).
    ///
    /// ## `resolver_network`
    ///
    /// Used for request-response certificate fetching.
    pub fn start(
        mut self,
        vote_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(vote_network, certificate_network, resolver_network)
                .await
        )
    }

    async fn run(
        self,
        vote_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
    ) {
        // Start the batcher
        let (vote_sender, vote_receiver) = vote_network;
        let (certificate_sender, certificate_receiver) = certificate_network;
        let mut batcher_task = self.batcher.start(
            self.voter_mailbox.clone(),
            vote_receiver,
            certificate_receiver,
        );

        // Start the resolver
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver_task =
            self.resolver
                .start(self.voter_mailbox, resolver_sender, resolver_receiver);

        // Start the voter
        let mut voter_task = self.voter.start(
            self.batcher_mailbox,
            self.resolver_mailbox,
            vote_sender,
            certificate_sender,
        );

        // Wait for any actor to finish (which indicates a failure)
        let mut shutdown = self.context.stopped();
        select! {
            _ = &mut shutdown => {
                debug!("context shutdown, stopping engine");
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
