//! Engine implementation for minimmit consensus.
//!
//! The Engine orchestrates the voter and resolver actors and manages
//! the network channels for consensus communication.

use super::{
    actors::{resolver, voter},
    config::Config,
    elector::Config as Elector,
    types::{Activity, Context},
};
use crate::{minimmit::scheme::Scheme, Automaton, Relay, Reporter};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use rand_core::CryptoRngCore;
use tracing::debug;

/// Instance of `minimmit` consensus engine.
///
/// Unlike simplex which uses 3 actors (batcher, voter, resolver), minimmit
/// uses only 2 actors (voter, resolver) since the voter handles vote
/// collection directly.
pub struct Engine<
    E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,

    voter: voter::Actor<E, S, L, B, D, A, R, F>,
    voter_mailbox: voter::Mailbox<S, D>,

    resolver: resolver::Actor<E, S, B, D>,
    resolver_mailbox: resolver::Mailbox<S, D>,
}

impl<
        E: Clock + CryptoRngCore + Spawner + Storage + Metrics,
        S: Scheme<D>,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<S, D>>,
    > Engine<E, S, L, B, D, A, R, F>
{
    /// Create a new `minimmit` consensus engine.
    pub fn new(context: E, cfg: Config<S, L, B, D, A, R, F>) -> Self {
        // Ensure configuration is valid
        cfg.assert();

        // Calculate quorums before moving cfg fields
        let m_quorum = cfg.m_quorum();
        let l_quorum = cfg.l_quorum();

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            context.with_label("voter"),
            voter::Config {
                namespace: cfg.namespace.clone(),
                scheme: cfg.scheme.clone(),
                elector: cfg.elector,
                blocker: cfg.blocker.clone(),
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                partition: cfg.partition,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                m_quorum,
                l_quorum,
                leader_timeout: cfg.leader_timeout,
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
                namespace: cfg.namespace,
                blocker: cfg.blocker,
                scheme: cfg.scheme,
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

            resolver,
            resolver_mailbox,
        }
    }

    /// Start the `minimmit` consensus engine.
    ///
    /// This will also rebuild the state of the engine from the journal.
    ///
    /// # Network Channels
    ///
    /// The engine requires three separate network channels:
    ///
    /// ## `vote_network`
    ///
    /// Carries **individual votes**:
    /// - [`Notarize`](super::types::Notarize): Vote to notarize a proposal
    /// - [`Nullify`](super::types::Nullify): Vote to skip a view
    ///
    /// ## `certificate_network`
    ///
    /// Carries **certificates**:
    /// - [`Notarization`](super::types::Notarization): Proof that a proposal was notarized
    /// - [`Nullification`](super::types::Nullification): Proof that a view was skipped
    ///
    /// ## `resolver_network`
    ///
    /// Used for request-response certificate fetching. When a node needs to
    /// catch up on a view it missed (e.g., to verify a proposal's parent), it
    /// uses this channel to request certificates from peers.
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
        // Start the resolver (sends certificates to voter via voter_mailbox)
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver_task = self.resolver.start(
            self.voter_mailbox.clone(),
            resolver_sender,
            resolver_receiver,
        );

        // Start the voter
        let (vote_sender, vote_receiver) = vote_network;
        let (certificate_sender, certificate_receiver) = certificate_network;
        let mut voter_task = self.voter.start(
            self.resolver_mailbox,
            vote_sender,
            vote_receiver,
            certificate_sender,
            certificate_receiver,
        );

        // Wait for the resolver or voter to finish
        let mut shutdown = self.context.stopped();
        select! {
            _ = &mut shutdown => {
                debug!("context shutdown, stopping engine");
            },
            _ = &mut voter_task => {
                panic!("voter should not finish");
            },
            _ = &mut resolver_task => {
                panic!("resolver should not finish");
            },
        }
    }
}
