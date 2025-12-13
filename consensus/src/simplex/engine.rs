use futures::future::Either;
use super::{
    actors::{batcher, resolver, voter},
    config::Config,
    types::{Activity, Context},
};
use crate::{simplex::signing_scheme::Scheme, Automaton, Relay, Reporter};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Listener, Metrics, Spawner, Storage};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use tracing::debug;
use crate::simplex::actors::observer;

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
    L: Listener,
> {
    context: ContextCell<E>,

    voter: voter::Actor<E, P, S, B, D, A, R, F>,
    voter_mailbox: voter::Mailbox<S, D>,

    batcher: batcher::Actor<E, P, S, B, D, F>,
    batcher_mailbox: batcher::Mailbox<S, D>,

    resolver: resolver::Actor<E, P, S, B, D>,
    resolver_mailbox: resolver::Mailbox<S, D>,

    observer: Option<observer::Actor<E, S, D, L>>,
    observer_mailbox: Option<observer::Mailbox<S, D>>,
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
    L: Listener,
> Engine<E, P, S, B, D, A, R, F, L>
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

        let observer_config = cfg.listen_addr.map(|listen_addr| observer::Config {
            listen_addr,
            max_observers: cfg.max_observers.unwrap_or(100),
        });
        let (observer, observer_mailbox) = observer_config.map(|cfg| {
            observer::Actor::new(context.with_label("observer"), cfg)
        }).unzip();

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            context.with_label("resolver"),
            resolver::Config {
                blocker: cfg.blocker,
                scheme: cfg.scheme,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                namespace: cfg.namespace,
                fetch_concurrent: cfg.fetch_concurrent,
                fetch_timeout: cfg.fetch_timeout,
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

            observer,
            observer_mailbox,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    ///
    /// # Network Channels
    ///
    /// The engine requires three separate network channels, each carrying votes or
    /// certificates to help drive the consensus engine.
    ///
    /// ## `vote_network`
    ///
    /// Carries **individual votes**:
    /// - [`Notarize`](super::types::Notarize): Vote to notarize a proposal
    /// - [`Nullify`](super::types::Nullify): Vote to skip a view
    /// - [`Finalize`](super::types::Finalize): Vote to finalize a notarized proposal
    ///
    /// These messages are sent to the batcher, which performs batch signature
    /// verification before forwarding valid votes to the voter for aggregation.
    ///
    /// ## `certificate_network`
    ///
    /// Carries **certificates**:
    /// - [`Notarization`](super::types::Notarization): Proof that a proposal was notarized
    /// - [`Nullification`](super::types::Nullification): Proof that a view was skipped
    /// - [`Finalization`](super::types::Finalization): Proof that a proposal was finalized
    ///
    /// Certificates are broadcast on this channel as soon as they are constructed
    /// from collected votes. We separate this from the `vote_network` to optimistically
    /// allow for certificate processing to short-circuit vote processing (if we receive
    /// a certificate before processing pending votes, we can skip them).
    ///
    /// ## `resolver_network`
    ///
    /// Used for request-response certificate fetching. When a node needs to
    /// catch up on a view it missed (e.g., to verify a proposal's parent), it
    /// uses this channel to request certificates from peers. The resolver handles
    /// rate limiting, retries, and peer selection for these requests.
    pub fn start(
        mut self,
        vote_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        certificate_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        resolver_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        listener: L,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(vote_network, certificate_network, resolver_network, listener)
                .await
        )
    }

    async fn run(
        self,
        vote_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        certificate_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        resolver_network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        listener: L,
    ) {
        // Start the batcher (receives votes via vote_network, certificates via certificate_network)
        // Batcher sends proposals/certificates to voter via voter_mailbox
        let (vote_sender, vote_receiver) = vote_network;
        let (certificate_sender, certificate_receiver) = certificate_network;
        let mut batcher_task = self.batcher.start(
            self.voter_mailbox.clone(),
            vote_receiver,
            certificate_receiver,
        );

        // Start the observer
        let mut observer_task = match self.observer {
            Some(observer) => Either::Left(observer.start(listener)),
            None => Either::Right(futures::future::pending()),
        };

        // Start the resolver (sends certificates to voter via voter_mailbox)
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver_task = self.resolver.start(
            self.voter_mailbox,
            resolver_sender,
            resolver_receiver,
            self.observer_mailbox,
        );

        // Start the voter
        let mut voter_task = self.voter.start(
            self.batcher_mailbox,
            self.resolver_mailbox,
            vote_sender,
            certificate_sender,
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
            _ = &mut batcher_task => {
                panic!("batcher should not finish");
            },
            _ = &mut resolver_task => {
                panic!("resolver should not finish");
            },
            _ = &mut observer_task => {
                panic!("observer should not finish");
            }
        }
    }
}
