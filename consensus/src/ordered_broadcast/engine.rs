//! Engine for the module.
//!
//! It is responsible for:
//! - Proposing nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer's chain
//! - Assembling certificates from votes for each chunk
//! - Notifying other actors of new chunks and certificates

use super::{
    metrics, scheme,
    types::{
        Ack, Activity, Chunk, ChunkSigner, ChunkVerifier, Context, Error, Lock, Node, Parent,
        Proposal, SequencersProvider,
    },
    AckManager, Config, TipManager,
};
use crate::{
    types::{Epoch, EpochDelta, Height, HeightDelta},
    Automaton, Monitor, Relay, Reporter,
};
use commonware_codec::Encode;
use commonware_cryptography::{
    certificate::{Provider, Scheme as _, Verifier},
    Digest, PublicKey, Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Receiver, Recipients, Sender,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{histogram, status::Status, GaugeExt},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JournalConfig, Journal};
use commonware_utils::{channel::oneshot, futures::Pool as FuturesPool, ordered::Quorum};
use futures::{
    future::{self, Either},
    pin_mut, StreamExt,
};
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, warn};

/// Represents a pending verification request to the automaton.
struct Verify<C: PublicKey, D: Digest> {
    timer: histogram::Timer,
    context: Context<C>,
    payload: D,
    result: Result<bool, Error>,
}

/// Instance of the engine.
pub struct Engine<
    E: BufferPooler + Clock + Spawner + CryptoRngCore + Storage + Metrics,
    C: Signer,
    S: SequencersProvider<PublicKey = C::PublicKey>,
    P: Provider<Scope = Epoch, Scheme: scheme::Scheme<C::PublicKey, D>>,
    D: Digest,
    A: Automaton<Context = Context<C::PublicKey>, Digest = D>,
    R: Relay<Digest = D, PublicKey = C::PublicKey, Plan = ()>,
    Z: Reporter<Activity = Activity<C::PublicKey, P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
    T: Strategy,
> {
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    context: ContextCell<E>,
    sequencer_signer: Option<ChunkSigner<C>>,
    sequencers_provider: S,
    validators_provider: P,
    automaton: A,
    relay: R,
    monitor: M,
    reporter: Z,
    strategy: T,

    ////////////////////////////////////////
    // Namespace Constants
    ////////////////////////////////////////

    // Verifier for chunk signatures.
    chunk_verifier: ChunkVerifier,

    ////////////////////////////////////////
    // Timeouts
    ////////////////////////////////////////

    // The configured timeout for rebroadcasting a chunk to all validators
    rebroadcast_timeout: Duration,
    rebroadcast_deadline: Option<SystemTime>,

    ////////////////////////////////////////
    // Pruning
    ////////////////////////////////////////

    // A tuple representing the epochs to keep in memory.
    // The first element is the number of old epochs to keep.
    // The second element is the number of future epochs to accept.
    //
    // For example, if the current epoch is 10, and the bounds are (1, 2), then
    // epochs 9, 10, 11, and 12 are kept (and accepted);
    // all others are pruned or rejected.
    epoch_bounds: (EpochDelta, EpochDelta),

    // The number of future heights to accept acks for.
    // This is used to prevent spam of acks for arbitrary heights.
    //
    // For example, if the current tip for a sequencer is at height 100,
    // and the height_bound is 10, then acks for heights 100-110 are accepted.
    height_bound: HeightDelta,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////

    // A stream of futures.
    //
    // Each future represents a verification request to the automaton
    // that will either timeout or resolve with a boolean.
    //
    // There is no limit to the number of futures in this pool, so the automaton
    // can apply backpressure by dropping the verification requests if necessary.
    pending_verifies: FuturesPool<Verify<C::PublicKey, D>>,

    ////////////////////////////////////////
    // Storage
    ////////////////////////////////////////

    // The number of heights per each journal section.
    journal_heights_per_section: NonZeroU64,

    // The number of bytes to buffer when replaying a journal.
    journal_replay_buffer: NonZeroUsize,

    // The size of the write buffer to use for each blob in the journal.
    journal_write_buffer: NonZeroUsize,

    // A prefix for the journal names.
    // The rest of the name is the hex-encoded public keys of the relevant sequencer.
    journal_name_prefix: String,

    // Compression level for the journal.
    journal_compression: Option<u8>,

    // Page cache for the journal.
    journal_page_cache: CacheRef,

    // A map of sequencer public keys to their journals.
    #[allow(clippy::type_complexity)]
    journals: BTreeMap<C::PublicKey, Journal<E, Node<C::PublicKey, P::Scheme, D>>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // Tracks the current tip for each sequencer.
    // The tip is a `Node` which is comprised of a `Chunk` and,
    // if not the genesis chunk for that sequencer,
    // a certificate over the parent chunk.
    tip_manager: TipManager<C::PublicKey, P::Scheme, D>,

    // Tracks the acknowledgements for chunks.
    // This is comprised of votes or certificates.
    ack_manager: AckManager<C::PublicKey, P::Scheme, D>,

    // The current epoch.
    epoch: Epoch,

    ////////////////////////////////////////
    // Network
    ////////////////////////////////////////

    // Whether to send proposals as priority messages.
    priority_proposals: bool,

    // Whether to send acks as priority messages.
    priority_acks: bool,

    ////////////////////////////////////////
    // Metrics
    ////////////////////////////////////////

    // Metrics
    metrics: metrics::Metrics<C::PublicKey>,

    // The timer of my last new proposal
    propose_timer: Option<histogram::Timer>,
}

impl<
        E: BufferPooler + Clock + Spawner + CryptoRngCore + Storage + Metrics,
        C: Signer,
        S: SequencersProvider<PublicKey = C::PublicKey>,
        P: Provider<Scope = Epoch, Scheme: scheme::Scheme<C::PublicKey, D, PublicKey = C::PublicKey>>,
        D: Digest,
        A: Automaton<Context = Context<C::PublicKey>, Digest = D>,
        R: Relay<Digest = D, PublicKey = C::PublicKey, Plan = ()>,
        Z: Reporter<Activity = Activity<C::PublicKey, P::Scheme, D>>,
        M: Monitor<Index = Epoch>,
        T: Strategy,
    > Engine<E, C, S, P, D, A, R, Z, M, T>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<C, S, P, D, A, R, Z, M, T>) -> Self {
        let metrics = metrics::Metrics::init(&context);

        Self {
            context: ContextCell::new(context),
            sequencer_signer: cfg.sequencer_signer,
            sequencers_provider: cfg.sequencers_provider,
            validators_provider: cfg.validators_provider,
            automaton: cfg.automaton,
            relay: cfg.relay,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            strategy: cfg.strategy,
            chunk_verifier: cfg.chunk_verifier,
            rebroadcast_timeout: cfg.rebroadcast_timeout,
            rebroadcast_deadline: None,
            epoch_bounds: cfg.epoch_bounds,
            height_bound: cfg.height_bound,
            pending_verifies: FuturesPool::default(),
            journal_heights_per_section: cfg.journal_heights_per_section,
            journal_replay_buffer: cfg.journal_replay_buffer,
            journal_write_buffer: cfg.journal_write_buffer,
            journal_name_prefix: cfg.journal_name_prefix,
            journal_compression: cfg.journal_compression,
            journal_page_cache: cfg.journal_page_cache,
            journals: BTreeMap::new(),
            tip_manager: TipManager::<C::PublicKey, P::Scheme, D>::new(),
            ack_manager: AckManager::<C::PublicKey, P::Scheme, D>::new(),
            epoch: Epoch::zero(),
            priority_proposals: cfg.priority_proposals,
            priority_acks: cfg.priority_acks,
            metrics,
            propose_timer: None,
        }
    }

    /// Runs the engine until the context is stopped.
    ///
    /// The engine will handle:
    /// - Requesting and processing proposals from the application
    /// - Timeouts
    ///   - Refreshing the Epoch
    ///   - Rebroadcasting Proposals
    /// - Messages from the network:
    ///   - Nodes
    ///   - Acks
    pub fn start(
        mut self,
        chunk_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        ack_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(chunk_network, ack_network))
    }

    /// Inner run loop called by `start`.
    async fn run(
        mut self,
        chunk_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        ack_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        let mut node_sender = chunk_network.0;
        let mut node_receiver = chunk_network.1;
        let (mut ack_sender, mut ack_receiver) = wrap(
            (),
            self.context.network_buffer_pool().clone(),
            ack_network.0,
            ack_network.1,
        );

        // Tracks if there is an outstanding proposal request to the automaton.
        let mut pending: Option<(Context<C::PublicKey>, oneshot::Receiver<D>)> = None;

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        // Before starting on the main loop, initialize my own sequencer journal
        // and attempt to rebroadcast if necessary.
        if let Some(ref signer) = self.sequencer_signer {
            self.journal_prepare(&signer.public_key()).await;
            if let Err(err) = self.rebroadcast(&mut node_sender) {
                // Rebroadcasting may return a non-critical error, so log the error and continue.
                info!(?err, "initial rebroadcast failed");
            }
        }

        select_loop! {
            self.context,
            on_start => {
                // Request a new proposal if necessary
                if pending.is_none() {
                    if let Some(context) = self.should_propose() {
                        let receiver = self.automaton.propose(context.clone()).await;
                        pending = Some((context, receiver));
                    }
                }

                // Create deadline futures.
                //
                // If the deadline is None, the future will never resolve.
                let rebroadcast = match self.rebroadcast_deadline {
                    Some(deadline) => Either::Left(self.context.sleep_until(deadline)),
                    None => Either::Right(future::pending()),
                };
                let propose = match &mut pending {
                    Some((_context, receiver)) => Either::Left(receiver),
                    None => Either::Right(futures::future::pending()),
                };
            },
            on_stopped => {
                debug!("shutdown");
            },
            // Handle refresh epoch deadline
            Some(epoch) = epoch_updates.recv() else {
                error!("epoch subscription failed");
                break;
            } => {
                // Refresh the epoch
                debug!(current = %self.epoch, new = %epoch, "refresh epoch");
                assert!(epoch >= self.epoch);
                self.epoch = epoch;
                continue;
            },

            // Handle rebroadcast deadline
            _ = rebroadcast => {
                if let Some(ref signer) = self.sequencer_signer {
                    debug!(epoch = %self.epoch, sender = ?signer.public_key(), "rebroadcast");
                    if let Err(err) = self.rebroadcast(&mut node_sender) {
                        info!(?err, "rebroadcast failed");
                        continue;
                    }
                }
            },

            // Propose a new chunk
            receiver = propose => {
                // Clear the pending proposal
                let (context, _) = pending.take().unwrap();
                debug!(height = %context.height, "propose");

                // Error handling for dropped proposals
                let Ok(payload) = receiver else {
                    warn!(?context, "automaton dropped proposal");
                    continue;
                };

                // Propose the chunk
                if let Err(err) = self
                    .propose(context.clone(), payload, &mut node_sender)
                    .await
                {
                    warn!(?err, ?context, "propose new failed");
                    continue;
                }
            },

            // Handle incoming nodes
            msg = node_receiver.recv() => {
                // Error handling
                let (sender, msg) = match msg {
                    Ok(r) => r,
                    Err(err) => {
                        error!(?err, "node receiver failed");
                        break;
                    }
                };
                let mut guard = self.metrics.nodes.guard(Status::Invalid);

                // Decode using staged decoding with epoch-aware certificate bounds
                let node = match Node::read_staged(&mut msg.as_ref(), &self.validators_provider) {
                    Ok(node) => node,
                    Err(err) => {
                        debug!(?err, ?sender, "node decode failed");
                        continue;
                    }
                };

                let result = match self.prepare_and_validate_node(&node, &sender).await {
                    Ok(result) => result,
                    Err(err) => {
                        debug!(?err, ?sender, "node validate failed");
                        continue;
                    }
                };

                // Handle the parent certificate
                if let Some(parent_chunk) = result {
                    let parent = node.parent.as_ref().unwrap();
                    self.handle_certificate(
                        &parent_chunk,
                        parent.epoch,
                        parent.certificate.clone(),
                    );
                }

                // Process the node
                //
                // Note, this node may be a duplicate. If it is, we will attempt to verify it and vote
                // on it again (our original vote may have been lost).
                self.handle_node(&node).await;
                debug!(?sender, height = %node.chunk.height, "node");
                guard.set(Status::Success);
            },

            // Handle incoming acks
            msg = ack_receiver.recv() => {
                // Error handling
                let (sender, msg) = match msg {
                    Ok(r) => r,
                    Err(err) => {
                        warn!(?err, "ack receiver failed");
                        break;
                    }
                };
                let mut guard = self.metrics.acks.guard(Status::Invalid);
                let ack = match msg {
                    Ok(ack) => ack,
                    Err(err) => {
                        debug!(?err, ?sender, "ack decode failed");
                        continue;
                    }
                };
                if let Err(err) = self.validate_ack(&ack, &sender) {
                    debug!(?err, ?sender, "ack validate failed");
                    continue;
                };
                if let Err(err) = self.handle_ack(&ack) {
                    debug!(?err, ?sender, "ack handle failed");
                    guard.set(Status::Failure);
                    continue;
                }
                debug!(?sender, epoch = %ack.epoch, sequencer = ?ack.chunk.sequencer, height = %ack.chunk.height, "ack");
                guard.set(Status::Success);
            },

            // Handle completed verification futures.
            verify = self.pending_verifies.next_completed() => {
                let Verify {
                    timer,
                    context,
                    payload,
                    result,
                } = verify;
                match result {
                    Err(err) => {
                        warn!(?err, ?context, "verified returned error");
                        self.metrics.verify.inc(Status::Dropped);
                    }
                    Ok(false) => {
                        timer.observe(self.context.as_ref());
                        debug!(?context, "verified was false");
                        self.metrics.verify.inc(Status::Failure);
                    }
                    Ok(true) => {
                        timer.observe(self.context.as_ref());
                        debug!(?context, "verified");
                        self.metrics.verify.inc(Status::Success);
                        if let Err(err) = self
                            .handle_app_verified(&context, &payload, &mut ack_sender)
                            .await
                        {
                            debug!(?err, ?context, ?payload, "verified handle failed");
                        }
                    }
                }
            },
        }

        // Sync and drop all journals, regardless of how we exit the loop
        self.pending_verifies.cancel_all();
        while let Some((_, mut journal)) = self.journals.pop_first() {
            journal.sync_all().await.expect("unable to sync journal");
        }
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    /// Handles a verified message from the automaton.
    ///
    /// This is called when the automaton has verified a payload.
    /// The chunk will be signed if it matches the current tip.
    async fn handle_app_verified(
        &mut self,
        context: &Context<C::PublicKey>,
        payload: &D,
        ack_sender: &mut WrappedSender<
            impl Sender<PublicKey = C::PublicKey>,
            Ack<C::PublicKey, P::Scheme, D>,
        >,
    ) -> Result<(), Error> {
        // Get the tip
        let Some(tip) = self.tip_manager.get(&context.sequencer) else {
            return Err(Error::AppVerifiedNoTip);
        };

        // Return early if the height does not match
        if tip.chunk.height != context.height {
            return Err(Error::AppVerifiedHeightMismatch);
        }

        // Return early if the payload does not match
        if tip.chunk.payload != *payload {
            return Err(Error::AppVerifiedPayloadMismatch);
        }

        // Emit the activity
        self.reporter.report(Activity::Tip(Proposal::new(
            tip.chunk.clone(),
            tip.signature.clone(),
        )));

        // Get the validator scheme for the current epoch
        let Some(scheme) = self.validators_provider.scheme(self.epoch) else {
            return Err(Error::UnknownScheme(self.epoch));
        };

        // Construct vote (if a validator)
        let Some(ack) = Ack::sign(scheme.as_ref(), tip.chunk.clone(), self.epoch) else {
            return Err(Error::NotSigner(self.epoch));
        };

        // Sync the journal to prevent ever acking two conflicting chunks at
        // the same height, even if the node crashes and restarts.
        self.journal_sync(&context.sequencer, context.height).await;

        // The recipients are all the validators in the epoch and the sequencer.
        // The sequencer may or may not be a validator.
        let recipients = {
            let validators = scheme.participants();
            let mut recipients = validators.iter().cloned().collect::<Vec<_>>();
            if !validators.iter().any(|v| v == &tip.chunk.sequencer) {
                recipients.push(tip.chunk.sequencer.clone());
            }
            recipients
        };

        // Handle the ack internally
        self.handle_ack(&ack)?;

        // Send the ack to the network
        ack_sender.send(Recipients::Some(recipients), ack, self.priority_acks);

        Ok(())
    }

    /// Handles a certificate, either received from a `Node` from the network or generated locally.
    ///
    /// The certificate must already be verified.
    /// If the certificate is new, it is stored and the proof is emitted to the committer.
    /// If the certificate is already known, it is ignored.
    fn handle_certificate(
        &mut self,
        chunk: &Chunk<C::PublicKey, D>,
        epoch: Epoch,
        certificate: <P::Scheme as Verifier>::Certificate,
    ) {
        // Set the certificate, returning early if it already exists
        if !self.ack_manager.add_certificate(
            &chunk.sequencer,
            chunk.height,
            epoch,
            certificate.clone(),
        ) {
            return;
        }

        // If the certificate is for my sequencer, record metric
        if let Some(ref signer) = self.sequencer_signer {
            if chunk.sequencer == signer.public_key() {
                if let Some(timer) = self.propose_timer.take() {
                    timer.observe(self.context.as_ref());
                }
            }
        }

        // Emit the activity
        self.reporter
            .report(Activity::Lock(Lock::new(chunk.clone(), epoch, certificate)));
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, certificate already exists, is outside the epoch bounds, etc.).
    fn handle_ack(&mut self, ack: &Ack<C::PublicKey, P::Scheme, D>) -> Result<(), Error> {
        // Get the scheme for the ack's epoch
        let Some(scheme) = self.validators_provider.scheme(ack.epoch) else {
            return Err(Error::UnknownScheme(ack.epoch));
        };

        // Add the vote. If a new certificate is formed, handle it.
        if let Some(certificate) = self
            .ack_manager
            .add_ack(ack, scheme.as_ref(), &self.strategy)
        {
            debug!(epoch = %ack.epoch, sequencer = ?ack.chunk.sequencer, height = %ack.chunk.height, "recovered certificate");
            self.metrics.certificates.inc();
            self.handle_certificate(&ack.chunk, ack.epoch, certificate);
        }

        Ok(())
    }

    /// Handles a valid `Node` message, storing it as the tip.
    /// Alerts the automaton of the new node.
    /// Also appends the `Node` to the journal if it's new.
    async fn handle_node(&mut self, node: &Node<C::PublicKey, P::Scheme, D>) {
        // Store the tip
        let is_new = self.tip_manager.put(node);

        // If a higher height than the previous tip...
        if is_new {
            // Update metrics for sequencer height
            let _ = self
                .metrics
                .sequencer_heights
                .get_or_create_by(&node.chunk.sequencer)
                .try_set(node.chunk.height.get());

            // Append to journal if the `Node` is new, making sure to sync the journal
            // to prevent sending two conflicting chunks to the automaton, even if
            // the node crashes and restarts.
            self.journal_append(node.clone()).await;
            self.journal_sync(&node.chunk.sequencer, node.chunk.height)
                .await;
        }

        // Verify the chunk with the automaton
        let context = Context {
            sequencer: node.chunk.sequencer.clone(),
            height: node.chunk.height,
        };
        let payload = node.chunk.payload;
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.verify_duration.timer(self.context.as_ref());
        self.pending_verifies.push(async move {
            let receiver = automaton.verify(context.clone(), payload).await;
            let result = receiver.await.map_err(Error::AppVerifyCanceled);
            Verify {
                timer,
                context,
                payload,
                result,
            }
        });
    }

    ////////////////////////////////////////
    // Proposing
    ////////////////////////////////////////

    /// Returns a `Context` if the engine should request a proposal from the automaton.
    ///
    /// Should only be called if the engine is not already waiting for a proposal.
    fn should_propose(&self) -> Option<Context<C::PublicKey>> {
        // Return `None` if we don't have a sequencer signer
        let me = self.sequencer_signer.as_ref()?.public_key();

        // Return `None` if I am not a sequencer in the current epoch
        self.sequencers_provider
            .sequencers(self.epoch)?
            .position(&me)?;

        // Return the next context unless my current tip has no certificate
        match self.tip_manager.get(&me) {
            None => Some(Context {
                sequencer: me,
                height: Height::zero(),
            }),
            Some(tip) => self
                .ack_manager
                .get_certificate(&me, tip.chunk.height)
                .map(|_| Context {
                    sequencer: me,
                    height: tip.chunk.height.next(),
                }),
        }
    }

    /// Propose a new chunk to the network.
    ///
    /// The result is returned to the caller via the provided channel.
    /// The proposal is only successful if the parent Chunk and certificate are known.
    async fn propose(
        &mut self,
        context: Context<C::PublicKey>,
        payload: D,
        node_sender: &mut impl Sender<PublicKey = C::PublicKey>,
    ) -> Result<(), Error> {
        let mut guard = self.metrics.propose.guard(Status::Dropped);
        let signer = self
            .sequencer_signer
            .as_mut()
            .ok_or(Error::IAmNotASequencer(self.epoch))?;
        let me = signer.public_key();

        // Error-check context sequencer
        if context.sequencer != me {
            return Err(Error::ContextSequencer);
        }

        // Error-check that I am a sequencer in the current epoch
        self.sequencers_provider
            .sequencers(self.epoch)
            .and_then(|s| s.position(&me))
            .ok_or(Error::IAmNotASequencer(self.epoch))?;

        // Get parent Chunk and certificate
        let mut height = Height::zero();
        let mut parent = None;
        if let Some(tip) = self.tip_manager.get(&me) {
            // Get certificate, or, if it doesn't exist, return an error
            let Some((epoch, certificate)) =
                self.ack_manager.get_certificate(&me, tip.chunk.height)
            else {
                return Err(Error::MissingCertificate);
            };

            // Update height and parent
            height = tip.chunk.height.next();
            parent = Some(Parent::new(tip.chunk.payload, epoch, certificate.clone()));
        }

        // Error-check context height
        if context.height != height {
            return Err(Error::ContextHeight);
        }

        // Construct new node
        let node = Node::sign(signer, height, payload, parent);

        // Deal with the chunk as if it were received over the network
        self.handle_node(&node).await;

        // Sync the journal to prevent ever proposing two conflicting chunks
        // at the same height, even if the node crashes and restarts
        self.journal_sync(&me, height).await;

        // Record the start time of the proposal
        self.propose_timer = Some(self.metrics.e2e_duration.timer(self.context.as_ref()));

        // Broadcast to network
        if let Err(err) = self.broadcast(node, node_sender, self.epoch) {
            guard.set(Status::Failure);
            return Err(err);
        };

        // Return success
        guard.set(Status::Success);
        Ok(())
    }

    /// Attempt to rebroadcast the highest-height chunk of this sequencer to all validators.
    ///
    /// This is only done if:
    /// - this instance is the sequencer for the current epoch.
    /// - this instance has a chunk to rebroadcast.
    /// - this instance has not yet collected the certificate for the chunk.
    fn rebroadcast(
        &mut self,
        node_sender: &mut impl Sender<PublicKey = C::PublicKey>,
    ) -> Result<(), Error> {
        let mut guard = self.metrics.rebroadcast.guard(Status::Dropped);

        // Unset the rebroadcast deadline
        self.rebroadcast_deadline = None;

        // Return if we don't have a sequencer signer
        let signer = self
            .sequencer_signer
            .as_ref()
            .ok_or(Error::IAmNotASequencer(self.epoch))?;
        let me = signer.public_key();

        // Return if not a sequencer in the current epoch
        self.sequencers_provider
            .sequencers(self.epoch)
            .and_then(|s| s.position(&me))
            .ok_or(Error::IAmNotASequencer(self.epoch))?;

        // Return if no chunk to rebroadcast
        let Some(tip) = self.tip_manager.get(&me) else {
            return Err(Error::NothingToRebroadcast);
        };

        // Return if certificate already collected
        if self
            .ack_manager
            .get_certificate(&me, tip.chunk.height)
            .is_some()
        {
            return Err(Error::AlreadyCertified);
        }

        // Broadcast the message, which resets the rebroadcast deadline
        guard.set(Status::Failure);
        self.broadcast(tip, node_sender, self.epoch)?;
        guard.set(Status::Success);
        Ok(())
    }

    /// Send a  `Node` message to all validators in the given epoch.
    fn broadcast(
        &mut self,
        node: Node<C::PublicKey, P::Scheme, D>,
        node_sender: &mut impl Sender<PublicKey = C::PublicKey>,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Get the scheme for the epoch to access validators
        let Some(scheme) = self.validators_provider.scheme(epoch) else {
            return Err(Error::UnknownScheme(epoch));
        };
        let validators = scheme.participants();

        // Tell the relay to broadcast the full data
        let _ = self.relay.broadcast(node.chunk.payload, ());

        // Send the node to all validators
        node_sender.send(
            Recipients::Some(validators.iter().cloned().collect()),
            node.encode(),
            self.priority_proposals,
        );

        // Set the rebroadcast deadline
        self.rebroadcast_deadline = Some(self.context.current() + self.rebroadcast_timeout);

        Ok(())
    }

    ////////////////////////////////////////
    // Validation
    ////////////////////////////////////////

    /// Prepares the sender's journal, then validates an inbound `Node`.
    ///
    /// If valid (and not already the tracked tip for the sender), returns the implied
    /// parent chunk and its certificate.
    /// Else returns an error if the `Node` is invalid.
    ///
    /// Origin checks run before journal replay, and tip-dependent checks run after replay.
    async fn prepare_and_validate_node(
        &mut self,
        node: &Node<C::PublicKey, P::Scheme, D>,
        sender: &C::PublicKey,
    ) -> Result<Option<Chunk<C::PublicKey, D>>, Error> {
        // Verify the sender
        if node.chunk.sequencer != *sender {
            return Err(Error::PeerMismatch);
        }

        // Verify the sequencer before opening the journal so arbitrary peers cannot create
        // journal partitions.
        self.validate_chunk_sequencer(&node.chunk, self.epoch)?;

        // Replay before checking the tracked tip so validation observes recovered journal state.
        self.journal_prepare(sender).await;

        // Optimization: If the node is exactly equal to the tip,
        // don't perform further validation.
        if let Some(tip) = self.tip_manager.get(sender) {
            if tip == *node {
                return Ok(None);
            }
        }

        // Validate chunk against the recovered tip.
        self.validate_chunk_tip(&node.chunk)?;

        // Verify the node
        node.verify(
            self.context.as_mut(),
            &self.chunk_verifier,
            &self.validators_provider,
            &self.strategy,
        )
    }

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and vote if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &mut self,
        ack: &Ack<C::PublicKey, P::Scheme, D>,
        sender: &<P::Scheme as Verifier>::PublicKey,
    ) -> Result<(), Error> {
        // Validate chunk
        self.validate_chunk_sequencer(&ack.chunk, ack.epoch)?;
        self.validate_chunk_tip(&ack.chunk)?;

        // Get the scheme for the epoch to validate the sender
        let Some(scheme) = self.validators_provider.scheme(ack.epoch) else {
            return Err(Error::UnknownScheme(ack.epoch));
        };

        // Validate sender is a participant and matches the vote signer
        let participants = scheme.participants();
        let Some(index) = participants.index(sender) else {
            return Err(Error::UnknownValidator(ack.epoch, sender.to_string()));
        };
        if index != ack.attestation.signer {
            return Err(Error::PeerMismatch);
        }

        // Spam prevention: If the ack is for an epoch that is too old or too new, ignore.
        {
            let (eb_lo, eb_hi) = self.epoch_bounds;
            let bound_lo = self.epoch.saturating_sub(eb_lo);
            let bound_hi = self.epoch.saturating_add(eb_hi);
            if ack.epoch < bound_lo || ack.epoch > bound_hi {
                return Err(Error::AckEpochOutsideBounds(ack.epoch, bound_lo, bound_hi));
            }
        }

        // Spam prevention: If the ack is for a height that is too old or too new, ignore.
        {
            let bound_lo = self
                .tip_manager
                .get(&ack.chunk.sequencer)
                .map(|t| t.chunk.height)
                .unwrap_or(Height::zero());
            let bound_hi = bound_lo.saturating_add(self.height_bound);
            if ack.chunk.height < bound_lo || ack.chunk.height > bound_hi {
                return Err(Error::AckHeightOutsideBounds(
                    ack.chunk.height,
                    bound_lo,
                    bound_hi,
                ));
            }
        }

        // Validate the vote signature
        if !ack.verify(self.context.as_mut(), scheme.as_ref(), &self.strategy) {
            return Err(Error::InvalidAckSignature);
        }

        Ok(())
    }

    /// Checks that the chunk sequencer is known for the epoch.
    ///
    /// This can run before journal replay because it does not depend on tracked tips.
    fn validate_chunk_sequencer(
        &self,
        chunk: &Chunk<C::PublicKey, D>,
        epoch: Epoch,
    ) -> Result<(), Error> {
        if self
            .sequencers_provider
            .sequencers(epoch)
            .and_then(|s| s.position(&chunk.sequencer))
            .is_none()
        {
            return Err(Error::UnknownSequencer(epoch, chunk.sequencer.to_string()));
        }

        Ok(())
    }

    /// Checks the chunk against the currently tracked tip for its sequencer.
    ///
    /// For inbound nodes, call this only after replaying the sender's journal.
    fn validate_chunk_tip(&self, chunk: &Chunk<C::PublicKey, D>) -> Result<(), Error> {
        if let Some(tip) = self.tip_manager.get(&chunk.sequencer) {
            // Height must be at least the tip height
            match chunk.height.cmp(&tip.chunk.height) {
                std::cmp::Ordering::Less => {
                    return Err(Error::ChunkHeightTooLow(chunk.height, tip.chunk.height));
                }
                std::cmp::Ordering::Equal => {
                    // Ensure this matches the tip if the height is the same
                    if tip.chunk.payload != chunk.payload {
                        return Err(Error::ChunkMismatch(
                            chunk.sequencer.to_string(),
                            chunk.height,
                        ));
                    }
                }
                std::cmp::Ordering::Greater => {}
            }
        }

        Ok(())
    }

    ////////////////////////////////////////
    // Journal
    ////////////////////////////////////////

    /// Returns the section of the journal for the given height.
    const fn get_journal_section(&self, height: Height) -> u64 {
        height.get() / self.journal_heights_per_section.get()
    }

    /// Ensures the journal exists and is initialized for the given sequencer.
    /// If the journal does not exist, it is created and replayed.
    /// Else, no action is taken.
    async fn journal_prepare(&mut self, sequencer: &C::PublicKey) {
        // Return early if the journal already exists
        if self.journals.contains_key(sequencer) {
            return;
        }

        // Initialize journal
        let cfg = JournalConfig {
            partition: format!("{}{}", &self.journal_name_prefix, sequencer),
            compression: self.journal_compression,
            codec_config: P::Scheme::certificate_codec_config_unbounded(),
            page_cache: self.journal_page_cache.clone(),
            write_buffer: self.journal_write_buffer,
        };
        let mut journal = Journal::<_, Node<C::PublicKey, P::Scheme, D>>::init(
            self.context
                .child("journal")
                .with_attribute("sequencer", sequencer),
            cfg,
        )
        .await
        .expect("unable to init journal");

        // Replay journal
        {
            debug!(?sequencer, "journal replay begin");

            // Prepare the stream
            let stream = journal
                .replay(0, 0, self.journal_replay_buffer)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);

            // Read from the stream, which may be in arbitrary order.
            // Remember the highest node height
            let mut tip: Option<Node<C::PublicKey, P::Scheme, D>> = None;
            let mut num_items = 0;
            while let Some(msg) = stream.next().await {
                let (_, _, _, node) = msg.expect("unable to read from journal");
                num_items += 1;
                let height = node.chunk.height;
                match tip {
                    None => {
                        tip = Some(node);
                    }
                    Some(ref t) => {
                        if height > t.chunk.height {
                            tip = Some(node);
                        }
                    }
                }
            }

            // Set the tip only once. The items from the journal may be in arbitrary order,
            // and the tip manager will panic if inserting tips out-of-order.
            if let Some(node) = tip.take() {
                let is_new = self.tip_manager.put(&node);
                assert!(is_new);
            }

            debug!(?sequencer, ?num_items, "journal replay end");
        }

        // Store journal
        self.journals.insert(sequencer.clone(), journal);
    }

    /// Write a `Node` to the appropriate journal, which contains the tip `Chunk` for the sequencer.
    ///
    /// To prevent ever writing two conflicting `Chunk`s at the same height,
    /// the journal must already be open and replayed.
    async fn journal_append(&mut self, node: Node<C::PublicKey, P::Scheme, D>) {
        let section = self.get_journal_section(node.chunk.height);
        self.journals
            .get_mut(&node.chunk.sequencer)
            .expect("journal does not exist")
            .append(section, &node)
            .await
            .expect("unable to append to journal");
    }

    /// Syncs (ensures all data is written to disk) and prunes the journal for the given sequencer and height.
    async fn journal_sync(&mut self, sequencer: &C::PublicKey, height: Height) {
        let section = self.get_journal_section(height);

        // Get journal
        let journal = self
            .journals
            .get_mut(sequencer)
            .expect("journal does not exist");

        // Sync journal
        journal.sync(section).await.expect("unable to sync journal");

        // Prune journal, ignoring errors
        let _ = journal.prune(section).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordered_broadcast::{
        mocks,
        scheme::ed25519,
        types::{AckSubject, SequencersProvider},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        certificate::{
            mocks::Fixture, Scheme as CertificateScheme, Verifier as CertificateVerifier,
        },
        ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
        sha256::Digest as Sha256Digest,
        Signer,
    };
    use commonware_macros::select;
    use commonware_p2p::{
        simulated::{Link, Network},
        Recipients, Sender,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, Quota, Runner as _, Supervisor as _,
    };
    use commonware_utils::{ordered::Set, sync::Mutex, Faults as _, N3f1, NZUsize, NZU16, NZU64};
    use std::{
        collections::BTreeMap,
        num::{NonZeroU16, NonZeroU32},
        sync::Arc,
        time::Duration,
    };

    const TEST_NAMESPACE: &[u8] = b"ordered_broadcast_engine_test";
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
    const RELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::from_millis(0),
        success_rate: 1.0,
    };
    type TestNode = Node<Ed25519PublicKey, ed25519::Scheme, Sha256Digest>;
    type TestReporter = mocks::ReporterMailbox<Ed25519PublicKey, ed25519::Scheme, Sha256Digest>;
    type TestEngine = Engine<
        deterministic::Context,
        PrivateKey,
        EpochSequencers,
        mocks::Provider<ed25519::Scheme>,
        Sha256Digest,
        mocks::Automaton<Ed25519PublicKey>,
        mocks::Automaton<Ed25519PublicKey>,
        TestReporter,
        mocks::Monitor,
        Sequential,
    >;

    #[derive(Clone, Default)]
    struct EpochSequencers {
        sequencers: Arc<Mutex<BTreeMap<Epoch, Arc<Set<Ed25519PublicKey>>>>>,
    }

    impl EpochSequencers {
        fn insert(&self, epoch: Epoch, sequencers: Vec<Ed25519PublicKey>) {
            self.sequencers
                .lock()
                .insert(epoch, Arc::new(Set::from_iter_dedup(sequencers)));
        }
    }

    impl SequencersProvider for EpochSequencers {
        type PublicKey = Ed25519PublicKey;

        fn sequencers(&self, epoch: Epoch) -> Option<Arc<Set<Self::PublicKey>>> {
            self.sequencers.lock().get(&epoch).cloned()
        }
    }

    fn certificate(
        fixture: &Fixture<ed25519::Scheme>,
        chunk: &Chunk<Ed25519PublicKey, Sha256Digest>,
        epoch: Epoch,
    ) -> <ed25519::Scheme as CertificateVerifier>::Certificate {
        let ctx = AckSubject { chunk, epoch };
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;
        let attestations = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect::<Vec<_>>();
        fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("certificate should assemble")
    }

    fn engine(
        context: deterministic::Context,
        fixture: &Fixture<ed25519::Scheme>,
        sequencers_provider: EpochSequencers,
        reporter: TestReporter,
        epoch: Epoch,
        journal_name_prefix: String,
    ) -> TestEngine {
        let validators_provider = mocks::Provider::new();
        assert!(validators_provider.register(epoch, fixture.schemes[0].clone()));

        let chunk_verifier = ChunkVerifier::new(TEST_NAMESPACE);
        let automaton = mocks::Automaton::<Ed25519PublicKey>::new(|_| false);
        let mut engine = Engine::new(
            context.child("engine"),
            Config {
                sequencer_signer: None::<ChunkSigner<PrivateKey>>,
                chunk_verifier,
                sequencers_provider,
                validators_provider,
                automaton: automaton.clone(),
                relay: automaton,
                reporter,
                monitor: mocks::Monitor::new(epoch),
                priority_proposals: false,
                priority_acks: false,
                rebroadcast_timeout: Duration::from_secs(1),
                epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                height_bound: HeightDelta::new(2),
                journal_heights_per_section: NZU64!(10),
                journal_replay_buffer: NZUsize!(4096),
                journal_write_buffer: NZUsize!(4096),
                journal_name_prefix,
                journal_compression: Some(3),
                journal_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            },
        );
        engine.epoch = epoch;
        engine
    }

    #[test]
    fn stale_node_after_restart_is_rejected_and_engine_continues() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let epoch = Epoch::new(10);
            let fixture = ed25519::fixture(&mut context, TEST_NAMESPACE, 4);
            let validator = fixture.participants[0].clone();
            let sequencer_sk = PrivateKey::from_seed(u64::MAX);
            let sequencer = sequencer_sk.public_key();
            let sequencers_provider = EpochSequencers::default();
            sequencers_provider.insert(epoch, vec![sequencer.clone()]);
            let journal_name_prefix = format!("ordered-broadcast-restart-{validator}-");

            let mut signer = ChunkSigner::new(TEST_NAMESPACE, sequencer_sk);
            let stale: TestNode = Node::sign(
                &mut signer,
                Height::zero(),
                Sha256Digest::from([1; 32]),
                None,
            );
            let stale_certificate = certificate(&fixture, &stale.chunk, epoch);
            let persisted: TestNode = Node::sign(
                &mut signer,
                Height::new(1),
                Sha256Digest::from([2; 32]),
                Some(Parent::new(stale.chunk.payload, epoch, stale_certificate)),
            );
            let persisted_certificate = certificate(&fixture, &persisted.chunk, epoch);
            let successor: TestNode = Node::sign(
                &mut signer,
                Height::new(2),
                Sha256Digest::from([3; 32]),
                Some(Parent::new(
                    persisted.chunk.payload,
                    epoch,
                    persisted_certificate,
                )),
            );

            // Persist height 1 without loading it into the restarted engine.
            {
                let (_reporter, reporter) = mocks::Reporter::new(
                    context.child("writer_reporter"),
                    ChunkVerifier::new(TEST_NAMESPACE),
                    fixture.verifier.clone(),
                    None,
                );
                let mut writer = engine(
                    context.child("writer"),
                    &fixture,
                    sequencers_provider.clone(),
                    reporter,
                    epoch,
                    journal_name_prefix.clone(),
                );
                writer.journal_prepare(&sequencer).await;
                writer.journal_append(persisted.clone()).await;
                writer.journal_sync(&sequencer, persisted.chunk.height).await;
            }

            let participants = vec![validator.clone(), sequencer.clone()];
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants,
            )
            .await;
            network.start();

            let validator_control = oracle.control(validator.clone());
            let (validator_node_sender, validator_node_receiver) =
                validator_control.register(0, TEST_QUOTA).await.unwrap();
            let (validator_ack_sender, validator_ack_receiver) =
                validator_control.register(1, TEST_QUOTA).await.unwrap();
            let sequencer_control = oracle.control(sequencer.clone());
            let (mut sequencer_node_sender, _sequencer_node_receiver) =
                sequencer_control.register(0, TEST_QUOTA).await.unwrap();
            let (_sequencer_ack_sender, _sequencer_ack_receiver) =
                sequencer_control.register(1, TEST_QUOTA).await.unwrap();

            oracle
                .add_link(sequencer.clone(), validator.clone(), RELIABLE_LINK)
                .await
                .unwrap();
            oracle
                .add_link(validator.clone(), sequencer.clone(), RELIABLE_LINK)
                .await
                .unwrap();

            let (reporter, mut reporter_mailbox) = mocks::Reporter::new(
                context.child("reporter"),
                ChunkVerifier::new(TEST_NAMESPACE),
                fixture.verifier.clone(),
                None,
            );
            reporter.start();
            let restarted = engine(
                context.child("restarted"),
                &fixture,
                sequencers_provider,
                reporter_mailbox.clone(),
                epoch,
                journal_name_prefix,
            );
            restarted.start(
                (validator_node_sender, validator_node_receiver),
                (validator_ack_sender, validator_ack_receiver),
            );

            // Deliver the old signed node first, then a valid successor.
            sequencer_node_sender.send(
                Recipients::Some(vec![validator.clone()]),
                stale.encode(),
                false,
            );
            context.sleep(Duration::from_millis(10)).await;
            sequencer_node_sender.send(
                Recipients::Some(vec![validator.clone()]),
                successor.encode(),
                false,
            );

            // The successor carries the persisted node's certificate. Observing that lock means
            // the engine rejected the stale node and continued processing traffic.
            let wait_for_persisted_lock = async {
                loop {
                    if reporter_mailbox.get_tip(sequencer.clone()).await
                        == Some((persisted.chunk.height, epoch))
                    {
                        break;
                    }
                    context.sleep(Duration::from_millis(10)).await;
                }
            };
            select! {
                _ = wait_for_persisted_lock => {},
                _ = context.sleep(Duration::from_secs(5)) => panic!("timed out waiting for engine progress"),
            }
        });
    }
}
