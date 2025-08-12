//! Engine for the module.
//!
//! It is responsible for:
//! - Proposing nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer’s chain
//! - Recovering threshold signatures from partial signatures for each chunk
//! - Notifying other actors of new chunks and threshold signatures

use super::{
    metrics,
    types::{Ack, Activity, Chunk, Context, Epoch, Error, Lock, Node, Parent, Proposal},
    AckManager, Config, TipManager,
};
use crate::{Automaton, Monitor, Relay, Reporter, Supervisor, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{group, poly, variant::Variant},
    Digest, PublicKey, Signer,
};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef,
    telemetry::metrics::{
        histogram,
        status::{CounterExt, Status},
    },
    Clock, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::{self, variable::Journal};
use commonware_utils::futures::Pool as FuturesPool;
use futures::{
    channel::oneshot,
    future::{self, Either},
    pin_mut, StreamExt,
};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, warn};

/// Represents a pending verification request to the automaton.
struct Verify<C: PublicKey, D: Digest, E: Clock> {
    timer: histogram::Timer<E>,
    context: Context<C>,
    payload: D,
    result: Result<bool, Error>,
}

/// Instance of the engine.
pub struct Engine<
    E: Clock + Spawner + Storage + Metrics,
    C: Signer,
    V: Variant,
    D: Digest,
    A: Automaton<Context = Context<C::PublicKey>, Digest = D> + Clone,
    R: Relay<Digest = D>,
    Z: Reporter<Activity = Activity<C::PublicKey, V, D>>,
    M: Monitor<Index = Epoch>,
    Su: Supervisor<Index = Epoch, PublicKey = C::PublicKey>,
    TSu: ThresholdSupervisor<
        Index = Epoch,
        PublicKey = C::PublicKey,
        Identity = V::Public,
        Polynomial = poly::Public<V>,
        Share = group::Share,
    >,
    NetS: Sender<PublicKey = C::PublicKey>,
    NetR: Receiver<PublicKey = C::PublicKey>,
> {
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    context: E,
    crypto: C,
    automaton: A,
    relay: R,
    monitor: M,
    sequencers: Su,
    validators: TSu,
    reporter: Z,

    ////////////////////////////////////////
    // Namespace Constants
    ////////////////////////////////////////

    // The namespace signatures.
    namespace: Vec<u8>,

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
    epoch_bounds: (u64, u64),

    // The number of future heights to accept acks for.
    // This is used to prevent spam of acks for arbitrary heights.
    //
    // For example, if the current tip for a sequencer is at height 100,
    // and the height_bound is 10, then acks for heights 100-110 are accepted.
    height_bound: u64,

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
    pending_verifies: FuturesPool<Verify<C::PublicKey, D, E>>,

    ////////////////////////////////////////
    // Storage
    ////////////////////////////////////////

    // The number of heights per each journal section.
    journal_heights_per_section: u64,

    // The number of bytes to buffer when replaying a journal.
    journal_replay_buffer: NonZeroUsize,

    // The size of the write buffer to use for each blob in the journal.
    journal_write_buffer: NonZeroUsize,

    // A prefix for the journal names.
    // The rest of the name is the hex-encoded public keys of the relevant sequencer.
    journal_name_prefix: String,

    // Compression level for the journal.
    journal_compression: Option<u8>,

    // Buffer pool for the journal.
    journal_buffer_pool: PoolRef,

    // A map of sequencer public keys to their journals.
    #[allow(clippy::type_complexity)]
    journals: BTreeMap<C::PublicKey, Journal<E, Node<C::PublicKey, V, D>>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // Tracks the current tip for each sequencer.
    // The tip is a `Node` which is comprised of a `Chunk` and,
    // if not the genesis chunk for that sequencer,
    // a threshold signature over the parent chunk.
    tip_manager: TipManager<C::PublicKey, V, D>,

    // Tracks the acknowledgements for chunks.
    // This is comprised of partial signatures or threshold signatures.
    ack_manager: AckManager<C::PublicKey, V, D>,

    // The current epoch.
    epoch: Epoch,

    ////////////////////////////////////////
    // Network
    ////////////////////////////////////////

    // Whether to send proposals as priority messages.
    priority_proposals: bool,

    // Whether to send acks as priority messages.
    priority_acks: bool,

    // The network sender and receiver types.
    _phantom: PhantomData<(NetS, NetR)>,

    ////////////////////////////////////////
    // Metrics
    ////////////////////////////////////////

    // Metrics
    metrics: metrics::Metrics<E>,

    // The timer of my last new proposal
    propose_timer: Option<histogram::Timer<E>>,
}

impl<
        E: Clock + Spawner + Storage + Metrics,
        C: Signer,
        V: Variant,
        D: Digest,
        A: Automaton<Context = Context<C::PublicKey>, Digest = D> + Clone,
        R: Relay<Digest = D>,
        Z: Reporter<Activity = Activity<C::PublicKey, V, D>>,
        M: Monitor<Index = Epoch>,
        Su: Supervisor<Index = Epoch, PublicKey = C::PublicKey>,
        TSu: ThresholdSupervisor<
            Index = Epoch,
            PublicKey = C::PublicKey,
            Identity = V::Public,
            Polynomial = poly::Public<V>,
            Share = group::Share,
        >,
        NetS: Sender<PublicKey = C::PublicKey>,
        NetR: Receiver<PublicKey = C::PublicKey>,
    > Engine<E, C, V, D, A, R, Z, M, Su, TSu, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<C, V, D, A, R, Z, M, Su, TSu>) -> Self {
        let metrics = metrics::Metrics::init(context.clone());

        Self {
            context,
            crypto: cfg.crypto,
            automaton: cfg.automaton,
            relay: cfg.relay,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            sequencers: cfg.sequencers,
            validators: cfg.validators,
            namespace: cfg.namespace,
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
            journal_buffer_pool: cfg.journal_buffer_pool,
            journals: BTreeMap::new(),
            tip_manager: TipManager::<C::PublicKey, V, D>::new(),
            ack_manager: AckManager::<C::PublicKey, V, D>::new(),
            epoch: 0,
            priority_proposals: cfg.priority_proposals,
            priority_acks: cfg.priority_acks,
            _phantom: PhantomData,
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
    pub fn start(mut self, chunk_network: (NetS, NetR), ack_network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(chunk_network, ack_network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, chunk_network: (NetS, NetR), ack_network: (NetS, NetR)) {
        let (mut node_sender, mut node_receiver) = wrap((), chunk_network.0, chunk_network.1);
        let (mut ack_sender, mut ack_receiver) = wrap((), ack_network.0, ack_network.1);
        let mut shutdown = self.context.stopped();

        // Tracks if there is an outstanding proposal request to the automaton.
        let mut pending: Option<(Context<C::PublicKey>, oneshot::Receiver<D>)> = None;

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        // Before starting on the main loop, initialize my own sequencer journal
        // and attempt to rebroadcast if necessary.
        self.journal_prepare(&self.crypto.public_key()).await;
        if let Err(err) = self.rebroadcast(&mut node_sender).await {
            // Rebroadcasting may return a non-critical error, so log the error and continue.
            info!(?err, "initial rebroadcast failed");
        }

        loop {
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

            // Process the next event
            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("shutdown");
                    break;
                },

                // Handle refresh epoch deadline
                epoch = epoch_updates.next() => {
                    // Error handling
                    let Some(epoch) = epoch else {
                        error!("epoch subscription failed");
                        break;
                    };

                    // Refresh the epoch
                    debug!(current=self.epoch, new=epoch, "refresh epoch");
                    assert!(epoch >= self.epoch);
                    self.epoch = epoch;
                    continue;
                },

                // Handle rebroadcast deadline
                _ = rebroadcast => {
                    debug!(epoch = self.epoch, sender=?self.crypto.public_key(), "rebroadcast");
                    if let Err(err) = self.rebroadcast(&mut node_sender).await {
                        info!(?err, "rebroadcast failed");
                        continue;
                    }
                },

                // Propose a new chunk
                receiver = propose => {
                    // Clear the pending proposal
                    let (context, _) = pending.take().unwrap();
                    debug!(height = context.height, "propose");

                    // Error handling for dropped proposals
                    let Ok(payload) = receiver else {
                        warn!(?context, "automaton dropped proposal");
                        continue;
                    };

                    // Propose the chunk
                    if let Err(err) = self.propose(context.clone(), payload, &mut node_sender).await {
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
                    let node = match msg {
                        Ok(node) => node,
                        Err(err) => {
                            debug!(?err, ?sender, "node decode failed");
                            continue;
                        }
                    };
                    let result = match self.validate_node(&node, &sender) {
                        Ok(result) => result,
                        Err(err) => {
                            debug!(?err, ?sender, "node validate failed");
                            continue;
                        }
                    };

                    // Initialize journal for sequencer if it does not exist
                    self.journal_prepare(&sender).await;

                    // Handle the parent threshold signature
                    if let Some(parent_chunk) = result {
                        let parent = node.parent.as_ref().unwrap();
                        self.handle_threshold(&parent_chunk, parent.epoch, parent.signature).await;
                    }

                    // Process the node
                    //
                    // Note, this node may be a duplicate. If it is, we will attempt to verify it and vote
                    // on it again (our original vote may have been lost).
                    self.handle_node(&node).await;
                    debug!(?sender, height=node.chunk.height, "node");
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
                    if let Err(err) = self.handle_ack(&ack).await {
                        debug!(?err, ?sender, "ack handle failed");
                        guard.set(Status::Failure);
                        continue;
                    }
                    debug!(?sender, epoch=ack.epoch, sequencer=?ack.chunk.sequencer, height=ack.chunk.height, "ack");
                    guard.set(Status::Success);
                },

                // Handle completed verification futures.
                verify = self.pending_verifies.next_completed() => {
                    let Verify { timer, context, payload, result } = verify;
                    drop(timer); // Record metric. Explicitly reference timer to avoid lint warning.
                    match result {
                        Err(err) => {
                            warn!(?err, ?context, "verified returned error");
                            self.metrics.verify.inc(Status::Dropped);
                        }
                        Ok(false) => {
                            debug!(?context, "verified was false");
                            self.metrics.verify.inc(Status::Failure);
                        }
                        Ok(true) => {
                            debug!(?context, "verified");
                            self.metrics.verify.inc(Status::Success);
                            if let Err(err) = self.handle_app_verified(&context, &payload, &mut ack_sender).await {
                                debug!(?err, ?context, ?payload, "verified handle failed");
                            }
                        },
                    }
                },
            }
        }

        // Close all journals, regardless of how we exit the loop
        self.pending_verifies.cancel_all();
        while let Some((_, journal)) = self.journals.pop_first() {
            journal.close().await.expect("unable to close journal");
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
        ack_sender: &mut WrappedSender<NetS, Ack<C::PublicKey, V, D>>,
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
        self.reporter
            .report(Activity::Tip(Proposal::new(
                tip.chunk.clone(),
                tip.signature.clone(),
            )))
            .await;

        // Construct partial signature (if a validator)
        let Some(share) = self.validators.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let ack = Ack::sign(&self.namespace, share, tip.chunk.clone(), self.epoch);

        // Sync the journal to prevent ever acking two conflicting chunks at
        // the same height, even if the node crashes and restarts.
        self.journal_sync(&context.sequencer, context.height).await;

        // The recipients are all the validators in the epoch and the sequencer.
        // The sequencer may or may not be a validator.
        let recipients = {
            let Some(validators) = self.validators.participants(self.epoch) else {
                return Err(Error::UnknownValidators(self.epoch));
            };
            let mut recipients = validators.clone();
            if self
                .validators
                .is_participant(self.epoch, &tip.chunk.sequencer)
                .is_none()
            {
                recipients.push(tip.chunk.sequencer.clone());
            }
            recipients
        };

        // Handle the ack internally
        self.handle_ack(&ack).await?;

        // Send the ack to the network
        ack_sender
            .send(Recipients::Some(recipients), ack, self.priority_acks)
            .await
            .map_err(|_| Error::UnableToSendMessage)?;

        Ok(())
    }

    /// Handles a threshold, either received from a `Node` from the network or generated locally.
    ///
    /// The threshold must already be verified.
    /// If the threshold is new, it is stored and the proof is emitted to the committer.
    /// If the threshold is already known, it is ignored.
    async fn handle_threshold(
        &mut self,
        chunk: &Chunk<C::PublicKey, D>,
        epoch: Epoch,
        threshold: V::Signature,
    ) {
        // Set the threshold signature, returning early if it already exists
        if !self
            .ack_manager
            .add_threshold(&chunk.sequencer, chunk.height, epoch, threshold)
        {
            return;
        }

        // If the threshold is for my sequencer, record metric
        if chunk.sequencer == self.crypto.public_key() {
            self.propose_timer.take();
        }

        // Emit the activity
        self.reporter
            .report(Activity::Lock(Lock::new(chunk.clone(), epoch, threshold)))
            .await;
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(&mut self, ack: &Ack<C::PublicKey, V, D>) -> Result<(), Error> {
        // Get the quorum
        let Some(polynomial) = self.validators.polynomial(ack.epoch) else {
            return Err(Error::UnknownPolynomial(ack.epoch));
        };
        let quorum = polynomial.required();

        // Add the partial signature. If a new threshold is formed, handle it.
        if let Some(threshold) = self.ack_manager.add_ack(ack, quorum) {
            debug!(epoch=ack.epoch, sequencer=?ack.chunk.sequencer, height=ack.chunk.height, "recovered threshold");
            self.metrics.threshold.inc();
            self.handle_threshold(&ack.chunk, ack.epoch, threshold)
                .await;
        }

        Ok(())
    }

    /// Handles a valid `Node` message, storing it as the tip.
    /// Alerts the automaton of the new node.
    /// Also appends the `Node` to the journal if it's new.
    async fn handle_node(&mut self, node: &Node<C::PublicKey, V, D>) {
        // Store the tip
        let is_new = self.tip_manager.put(node);

        // If a higher height than the previous tip...
        if is_new {
            // Update metrics for sequencer height
            self.metrics
                .sequencer_heights
                .get_or_create(&metrics::SequencerLabel::from(&node.chunk.sequencer))
                .set(node.chunk.height as i64);

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
        let timer = self.metrics.verify_duration.timer();
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
        let me = self.crypto.public_key();

        // Return `None` if I am not a sequencer in the current epoch
        self.sequencers.is_participant(self.epoch, &me)?;

        // Return the next context unless my current tip has no threshold signature
        match self.tip_manager.get(&me) {
            None => Some(Context {
                sequencer: me,
                height: 0,
            }),
            Some(tip) => self
                .ack_manager
                .get_threshold(&me, tip.chunk.height)
                .map(|_| Context {
                    sequencer: me,
                    height: tip.chunk.height.checked_add(1).unwrap(),
                }),
        }
    }

    /// Propose a new chunk to the network.
    ///
    /// The result is returned to the caller via the provided channel.
    /// The proposal is only successful if the parent Chunk and threshold signature are known.
    async fn propose(
        &mut self,
        context: Context<C::PublicKey>,
        payload: D,
        node_sender: &mut WrappedSender<NetS, Node<C::PublicKey, V, D>>,
    ) -> Result<(), Error> {
        let mut guard = self.metrics.propose.guard(Status::Dropped);
        let me = self.crypto.public_key();

        // Error-check context sequencer
        if context.sequencer != me {
            return Err(Error::ContextSequencer);
        }

        // Error-check that I am a sequencer in the current epoch
        if self.sequencers.is_participant(self.epoch, &me).is_none() {
            return Err(Error::IAmNotASequencer(self.epoch));
        }

        // Get parent Chunk and threshold signature
        let mut height = 0;
        let mut parent = None;
        if let Some(tip) = self.tip_manager.get(&me) {
            // Get threshold, or, if it doesn't exist, return an error
            let Some((epoch, threshold)) = self.ack_manager.get_threshold(&me, tip.chunk.height)
            else {
                return Err(Error::MissingThreshold);
            };

            // Update height and parent
            height = tip.chunk.height + 1;
            parent = Some(Parent::new(tip.chunk.payload, epoch, threshold));
        }

        // Error-check context height
        if context.height != height {
            return Err(Error::ContextHeight);
        }

        // Construct new node
        let node = Node::sign(&self.namespace, &mut self.crypto, height, payload, parent);

        // Deal with the chunk as if it were received over the network
        self.handle_node(&node).await;

        // Sync the journal to prevent ever proposing two conflicting chunks
        // at the same height, even if the node crashes and restarts
        self.journal_sync(&me, height).await;

        // Record the start time of the proposal
        self.propose_timer = Some(self.metrics.e2e_duration.timer());

        // Broadcast to network
        if let Err(err) = self.broadcast(node, node_sender, self.epoch).await {
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
    /// - this instance has not yet collected the threshold signature for the chunk.
    async fn rebroadcast(
        &mut self,
        node_sender: &mut WrappedSender<NetS, Node<C::PublicKey, V, D>>,
    ) -> Result<(), Error> {
        let mut guard = self.metrics.rebroadcast.guard(Status::Dropped);

        // Unset the rebroadcast deadline
        self.rebroadcast_deadline = None;

        // Return if not a sequencer in the current epoch
        let me = self.crypto.public_key();
        if self.sequencers.is_participant(self.epoch, &me).is_none() {
            return Err(Error::IAmNotASequencer(self.epoch));
        }

        // Return if no chunk to rebroadcast
        let Some(tip) = self.tip_manager.get(&me) else {
            return Err(Error::NothingToRebroadcast);
        };

        // Return if threshold already collected
        if self
            .ack_manager
            .get_threshold(&me, tip.chunk.height)
            .is_some()
        {
            return Err(Error::AlreadyThresholded);
        }

        // Broadcast the message, which resets the rebroadcast deadline
        guard.set(Status::Failure);
        self.broadcast(tip, node_sender, self.epoch).await?;
        guard.set(Status::Success);
        Ok(())
    }

    /// Send a  `Node` message to all validators in the given epoch.
    async fn broadcast(
        &mut self,
        node: Node<C::PublicKey, V, D>,
        node_sender: &mut WrappedSender<NetS, Node<C::PublicKey, V, D>>,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Get the validators for the epoch
        let Some(validators) = self.validators.participants(epoch) else {
            return Err(Error::UnknownValidators(epoch));
        };

        // Tell the relay to broadcast the full data
        self.relay.broadcast(node.chunk.payload).await;

        // Send the node to all validators
        node_sender
            .send(
                Recipients::Some(validators.clone()),
                node,
                self.priority_proposals,
            )
            .await
            .map_err(|_| Error::BroadcastFailed)?;

        // Set the rebroadcast deadline
        self.rebroadcast_deadline = Some(self.context.current() + self.rebroadcast_timeout);

        Ok(())
    }

    ////////////////////////////////////////
    // Validation
    ////////////////////////////////////////

    /// Takes a raw `Node` (from sender) from the p2p network and validates it.
    ///
    /// If valid (and not already the tracked tip for the sender), returns the implied
    /// parent chunk and its threshold signature.
    /// Else returns an error if the `Node` is invalid.
    fn validate_node(
        &mut self,
        node: &Node<C::PublicKey, V, D>,
        sender: &C::PublicKey,
    ) -> Result<Option<Chunk<C::PublicKey, D>>, Error> {
        // Verify the sender
        if node.chunk.sequencer != *sender {
            return Err(Error::PeerMismatch);
        }

        // Optimization: If the node is exactly equal to the tip,
        // don't perform further validation.
        if let Some(tip) = self.tip_manager.get(sender) {
            if tip == *node {
                return Ok(None);
            }
        }

        // Validate chunk
        self.validate_chunk(&node.chunk, self.epoch)?;

        // Verify the signature
        node.verify(&self.namespace, self.validators.identity())
            .map_err(|_| Error::InvalidNodeSignature)
    }

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &self,
        ack: &Ack<C::PublicKey, V, D>,
        sender: &C::PublicKey,
    ) -> Result<(), Error> {
        // Validate chunk
        self.validate_chunk(&ack.chunk, ack.epoch)?;

        // Validate sender
        let Some(index) = self.validators.is_participant(ack.epoch, sender) else {
            return Err(Error::UnknownValidator(ack.epoch, sender.to_string()));
        };
        if index != ack.signature.index {
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
                .unwrap_or(0);
            let bound_hi = bound_lo + self.height_bound;
            if ack.chunk.height < bound_lo || ack.chunk.height > bound_hi {
                return Err(Error::AckHeightOutsideBounds(
                    ack.chunk.height,
                    bound_lo,
                    bound_hi,
                ));
            }
        }

        // Validate partial signature
        // Optimization: If the ack already exists, don't verify
        let Some(polynomial) = self.validators.polynomial(ack.epoch) else {
            return Err(Error::UnknownPolynomial(ack.epoch));
        };
        if !ack.verify(&self.namespace, polynomial) {
            return Err(Error::InvalidAckSignature);
        }

        Ok(())
    }

    /// Takes a raw chunk from the p2p network and validates it against the epoch.
    ///
    /// Returns the chunk if the chunk is valid.
    /// Returns an error if the chunk is invalid.
    fn validate_chunk(&self, chunk: &Chunk<C::PublicKey, D>, epoch: Epoch) -> Result<(), Error> {
        // Verify sequencer
        if self
            .sequencers
            .is_participant(epoch, &chunk.sequencer)
            .is_none()
        {
            return Err(Error::UnknownSequencer(epoch, chunk.sequencer.to_string()));
        }

        // Verify height
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
    fn get_journal_section(&self, height: u64) -> u64 {
        height / self.journal_heights_per_section
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
        let cfg = journal::variable::Config {
            partition: format!("{}{}", &self.journal_name_prefix, sequencer),
            compression: self.journal_compression,
            codec_config: (),
            buffer_pool: self.journal_buffer_pool.clone(),
            write_buffer: self.journal_write_buffer,
        };
        let journal =
            Journal::<_, Node<C::PublicKey, V, D>>::init(self.context.with_label("journal"), cfg)
                .await
                .expect("unable to init journal");

        // Replay journal
        {
            debug!(?sequencer, "journal replay begin");

            // Prepare the stream
            let stream = journal
                .replay(self.journal_replay_buffer)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);

            // Read from the stream, which may be in arbitrary order.
            // Remember the highest node height
            let mut tip: Option<Node<C::PublicKey, V, D>> = None;
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
    async fn journal_append(&mut self, node: Node<C::PublicKey, V, D>) {
        let section = self.get_journal_section(node.chunk.height);
        self.journals
            .get_mut(&node.chunk.sequencer)
            .expect("journal does not exist")
            .append(section, node)
            .await
            .expect("unable to append to journal");
    }

    /// Syncs (ensures all data is written to disk) and prunes the journal for the given sequencer and height.
    async fn journal_sync(&mut self, sequencer: &C::PublicKey, height: u64) {
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
