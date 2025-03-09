//! Engine for the broadcast module.
//!
//! It is responsible for:
//! - Broadcasting nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer’s chain
//! - Recovering threshold signatures from partial signatures for each chunk
//! - Notifying other actors of new chunks and threshold signatures

use super::{
    metrics, namespace, parsed, serializer, AckManager, Config, Context, Epoch, Prover, TipManager,
};
use crate::{Automaton, Committer, Coordinator, Relay};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self},
        ops,
        poly::{self},
    },
    Digest, Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{
    telemetry::{
        histogram,
        status::{CounterExt, Status},
    },
    Blob, Clock, Handle, Metrics, Spawner, Storage,
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
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Represents a pending verification request to the automaton.
struct Verify<C: Scheme, D: Array, E: Clock> {
    timer: histogram::Timer<E>,
    context: Context<C::PublicKey>,
    payload: D,
    result: Result<bool, Error>,
}

/// Instance of the `linked` broadcast engine.
pub struct Engine<
    B: Blob,
    E: Clock + Spawner + Storage<B> + Metrics,
    C: Scheme,
    D: Array,
    A: Automaton<Context = Context<C::PublicKey>, Digest = D> + Clone,
    R: Relay<Digest = D>,
    Z: Committer<Digest = D>,
    S: Coordinator<
        Index = Epoch,
        Seed = group::Signature,
        Share = group::Share,
        Identity = poly::Public,
        PublicKey = C::PublicKey,
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
    coordinator: S,
    collector: Z,

    ////////////////////////////////////////
    // Namespace Constants
    ////////////////////////////////////////

    // The namespace for chunk signatures.
    chunk_namespace: Vec<u8>,

    // The namespace for ack signatures.
    ack_namespace: Vec<u8>,

    ////////////////////////////////////////
    // Timeouts
    ////////////////////////////////////////

    // The configured timeout for refreshing the epoch
    refresh_epoch_timeout: Duration,
    refresh_epoch_deadline: Option<SystemTime>,

    // The configured timeout for rebroadcasting a chunk to all signers
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
    // Each future represents a verification request to the application
    // that will either timeout or resolve with a boolean.
    pending_verifies: FuturesPool<Verify<C, D, E>>,

    // The maximum number of items in `pending_verifies`.
    verify_concurrent: usize,

    ////////////////////////////////////////
    // Storage
    ////////////////////////////////////////

    // The number of heights per each journal section.
    journal_heights_per_section: u64,

    // The number of concurrent operations when replaying journals.
    journal_replay_concurrency: usize,

    // A prefix for the journal names.
    // The rest of the name is the hex-encoded public keys of the relevant sequencer.
    journal_name_prefix: String,

    // A map of sequencer public keys to their journals.
    journals: BTreeMap<C::PublicKey, Journal<B, E>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // Tracks the current tip for each sequencer.
    // The tip is a `Node` which is comprised of a `Chunk` and,
    // if not the genesis chunk for that sequencer,
    // a threshold signature over the parent chunk.
    tip_manager: TipManager<C, D>,

    // Tracks the acknowledgements for chunks.
    // This is comprised of partial signatures or threshold signatures.
    ack_manager: AckManager<D, C::PublicKey>,

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

    // The timer of my last broadcast_new
    broadcast_timer: Option<histogram::Timer<E>>,
}

impl<
        B: Blob,
        E: Clock + Spawner + Storage<B> + Metrics,
        C: Scheme,
        D: Array,
        A: Automaton<Context = Context<C::PublicKey>, Digest = D> + Clone,
        R: Relay<Digest = D>,
        Z: Committer<Digest = D>,
        S: Coordinator<
            Index = Epoch,
            Seed = group::Signature,
            Share = group::Share,
            Identity = poly::Public,
            PublicKey = C::PublicKey,
        >,
        NetS: Sender<PublicKey = C::PublicKey>,
        NetR: Receiver<PublicKey = C::PublicKey>,
    > Engine<B, E, C, D, A, R, Z, S, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<C, D, A, R, Z, S>) -> Self {
        let metrics = metrics::Metrics::init(context.clone());

        Self {
            context,
            crypto: cfg.crypto,
            automaton: cfg.automaton,
            relay: cfg.relay,
            collector: cfg.collector,
            coordinator: cfg.coordinator,
            chunk_namespace: namespace::chunk(&cfg.namespace),
            ack_namespace: namespace::ack(&cfg.namespace),
            refresh_epoch_timeout: cfg.refresh_epoch_timeout,
            refresh_epoch_deadline: None,
            rebroadcast_timeout: cfg.rebroadcast_timeout,
            rebroadcast_deadline: None,
            epoch_bounds: cfg.epoch_bounds,
            height_bound: cfg.height_bound,
            pending_verifies: FuturesPool::default(),
            verify_concurrent: cfg.verify_concurrent,
            journal_heights_per_section: cfg.journal_heights_per_section,
            journal_replay_concurrency: cfg.journal_replay_concurrency,
            journal_name_prefix: cfg.journal_name_prefix,
            journals: BTreeMap::new(),
            tip_manager: TipManager::<C, D>::new(),
            ack_manager: AckManager::<D, C::PublicKey>::new(),
            epoch: 0,
            priority_proposals: cfg.priority_proposals,
            priority_acks: cfg.priority_acks,
            _phantom: PhantomData,
            metrics,
            broadcast_timer: None,
        }
    }

    /// Runs the engine until the context is stopped.
    ///
    /// The engine will handle:
    /// - Requesting and processing proposals from the application
    /// - Timeouts
    ///   - Refreshing the Epoch
    ///   - Rebroadcasting Nodes
    /// - Messages from the network:
    ///   - Nodes
    ///   - Acks
    pub fn start(mut self, chunk_network: (NetS, NetR), ack_network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(chunk_network, ack_network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, chunk_network: (NetS, NetR), ack_network: (NetS, NetR)) {
        let (mut node_sender, mut node_receiver) = chunk_network;
        let (mut ack_sender, mut ack_receiver) = ack_network;
        let mut shutdown = self.context.stopped();

        // Before starting on the main loop, initialize my own sequencer journal
        // and attempt to rebroadcast if necessary.
        self.refresh_epoch();
        self.journal_prepare(&self.crypto.public_key()).await;
        if let Err(err) = self.rebroadcast(&mut node_sender).await {
            // Rebroadcasting my return a non-critical error, so log the error and continue.
            info!(?err, "initial rebroadcast failed");
        }

        // Track if there is an outstanding proposal request to the automaton.
        let mut pending_propose: Option<(Context<C::PublicKey>, oneshot::Receiver<D>)> = None;

        loop {
            // Enter the epoch
            self.refresh_epoch();

            // Create deadline futures.
            // If the deadline is None, the future will never resolve.
            let refresh_epoch = match self.refresh_epoch_deadline {
                Some(deadline) => Either::Left(self.context.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };
            let rebroadcast = match self.rebroadcast_deadline {
                Some(deadline) => Either::Left(self.context.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };

            // Set the proposal context if necessary
            let me = self.crypto.public_key();
            let mut proposal_context: Option<Context<C::PublicKey>> = None;
            if pending_propose.is_none() && self.coordinator.is_sequencer(self.epoch, &me).is_some()
            {
                // Check my existing tip
                proposal_context = match self.tip_manager.get(&me) {
                    // Genesis proposal
                    None => Some(Context {
                        sequencer: me,
                        height: 0,
                    }),

                    // Propose the next height if-and-only-if the threshold exists
                    Some(tip) => self
                        .ack_manager
                        .get_threshold(&me, tip.chunk.height)
                        .map(|_| Context {
                            sequencer: me,
                            height: tip.chunk.height.checked_add(1).unwrap(),
                        }),
                }
            }

            // Propose a new chunk if necessary
            if let Some(context) = proposal_context.take() {
                let receiver = self.automaton.propose(context.clone()).await;
                pending_propose = Some((context, receiver));
            };
            let propose_wait = match &mut pending_propose {
                Some((_context, receiver)) => Either::Left(receiver),
                None => Either::Right(futures::future::pending()),
            };

            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("shutdown");
                    self.pending_verifies.cancel_all();
                    while let Some((_, journal)) = self.journals.pop_first() {
                        journal.close().await.expect("unable to close journal");
                    }
                    return;
                },

                // Handle refresh epoch deadline
                _ = refresh_epoch => {
                    debug!("refresh epoch");
                    // Simply continue; the epoch will be refreshed on the next iteration.
                    continue;
                },

                // Handle rebroadcast deadline
                _ = rebroadcast => {
                    debug!("rebroadcast");
                    if let Err(err) = self.rebroadcast(&mut node_sender).await {
                        info!(?err, "rebroadcast failed");
                        continue;
                    }
                },

                // Propose a new chunk
                receiver = propose_wait => {
                    debug!("broadcast");

                    // Clear the pending proposal
                    let (context, _) = pending_propose.take().unwrap();

                    // Error handling for dropped proposals
                    let Ok(payload) = receiver else {
                        warn!(?context, "automaton dropped proposal");
                        continue;
                    };

                    // Broadcast the message
                    if let Err(err) = self.broadcast_new(context.clone(), payload, &mut node_sender).await {
                        warn!(?err, ?context, "broadcast new failed");
                        continue;
                    }
                },

                // Handle incoming nodes
                msg = node_receiver.recv() => {
                    debug!("node network");
                    // Error handling
                    let (sender, msg) = match msg {
                        Ok(r) => r,
                        Err(err) => {
                            error!(?err, "node receiver failed");
                            break;
                        }
                    };
                    let mut guard = self.metrics.nodes.guard(Status::Invalid);
                    let node = match parsed::Node::<C, D>::decode(&msg) {
                        Ok(node) => node,
                        Err(err) => {
                            warn!(?err, ?sender, "node decode failed");
                            continue;
                        }
                    };
                    if let Err(err) = self.validate_node(&node, &sender) {
                        warn!(?err, ?node, ?sender, "node validate failed");
                        continue;
                    };

                    // Initialize journal for sequencer if it does not exist
                    self.journal_prepare(&sender).await;

                    // Handle the parent threshold signature
                    if let Some(parent) = node.parent.as_ref() {
                        self.handle_threshold(&node.chunk, parent.epoch, parent.threshold).await;
                    }

                    // Process the new node
                    self.handle_node(&node).await;
                    guard.set(Status::Success);
                },

                // Handle incoming acks
                msg = ack_receiver.recv() => {
                    debug!("ack network");
                    // Error handling
                    let (sender, msg) = match msg {
                        Ok(r) => r,
                        Err(err) => {
                            warn!(?err, "ack receiver failed");
                            break;
                        }
                    };
                    let mut guard = self.metrics.acks.guard(Status::Invalid);
                    let ack = match parsed::Ack::decode(&msg) {
                        Ok(ack) => ack,
                        Err(err) => {
                            warn!(?err, ?sender, "ack decode failed");
                            continue;
                        }
                    };
                    if let Err(err) = self.validate_ack(&ack, &sender) {
                        warn!(?err, ?ack, ?sender, "ack validate failed");
                        continue;
                    };
                    if let Err(err) = self.handle_ack(&ack).await {
                        warn!(?err, ?ack, "ack handle failed");
                        guard.set(Status::Failure);
                        continue;
                    }
                    guard.set(Status::Success);
                },

                // Handle completed verification futures.
                verify = self.pending_verifies.next_completed() => {
                    let Verify { timer, context, payload, result } = verify;
                    drop(timer); // Record metric. Explicitly reference timer to avoid lint warning
                    match result {
                        Err(err) => {
                            warn!(?err, ?context, ?payload, "verified returned error");
                            self.metrics.verify.inc(Status::Dropped);
                        }
                        Ok(false) => {
                            warn!(?context, ?payload, "verified was false");
                            self.metrics.verify.inc(Status::Failure);
                        }
                        Ok(true) => {
                            debug!(?context, ?payload, "verified");
                            self.metrics.verify.inc(Status::Success);
                            if let Err(err) = self.handle_app_verified(&context, &payload, &mut ack_sender).await {
                                warn!(?err, ?context, ?payload, "verified handle failed");
                            }
                        },
                    }
                },
            }
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
        ack_sender: &mut NetS,
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

        // Construct partial signature
        let Some(share) = self.coordinator.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let partial = ops::partial_sign_message(
            share,
            Some(&self.ack_namespace),
            &serializer::ack(&tip.chunk, self.epoch),
        );

        // Sync the journal to prevent ever acking two conflicting chunks at
        // the same height, even if the node crashes and restarts.
        self.journal_sync(&context.sequencer, context.height).await;

        // The recipients are all the signers in the epoch and the sequencer.
        // The sequencer may or may not be a signer.
        let recipients = {
            let Some(signers) = self.coordinator.participants(self.epoch) else {
                return Err(Error::UnknownSigners(self.epoch));
            };
            let mut recipients = signers.clone();
            if self
                .coordinator
                .is_participant(self.epoch, &tip.chunk.sequencer)
                .is_none()
            {
                recipients.push(tip.chunk.sequencer.clone());
            }
            recipients
        };

        // Send the ack to the network
        let ack = parsed::Ack {
            chunk: tip.chunk,
            epoch: self.epoch,
            partial,
        };
        ack_sender
            .send(
                Recipients::Some(recipients),
                ack.encode().into(),
                self.priority_acks,
            )
            .await
            .map_err(|_| Error::UnableToSendMessage)?;

        // Handle the ack internally
        self.handle_ack(&ack).await?;

        Ok(())
    }

    /// Handles a threshold, either received from a `Node` from the network or generated locally.
    ///
    /// The threshold must already be verified.
    /// If the threshold is new, it is stored and the proof is emitted to the collector.
    /// If the threshold is already known, it is ignored.
    async fn handle_threshold(
        &mut self,
        chunk: &parsed::Chunk<D, C::PublicKey>,
        epoch: Epoch,
        threshold: group::Signature,
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
            self.broadcast_timer.take();
        }

        // Emit the proof
        let context = Context {
            sequencer: chunk.sequencer.clone(),
            height: chunk.height,
        };
        let proof =
            Prover::<C, D>::serialize_threshold(&context, &chunk.payload, epoch, &threshold);
        self.collector.finalized(proof, chunk.payload.clone()).await;
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(&mut self, ack: &parsed::Ack<D, C::PublicKey>) -> Result<(), Error> {
        // Get the quorum
        let Some(identity) = self.coordinator.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        let quorum = identity.required();

        // Add the partial signature. If a new threshold is formed, handle it.
        if let Some(threshold) = self.ack_manager.add_ack(ack, quorum) {
            self.metrics.threshold.inc();
            self.handle_threshold(&ack.chunk, ack.epoch, threshold)
                .await;
        }

        Ok(())
    }

    /// Handles a valid `Node` message, storing it as the tip.
    /// Alerts the automaton of the new node.
    /// Also appends the `Node` to the journal if it's new.
    async fn handle_node(&mut self, node: &parsed::Node<C, D>) {
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
            self.journal_append(node).await;
            self.journal_sync(&node.chunk.sequencer, node.chunk.height)
                .await;
        }

        // Drop the node if there are too many pending verifies
        let n = self.pending_verifies.len();
        if n >= self.verify_concurrent {
            warn!(?n, "too many pending verifies");
            return;
        }

        // Verify the chunk with the automaton
        let context = Context {
            sequencer: node.chunk.sequencer.clone(),
            height: node.chunk.height,
        };
        let payload = node.chunk.payload.clone();
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.verify_duration.timer();
        self.pending_verifies.push(async move {
            let receiver = automaton.verify(context.clone(), payload.clone()).await;
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
    // Broadcasting
    ////////////////////////////////////////

    /// Broadcast a message to the network.
    ///
    /// The result is returned to the caller via the provided channel.
    /// The broadcast is only successful if the parent Chunk and threshold signature are known.
    async fn broadcast_new(
        &mut self,
        context: Context<C::PublicKey>,
        payload: D,
        node_sender: &mut NetS,
    ) -> Result<(), Error> {
        let mut guard = self.metrics.new_broadcast.guard(Status::Dropped);
        let me = self.crypto.public_key();

        // Error-check context sequencer
        if context.sequencer != me {
            return Err(Error::ContextSequencer);
        }

        // Error-check that I am a sequencer in the current epoch
        if self.coordinator.is_sequencer(self.epoch, &me).is_none() {
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
            parent = Some(parsed::Parent {
                payload: tip.chunk.payload,
                threshold,
                epoch,
            });
        }

        // Error-check context height
        if context.height != height {
            return Err(Error::ContextHeight);
        }

        // Construct new node
        let chunk = parsed::Chunk {
            sequencer: me.clone(),
            height,
            payload,
        };
        let signature = self
            .crypto
            .sign(Some(&self.chunk_namespace), &serializer::chunk(&chunk));
        let node = parsed::Node::<C, D> {
            chunk,
            signature,
            parent,
        };

        // Deal with the chunk as if it were received over the network
        self.handle_node(&node).await;

        // Sync the journal to prevent ever broadcasting two conflicting chunks
        // at the same height, even if the node crashes and restarts
        self.journal_sync(&me, height).await;

        // Record the start time of the broadcast
        self.broadcast_timer = Some(self.metrics.e2e_duration.timer());

        // Broadcast to network
        if let Err(err) = self.broadcast(&node, node_sender, self.epoch).await {
            guard.set(Status::Failure);
            return Err(err);
        };

        // Return success
        guard.set(Status::Success);
        Ok(())
    }

    /// Attempt to rebroadcast the highest-height chunk of this sequencer to all signers.
    ///
    /// This is only done if:
    /// - this instance is the sequencer for the current epoch.
    /// - this instance has a chunk to rebroadcast.
    /// - this instance has not yet collected the threshold signature for the chunk.
    async fn rebroadcast(&mut self, node_sender: &mut NetS) -> Result<(), Error> {
        let mut guard = self.metrics.rebroadcast.guard(Status::Dropped);

        // Unset the rebroadcast deadline
        self.rebroadcast_deadline = None;

        // Return if not a sequencer in the current epoch
        let me = self.crypto.public_key();
        if self.coordinator.is_sequencer(self.epoch, &me).is_none() {
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
            return Err(Error::AlreadyBroadcast);
        }

        // Broadcast the message, which resets the rebroadcast deadline
        guard.set(Status::Failure);
        self.broadcast(&tip, node_sender, self.epoch).await?;
        guard.set(Status::Success);
        Ok(())
    }

    /// Send a  `Node` message to all signers in the given epoch.
    async fn broadcast(
        &mut self,
        node: &parsed::Node<C, D>,
        node_sender: &mut NetS,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Get the signers for the epoch
        let Some(signers) = self.coordinator.participants(epoch) else {
            return Err(Error::UnknownSigners(epoch));
        };

        // Tell the relay to broadcast the full data
        self.relay.broadcast(node.chunk.payload.clone()).await;

        // Send the node to all signers
        node_sender
            .send(
                Recipients::Some(signers.clone()),
                node.encode().into(),
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
    /// If valid, returns the implied parent chunk and its threshold signature.
    /// Else returns an error if the `Node` is invalid.
    fn validate_node(
        &mut self,
        node: &parsed::Node<C, D>,
        sender: &C::PublicKey,
    ) -> Result<(), Error> {
        // Verify the sender
        if node.chunk.sequencer != *sender {
            return Err(Error::PeerMismatch);
        }

        // Optimization: If the node is exactly equal to the tip,
        // don't perform any further validation.
        if let Some(tip) = self.tip_manager.get(sender) {
            if tip == *node {
                return Ok(());
            }
        }

        // Validate chunk
        self.validate_chunk(&node.chunk, self.epoch)?;

        // Verify the signature
        if !C::verify(
            Some(&self.chunk_namespace),
            &serializer::chunk(&node.chunk),
            sender,
            &node.signature,
        ) {
            return Err(Error::InvalidNodeSignature);
        }

        // Verify no parent
        if node.chunk.height == 0 {
            if node.parent.is_some() {
                return Err(Error::GenesisChunkMustNotHaveParent);
            }
            return Ok(());
        }

        // Verify parent
        let Some(parent) = &node.parent else {
            return Err(Error::NodeMissingParent);
        };
        let parent_chunk = parsed::Chunk {
            sequencer: sender.clone(),
            height: node.chunk.height.checked_sub(1).unwrap(),
            payload: parent.payload,
        };

        // Verify parent threshold signature
        let Some(identity) = self.coordinator.identity(parent.epoch) else {
            return Err(Error::UnknownIdentity(parent.epoch));
        };
        let public_key = poly::public(identity);
        ops::verify_message(
            public_key,
            Some(&self.ack_namespace),
            &serializer::ack(&parent_chunk, parent.epoch),
            &parent.threshold,
        )
        .map_err(|_| Error::InvalidThresholdSignature)?;

        Ok(())
    }

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &self,
        ack: &parsed::Ack<D, C::PublicKey>,
        sender: &C::PublicKey,
    ) -> Result<(), Error> {
        // Validate chunk
        self.validate_chunk(&ack.chunk, ack.epoch)?;

        // Validate sender
        let Some(signer_index) = self.coordinator.is_participant(ack.epoch, sender) else {
            return Err(Error::UnknownSigner(ack.epoch, sender.to_string()));
        };
        if signer_index != ack.partial.index {
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
        let Some(identity) = self.coordinator.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        ops::partial_verify_message(
            identity,
            Some(&self.ack_namespace),
            &serializer::ack(&ack.chunk, ack.epoch),
            &ack.partial,
        )
        .map_err(|_| Error::InvalidPartialSignature)?;

        Ok(())
    }

    /// Takes a raw chunk from the p2p network and validates it against the epoch.
    ///
    /// Returns the chunk if the chunk is valid.
    /// Returns an error if the chunk is invalid.
    fn validate_chunk(
        &self,
        chunk: &parsed::Chunk<D, C::PublicKey>,
        epoch: Epoch,
    ) -> Result<(), Error> {
        // Verify sequencer
        if self
            .coordinator
            .is_sequencer(epoch, &chunk.sequencer)
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
        };
        let mut journal = Journal::init(self.context.clone(), cfg)
            .await
            .expect("unable to init journal");

        // Replay journal
        {
            debug!(?sequencer, "journal replay begin");

            // Prepare the stream
            let stream = journal
                .replay(self.journal_replay_concurrency, None)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);

            // Read from the stream, which may be in arbitrary order.
            // Remember the highest node height
            let mut tip: Option<parsed::Node<C, D>> = None;
            let mut num_items = 0;
            while let Some(msg) = stream.next().await {
                num_items += 1;
                let (_, _, _, msg) = msg.expect("unable to decode journal message");
                let node = parsed::Node::<C, D>::decode(&msg)
                    .expect("journal message is unexpected format");
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
    async fn journal_append(&mut self, node: &parsed::Node<C, D>) {
        let section = self.get_journal_section(node.chunk.height);
        self.journals
            .get_mut(&node.chunk.sequencer)
            .expect("journal does not exist")
            .append(section, node.encode().into())
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

    ////////////////////////////////////////
    // Epoch
    ////////////////////////////////////////

    /// Updates the epoch to the value of the coordinator, and sets the refresh epoch deadline.
    fn refresh_epoch(&mut self) {
        // Set the refresh epoch deadline
        self.refresh_epoch_deadline = Some(self.context.current() + self.refresh_epoch_timeout);

        // Ensure epoch is not before the current epoch
        let epoch = self.coordinator.index();
        assert!(epoch >= self.epoch);

        // Update the epoch
        self.epoch = epoch;
    }
}

/// Errors that can occur when running the engine.
#[derive(Error, Debug)]
enum Error {
    // Application Verification Errors
    #[error("Application verify error: {0}")]
    AppVerifyCanceled(oneshot::Canceled),
    #[error("Application verified no tip")]
    AppVerifiedNoTip,
    #[error("Application verified height mismatch")]
    AppVerifiedHeightMismatch,
    #[error("Application verified payload mismatch")]
    AppVerifiedPayloadMismatch,

    // P2P Errors
    #[error("Unable to send message")]
    UnableToSendMessage,

    // Broadcast errors
    #[error("Already broadcast")]
    AlreadyBroadcast,
    #[error("I am not a sequencer in epoch {0}")]
    IAmNotASequencer(u64),
    #[error("Nothing to rebroadcast")]
    NothingToRebroadcast,
    #[error("Broadcast failed")]
    BroadcastFailed,
    #[error("Missing threshold")]
    MissingThreshold,
    #[error("Invalid context sequencer")]
    ContextSequencer,
    #[error("Invalid context height")]
    ContextHeight,

    // Proto Malformed Errors
    #[error("Genesis chunk must not have a parent")]
    GenesisChunkMustNotHaveParent,
    #[error("Node missing parent")]
    NodeMissingParent,

    // Epoch Errors
    #[error("Unknown identity at epoch {0}")]
    UnknownIdentity(u64),
    #[error("Unknown signers at epoch {0}")]
    UnknownSigners(u64),
    #[error("Epoch {0} has no sequencer {1}")]
    UnknownSequencer(u64, String),
    #[error("Epoch {0} has no signer {1}")]
    UnknownSigner(u64, String),
    #[error("Unknown share at epoch {0}")]
    UnknownShare(u64),

    // Peer Errors
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
    #[error("Invalid threshold signature")]
    InvalidThresholdSignature,
    #[error("Invalid partial signature")]
    InvalidPartialSignature,
    #[error("Invalid node signature")]
    InvalidNodeSignature,

    // Ignorable Message Errors
    #[error("Invalid ack epoch {0} outside bounds {1} - {2}")]
    AckEpochOutsideBounds(u64, u64, u64),
    #[error("Invalid ack height {0} outside bounds {1} - {2}")]
    AckHeightOutsideBounds(u64, u64, u64),
    #[error("Chunk height {0} lower than tip height {1}")]
    ChunkHeightTooLow(u64, u64),

    // Slashable Errors
    #[error("Chunk mismatch from sender {0} with height {1}")]
    ChunkMismatch(String, u64),
}
