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
    types::{Ack, Activity, Epoch, Error, Index, Item, Lock},
    Config, Manager,
};
use crate::{Automaton, Monitor, Relay, Reporter, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{group, poly},
    Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Receiver, Recipients, Sender,
};
use commonware_runtime::{
    telemetry::metrics::{
        histogram,
        status::{CounterExt, Status},
    },
    Clock, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::{self, variable::Journal};
use commonware_utils::{futures::Pool as FuturesPool, Array};
use futures::{
    channel::oneshot,
    future::{self, Either},
    pin_mut, StreamExt,
};
use std::{
    collections::HashMap,
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, warn};

struct Propose<D: Digest, E: Clock> {
    timer: histogram::Timer<E>,
    index: Index,
    result: Result<D, Error>,
}

/// Instance of the engine.
pub struct Engine<
    E: Clock + Spawner + Storage + Metrics,
    P: Array,
    D: Digest,
    A: Automaton<Context = Index, Digest = D> + Clone,
    R: Relay<Digest = D>,
    Z: Reporter<Activity = Activity<D>>,
    M: Monitor<Index = Epoch>,
    TSu: ThresholdSupervisor<
        Index = Epoch,
        PublicKey = P,
        Share = group::Share,
        Identity = poly::Public,
    >,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
> {
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    context: E,
    automaton: A,
    relay: R,
    monitor: M,
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

    // The configured timeout for re-acking. TODO
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
    // Storage
    ////////////////////////////////////////

    // The number of heights per each journal section.
    journal_heights_per_section: u64,

    // The number of concurrent operations when replaying journals.
    journal_replay_concurrency: usize,

    // A prefix for the journal name.
    journal_name: String,

    // Compression level for the journal.
    journal_compression: Option<u8>,

    // A map of sequencer public keys to their journals.
    journal: Option<Journal<E, (), Item<D>>>,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    pending: FuturesPool<Propose<D, E>>,

    /// If the number of pending requests is than this number, we will request a new proposal from
    /// the automaton.
    ///
    /// While this doesn't supply an upper limit, it essentially gives a lower bound on the number
    /// of outstanding pending requests.
    concurrent_proposals: usize,

    /// Items that we have received from peers but are waiting for the pending response to get back.
    gated: HashMap<Index, HashMap<P, Ack<D>>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // Tracks the acknowledgements for chunks.
    // This is comprised of partial signatures or threshold signatures.
    manager: Manager<D>,

    // The current epoch.
    epoch: Epoch,

    ////////////////////////////////////////
    // Network
    ////////////////////////////////////////

    // Whether to send acks as priority messages.
    priority_acks: bool,

    // The network sender and receiver types.
    _phantom: PhantomData<(NetS, NetR)>,

    ////////////////////////////////////////
    // Metrics
    ////////////////////////////////////////

    // Metrics
    metrics: metrics::Metrics,
}

impl<
        E: Clock + Spawner + Storage + Metrics,
        P: Array,
        D: Digest,
        A: Automaton<Context = Index, Digest = D> + Clone,
        R: Relay<Digest = D>,
        Z: Reporter<Activity = Activity<D>>,
        M: Monitor<Index = Epoch>,
        TSu: ThresholdSupervisor<
            Index = Epoch,
            PublicKey = P,
            Share = group::Share,
            Identity = poly::Public,
        >,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, D, A, R, Z, M, TSu, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<P, D, A, R, Z, M, TSu>) -> Self {
        let metrics = metrics::Metrics::init(context.clone());

        Self {
            context,
            automaton: cfg.automaton,
            relay: cfg.relay,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            validators: cfg.validators,
            namespace: cfg.namespace,
            rebroadcast_timeout: cfg.rebroadcast_timeout,
            rebroadcast_deadline: None,
            epoch_bounds: cfg.epoch_bounds,
            height_bound: cfg.height_bound,
            journal_heights_per_section: cfg.journal_heights_per_section,
            journal_replay_concurrency: cfg.journal_replay_concurrency,
            journal_name: cfg.journal_name,
            journal_compression: cfg.journal_compression,
            journal: None,
            manager: Manager::<D>::new(),
            epoch: 0,
            priority_acks: cfg.priority_acks,
            _phantom: PhantomData,
            metrics,
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
    pub fn start(mut self, network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, network: (NetS, NetR)) {
        let (mut net_sender, mut net_receiver) = wrap((), network.0, network.1);
        let mut shutdown = self.context.stopped();

        // Tracks if there is an outstanding proposal request to the automaton.
        let mut pending: Option<(Index, oneshot::Receiver<D>)> = None;

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        loop {
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

                // Sign a new dot
                digest = propose => {
                    // Clear the pending proposal
                    let (index, _) = pending.take().unwrap();
                    debug!(?index, "ack");

                    // Error handling for dropped proposals
                    let Ok(digest) = digest else {
                        warn!(?index, "automaton dropped proposal");
                        continue;
                    };

                    // Ack the dot
                    if let Err(err) = self.handle_propose(index, digest, &mut net_sender).await {
                        warn!(?err, ?index, "propose failed");
                        continue;
                    }
                },

                // Handle incoming acks
                msg = net_receiver.recv() => {
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
                            warn!(?err, ?sender, "ack decode failed");
                            continue;
                        }
                    };
                    if let Err(err) = self.validate_ack(&ack, &sender) {
                        warn!(?err, ?sender, "ack validate failed");
                        continue;
                    };
                    if let Err(err) = self.handle_ack(&ack).await {
                        warn!(?err, ?sender, "ack handle failed");
                        guard.set(Status::Failure);
                        continue;
                    }
                    debug!(?sender, epoch=ack.epoch, index=ack.item.index, "ack");
                    guard.set(Status::Success);
                },
            }
        }

        // Close journal, regardless of how we exit the loop
        if let Some(journal) = self.journal.take() {
            journal.close().await.expect("unable to close journal");
        }
    }

    ////////////////////////////////////////
    // Proposal
    ////////////////////////////////////////

    /// Returns an `Index` to propose at if the engine should request a proposal from the automaton.
    ///
    /// Should only be called if the engine is not already waiting for a proposal.
    fn should_propose(&self) -> Option<Index> {
        let share = self.validators.share(self.epoch)?;

        // Return the next context unless my current tip has no threshold signature
        match self.manager.get() {
            None => Some(0),
            Some(tip) => self
                .manager
                .get_threshold(tip.item.index)
                .map(|_| tip.item.index.checked_add(1)),
        }
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    async fn handle_propose(
        &mut self,
        index: Index,
        digest: D,
        sender: &mut WrappedSender<NetS, (), Ack<D>>,
    ) -> Result<(), Error> {
        // Create ack
        let dot = Item {
            index,
            epoch: self.epoch,
            digest,
        };
        let ack = Ack::sign(
            &self.namespace,
            self.validators.share(self.epoch).unwrap(),
            dot,
        );

        // Handle ack as if it was received over the network
        self.handle_ack(&ack).await?;

        // Send ack over the network.
        sender
            .send(Recipients::All, ack, self.priority_acks)
            .await
            .map_err(|err| {
                warn!(?err, "failed to send ack");
                Error::UnableToSendMessage
            })?;

        Ok(())
    }

    /// Handles a threshold, either received from a `Node` from the network or generated locally.
    ///
    /// The threshold must already be verified.
    /// If the threshold is new, it is stored and the proof is emitted to the committer.
    /// If the threshold is already known, it is ignored.
    async fn handle_threshold(&mut self, dot: &Item<D>, threshold: group::Signature) {
        // Set the threshold signature, returning early if it already exists
        if !self.manager.add_threshold(dot.index, dot.epoch, threshold) {
            return;
        }

        // Emit the activity
        self.reporter
            .report(Activity::Lock(Lock {
                dot: dot.clone(),
                signature: threshold,
            }))
            .await;
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(&mut self, ack: &Ack<D>) -> Result<(), Error> {
        // Get the quorum
        let Some(identity) = self.validators.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        let quorum = identity.required();

        // Add the partial signature. If a new threshold is formed, handle it.
        if let Some(threshold) = self.manager.add_ack(ack, quorum) {
            debug!(
                epoch = ack.epoch,
                index = ack.item.index,
                "recovered threshold"
            );
            self.metrics.threshold.inc();
            self.handle_threshold(&ack.item, threshold).await;
        }

        Ok(())
    }

    ////////////////////////////////////////
    // Validation
    ////////////////////////////////////////

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(&self, ack: &Ack<D>, sender: &P) -> Result<(), Error> {
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
            let bound_lo = self.tip_manager.get(&ack.item.index).unwrap_or(0);
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
        let Some(identity) = self.validators.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        if !ack.verify(&self.namespace, identity) {
            return Err(Error::InvalidAckSignature);
        }

        Ok(())
    }

    ////////////////////////////////////////
    // Journal
    ////////////////////////////////////////

    /// Returns the section of the journal for the given height.
    fn get_journal_section(&self, index: u64) -> u64 {
        index / self.journal_heights_per_section
    }

    /// Ensures the journal exists and is initialized for the given sequencer.
    /// If the journal does not exist, it is created and replayed.
    /// Else, no action is taken.
    async fn journal_prepare(&mut self) {
        // Return early if the journal already exists
        if self.journal.is_some() {
            return;
        }

        // Initialize journal
        let cfg = journal::variable::Config {
            partition: format!("{}", &self.journal_name),
            compression: self.journal_compression,
            codec_config: (),
        };
        let mut journal = Journal::<_, _, Ack<D>>::init(self.context.with_label("journal"), cfg)
            .await
            .expect("unable to init journal");

        // Replay journal
        {
            debug!("journal replay begin");

            // Prepare the stream
            let stream = journal
                .replay(self.journal_replay_concurrency)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);

            // Read from the stream, which may be in arbitrary order.
            // Remember the highest node height
            let mut tip: Option<Item<D>> = None;
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

            debug!(?num_items, "journal replay end");
        }

        // Store journal
        self.journal = Some(journal);
    }

    /// Write a `Node` to the appropriate journal, which contains the tip `Chunk` for the sequencer.
    ///
    /// To prevent ever writing two conflicting `Chunk`s at the same height,
    /// the journal must already be open and replayed.
    async fn journal_append(&mut self, ack: Ack<D>) {
        let section = self.get_journal_section(ack.item.index);
        self.journal
            .expect("journal uninitialized")
            .append(section, ack)
            .await
            .expect("unable to append to journal");
    }

    /// Syncs (ensures all data is written to disk) and prunes the journal for the given sequencer and height.
    async fn journal_sync(&mut self, index: Index) {
        let mut journal = self.journal.expect("journal uninitialized");
        let section = self.get_journal_section(index);
        journal.sync(section).await.expect("unable to sync journal");
        let _ = journal.prune(section).await;
    }
}
