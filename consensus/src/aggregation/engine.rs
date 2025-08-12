//! Engine for the module.

use super::{
    metrics,
    safe_tip::SafeTip,
    types::{Ack, Activity, Epoch, Error, Index, Item, TipAck},
    Config,
};
use crate::{Automaton, Monitor, Reporter, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{group, ops::threshold_signature_recover, poly, variant::Variant},
    Digest, PublicKey,
};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef,
    telemetry::metrics::{
        histogram,
        status::{CounterExt, Status},
    },
    Clock, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::variable::{Config as JConfig, Journal};
use commonware_utils::{futures::Pool as FuturesPool, PrioritySet};
use futures::{
    future::{self, Either},
    pin_mut, StreamExt,
};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, trace, warn};

/// An entry for an index that does not yet have a threshold signature.
enum Pending<V: Variant, D: Digest> {
    /// The automaton has not yet provided the digest for this index.
    /// The signatures may have arbitrary digests.
    Unverified(HashMap<Epoch, HashMap<u32, Ack<V, D>>>),

    /// Verified by the automaton. Now stores the digest.
    Verified(D, HashMap<Epoch, HashMap<u32, Ack<V, D>>>),
}

/// The type returned by the `pending` pool, used by the application to return which digest is
/// associated with the given index.
struct DigestRequest<D: Digest, E: Clock> {
    /// The index in question.
    index: Index,

    /// The result of the verification.
    result: Result<D, Error>,

    /// Records the time taken to get the digest.
    timer: histogram::Timer<E>,
}

/// Instance of the engine.
pub struct Engine<
    E: Clock + Spawner + Storage + Metrics,
    P: PublicKey,
    V: Variant,
    D: Digest,
    A: Automaton<Context = Index, Digest = D> + Clone,
    Z: Reporter<Activity = Activity<V, D>>,
    M: Monitor<Index = Epoch>,
    B: Blocker<PublicKey = P>,
    TSu: ThresholdSupervisor<
        Index = Epoch,
        PublicKey = P,
        Share = group::Share,
        Identity = poly::Public<V>,
    >,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
> {
    // ---------- Interfaces ----------
    context: E,
    automaton: A,
    monitor: M,
    validators: TSu,
    reporter: Z,
    blocker: B,

    // ---------- Namespace Constants ----------
    /// The namespace signatures.
    namespace: Vec<u8>,

    // Pruning
    /// A tuple representing the epochs to keep in memory.
    /// The first element is the number of old epochs to keep.
    /// The second element is the number of future epochs to accept.
    ///
    /// For example, if the current epoch is 10, and the bounds are (1, 2), then
    /// epochs 9, 10, 11, and 12 are kept (and accepted);
    /// all others are pruned or rejected.
    epoch_bounds: (u64, u64),

    /// The concurrent number of chunks to process.
    window: u64,

    // Messaging
    /// Pool of pending futures to request a digest from the automaton.
    digest_requests: FuturesPool<DigestRequest<D, E>>,

    // State
    /// The current epoch.
    epoch: Epoch,

    /// The current tip.
    tip: Index,

    /// Tracks the tips of all validators.
    safe_tip: SafeTip<P>,

    /// The keys represent the set of all `Index` values for which we are attempting to form a
    /// threshold signature, but do not yet have one. Values may be [Pending::Unverified] or
    /// [Pending::Verified], depending on whether the automaton has verified the digest or not.
    pending: BTreeMap<Index, Pending<V, D>>,

    /// A map of indices with a threshold signature. Cached in memory if needed to send to other peers.
    confirmed: BTreeMap<Index, (D, V::Signature)>,

    // ---------- Rebroadcasting ----------
    /// The frequency at which to rebroadcast pending indices.
    rebroadcast_timeout: Duration,

    /// A set of deadlines for rebroadcasting `Index` values that do not have a threshold signature.
    rebroadcast_deadlines: PrioritySet<Index, SystemTime>,

    // ---------- Journal ----------
    /// Journal for storing acks signed by this node.
    journal: Option<Journal<E, Activity<V, D>>>,
    journal_partition: String,
    journal_write_buffer: NonZeroUsize,
    journal_replay_buffer: NonZeroUsize,
    journal_heights_per_section: u64,
    journal_compression: Option<u8>,
    journal_buffer_pool: PoolRef,

    // ---------- Network ----------
    /// Whether to send acks as priority messages.
    priority_acks: bool,

    /// The network sender and receiver types.
    _phantom: PhantomData<(NetS, NetR)>,

    // ---------- Metrics ----------
    /// Metrics
    metrics: metrics::Metrics<E>,
}

impl<
        E: Clock + Spawner + Storage + Metrics,
        P: PublicKey,
        V: Variant,
        D: Digest,
        A: Automaton<Context = Index, Digest = D> + Clone,
        Z: Reporter<Activity = Activity<V, D>>,
        M: Monitor<Index = Epoch>,
        B: Blocker<PublicKey = P>,
        TSu: ThresholdSupervisor<
            Index = Epoch,
            PublicKey = P,
            Share = group::Share,
            Identity = poly::Public<V>,
        >,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, V, D, A, Z, M, B, TSu, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<P, V, D, A, Z, M, B, TSu>) -> Self {
        let metrics = metrics::Metrics::init(context.clone());

        Self {
            context,
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            validators: cfg.validators,
            blocker: cfg.blocker,
            namespace: cfg.namespace,
            epoch_bounds: cfg.epoch_bounds,
            window: cfg.window.into(),
            epoch: 0,
            tip: 0,
            safe_tip: SafeTip::default(),
            digest_requests: FuturesPool::default(),
            pending: BTreeMap::new(),
            confirmed: BTreeMap::new(),
            rebroadcast_timeout: cfg.rebroadcast_timeout.into(),
            rebroadcast_deadlines: PrioritySet::new(),
            journal: None,
            journal_partition: cfg.journal_partition,
            journal_write_buffer: cfg.journal_write_buffer,
            journal_replay_buffer: cfg.journal_replay_buffer,
            journal_heights_per_section: cfg.journal_heights_per_section.into(),
            journal_compression: cfg.journal_compression,
            journal_buffer_pool: cfg.journal_buffer_pool,
            priority_acks: cfg.priority_acks,
            _phantom: PhantomData,
            metrics,
        }
    }

    /// Runs the engine until the context is stopped.
    ///
    /// The engine will handle:
    /// - Requesting and processing digests from the automaton
    /// - Timeouts
    ///   - Refreshing the Epoch
    ///   - Rebroadcasting Acks
    /// - Messages from the network:
    ///   - Acks from other validators
    pub fn start(mut self, network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, (net_sender, net_receiver): (NetS, NetR)) {
        let (mut net_sender, mut net_receiver) = wrap((), net_sender, net_receiver);
        let mut shutdown = self.context.stopped();

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        // Initialize Journal
        let journal_cfg = JConfig {
            partition: self.journal_partition.clone(),
            compression: self.journal_compression,
            codec_config: (),
            buffer_pool: self.journal_buffer_pool.clone(),
            write_buffer: self.journal_write_buffer,
        };
        let journal = Journal::init(self.context.with_label("journal"), journal_cfg)
            .await
            .expect("init failed");
        self.replay(&journal).await;
        self.journal = Some(journal);

        // Initialize the tip manager
        self.safe_tip.init(
            self.validators
                .participants(self.epoch)
                .expect("unknown participants"),
        );

        loop {
            self.metrics.tip.set(self.tip as i64);

            // Propose a new digest if we are processing less than the window
            let next = self.next();
            if next < self.tip + self.window {
                trace!("requesting new digest: index {}", next);
                self.get_digest(next);
                continue;
            }

            // Get the rebroadcast deadline for the next index
            let rebroadcast = match self.rebroadcast_deadlines.peek() {
                Some((_, &deadline)) => Either::Left(self.context.sleep_until(deadline)),
                None => Either::Right(future::pending()),
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

                    // Update the tip manager
                    self.safe_tip.reconcile(self.validators.participants(epoch).unwrap());

                    // Update data structures by purging old epochs
                    let min_epoch = self.epoch.saturating_sub(self.epoch_bounds.0);
                    self.pending.iter_mut().for_each(|(_, pending)| {
                        match pending {
                            Pending::Unverified(acks) => {
                                acks.retain(|epoch, _| *epoch >= min_epoch);
                            }
                            Pending::Verified(_, acks) => {
                                acks.retain(|epoch, _| *epoch >= min_epoch);
                            }
                        }
                    });

                    continue;
                },

                // Sign a new ack
                request = self.digest_requests.next_completed() => {
                    let DigestRequest { index, result, timer } = request;
                    drop(timer); // Record metric. Explicitly reference timer to avoid lint warning.
                    match result {
                        Err(err) => {
                            warn!(?err, ?index, "automaton returned error");
                            self.metrics.digest.inc(Status::Dropped);
                        }
                        Ok(digest) => {
                            if let Err(err) = self.handle_digest(index, digest, &mut net_sender).await {
                                warn!(?err, ?index, "handle_digest failed");
                                continue;
                            }
                        }
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
                    let TipAck { ack, tip } = match msg {
                        Ok(peer_ack) => peer_ack,
                        Err(err) => {
                            warn!(?err, ?sender, "ack decode failed, blocking peer");
                            self.blocker.block(sender).await;
                            continue;
                        }
                    };

                    // Update the tip manager
                    if self.safe_tip.update(sender.clone(), tip).is_some() {
                        // Fast-forward our tip if needed
                        let safe_tip = self.safe_tip.get();
                        if safe_tip > self.tip {
                           self.fast_forward_tip(safe_tip).await;
                        }
                    }

                    // Validate that we need to process the ack
                    if let Err(err) = self.validate_ack(&ack, &sender) {
                        if err.blockable() {
                            warn!(?sender, ?err, "blocking peer for validation failure");
                            self.blocker.block(sender).await;
                        } else {
                            debug!(?sender, ?err, "ack validate failed");
                        }
                        continue;
                    };

                    // Handle the ack
                    if let Err(err) = self.handle_ack(&ack).await {
                        warn!(?err, ?sender, "ack handle failed");
                        guard.set(Status::Failure);
                        continue;
                    }

                    // Update the metrics
                    debug!(?sender, epoch=ack.epoch, index=ack.item.index, "ack");
                    guard.set(Status::Success);
                },

                // Rebroadcast
                _ = rebroadcast => {
                    // Get the next index to rebroadcast
                    let (index, _) = self.rebroadcast_deadlines.pop().expect("no rebroadcast deadline");
                    trace!("rebroadcasting: index {}", index);
                    if let Err(err) = self.handle_rebroadcast(index, &mut net_sender).await {
                        warn!(?err, ?index, "rebroadcast failed");
                    };
                }
            }
        }

        // Close journal on shutdown
        if let Some(journal) = self.journal.take() {
            journal
                .close()
                .await
                .expect("unable to close aggregation journal");
        }
    }

    // ---------- Handling ----------

    /// Handles a digest returned by the automaton.
    async fn handle_digest(
        &mut self,
        index: Index,
        digest: D,
        sender: &mut WrappedSender<NetS, TipAck<V, D>>,
    ) -> Result<(), Error> {
        // Entry must be `Pending::Unverified`, or return early
        if !matches!(self.pending.get(&index), Some(Pending::Unverified(_))) {
            return Err(Error::AckIndex(index));
        };

        // Move the entry to `Pending::Verified`
        let Some(Pending::Unverified(acks)) = self.pending.remove(&index) else {
            panic!("Pending::Unverified entry not found");
        };
        self.pending
            .insert(index, Pending::Verified(digest, HashMap::new()));

        // Handle each `ack` as if it was received over the network. This inserts the values into
        // the new map, and may form a threshold signature if enough acks are present.
        for epoch_acks in acks.values() {
            for epoch_ack in epoch_acks.values() {
                let _ = self.handle_ack(epoch_ack).await; // Ignore any errors (e.g. invalid signature)
            }
            // Break early if a threshold signature was formed
            if self.confirmed.contains_key(&index) {
                break;
            }
        }

        // Sign my own ack
        let ack = self.sign_ack(index, digest).await?;

        // Set the rebroadcast deadline for this index
        self.set_rebroadcast_deadline(index);

        // Handle ack as if it was received over the network
        let _ = self.handle_ack(&ack).await; // Ignore any errors (e.g. threshold already exists)

        // Send ack over the network.
        self.broadcast(ack, sender).await?;

        Ok(())
    }

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(&mut self, ack: &Ack<V, D>) -> Result<(), Error> {
        // Get the quorum
        let quorum = self.validators.identity().required();

        // Get the acks
        let acks_by_epoch = match self.pending.get_mut(&ack.item.index) {
            None => {
                // If the index is not in the pending pool, it may be confirmed
                // (i.e. we have a threshold signature for it).
                return Err(Error::AckIndex(ack.item.index));
            }
            Some(Pending::Unverified(acks)) => acks,
            Some(Pending::Verified(_, acks)) => acks,
        };

        // We already checked that we don't have the ack

        // Add the partial signature
        let acks = acks_by_epoch.entry(ack.epoch).or_default();
        if acks.contains_key(&ack.signature.index) {
            return Ok(());
        }
        acks.insert(ack.signature.index, ack.clone());

        // If a new threshold is formed, handle it
        if acks.len() >= (quorum as usize) {
            let item = ack.item.clone();
            let partials = acks.values().map(|ack| &ack.signature);
            let threshold = threshold_signature_recover::<V, _>(quorum, partials)
                .expect("Failed to recover threshold signature");
            self.metrics.threshold.inc();
            self.handle_threshold(item, threshold).await;
        }

        Ok(())
    }

    /// Handles a threshold signature.
    async fn handle_threshold(&mut self, item: Item<D>, threshold: V::Signature) {
        // Check if we already have the threshold
        let index = item.index;
        if self.confirmed.contains_key(&index) {
            return;
        }

        // Store the threshold
        self.confirmed.insert(index, (item.digest, threshold));

        // Journal and notify the automaton
        let recovered = Activity::Recovered(item, threshold);
        self.record(recovered.clone()).await;
        self.sync(index).await;
        self.reporter.report(recovered).await;

        // Increase the tip if needed
        if index == self.tip {
            // Compute the next tip
            let mut new_tip = index.saturating_add(1);
            while self.confirmed.contains_key(&new_tip) && new_tip < Index::MAX {
                new_tip = new_tip.saturating_add(1);
            }

            // If the next tip is larger, try to fast-forward the tip (may not be possible)
            if new_tip > self.tip {
                self.fast_forward_tip(new_tip).await;
            }
        }
    }

    /// Handles a rebroadcast request for the given index.
    async fn handle_rebroadcast(
        &mut self,
        index: Index,
        sender: &mut WrappedSender<NetS, TipAck<V, D>>,
    ) -> Result<(), Error> {
        let Some(Pending::Verified(digest, acks)) = self.pending.get(&index) else {
            // The index may already be confirmed; continue silently if so
            return Ok(());
        };

        // Get our signature
        let Some(share) = self.validators.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let ack = acks
            .get(&self.epoch)
            .and_then(|acks| acks.get(&share.index).cloned());
        let ack = match ack {
            Some(ack) => ack,
            None => self.sign_ack(index, *digest).await?,
        };

        // Reinsert the index with a new deadline
        self.set_rebroadcast_deadline(index);

        // Broadcast the ack to all peers
        self.broadcast(ack, sender).await
    }

    // ---------- Validation ----------

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(&self, ack: &Ack<V, D>, sender: &P) -> Result<(), Error> {
        // Validate epoch
        {
            let (eb_lo, eb_hi) = self.epoch_bounds;
            let bound_lo = self.epoch.saturating_sub(eb_lo);
            let bound_hi = self.epoch.saturating_add(eb_hi);
            if ack.epoch < bound_lo || ack.epoch > bound_hi {
                return Err(Error::AckEpochOutsideBounds(ack.epoch, bound_lo, bound_hi));
            }
        }

        // Validate sender
        let Some(sig_index) = self.validators.is_participant(ack.epoch, sender) else {
            return Err(Error::UnknownValidator(ack.epoch, sender.to_string()));
        };
        if sig_index != ack.signature.index {
            return Err(Error::PeerMismatch);
        }

        // Validate height
        if ack.item.index < self.tip {
            return Err(Error::AckThresholded(ack.item.index));
        }
        if ack.item.index >= self.tip + self.window {
            return Err(Error::AckIndex(ack.item.index));
        }

        // Validate that we don't already have the ack
        if self.confirmed.contains_key(&ack.item.index) {
            return Err(Error::AckThresholded(ack.item.index));
        }
        let have_ack = match self.pending.get(&ack.item.index) {
            None => false,
            Some(Pending::Unverified(epoch_map)) => epoch_map
                .get(&ack.epoch)
                .is_some_and(|acks| acks.contains_key(&ack.signature.index)),
            Some(Pending::Verified(_, epoch_map)) => epoch_map
                .get(&ack.epoch)
                .is_some_and(|acks| acks.contains_key(&ack.signature.index)),
        };
        if have_ack {
            return Err(Error::AckDuplicate(sender.to_string(), ack.item.index));
        }

        // Validate partial signature
        if !ack.verify(&self.namespace, self.validators.identity()) {
            return Err(Error::InvalidAckSignature);
        }

        Ok(())
    }

    // ---------- Helpers ----------

    /// Sets `index` as pending and requests the digest from the automaton.
    fn get_digest(&mut self, index: Index) {
        assert!(self
            .pending
            .insert(index, Pending::Unverified(HashMap::new()))
            .is_none());

        let mut automaton = self.automaton.clone();
        let timer = self.metrics.digest_duration.timer();
        self.digest_requests.push(async move {
            let receiver = automaton.propose(index).await;
            let result = receiver.await.map_err(Error::AppProposeCanceled);
            DigestRequest {
                index,
                result,
                timer,
            }
        });
    }

    // Sets the rebroadcast deadline for the given `index`.
    fn set_rebroadcast_deadline(&mut self, index: Index) {
        self.rebroadcast_deadlines
            .put(index, self.context.current() + self.rebroadcast_timeout);
    }

    /// Signs an ack for the given index, and digest. Stores the ack in the journal and returns it.
    /// Returns an error if the share is unknown at the current epoch.
    async fn sign_ack(&mut self, index: Index, digest: D) -> Result<Ack<V, D>, Error> {
        let Some(share) = self.validators.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };

        // Sign the item
        let item = Item { index, digest };
        let ack = Ack::sign(&self.namespace, self.epoch, share, item);

        // Journal the ack
        self.record(Activity::Ack(ack.clone())).await;
        self.sync(index).await;

        Ok(ack)
    }

    /// Broadcasts an ack to all peers with the appropriate priority.
    ///
    /// Returns an error if the sender returns an error.
    async fn broadcast(
        &mut self,
        ack: Ack<V, D>,
        sender: &mut WrappedSender<NetS, TipAck<V, D>>,
    ) -> Result<(), Error> {
        sender
            .send(
                Recipients::All,
                TipAck { ack, tip: self.tip },
                self.priority_acks,
            )
            .await
            .map_err(|err| {
                warn!(?err, "failed to send ack");
                Error::UnableToSendMessage
            })?;
        Ok(())
    }

    /// Returns the next index that we should process. This is the minimum index for
    /// which we do not have a digest or an outstanding request to the automaton for the digest.
    fn next(&self) -> Index {
        let max_pending = self
            .pending
            .last_key_value()
            .map(|(k, _)| k.saturating_add(1))
            .unwrap_or_default();
        let max_confirmed = self
            .confirmed
            .last_key_value()
            .map(|(k, _)| k.saturating_add(1))
            .unwrap_or_default();
        max(self.tip, max(max_pending, max_confirmed))
    }

    /// Increases the tip to the given value, pruning stale entries.
    ///
    /// # Panics
    ///
    /// Panics if the given tip is less-than-or-equal-to the current tip.
    async fn fast_forward_tip(&mut self, tip: Index) {
        assert!(tip > self.tip);

        // Prune data structures
        self.pending.retain(|index, _| *index >= tip);
        self.confirmed.retain(|index, _| *index >= tip);

        // Add tip to journal
        self.record(Activity::Tip(tip)).await;
        self.sync(tip).await;
        self.reporter.report(Activity::Tip(tip)).await;

        // Prune journal, ignoring errors
        let section = self.get_journal_section(tip);
        let journal = self.journal.as_mut().expect("journal must be initialized");
        let _ = journal.prune(section).await;

        // Update the tip
        self.tip = tip;
    }

    // ---------- Journal ----------

    /// Returns the section of the journal for the given `index`.
    fn get_journal_section(&self, index: Index) -> u64 {
        index / self.journal_heights_per_section
    }

    /// Replays the journal, updating the state of the engine.
    async fn replay(&mut self, journal: &Journal<E, Activity<V, D>>) {
        let mut tip = Index::default();
        let mut recovered = Vec::new();
        let mut acks = Vec::new();
        let stream = journal
            .replay(self.journal_replay_buffer)
            .await
            .expect("replay failed");
        pin_mut!(stream);
        while let Some(msg) = stream.next().await {
            let (_, _, _, activity) = msg.expect("replay failed");
            match activity {
                Activity::Tip(index) => {
                    tip = max(tip, index);
                }
                Activity::Recovered(item, signature) => {
                    recovered.push((item, signature));
                }
                Activity::Ack(ack) => {
                    acks.push(ack);
                }
            }
        }
        // Update the tip to the highest index in the journal
        self.tip = tip;
        // Add recovered signatures
        recovered
            .iter()
            .filter(|(item, _)| item.index >= tip)
            .for_each(|(item, signature)| {
                self.confirmed.insert(item.index, (item.digest, *signature));
            });
        // Add any acks that haven't resulted in a threshold signature
        acks = acks
            .into_iter()
            .filter(|ack| ack.item.index >= tip && !self.confirmed.contains_key(&ack.item.index))
            .collect::<Vec<_>>();
        acks.iter().for_each(|ack| {
            assert!(self
                .pending
                .insert(
                    ack.item.index,
                    Pending::Verified(
                        ack.item.digest,
                        HashMap::from([(
                            ack.epoch,
                            HashMap::from([(ack.signature.index, ack.clone())]),
                        )]),
                    ),
                )
                .is_none());
            self.set_rebroadcast_deadline(ack.item.index);
        });
    }

    /// Appends an activity to the journal.
    async fn record(&mut self, activity: Activity<V, D>) {
        let index = match activity {
            Activity::Ack(ref ack) => ack.item.index,
            Activity::Recovered(ref item, _) => item.index,
            Activity::Tip(index) => index,
        };
        let section = self.get_journal_section(index);
        self.journal
            .as_mut()
            .expect("journal must be initialized")
            .append(section, activity)
            .await
            .expect("unable to append to journal");
    }

    /// Syncs (ensures all data is written to disk).
    async fn sync(&mut self, index: Index) {
        let section = self.get_journal_section(index);
        let journal = self.journal.as_mut().expect("journal must be initialized");
        journal.sync(section).await.expect("unable to sync journal");
    }
}
