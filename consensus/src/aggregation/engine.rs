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
    safe_tip::SafeTip,
    types::{Ack, Activity, Epoch, Error, Index, Item, Lock},
    Config,
};
use crate::{aggregation::wire::PeerAck, Automaton, Monitor, Reporter, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{group, ops::threshold_signature_recover, poly, variant::Variant},
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
use commonware_utils::{futures::Pool as FuturesPool, Array, PrioritySet};
use futures::{
    future::{self, Either},
    StreamExt,
};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, warn};

/// An entry for an index that does not yet have a threshold signature.
///
/// For efficiency, we validate the partial signatures lazily (only in the event that we receive a
/// quorum) number of them. For this reason, the signatures stored in this structure are not
/// necessarily valid. Furthermore, the digest for which the signature is purported does not need to
/// be stored; if the digest is invalid, the signature will also be invalid. Either way, the signer
/// of an invalid message will be blocked.
enum Pending<V: Variant, D: Digest> {
    /// Not yet verified by the automaton. Unknown digest.
    Unverified(HashMap<Epoch, HashMap<u32, Ack<V, D>>>),

    /// Verified by the automaton. Now stores the digest.
    Verified(D, HashMap<Epoch, HashMap<u32, Ack<V, D>>>),
}

/// The type returned by the `pending` pool, used by the application to return which digest is
/// associated with the given index.
struct Verify<D: Digest, E: Clock> {
    /// The index in question.
    index: Index,

    /// The result of the verification.
    result: Result<D, Error>,

    /// Records the time taken to verify the digest.
    timer: histogram::Timer<E>,
}

/// Instance of the engine.
pub struct Engine<
    E: Clock + Spawner + Storage + Metrics,
    P: Array,
    V: Variant,
    D: Digest,
    A: Automaton<Context = Index, Digest = D> + Clone,
    Z: Reporter<Activity = Activity<V, D>>,
    M: Monitor<Index = Epoch>,
    TSu: ThresholdSupervisor<
        Index = Epoch,
        PublicKey = P,
        Share = group::Share,
        Identity = poly::Public<V>,
    >,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
> {
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    context: E,
    automaton: A,
    monitor: M,
    validators: TSu,
    reporter: Z,

    ////////////////////////////////////////
    // Namespace Constants
    ////////////////////////////////////////
    /// The namespace signatures.
    namespace: Vec<u8>,

    ////////////////////////////////////////
    // Pruning
    ////////////////////////////////////////
    /// A tuple representing the epochs to keep in memory.
    /// The first element is the number of old epochs to keep.
    /// The second element is the number of future epochs to accept.
    ///
    /// For example, if the current epoch is 10, and the bounds are (1, 2), then
    /// epochs 9, 10, 11, and 12 are kept (and accepted);
    /// all others are pruned or rejected.
    epoch_bounds: (u64, u64),

    /// The number of future heights to accept acks for.
    /// This is used to prevent spam of acks for arbitrary heights.
    window: u64,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    /// Pool of pending futures.
    verifies: FuturesPool<Verify<D, E>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////
    /// The current epoch.
    epoch: Epoch,

    /// The current tip.
    tip: Index,

    /// Tracks the tips of all validators.
    safe_tip: SafeTip<P>,

    /// The keys represent the set of all `Index` values for which we are attempting to form a
    /// threshold signature, but do not yet have one. Values may be [`Pending::Unverified`] or
    /// [`Pending::Verified`], depending on whether the automaton has verified the digest or not.
    pending: BTreeMap<Index, Pending<V, D>>,

    /// A map of indices with a threshold signature. Cached in memory if needed to send to other peers.
    confirmed: BTreeMap<Index, (D, V::Signature)>,

    ////////////////////////////////////////
    // Rebroadcasting
    ////////////////////////////////////////
    /// The frequency at which to rebroadcast pending indices.
    rebroadcast_timeout: Duration,

    /// A set of deadlines for rebroadcasting `Index` values that do not have a threshold signature.
    rebroadcast_deadlines: PrioritySet<Index, SystemTime>,

    ////////////////////////////////////////
    // Network
    ////////////////////////////////////////
    /// Whether to send acks as priority messages.
    priority_acks: bool,

    /// The network sender and receiver types.
    _phantom: PhantomData<(NetS, NetR)>,

    ////////////////////////////////////////
    // Metrics
    ////////////////////////////////////////
    /// Metrics
    metrics: metrics::Metrics<E>,
}

impl<
        E: Clock + Spawner + Storage + Metrics,
        P: Array,
        V: Variant,
        D: Digest,
        A: Automaton<Context = Index, Digest = D> + Clone,
        Z: Reporter<Activity = Activity<V, D>>,
        M: Monitor<Index = Epoch>,
        TSu: ThresholdSupervisor<
            Index = Epoch,
            PublicKey = P,
            Share = group::Share,
            Identity = poly::Public<V>,
        >,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, V, D, A, Z, M, TSu, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<P, V, D, A, Z, M, TSu>) -> Self {
        let metrics = metrics::Metrics::init(context.clone());

        Self {
            context,
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            validators: cfg.validators,
            namespace: cfg.namespace,
            epoch_bounds: cfg.epoch_bounds,
            window: cfg.window,
            epoch: 0,
            tip: 0,
            safe_tip: SafeTip::default(),
            verifies: FuturesPool::default(),
            pending: BTreeMap::new(),
            confirmed: BTreeMap::new(),
            rebroadcast_timeout: cfg.rebroadcast_timeout,
            rebroadcast_deadlines: PrioritySet::new(),
            priority_acks: cfg.priority_acks,
            _phantom: PhantomData,
            metrics,
        }
    }

    /// Runs the engine until the context is stopped.
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

        // Initialize the tip manager
        self.safe_tip
            .init(self.validators.participants(self.epoch).unwrap());

        loop {
            self.metrics.tip.set(self.tip as i64);

            // Propose a new digest if we are processing less than the window
            let next = self.next();
            if next < self.tip + self.window {
                self.verify(next);
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
                verify = self.verifies.next_completed() => {
                    let Verify { index, result, timer } = verify;
                    drop(timer); // Record metric. Explicitly reference timer to avoid lint warning
                    match result {
                        Err(err) => {
                            warn!(?err, ?index, "verify returned error");
                            self.metrics.verify.inc(Status::Dropped);
                        }
                        Ok(digest) => {
                            if let Err(err) = self.handle_verify(index, digest, &mut net_sender).await {
                                warn!(?err, ?index, "verify failed");
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
                    let peer_ack = match msg {
                        Ok(peer_ack) => peer_ack,
                        Err(err) => {
                            warn!(?err, ?sender, "ack decode failed");
                            continue;
                        }
                    };
                    let PeerAck { ack, tip } = peer_ack;

                    // Update the tip manager
                    if self.safe_tip.update(sender.clone(), tip).is_some() {
                        // Fast-forward our tip if needed
                        let safe_tip = self.safe_tip.get();
                        if safe_tip > self.tip {
                           self.fast_forward_tip(safe_tip);
                        }
                    }

                    // Validate that we need to process the ack
                    if let Err(err) = self.validate_ack(&ack, &sender) {
                        warn!(?err, ?sender, "ack validate failed");
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
                    if let Err(err) = self.handle_rebroadcast(index, &mut net_sender).await {
                        warn!(?err, ?index, "rebroadcast failed");
                    };
                }
            }
        }

        // TODO: Close journal
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    async fn handle_verify(
        &mut self,
        index: Index,
        digest: D,
        sender: &mut WrappedSender<NetS, PeerAck<V, D>>,
    ) -> Result<(), Error> {
        // Entry must be `Pending::Unverified`, or return early
        if !matches!(self.pending.get(&index), Some(Pending::Unverified(_))) {
            return Err(Error::AckIndex(index));
        };

        // Move the entry to `Pending::Verified`
        let Some(Pending::Unverified(epoch_map)) = self.pending.remove(&index) else {
            panic!("Pending::Unverified entry not found");
        };
        self.pending
            .insert(index, Pending::Verified(digest, HashMap::new()));

        // Handle each `ack` as if it was received over the network. This inserts the values into
        // the new map, and may form a threshold signature if enough acks are present.
        for acks in epoch_map.values() {
            for ack in acks.values() {
                let _ = self.handle_ack(ack).await; // Ignore any errors
            }
            // Return early if a threshold signature was formed
            if self.confirmed.contains_key(&index) {
                return Ok(());
            }
        }

        // Sign my own ack
        let Some(share) = self.validators.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let ack = Ack::sign(&self.namespace, self.epoch, share, Item { index, digest });

        // Set the rebroadcast deadline for this index
        self.rebroadcast_deadlines
            .put(index, self.context.current() + self.rebroadcast_timeout);

        // Handle ack as if it was received over the network
        self.handle_ack(&ack).await?;

        // Send ack over the network.
        self.broadcast(ack, sender).await
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
                // If the index is not in the pending pool, it may be in the gated pool
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
            let partials = acks // TODO: don't collect into vec
                .values()
                .map(|ack| ack.signature.clone())
                .collect::<Vec<_>>();
            let threshold = threshold_signature_recover::<V, _>(quorum, &partials)
                .expect("Failed to recover threshold signature");
            self.metrics.threshold.inc();
            self.handle_threshold(item, threshold).await;
        }

        Ok(())
    }

    /// Handles a threshold signature.
    async fn handle_threshold(&mut self, item: Item<D>, threshold: V::Signature) {
        // Check if we already have the threshold
        if self.confirmed.contains_key(&item.index) {
            return;
        }

        // Store the threshold
        self.confirmed.insert(item.index, (item.digest, threshold));

        // Increase the tip if needed
        if item.index == self.tip {
            self.fast_forward_tip(item.index);
        }

        // Notify the automaton
        self.reporter
            .report(Activity::Lock(Lock {
                item,
                signature: threshold,
            }))
            .await;
    }

    /// Handles a rebroadcast request for the given index.
    async fn handle_rebroadcast(
        &mut self,
        index: Index,
        sender: &mut WrappedSender<NetS, PeerAck<V, D>>,
    ) -> Result<(), Error> {
        // Get our signature
        let Some(share) = self.validators.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let Some(Pending::Verified(digest, acks)) = self.pending.get(&index) else {
            // The index may already be confirmed; continue silently
            return Ok(());
        };
        let ack = match acks
            .get(&self.epoch)
            .and_then(|acks| acks.get(&share.index).cloned())
        {
            Some(ack) => ack,
            None => {
                // If we don't have an ack for this epoch, create one
                let ack = Ack::sign(
                    &self.namespace,
                    self.epoch,
                    share,
                    Item {
                        index,
                        digest: *digest,
                    },
                );
                self.handle_ack(&ack).await?;
                ack
            }
        };

        // Reinsert the index with a new deadline
        self.rebroadcast_deadlines
            .put(index, self.context.current() + self.rebroadcast_timeout);

        // Broadcast the ack to all peers
        self.broadcast(ack, sender).await
    }

    ////////////////////////////////////////
    // Validation
    ////////////////////////////////////////

    /// Sets `index` as pending and sends a verify request to the automaton.
    fn verify(&mut self, index: Index) {
        assert!(self
            .pending
            .insert(index, Pending::Unverified(HashMap::new()))
            .is_none());
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.verify_duration.timer();
        self.verifies.push(async move {
            let receiver = automaton.propose(index).await;
            let result = receiver.await.map_err(Error::AppProposeCanceled);
            Verify {
                index,
                result,
                timer,
            }
        });
    }

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
        if ack.item.index <= self.tip {
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

    ////////////////////////////////////////
    // Helpers
    ////////////////////////////////////////

    /// Broadcasts an ack to all peers with the appropriate priority.
    ///
    /// Returns an error if the sender returns an error.
    async fn broadcast(
        &mut self,
        ack: Ack<V, D>,
        sender: &mut WrappedSender<NetS, PeerAck<V, D>>,
    ) -> Result<(), Error> {
        sender
            .send(
                Recipients::All,
                PeerAck { ack, tip: self.tip },
                self.priority_acks,
            )
            .await
            .map_err(|err| {
                warn!(?err, "failed to send ack");
                Error::UnableToSendMessage
            })?;
        Ok(())
    }

    /// Returns the next index that we should request the digest for. This is the minimum index for
    /// which we do not have a digest or an outstanding request to the automaton for the digest.
    fn next(&self) -> Index {
        let max_pending = self
            .pending
            .last_key_value()
            .map(|(k, _)| *k + 1)
            .unwrap_or_default();
        let max_confirmed = self
            .confirmed
            .last_key_value()
            .map(|(k, _)| *k + 1)
            .unwrap_or_default();
        max(self.tip, max(max_pending, max_confirmed))
    }

    /// Increases the tip to the given value, pruning stale entries.
    ///
    /// # Panics
    ///
    /// Panics if the given tip is less-than-or-equal-to the current tip.
    fn fast_forward_tip(&mut self, tip: Index) {
        assert!(tip > self.tip);
        self.pending.retain(|index, _| *index >= tip);
        self.confirmed.retain(|index, _| *index >= tip);
        self.tip = tip;
    }
}
