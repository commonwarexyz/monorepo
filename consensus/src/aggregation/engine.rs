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
    bls12381::primitives::{
        group,
        ops::{self, threshold_signature_recover},
        poly,
        variant::Variant,
    },
    Digest, Scheme,
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
use commonware_utils::futures::Pool as FuturesPool;
use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    pin_mut, StreamExt,
};
use std::{
    cmp::{max, min},
    collections::{BTreeMap, BTreeSet, HashMap},
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, warn};

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
    C: Scheme,
    V: Variant,
    D: Digest,
    A: Automaton<Context = Index, Digest = D> + Clone,
    R: Relay<Digest = D>,
    Z: Reporter<Activity = Activity<V, D>>,
    M: Monitor<Index = Epoch>,
    TSu: ThresholdSupervisor<
        Index = Epoch,
        PublicKey = C::PublicKey,
        Share = group::Share,
        Identity = poly::Public<V>,
    >,
    NetS: Sender<PublicKey = C::PublicKey>,
    NetR: Receiver<PublicKey = C::PublicKey>,
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
    window: u64,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    /// Pool of pending futures.
    verifies: FuturesPool<Verify<D, E>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////

    // The current epoch.
    epoch: Epoch,

    /// The keys represent the set of all outstanding requests to the automaton.
    ///
    /// The inner map may be empty. If we receive an `Ack` for an outstanding index, we store it in
    /// the inner map. This is because we are not yet sure if the digest is valid or not. This data
    /// structure essentially acts as the staging area for the `Ack` before we verify it and store
    /// it in the `acks` map.
    gated: BTreeMap<Index, HashMap<Epoch, HashMap<u32, V::Signature>>>,

    /// The keys represent the set of all verified indices with their corresponding digests.
    ///
    /// The inner map contains the `Acks` for the
    acks: BTreeMap<Index, (D, HashMap<Epoch, HashMap<u32, V::Signature>>)>,

    /// A map of indices with a threshold signature. Cached in memory if needed to send to other peers.
    confirmed: BTreeMap<Index, (D, V::Signature)>,

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
        C: Scheme,
        V: Variant,
        D: Digest,
        A: Automaton<Context = Index, Digest = D> + Clone,
        R: Relay<Digest = D>,
        Z: Reporter<Activity = Activity<V, D>>,
        M: Monitor<Index = Epoch>,
        TSu: ThresholdSupervisor<
            Index = Epoch,
            PublicKey = C::PublicKey,
            Share = group::Share,
            Identity = poly::Public<V>,
        >,
        NetS: Sender<PublicKey = C::PublicKey>,
        NetR: Receiver<PublicKey = C::PublicKey>,
    > Engine<E, C, V, D, A, R, Z, M, TSu, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<C, V, D, A, R, Z, M, TSu>) -> Self {
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
            window: cfg.window,
            epoch: 0,
            verifies: FuturesPool::default(),
            gated: BTreeMap::new(),
            acks: BTreeMap::new(),
            confirmed: BTreeMap::new(),
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

        // Tracks if there is an outstanding proposal request to the automaton.
        let mut pending: Option<(Index, oneshot::Receiver<D>)> = None;

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        loop {
            // TODO: Rebroadcasting

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

                    // TODO: update data structures by purging old epochs

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

        // TODO: Close journal
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    async fn handle_verify(
        &mut self,
        index: Index,
        digest: D,
        sender: &mut WrappedSender<NetS, Ack<V, D>>,
    ) -> Result<(), Error> {
        // Remove entry from `gated`, moving over any relevant items to `acks`
        let Some(acks) = self.gated.remove(&index) else {
            // Index is no longer relevant
            return Ok(());
        };
        assert!(self.acks.insert(index, (digest, acks)).is_none());

        // Sign my own ack
        let Some(share) = self.validators.share(self.epoch) else {
            return Err(Error::UnknownShare(self.epoch));
        };
        let ack = Ack::sign(&self.namespace, self.epoch, share, Item { index, digest });

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

    /// Handles an ack
    ///
    /// Returns an error if the ack is invalid, or can be ignored
    /// (e.g. already exists, threshold already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(&mut self, ack: &Ack<V, D>) -> Result<(), Error> {
        // Get the quorum
        let Some(identity) = self.validators.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        let quorum = identity.required();

        // Get the acks
        let acks_by_epoch = self
            .acks
            .get(&ack.item.index)
            .map(|(digest, abe)| {
                if ack.item.digest == *digest {
                    Err(Error::AckDigestMismatch(ack.item.index))
                } else {
                    Ok(abe)
                }
            })
            .ok_or_else(|| {
                self.gated
                    .get(&ack.item.index)
                    .ok_or(Error::AckIndexUnknown(ack.item.index))
            })?;

        // Add the partial signature
        let acks = acks_by_epoch.entry(ack.epoch).or_default();
        if acks.contains_key(&ack.signature.index) {
            return Ok(());
        }
        acks.insert(ack.signature.index, ack.signature.clone());

        // If a new threshold is formed, handle it
        if acks.len() >= (quorum as usize) {
            let threshold = threshold_signature_recover(quorum, acks.values())
                .expect("Failed to recover threshold signature");
            self.metrics.threshold.inc();
            self.handle_threshold(ack.item, threshold).await;
        }

        Ok(())
    }

    async fn handle_threshold(
        &mut self,
        item: Item<D>,
        threshold: V::Signature,
    ) -> Result<(), Error> {
        // Check if we already have the threshold
        if self.confirmed.contains_key(&item.index) {
            return Ok(());
        }

        // Store the threshold
        self.confirmed
            .insert(item.index, (item.digest.clone(), threshold.clone()));

        // Notify the automaton
        self.reporter
            .report(Activity::Lock(Lock {
                item,
                signature: threshold,
            }))
            .await;
        Ok(())
    }

    ////////////////////////////////////////
    // Validation
    ////////////////////////////////////////

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns the chunk, epoch, and partial signature if the ack is valid.
    /// Returns an error if the ack is invalid.
    fn validate_ack(&self, ack: &Ack<V, D>, sender: &C::PublicKey) -> Result<(), Error> {
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
        {
            let bound_lo = self.tip;
            let bound_hi = self.tip.saturating_add(self.window);
            if (bound_lo).contains(&ack.item.index) {
                return Err(Error::AckHeightOutsideBounds(
                    ack.item.index,
                    bound_lo,
                    bound_hi,
                ));
            }
        }

        // Validate that we don't already have the ack
        if self.confirmed.contains_key(&ack.item.index) {
            return Err(Error::AckAlreadyExists(ack.item.index));
        }
        if Some(existing) = self
            .gated
            .get(&ack.item.index)
            .map(|v| v.get(&ack.signature.index))
        {
            if ack.epoch <= existing.epoch {
                return Err(Error::AckAlreadyExists(ack.item.index));
            }
        }
        if Some(existing) = self
            .acks
            .get(&ack.item.index)
            .map(|v| v.get(&ack.signature.index))
        {
            if ack.epoch <= existing.epoch {
                return Err(Error::AckAlreadyExists(ack.item.index));
            }
        }

        // Validate partial signature
        let Some(identity) = self.validators.identity(ack.epoch) else {
            return Err(Error::UnknownIdentity(ack.epoch));
        };
        if !ack.verify(&self.namespace, identity) {
            return Err(Error::InvalidAckSignature);
        }

        Ok(())
    }

    ////////////////////////////////////////
    // Helpers
    ////////////////////////////////////////

    /// Returns the minimum index for which we do not have either:
    /// - The digest
    /// - An outstanding request to the automation for the digest
    fn next(&self) -> Index {
        let max_gated = self
            .gated
            .last_key_value()
            .map(|(k, _)| *k + 1)
            .unwrap_or_default();
        let max_acks = self
            .acks
            .last_key_value()
            .map(|(k, _)| *k + 1)
            .unwrap_or_default();
        let max_confirmed = self
            .confirmed
            .last_key_value()
            .map(|(k, _)| *k + 1)
            .unwrap_or_default();
        max(max(max_gated, max_acks), max_confirmed)
    }

    /// Returns the minimum index for which we do not have a threshold signature.
    fn tip(&self) -> Index {
        let min_gated = self
            .gated
            .first_key_value()
            .map(|(k, _)| *k)
            .unwrap_or_default();
        let min_acks = self
            .acks
            .first_key_value()
            .map(|(k, _)| *k)
            .unwrap_or_default();
        min(min_gated, min_acks)
    }
}
