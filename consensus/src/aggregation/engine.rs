//! Engine for the module.

use super::{
    metrics,
    safe_tip::SafeTip,
    types::{Ack, Activity, Error, Index, Item, TipAck},
    Config,
};
use crate::{
    aggregation::{scheme, types::Certificate},
    types::{Epoch, EpochDelta},
    Automaton, Monitor, Reporter,
};
use commonware_cryptography::{
    certificate::{Provider, Scheme},
    Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    buffer::PoolRef,
    spawn_cell,
    telemetry::metrics::{
        histogram,
        status::{CounterExt, GaugeExt, Status},
    },
    Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::{futures::Pool as FuturesPool, ordered::Quorum, PrioritySet};
use futures::{
    future::{self, Either},
    pin_mut, StreamExt,
};
use std::{
    cmp::max,
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, trace, warn};

/// An entry for an index that does not yet have a certificate.
enum Pending<S: Scheme, D: Digest> {
    /// The automaton has not yet provided the digest for this index.
    /// The signatures may have arbitrary digests.
    Unverified(BTreeMap<Epoch, BTreeMap<u32, Ack<S, D>>>),

    /// Verified by the automaton. Now stores the digest.
    Verified(D, BTreeMap<Epoch, BTreeMap<u32, Ack<S, D>>>),
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
    P: Provider<Scope = Epoch>,
    D: Digest,
    A: Automaton<Context = Index, Digest = D> + Clone,
    Z: Reporter<Activity = Activity<P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
    B: Blocker<PublicKey = <P::Scheme as Scheme>::PublicKey>,
> {
    // ---------- Interfaces ----------
    context: ContextCell<E>,
    automaton: A,
    monitor: M,
    provider: P,
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
    epoch_bounds: (EpochDelta, EpochDelta),

    /// The concurrent number of chunks to process.
    window: u64,

    /// Number of indices to track below the tip when collecting acks and/or pruning.
    activity_timeout: u64,

    // Messaging
    /// Pool of pending futures to request a digest from the automaton.
    digest_requests: FuturesPool<DigestRequest<D, E>>,

    // State
    /// The current epoch.
    epoch: Epoch,

    /// The current tip.
    tip: Index,

    /// Tracks the tips of all validators.
    safe_tip: SafeTip<<P::Scheme as Scheme>::PublicKey>,

    /// The keys represent the set of all `Index` values for which we are attempting to form a
    /// certificate, but do not yet have one. Values may be [Pending::Unverified] or [Pending::Verified],
    /// depending on whether the automaton has verified the digest or not.
    pending: BTreeMap<Index, Pending<P::Scheme, D>>,

    /// A map of indices with a certificate. Cached in memory if needed to send to other peers.
    confirmed: BTreeMap<Index, Certificate<P::Scheme, D>>,

    // ---------- Rebroadcasting ----------
    /// The frequency at which to rebroadcast pending indices.
    rebroadcast_timeout: Duration,

    /// A set of deadlines for rebroadcasting `Index` values that do not have a certificate.
    rebroadcast_deadlines: PrioritySet<Index, SystemTime>,

    // ---------- Journal ----------
    /// Journal for storing acks signed by this node.
    journal: Option<Journal<E, Activity<P::Scheme, D>>>,
    journal_partition: String,
    journal_write_buffer: NonZeroUsize,
    journal_replay_buffer: NonZeroUsize,
    journal_heights_per_section: u64,
    journal_compression: Option<u8>,
    journal_buffer_pool: PoolRef,

    // ---------- Network ----------
    /// Whether to send acks as priority messages.
    priority_acks: bool,

    // ---------- Metrics ----------
    /// Metrics
    metrics: metrics::Metrics<E>,
}

impl<
        E: Clock + Spawner + Storage + Metrics,
        P: Provider<Scope = Epoch, Scheme: scheme::Scheme<D>>,
        D: Digest,
        A: Automaton<Context = Index, Digest = D> + Clone,
        Z: Reporter<Activity = Activity<P::Scheme, D>>,
        M: Monitor<Index = Epoch>,
        B: Blocker<PublicKey = <P::Scheme as Scheme>::PublicKey>,
    > Engine<E, P, D, A, Z, M, B>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<P, D, A, Z, M, B>) -> Self {
        // TODO(#1833): Metrics should use the post-start context
        let metrics = metrics::Metrics::init(context.clone());

        Self {
            context: ContextCell::new(context),
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            provider: cfg.provider,
            blocker: cfg.blocker,
            namespace: cfg.namespace,
            epoch_bounds: cfg.epoch_bounds,
            window: cfg.window.into(),
            activity_timeout: cfg.activity_timeout,
            epoch: Epoch::zero(),
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
            metrics,
        }
    }

    /// Gets the scheme for a given epoch, returning an error if unavailable.
    fn scheme(&self, epoch: Epoch) -> Result<Arc<P::Scheme>, Error> {
        self.provider
            .scoped(epoch)
            .ok_or(Error::UnknownEpoch(epoch))
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
    pub fn start(
        mut self,
        network: (
            impl Sender<PublicKey = <P::Scheme as Scheme>::PublicKey>,
            impl Receiver<PublicKey = <P::Scheme as Scheme>::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(network).await)
    }

    /// Inner run loop called by `start`.
    async fn run(
        mut self,
        network: (
            impl Sender<PublicKey = <P::Scheme as Scheme>::PublicKey>,
            impl Receiver<PublicKey = <P::Scheme as Scheme>::PublicKey>,
        ),
    ) {
        let (mut sender, mut receiver) = wrap((), network.0, network.1);
        let mut shutdown = self.context.stopped();

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        // Initialize Journal
        let journal_cfg = JConfig {
            partition: self.journal_partition.clone(),
            compression: self.journal_compression,
            codec_config: P::Scheme::certificate_codec_config_unbounded(),
            buffer_pool: self.journal_buffer_pool.clone(),
            write_buffer: self.journal_write_buffer,
        };
        let journal = Journal::init(
            self.context.with_label("journal").into_present(),
            journal_cfg,
        )
        .await
        .expect("init failed");
        let unverified_indices = self.replay(&journal).await;
        self.journal = Some(journal);

        // Request digests for unverified indices
        for index in unverified_indices {
            trace!(index, "requesting digest for unverified index from replay");
            self.get_digest(index);
        }

        // Initialize the tip manager
        let scheme = self
            .scheme(self.epoch)
            .expect("current epoch scheme must exist");
        self.safe_tip.init(scheme.participants());

        loop {
            let _ = self.metrics.tip.try_set(self.tip);

            // Propose a new digest if we are processing less than the window
            let next = self.next();

            // Underflow safe: next >= self.tip is guaranteed by next()
            if next - self.tip < self.window {
                trace!(next, "requesting new digest");
                assert!(self
                    .pending
                    .insert(next, Pending::Unverified(BTreeMap::new()))
                    .is_none());
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
                    debug!(current = %self.epoch, new = %epoch, "refresh epoch");
                    assert!(epoch >= self.epoch);
                    self.epoch = epoch;

                    // Update the tip manager
                    let scheme = self.scheme(self.epoch)
                        .expect("current epoch scheme must exist");
                    self.safe_tip.reconcile(scheme.participants());

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
                            if let Err(err) = self.handle_digest(index, digest, &mut sender).await {
                                debug!(?err, ?index, "handle_digest failed");
                                continue;
                            }
                        }
                    }
                },

                // Handle incoming acks
                msg = receiver.recv() => {
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
                        debug!(?err, ?sender, "ack handle failed");
                        guard.set(Status::Failure);
                        continue;
                    }

                    // Update the metrics
                    debug!(?sender, epoch = %ack.epoch, index = ack.item.index, "ack");
                    guard.set(Status::Success);
                },

                // Rebroadcast
                _ = rebroadcast => {
                    // Get the next index to rebroadcast
                    let (index, _) = self.rebroadcast_deadlines.pop().expect("no rebroadcast deadline");
                    trace!("rebroadcasting: index {}", index);
                    if let Err(err) = self.handle_rebroadcast(index, &mut sender).await {
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
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Scheme>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
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
            .insert(index, Pending::Verified(digest, BTreeMap::new()));

        // Handle each `ack` as if it was received over the network. This inserts the values into
        // the new map, and may form a certificate if enough acks are present. Only process acks
        // that match the verified digest.
        for epoch_acks in acks.values() {
            for epoch_ack in epoch_acks.values() {
                // Drop acks that don't match the verified digest
                if epoch_ack.item.digest != digest {
                    continue;
                }

                // Handle the ack
                let _ = self.handle_ack(epoch_ack).await;
            }
            // Break early if a certificate was formed
            if self.confirmed.contains_key(&index) {
                break;
            }
        }

        // Sign my own ack
        let ack = self.sign_ack(index, digest).await?;

        // Set the rebroadcast deadline for this index
        self.rebroadcast_deadlines
            .put(index, self.context.current() + self.rebroadcast_timeout);

        // Handle ack as if it was received over the network
        let _ = self.handle_ack(&ack).await;

        // Send ack over the network.
        self.broadcast(ack, sender).await?;

        Ok(())
    }

    /// Handles an ack.
    ///
    /// Returns an error if the ack is invalid, or can be ignored (e.g. already exists, certificate
    /// already exists, is outside the epoch bounds, etc.).
    async fn handle_ack(&mut self, ack: &Ack<P::Scheme, D>) -> Result<(), Error> {
        // Get the quorum (from scheme participants for the ack's epoch)
        let scheme = self.scheme(ack.epoch)?;
        let quorum = scheme.participants().quorum();

        // Get the acks and check digest consistency
        let acks_by_epoch = match self.pending.get_mut(&ack.item.index) {
            None => {
                // If the index is not in the pending pool, it may be confirmed
                // (i.e. we have a certificate for it).
                return Err(Error::AckIndex(ack.item.index));
            }
            Some(Pending::Unverified(acks)) => acks,
            Some(Pending::Verified(digest, acks)) => {
                // If we have a verified digest, ensure the ack matches it
                if ack.item.digest != *digest {
                    return Err(Error::AckDigest(ack.item.index));
                }
                acks
            }
        };

        // Add the attestation (if not already present)
        let acks = acks_by_epoch.entry(ack.epoch).or_default();
        if acks.contains_key(&ack.attestation.signer) {
            return Ok(());
        }
        acks.insert(ack.attestation.signer, ack.clone());

        // If there exists a quorum of acks with the same digest (or for the verified digest if it exists), form a certificate
        let filtered = acks
            .values()
            .filter(|a| a.item.digest == ack.item.digest)
            .collect::<Vec<_>>();
        if filtered.len() >= quorum as usize {
            if let Some(certificate) = Certificate::from_acks(&*scheme, filtered) {
                self.metrics.certificates.inc();
                self.handle_certificate(certificate).await;
            }
        }

        Ok(())
    }

    /// Handles a certificate.
    async fn handle_certificate(&mut self, certificate: Certificate<P::Scheme, D>) {
        // Check if we already have the certificate
        let index = certificate.item.index;
        if self.confirmed.contains_key(&index) {
            return;
        }

        // Store the certificate
        self.confirmed.insert(index, certificate.clone());

        // Journal and notify the automaton
        let certified = Activity::Certified(certificate);
        self.record(certified.clone()).await;
        self.sync(index).await;
        self.reporter.report(certified).await;

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
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Scheme>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
    ) -> Result<(), Error> {
        let Some(Pending::Verified(digest, acks)) = self.pending.get(&index) else {
            // The index may already be confirmed; continue silently if so
            return Ok(());
        };

        // Get our signature
        let scheme = self.scheme(self.epoch)?;
        let Some(signer) = scheme.me() else {
            return Err(Error::NotSigner(self.epoch));
        };
        let ack = acks
            .get(&self.epoch)
            .and_then(|acks| acks.get(&signer).cloned());
        let ack = match ack {
            Some(ack) => ack,
            None => self.sign_ack(index, *digest).await?,
        };

        // Reinsert the index with a new deadline
        self.rebroadcast_deadlines
            .put(index, self.context.current() + self.rebroadcast_timeout);

        // Broadcast the ack to all peers
        self.broadcast(ack, sender).await
    }

    // ---------- Validation ----------

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &self,
        ack: &Ack<P::Scheme, D>,
        sender: &<P::Scheme as Scheme>::PublicKey,
    ) -> Result<(), Error> {
        // Validate epoch
        {
            let (eb_lo, eb_hi) = self.epoch_bounds;
            let bound_lo = self.epoch.saturating_sub(eb_lo);
            let bound_hi = self.epoch.saturating_add(eb_hi);
            if ack.epoch < bound_lo || ack.epoch > bound_hi {
                return Err(Error::AckEpochOutsideBounds(ack.epoch, bound_lo, bound_hi));
            }
        }

        // Validate sender matches the signer
        let scheme = self.scheme(ack.epoch)?;
        let participants = scheme.participants();
        let Some(signer) = participants.index(sender) else {
            return Err(Error::UnknownValidator(ack.epoch, sender.to_string()));
        };
        if signer != ack.attestation.signer {
            return Err(Error::PeerMismatch);
        }

        // Collect acks below the tip (if we don't yet have a certificate)
        let activity_threshold = self.tip.saturating_sub(self.activity_timeout);
        if ack.item.index < activity_threshold {
            return Err(Error::AckCertified(ack.item.index));
        }

        // If the index is above the tip (and the window), ignore for now
        if ack.item.index.saturating_sub(self.tip) >= self.window {
            return Err(Error::AckIndex(ack.item.index));
        }

        // Validate that we don't already have the ack
        if self.confirmed.contains_key(&ack.item.index) {
            return Err(Error::AckCertified(ack.item.index));
        }
        let have_ack = match self.pending.get(&ack.item.index) {
            None => false,
            Some(Pending::Unverified(epoch_map)) => epoch_map
                .get(&ack.epoch)
                .is_some_and(|acks| acks.contains_key(&ack.attestation.signer)),
            Some(Pending::Verified(digest, epoch_map)) => {
                // While we check this in the `handle_ack` function, checking early here avoids an
                // unnecessary signature check.
                if ack.item.digest != *digest {
                    return Err(Error::AckDigest(ack.item.index));
                }
                epoch_map
                    .get(&ack.epoch)
                    .is_some_and(|acks| acks.contains_key(&ack.attestation.signer))
            }
        };
        if have_ack {
            return Err(Error::AckDuplicate(sender.to_string(), ack.item.index));
        }

        // Validate signature
        if !ack.verify(&*scheme, &self.namespace) {
            return Err(Error::InvalidAckSignature);
        }

        Ok(())
    }

    // ---------- Helpers ----------

    /// Requests the digest from the automaton.
    ///
    /// Pending must contain the index.
    fn get_digest(&mut self, index: Index) {
        assert!(self.pending.contains_key(&index));
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

    /// Signs an ack for the given index, and digest. Stores the ack in the journal and returns it.
    /// Returns an error if the share is unknown at the current epoch.
    async fn sign_ack(&mut self, index: Index, digest: D) -> Result<Ack<P::Scheme, D>, Error> {
        let scheme = self.scheme(self.epoch)?;
        if scheme.me().is_none() {
            return Err(Error::NotSigner(self.epoch));
        }

        // Sign the item
        let item = Item { index, digest };
        let ack = Ack::sign(&*scheme, &self.namespace, self.epoch, item)
            .ok_or(Error::NotSigner(self.epoch))?;

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
        ack: Ack<P::Scheme, D>,
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Scheme>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
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

        // Prune data structures with buffer to prevent losing certificates
        let activity_threshold = tip.saturating_sub(self.activity_timeout);
        self.pending.retain(|index, _| *index >= activity_threshold);
        self.confirmed
            .retain(|index, _| *index >= activity_threshold);

        // Add tip to journal
        self.record(Activity::Tip(tip)).await;
        self.sync(tip).await;
        self.reporter.report(Activity::Tip(tip)).await;

        // Prune journal with buffer, ignoring errors
        let section = self.get_journal_section(activity_threshold);
        let journal = self.journal.as_mut().expect("journal must be initialized");
        let _ = journal.prune(section).await;

        // Update the tip
        self.tip = tip;
    }

    // ---------- Journal ----------

    /// Returns the section of the journal for the given `index`.
    const fn get_journal_section(&self, index: Index) -> u64 {
        index / self.journal_heights_per_section
    }

    /// Replays the journal, updating the state of the engine.
    /// Returns a list of unverified pending indices that need digest requests.
    async fn replay(&mut self, journal: &Journal<E, Activity<P::Scheme, D>>) -> Vec<Index> {
        let mut tip = Index::default();
        let mut certified = Vec::new();
        let mut acks = Vec::new();
        let stream = journal
            .replay(0, 0, self.journal_replay_buffer)
            .await
            .expect("replay failed");
        pin_mut!(stream);
        while let Some(msg) = stream.next().await {
            let (_, _, _, activity) = msg.expect("replay failed");
            match activity {
                Activity::Tip(index) => {
                    tip = max(tip, index);
                    self.reporter.report(Activity::Tip(index)).await;
                }
                Activity::Certified(certificate) => {
                    certified.push(certificate.clone());
                    self.reporter.report(Activity::Certified(certificate)).await;
                }
                Activity::Ack(ack) => {
                    acks.push(ack.clone());
                    self.reporter.report(Activity::Ack(ack)).await;
                }
            }
        }

        // Update the tip to the highest index in the journal
        self.tip = tip;
        let activity_threshold = tip.saturating_sub(self.activity_timeout);

        // Add certified items
        certified
            .iter()
            .filter(|certificate| certificate.item.index >= activity_threshold)
            .for_each(|certificate| {
                self.confirmed
                    .insert(certificate.item.index, certificate.clone());
            });

        // Group acks by index
        let mut acks_by_index: BTreeMap<Index, Vec<Ack<P::Scheme, D>>> = BTreeMap::new();
        for ack in acks {
            if ack.item.index >= activity_threshold && !self.confirmed.contains_key(&ack.item.index)
            {
                acks_by_index.entry(ack.item.index).or_default().push(ack);
            }
        }

        // Process each index's acks
        let mut unverified = Vec::new();
        for (index, mut acks_group) in acks_by_index {
            // Check if we have our own ack (which means we've verified the digest)
            let current_scheme = self.scheme(self.epoch).ok();
            let our_signer = current_scheme.as_ref().and_then(|s| s.me());
            let our_digest = our_signer.and_then(|signer| {
                acks_group
                    .iter()
                    .find(|ack| ack.epoch == self.epoch && ack.attestation.signer == signer)
                    .map(|ack| ack.item.digest)
            });

            // If our_digest exists, delete everything from acks_group that doesn't match it
            if let Some(digest) = our_digest {
                acks_group.retain(|other| other.item.digest == digest);
            }

            // Create a new epoch map
            let mut epoch_map = BTreeMap::new();
            for ack in acks_group {
                epoch_map
                    .entry(ack.epoch)
                    .or_insert_with(BTreeMap::new)
                    .insert(ack.attestation.signer, ack);
            }

            // Insert as Verified if we have our own ack (meaning we verified the digest),
            // otherwise as Unverified
            match our_digest {
                Some(digest) => {
                    self.pending
                        .insert(index, Pending::Verified(digest, epoch_map));

                    // If we've already generated an ack and it isn't yet confirmed, mark for immediate rebroadcast
                    self.rebroadcast_deadlines
                        .put(index, self.context.current());
                }
                None => {
                    self.pending.insert(index, Pending::Unverified(epoch_map));

                    // Add to unverified indices
                    unverified.push(index);
                }
            }
        }

        // After replay, ensure we have all indices from tip to next in pending or confirmed
        // to handle the case where we restart and some indices have no acks yet
        let next = self.next();
        for index in self.tip..next {
            // If we already have the index in pending or confirmed, skip
            if self.pending.contains_key(&index) || self.confirmed.contains_key(&index) {
                continue;
            }

            // Add missing index to pending
            self.pending
                .insert(index, Pending::Unverified(BTreeMap::new()));
            unverified.push(index);
        }
        info!(self.tip, next, ?unverified, "replayed journal");

        unverified
    }

    /// Appends an activity to the journal.
    async fn record(&mut self, activity: Activity<P::Scheme, D>) {
        let index = match activity {
            Activity::Ack(ref ack) => ack.item.index,
            Activity::Certified(ref certificate) => certificate.item.index,
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
