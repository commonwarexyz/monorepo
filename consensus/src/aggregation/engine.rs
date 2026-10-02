//! Engine for the module.

use super::{
    Config, metrics,
    safe_tip::SafeTip,
    types::{Ack, Activity, Error, Item, TipAck},
};
use crate::{
    Automaton, Monitor, Reporter,
    aggregation::{scheme, types::Certificate},
    types::{Epoch, EpochDelta, Height, HeightDelta, Participant},
};
use commonware_cryptography::{
    Digest,
    certificate::{Provider, Scheme, Verifier, optimistic_assemble},
};
use commonware_macros::select_loop;
use commonware_p2p::{
    Blocker, Receiver, Recipients, Sender,
    utils::codec::{WrappedSender, wrap},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, ReadOptions, Spawner, Storage,
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{GaugeExt, histogram, status::Status},
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::{
    N3f1, PrioritySet,
    futures::{Pool as FuturesPool, rebind},
    non_empty,
    ordered::Quorum,
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, trace, warn};

/// The acks received for one epoch of a height, split by whether their signature was checked.
struct Acks<S: Scheme, D: Digest> {
    /// Signature checked (our own acks and acks that survived a failed assembly).
    verified: BTreeMap<Participant, Ack<S, D>>,

    /// Signature not yet checked. Checked together once a quorum is stored.
    unverified: BTreeMap<Participant, Ack<S, D>>,
}

impl<S: Scheme, D: Digest> Default for Acks<S, D> {
    fn default() -> Self {
        Self {
            verified: BTreeMap::new(),
            unverified: BTreeMap::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Acks<S, D> {
    fn contains(&self, signer: &Participant) -> bool {
        self.verified.contains_key(signer) || self.unverified.contains_key(signer)
    }

    fn matching<'a>(&'a self, digest: &'a D) -> impl Iterator<Item = &'a Ack<S, D>> {
        self.verified
            .values()
            .chain(self.unverified.values())
            .filter(move |ack| ack.item.digest == *digest)
    }

    /// Assembles a certificate for `item` from the acks stored for it, checking the unverified
    /// signatures once. Signatures that fail are removed and returned; those that pass are kept
    /// as verified, and may still form a quorum.
    fn verify_quorum(
        &mut self,
        scheme: &S,
        rng: &mut impl CryptoRng,
        item: &Item<D>,
        quorum: usize,
        strategy: &impl Strategy,
    ) -> (Option<Certificate<S, D>>, Vec<Participant>)
    where
        S: scheme::Scheme<D>,
    {
        let pending = self
            .unverified
            .values()
            .filter(|ack| ack.item.digest == item.digest)
            .map(|ack| ack.attestation.clone())
            .collect::<Vec<_>>();
        let verification = match optimistic_assemble::<_, _, D, _, _>(
            scheme,
            rng,
            item,
            pending,
            self.verified
                .values()
                .filter(|ack| ack.item.digest == item.digest)
                .map(|ack| &ack.attestation),
            strategy,
        ) {
            Ok(certificate) => {
                let item = item.clone();
                return (Some(Certificate { item, certificate }), Vec::new());
            }
            Err(verification) => verification,
        };

        for attestation in verification.verified {
            if let Some(ack) = self.unverified.remove(&attestation.signer) {
                self.verified.insert(attestation.signer, ack);
            }
        }
        for signer in &verification.invalid {
            self.unverified.remove(signer);
        }

        // The signatures that verified may already form a quorum
        let verified = self
            .verified
            .values()
            .filter(|ack| ack.item.digest == item.digest)
            .collect::<Vec<_>>();
        let certificate = (verified.len() >= quorum).then(|| {
            Certificate::from_acks(scheme, non_empty![@verified], strategy)
                .expect("verified acknowledgement quorum must assemble")
        });
        (certificate, verification.invalid)
    }

    fn retain_digest(&mut self, digest: &D) {
        self.verified.retain(|_, ack| ack.item.digest == *digest);
        self.unverified.retain(|_, ack| ack.item.digest == *digest);
    }
}

/// An entry for a height that does not yet have a certificate.
struct Pending<S: Scheme, D: Digest> {
    /// The digest verified by the automaton. Until it is known, acks may have arbitrary digests.
    digest: Option<D>,

    epochs: BTreeMap<Epoch, Acks<S, D>>,
}

impl<S: Scheme, D: Digest> Pending<S, D> {
    const fn new(digest: Option<D>, epochs: BTreeMap<Epoch, Acks<S, D>>) -> Self {
        Self { digest, epochs }
    }

    /// Whether an ack for `digest` is consistent with the verified digest (if any).
    fn accepts(&self, digest: &D) -> bool {
        self.digest.as_ref().is_none_or(|d| d == digest)
    }

    fn has(&self, epoch: Epoch, signer: &Participant) -> bool {
        self.epochs
            .get(&epoch)
            .is_some_and(|acks| acks.contains(signer))
    }

    /// Records the digest verified by the automaton and drops acks that do not match it.
    fn verify(&mut self, digest: D) {
        self.epochs
            .values_mut()
            .for_each(|acks| acks.retain_digest(&digest));
        self.digest = Some(digest);
    }
}

/// The type returned by the `pending` pool, used by the application to return which digest is
/// associated with the given height.
struct DigestRequest<D: Digest> {
    /// The height in question.
    height: Height,

    /// The result of the verification.
    result: Result<D, Error>,

    /// Records the time taken to get the digest.
    timer: histogram::Timer,
}

/// Instance of the engine.
pub struct Engine<
    E: BufferPooler + Clock + Spawner + Storage + Metrics + CryptoRng,
    P: Provider<Scope = Epoch>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Activity<P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    T: Strategy,
> {
    // ---------- Interfaces ----------
    context: ContextCell<E>,
    automaton: A,
    monitor: M,
    provider: P,
    reporter: Z,
    blocker: B,
    strategy: T,

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
    window: HeightDelta,

    /// Number of heights to track below the tip when collecting acks and/or pruning.
    activity_timeout: HeightDelta,

    // Messaging
    /// Pool of pending futures to request a digest from the automaton.
    digest_requests: FuturesPool<'static, DigestRequest<D>>,

    // State
    /// The current epoch.
    epoch: Epoch,

    /// The current tip.
    tip: Height,

    /// Signers proven to have sent an invalid ack, per epoch. Bounded by the participants of
    /// the retained epochs, and pruned with them.
    invalid_signers: BTreeMap<Epoch, BTreeSet<Participant>>,

    /// Tracks the tips of all validators.
    safe_tip: SafeTip<<P::Scheme as Verifier>::PublicKey>,

    /// The keys represent the set of all `Height` values for which we are attempting to form a
    /// certificate, but do not yet have one. Values track the received acks and whether
    /// the automaton has verified the digest.
    pending: BTreeMap<Height, Pending<P::Scheme, D>>,

    /// A map of heights with a certificate. Cached in memory if needed to send to other peers.
    confirmed: BTreeMap<Height, Certificate<P::Scheme, D>>,

    // ---------- Rebroadcasting ----------
    /// The frequency at which to rebroadcast pending heights.
    rebroadcast_timeout: Duration,

    /// A set of deadlines for rebroadcasting `Height` values that do not have a certificate.
    rebroadcast_deadlines: PrioritySet<Height, SystemTime>,

    // ---------- Journal ----------
    /// Journal for storing acks signed by this node.
    journal: Option<Journal<E, Activity<P::Scheme, D>>>,
    journal_partition: String,
    journal_write_buffer: NonZeroUsize,
    journal_replay_buffer: NonZeroUsize,
    journal_heights_per_section: NonZeroU64,
    journal_compression: Option<u8>,
    journal_page_cache: CacheRef,

    // ---------- Network ----------
    /// Whether to send acks as priority messages.
    priority_acks: bool,

    // ---------- Metrics ----------
    /// Metrics
    metrics: metrics::Metrics,
}

impl<
    E: BufferPooler + Clock + Spawner + Storage + Metrics + CryptoRng,
    P: Provider<Scope = Epoch, Scheme: scheme::Scheme<D>>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Activity<P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    T: Strategy,
> Engine<E, P, D, A, Z, M, B, T>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<P, D, A, Z, M, B, T>) -> Self {
        let metrics = metrics::Metrics::init(&context);

        Self {
            context: ContextCell::new(context),
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            provider: cfg.provider,
            blocker: cfg.blocker,
            strategy: cfg.strategy,
            epoch_bounds: cfg.epoch_bounds,
            window: HeightDelta::new(cfg.window.into()),
            activity_timeout: cfg.activity_timeout,
            epoch: Epoch::zero(),
            tip: Height::zero(),
            invalid_signers: BTreeMap::new(),
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
            journal_heights_per_section: cfg.journal_heights_per_section,
            journal_compression: cfg.journal_compression,
            journal_page_cache: cfg.journal_page_cache,
            priority_acks: cfg.priority_acks,
            metrics,
        }
    }

    /// Gets the scheme for a given epoch, returning an error if unavailable.
    fn scheme(&self, epoch: Epoch) -> Result<Arc<P::Scheme>, Error> {
        self.provider
            .scheme(epoch)
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
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(
        mut self,
        network: (
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        ),
    ) {
        let (mut sender, mut receiver) = wrap(
            (),
            self.context.network_buffer_pool().clone(),
            network.0,
            network.1,
        );

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        // Initialize Journal
        let journal_cfg = JConfig {
            partition: self.journal_partition.clone(),
            compression: self.journal_compression,
            codec_config: P::Scheme::certificate_codec_config_unbounded(),
            page_cache: self.journal_page_cache.clone(),
            write_buffer: self.journal_write_buffer,
        };
        let journal = Journal::init(self.context.child("journal"), journal_cfg)
            .await
            .expect("init failed");
        let (journal, unverified_heights) = self.replay(journal).await;
        self.journal = Some(journal);

        // Request digests for unverified heights
        for height in unverified_heights {
            trace!(%height, "requesting digest for unverified height from replay");
            self.get_digest(height);
        }

        // Initialize the tip manager
        let scheme = self
            .scheme(self.epoch)
            .expect("current epoch scheme must exist");
        self.safe_tip.init(scheme.participants());

        select_loop! {
            self.context,
            on_start => {
                let _ = self.metrics.tip.try_set(self.tip.get());

                // Propose a new digest if we are processing less than the window
                let next = self.next();

                // Underflow safe: next >= self.tip is guaranteed by next()
                if next.delta_from(self.tip).unwrap() < self.window {
                    trace!(%next, "requesting new digest");
                    assert!(
                        self.pending
                            .insert(next, Pending::new(None, BTreeMap::new()))
                            .is_none()
                    );
                    self.get_digest(next);
                    continue;
                }

                // Get the rebroadcast deadline for the next height
                let rebroadcast = match self.rebroadcast_deadlines.peek() {
                    Some((_, &deadline)) => Either::Left(self.context.sleep_until(deadline)),
                    None => Either::Right(future::pending()),
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

                // Update the tip manager
                let scheme = self
                    .scheme(self.epoch)
                    .expect("current epoch scheme must exist");
                self.safe_tip.reconcile(scheme.participants());

                // Update data structures by purging old epochs
                let min_epoch = self.epoch.saturating_sub(self.epoch_bounds.0);
                self.invalid_signers.retain(|epoch, _| *epoch >= min_epoch);
                self.pending
                    .iter_mut()
                    .for_each(|(_, pending)| pending.epochs.retain(|epoch, _| *epoch >= min_epoch));

                // Heights verified without signing authority have no rebroadcast deadline.
                // Schedule one for each that is still unconfirmed once we can sign.
                if scheme.me().is_some() {
                    for (height, pending) in &self.pending {
                        if pending.digest.is_some()
                            && !self.confirmed.contains_key(height)
                            && !self.rebroadcast_deadlines.contains(height)
                        {
                            self.rebroadcast_deadlines.put(*height, self.context.current());
                        }
                    }
                }

                continue;
            },

            // Sign a new ack
            request = self.digest_requests.next_completed() => {
                let DigestRequest {
                    height,
                    result,
                    timer,
                } = request;
                match result {
                    Err(err) => {
                        warn!(?err, %height, "automaton returned error");
                        self.metrics.digest.inc(Status::Dropped);
                    }
                    Ok(digest) => {
                        timer.observe(self.context.as_ref());
                        self = self.handle_digest(height, digest, &mut sender).await;
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
                        commonware_p2p::block!(self.blocker, sender, ?err, "ack decode failed");
                        continue;
                    }
                };

                // Update the tip manager
                if self.safe_tip.update(sender.clone(), tip).is_some() {
                    // Fast-forward our tip if needed
                    let safe_tip = self.safe_tip.get();
                    if safe_tip > self.tip {
                        self = self.fast_forward_tip(safe_tip).await;
                    }
                }

                // Validate that we need to process the ack
                if let Err(err) = self.validate_ack(&ack, &sender) {
                    if err.blockable() {
                        commonware_p2p::block!(
                            self.blocker,
                            sender,
                            ?err,
                            "ack validation failure"
                        );
                    } else {
                        debug!(?sender, ?err, "ack validate failed");
                    }
                    continue;
                };

                // Handle the ack
                let accepted;
                (self, accepted) = self.handle_ack(&ack, false).await;
                if !accepted {
                    guard.set(Status::Failure);
                    continue;
                }

                // Update the metrics
                debug!(?sender, epoch = %ack.epoch, height = %ack.item.height, "ack");
                guard.set(Status::Success);
            },

            // Rebroadcast
            _ = rebroadcast => {
                // Get the next height to rebroadcast
                let (height, _) = self
                    .rebroadcast_deadlines
                    .pop()
                    .expect("no rebroadcast deadline");
                trace!(%height, "rebroadcasting");
                self = self.handle_rebroadcast(height, &mut sender).await;
            },
        }

        // Close journal on shutdown
        if let Some(journal) = self.journal.take() {
            journal.sync_all().await.expect("unable to sync journal");
        }
    }

    // ---------- Handling ----------

    /// Handles a digest returned by the automaton.
    async fn handle_digest(
        mut self,
        height: Height,
        digest: D,
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
    ) -> Self {
        // Entry must not have a verified digest yet, or return early
        let Some(pending) = self
            .pending
            .get_mut(&height)
            .filter(|pending| pending.digest.is_none())
        else {
            debug!(%height, "digest height not pending");
            return self;
        };
        pending.verify(digest);
        let epochs = pending.epochs.keys().copied().collect::<Vec<_>>();

        // The stored acks may already form a quorum
        let item = Item { height, digest };
        for epoch in epochs {
            self = self.try_certify(epoch, &item).await;
            if self.confirmed.contains_key(&height) {
                break;
            }
        }

        // Sign my own ack
        let signed;
        (self, signed) = self.sign_ack(height, digest).await;
        let Some(ack) = signed else {
            return self;
        };

        // Set the rebroadcast deadline for this height
        self.rebroadcast_deadlines
            .put(height, self.context.current() + self.rebroadcast_timeout);

        // Handle ack as if it was received over the network
        (self, _) = self.handle_ack(&ack, true).await;

        // Send ack over the network.
        self.broadcast(ack, sender);

        self
    }

    /// Handles an ack.
    ///
    /// Returns whether the ack was accepted for certification. Inapplicable acks
    /// (e.g. unknown scheme, non-pending height, digest mismatch) are rejected.
    /// Duplicate acks are accepted as no-ops.
    async fn handle_ack(mut self, ack: &Ack<P::Scheme, D>, own: bool) -> (Self, bool) {
        // Ensure the scheme for the ack's epoch exists
        if let Err(err) = self.scheme(ack.epoch) {
            debug!(?err, epoch = %ack.epoch, signer = %ack.attestation.signer, "ack for unknown scheme");
            return (self, false);
        }

        // Get the acks and check digest consistency
        let Some(pending) = self.pending.get_mut(&ack.item.height) else {
            // If the height is not in the pending pool, it may be confirmed
            // (i.e. we have a certificate for it).
            debug!(height = %ack.item.height, signer = %ack.attestation.signer, "ack height not pending");
            return (self, false);
        };
        if !pending.accepts(&ack.item.digest) {
            debug!(height = %ack.item.height, signer = %ack.attestation.signer, "ack digest mismatch");
            return (self, false);
        }

        // Add the attestation (if not already present)
        let acks = pending.epochs.entry(ack.epoch).or_default();
        if acks.contains(&ack.attestation.signer) {
            return (self, true);
        }
        let stored = if own {
            &mut acks.verified
        } else {
            &mut acks.unverified
        };
        stored.insert(ack.attestation.signer, ack.clone());

        self = self.try_certify(ack.epoch, &ack.item).await;
        (self, true)
    }

    /// Forms a certificate for `item` if a quorum of acks is stored for `epoch`.
    ///
    /// Unverified signatures are checked once, together with the quorum, by assembling and
    /// verifying a single certificate. If that fails, the bad signers are removed and blocked.
    async fn try_certify(mut self, epoch: Epoch, item: &Item<D>) -> Self {
        let Ok(scheme) = self.scheme(epoch) else {
            return self;
        };
        let quorum = usize::try_from(scheme.participants().quorum::<N3f1>())
            .expect("quorum exceeds usize::MAX");
        let Some(acks) = self
            .pending
            .get_mut(&item.height)
            .and_then(|pending| pending.epochs.get_mut(&epoch))
        else {
            return self;
        };
        if acks.matching(&item.digest).count() < quorum {
            return self;
        }

        // Assemble optimistically, bisecting to the bad signers only on failure
        let (certificate, invalid) = acks.verify_quorum(
            &*scheme,
            self.context.as_mut(),
            item,
            quorum,
            &self.strategy,
        );
        for signer in &invalid {
            if let Some(peer) = scheme.participants().key(*signer) {
                commonware_p2p::block!(self.blocker, peer.clone(), %signer, "invalid ack signature");
            }
        }

        // Forget unchecked acks of the invalid signers at every height, and ignore future ones
        if !invalid.is_empty() {
            let known = self.invalid_signers.entry(epoch).or_default();
            known.extend(invalid.iter().copied());
            for pending in self.pending.values_mut() {
                if let Some(acks) = pending.epochs.get_mut(&epoch) {
                    acks.unverified.retain(|signer, _| !known.contains(signer));
                }
            }
        }

        let Some(certificate) = certificate else {
            return self;
        };
        self.metrics.certificates.inc();
        self.handle_certificate(certificate).await
    }

    /// Handles a certificate.
    async fn handle_certificate(mut self, certificate: Certificate<P::Scheme, D>) -> Self {
        // Check if we already have the certificate
        let height = certificate.item.height;
        if self.confirmed.contains_key(&height) {
            return self;
        }

        // Store the certificate
        self.confirmed.insert(height, certificate.clone());

        // Journal and notify the automaton
        let certified = Activity::Certified(certificate);
        self = self.record(certified.clone()).await.sync(height).await;
        self.reporter.report(certified);

        // Increase the tip if needed
        if height == self.tip {
            // Compute the next tip
            let mut new_tip = height.next();
            while self.confirmed.contains_key(&new_tip) && new_tip.get() < u64::MAX {
                new_tip = new_tip.next();
            }

            // If the next tip is larger, try to fast-forward the tip (may not be possible)
            if new_tip > self.tip {
                self = self.fast_forward_tip(new_tip).await;
            }
        }

        self
    }

    /// Handles a rebroadcast request for the given height.
    async fn handle_rebroadcast(
        mut self,
        height: Height,
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
    ) -> Self {
        let Some(Pending {
            digest: Some(digest),
            epochs,
        }) = self.pending.get(&height)
        else {
            // The height may already be confirmed; continue silently if so
            return self;
        };
        let digest = *digest;

        // Get our signature
        let epoch = self.epoch;
        let scheme = match self.scheme(epoch) {
            Ok(scheme) => scheme,
            Err(err) => {
                warn!(?err, %height, "cannot rebroadcast: unknown scheme");
                return self;
            }
        };
        let Some(signer) = scheme.me() else {
            warn!(%epoch, %height, "cannot rebroadcast: not a signer");
            return self;
        };
        let ack = epochs
            .get(&epoch)
            .and_then(|acks| acks.verified.get(&signer).cloned());
        let ack = match ack {
            Some(ack) => ack,
            None => {
                let signed;
                (self, signed) = self.sign_ack(height, digest).await;
                match signed {
                    Some(ack) => {
                        (self, _) = self.handle_ack(&ack, true).await;
                        ack
                    }
                    None => return self,
                }
            }
        };

        // Reinsert the height with a new deadline
        self.rebroadcast_deadlines
            .put(height, self.context.current() + self.rebroadcast_timeout);

        // Broadcast the ack to all peers
        self.broadcast(ack, sender);

        self
    }

    // ---------- Validation ----------

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &mut self,
        ack: &Ack<P::Scheme, D>,
        sender: &<P::Scheme as Verifier>::PublicKey,
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

        // Discard acks from signers already proven invalid in this epoch
        if self
            .invalid_signers
            .get(&ack.epoch)
            .is_some_and(|signers| signers.contains(&signer))
        {
            return Err(Error::AckSignerInvalid(ack.epoch, signer));
        }

        // Collect acks below the tip (if we don't yet have a certificate)
        let activity_threshold = self.tip.saturating_sub(self.activity_timeout);
        if ack.item.height < activity_threshold {
            return Err(Error::AckCertified(ack.item.height));
        }

        // If the height is above the tip (and the window), ignore for now
        if ack
            .item
            .height
            .delta_from(self.tip)
            .is_some_and(|d| d >= self.window)
        {
            return Err(Error::AckHeight(ack.item.height));
        }

        // Validate that we don't already have the ack
        if self.confirmed.contains_key(&ack.item.height) {
            return Err(Error::AckCertified(ack.item.height));
        }
        if let Some(pending) = self.pending.get(&ack.item.height) {
            // While we check this in the `handle_ack` function, checking early here avoids an
            // unnecessary storage and quorum check.
            if !pending.accepts(&ack.item.digest) {
                return Err(Error::AckDigest(ack.item.height));
            }
            if pending.has(ack.epoch, &ack.attestation.signer) {
                return Err(Error::AckDuplicate(sender.to_string(), ack.item.height));
            }
        }

        Ok(())
    }

    // ---------- Helpers ----------

    /// Requests the digest from the automaton.
    ///
    /// Pending must contain the height.
    fn get_digest(&mut self, height: Height) {
        assert!(self.pending.contains_key(&height));
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.digest_duration.timer(self.context.as_ref());
        self.digest_requests.push(async move {
            let receiver = automaton.propose(height).await;
            let result = receiver.await.map_err(Error::AppProposeCanceled);
            DigestRequest {
                height,
                result,
                timer,
            }
        });
    }

    /// Signs an ack for the given height, and digest. Stores the ack in the journal and returns it.
    /// Returns `None` if this node cannot sign at the current epoch.
    async fn sign_ack(mut self, height: Height, digest: D) -> (Self, Option<Ack<P::Scheme, D>>) {
        let epoch = self.epoch;
        let scheme = match self.scheme(epoch) {
            Ok(scheme) => scheme,
            Err(err) => {
                warn!(?err, %height, "cannot sign ack: unknown scheme");
                return (self, None);
            }
        };

        // Sign the item
        let item = Item { height, digest };
        let Some(ack) = Ack::sign(&*scheme, epoch, item) else {
            debug!(%epoch, %height, "cannot sign ack: not a signer");
            return (self, None);
        };

        // Journal the ack
        self = self
            .record(Activity::Ack(ack.clone()))
            .await
            .sync(height)
            .await;

        (self, Some(ack))
    }

    /// Broadcasts an ack to all peers with the appropriate priority.
    fn broadcast(
        &mut self,
        ack: Ack<P::Scheme, D>,
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
    ) {
        sender.send(
            Recipients::All,
            TipAck { ack, tip: self.tip },
            self.priority_acks,
        );
    }

    /// Returns the next height that we should process. This is the minimum height for
    /// which we do not have a digest or an outstanding request to the automaton for the digest.
    fn next(&self) -> Height {
        let max_pending = self
            .pending
            .last_key_value()
            .map(|(k, _)| k.next())
            .unwrap_or_default();
        let max_confirmed = self
            .confirmed
            .last_key_value()
            .map(|(k, _)| k.next())
            .unwrap_or_default();
        max(self.tip, max(max_pending, max_confirmed))
    }

    /// Increases the tip to the given value, pruning stale entries.
    ///
    /// # Panics
    ///
    /// Panics if the given tip is less-than-or-equal-to the current tip.
    async fn fast_forward_tip(mut self, tip: Height) -> Self {
        assert!(tip > self.tip);

        // Prune data structures with buffer to prevent losing certificates
        let activity_threshold = tip.saturating_sub(self.activity_timeout);
        self.pending
            .retain(|height, _| *height >= activity_threshold);
        self.confirmed
            .retain(|height, _| *height >= activity_threshold);

        // Add tip to journal
        self = self.record(Activity::Tip(tip)).await.sync(tip).await;
        self.reporter.report(Activity::Tip(tip));

        // Prune journal with buffer
        let section = self.get_journal_section(activity_threshold);
        rebind(&mut self.journal, |journal| journal.prune(section))
            .await
            .expect("unable to prune journal");

        // Update the tip
        self.tip = tip;

        self
    }

    // ---------- Journal ----------

    /// Returns the section of the journal for the given `height`.
    const fn get_journal_section(&self, height: Height) -> u64 {
        height.get() / self.journal_heights_per_section.get()
    }

    /// Replays the journal, updating the state of the engine.
    /// Returns the journal and a list of unverified pending heights that need digest requests.
    async fn replay(
        &mut self,
        journal: Journal<E, Activity<P::Scheme, D>>,
    ) -> (Journal<E, Activity<P::Scheme, D>>, Vec<Height>) {
        let mut tip = Height::default();
        let mut certified = Vec::new();
        let mut acks = Vec::new();

        // Replay rebuilds the engine's in-memory state, so journal pages need
        // not remain in the OS page cache.
        let mut replay = journal
            .replay(0, 0, self.journal_replay_buffer, ReadOptions::DONT_CACHE)
            .await
            .expect("replay failed");
        while let Some(msg) = replay.next().await {
            let (_, _, _, activity) = msg.expect("replay failed");
            match activity {
                Activity::Tip(height) => {
                    tip = max(tip, height);
                    self.reporter.report(Activity::Tip(height));
                }
                Activity::Certified(certificate) => {
                    certified.push(certificate.clone());
                    self.reporter.report(Activity::Certified(certificate));
                }
                Activity::Ack(ack) => {
                    acks.push(ack.clone());
                    self.reporter.report(Activity::Ack(ack));
                }
            }
        }

        // Update the tip to the highest height in the journal
        self.tip = tip;
        let activity_threshold = tip.saturating_sub(self.activity_timeout);

        // Add certified items
        certified
            .iter()
            .filter(|certificate| certificate.item.height >= activity_threshold)
            .for_each(|certificate| {
                self.confirmed
                    .insert(certificate.item.height, certificate.clone());
            });

        // Group acks by height
        let mut acks_by_height: BTreeMap<Height, Vec<Ack<P::Scheme, D>>> = BTreeMap::new();
        for ack in acks {
            if ack.item.height >= activity_threshold
                && !self.confirmed.contains_key(&ack.item.height)
            {
                acks_by_height.entry(ack.item.height).or_default().push(ack);
            }
        }

        // Process each height's acks
        let mut unverified = Vec::new();
        for (height, mut acks_group) in acks_by_height {
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
            // The journal only holds acks we signed
            let mut epoch_map = BTreeMap::<Epoch, Acks<_, _>>::new();
            for ack in acks_group {
                epoch_map
                    .entry(ack.epoch)
                    .or_default()
                    .verified
                    .insert(ack.attestation.signer, ack);
            }

            // The digest is verified if we have our own ack
            self.pending
                .insert(height, Pending::new(our_digest, epoch_map));
            if our_digest.is_some() {
                // If we've already generated an ack and it isn't yet confirmed, mark for immediate rebroadcast
                self.rebroadcast_deadlines
                    .put(height, self.context.current());
            } else {
                unverified.push(height);
            }
        }

        // After replay, ensure we have all heights from tip to next in pending or confirmed
        // to handle the case where we restart and some heights have no acks yet
        let next = self.next();
        for height in Height::range(self.tip, next) {
            // If we already have the height in pending or confirmed, skip
            if self.pending.contains_key(&height) || self.confirmed.contains_key(&height) {
                continue;
            }

            // Add missing height to pending
            self.pending
                .insert(height, Pending::new(None, BTreeMap::new()));
            unverified.push(height);
        }
        info!(tip = %self.tip, %next, ?unverified, "replayed journal");

        (replay.finish().expect("replay failed"), unverified)
    }

    /// Appends an activity to the journal.
    async fn record(mut self, activity: Activity<P::Scheme, D>) -> Self {
        let height = match activity {
            Activity::Ack(ref ack) => ack.item.height,
            Activity::Certified(ref certificate) => certificate.item.height,
            Activity::Tip(h) => h,
        };
        let section = self.get_journal_section(height);
        rebind(&mut self.journal, |journal| {
            journal.append(section, &activity)
        })
        .await
        .expect("unable to append to journal");
        self
    }

    /// Syncs (ensures all data is written to disk).
    async fn sync(mut self, height: Height) -> Self {
        let section = self.get_journal_section(height);
        rebind(&mut self.journal, |journal| journal.sync(section))
            .await
            .expect("unable to sync journal");
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::{
            mocks,
            scheme::{bls12381_threshold, ed25519},
        },
        simplex::mocks::wrapped::{Behavior, Scheme as WrappedScheme},
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinSig, certificate::mocks::Fixture,
        sha256::Digest as Sha256Digest,
    };
    use commonware_p2p::Blocker;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZUsize, NonZeroDuration, sync::Mutex};

    /// Records the peers it is asked to block.
    #[derive(Clone, Default)]
    struct RecordingBlocker(Arc<Mutex<Vec<commonware_cryptography::ed25519::PublicKey>>>);

    impl Blocker for RecordingBlocker {
        type PublicKey = commonware_cryptography::ed25519::PublicKey;

        fn block(&mut self, peer: Self::PublicKey) -> Feedback {
            self.0.lock().push(peer);
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) =
                commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
            receiver
        }
    }

    type TestScheme = WrappedScheme<ed25519::Scheme>;
    type TestEngine<S = TestScheme> = Engine<
        deterministic::Context,
        mocks::Provider<S>,
        Sha256Digest,
        mocks::Application,
        mocks::ReporterMailbox<S, Sha256Digest>,
        mocks::Monitor,
        RecordingBlocker,
        Sequential,
    >;

    const EPOCH: Epoch = Epoch::new(111);

    /// Builds an engine for `scheme` over a 1-height window, with its journal open but not running.
    async fn test_engine<S>(
        context: &deterministic::Context,
        scheme: WrappedScheme<S>,
        verifier: WrappedScheme<S>,
        blocker: RecordingBlocker,
    ) -> TestEngine<WrappedScheme<S>>
    where
        S: scheme::Scheme<Sha256Digest, PublicKey = commonware_cryptography::ed25519::PublicKey>,
    {
        let provider = mocks::Provider::new();
        assert!(provider.register(EPOCH, scheme));
        let (_, reporter) = mocks::Reporter::new(context.child("reporter"), verifier);
        let mut engine = Engine::new(
            context.child("engine"),
            Config {
                monitor: mocks::Monitor::new(EPOCH),
                provider,
                automaton: mocks::Application::new(mocks::Strategy::Correct),
                reporter,
                blocker,
                priority_acks: false,
                rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(1)),
                epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                window: NonZeroU64::new(1).unwrap(),
                activity_timeout: HeightDelta::new(10),
                journal_partition: "aggregation-engine-test".to_string(),
                journal_write_buffer: NZUsize!(4096),
                journal_replay_buffer: NZUsize!(4096),
                journal_heights_per_section: NonZeroU64::new(6).unwrap(),
                journal_compression: None,
                journal_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                strategy: Sequential,
            },
        );
        engine.epoch = EPOCH;
        engine.journal = Some(
            Journal::init(
                context.child("journal"),
                JConfig {
                    partition: engine.journal_partition.clone(),
                    compression: None,
                    codec_config: WrappedScheme::<S>::certificate_codec_config_unbounded(),
                    page_cache: engine.journal_page_cache.clone(),
                    write_buffer: engine.journal_write_buffer,
                },
            )
            .await
            .unwrap(),
        );
        engine
    }

    fn signed<S: scheme::Scheme<Sha256Digest>>(
        scheme: &S,
        epoch: Epoch,
        height: Height,
        digest: Sha256Digest,
    ) -> Ack<S, Sha256Digest> {
        Ack::sign(scheme, epoch, Item { height, digest }).unwrap()
    }

    #[test]
    #[should_panic(expected = "verified acknowledgement quorum must assemble")]
    fn assembly_failure_panics() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, b"aggregation-recovery-failure", 4);
            let mut engine = test_engine(
                &context,
                WrappedScheme::new(schemes[0].clone(), Behavior::RecoveryFailure),
                WrappedScheme::new(verifier, Behavior::Honest),
                RecordingBlocker::default(),
            )
            .await;

            let height = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            engine
                .pending
                .insert(height, Pending::new(Some(digest), BTreeMap::new()));

            for scheme in schemes.iter().take(3) {
                let scheme = WrappedScheme::new(scheme.clone(), Behavior::Honest);
                (engine, _) = engine
                    .handle_ack(&signed(&scheme, EPOCH, height, digest), false)
                    .await;
            }
        });
    }

    fn bad_signature_is_removed_and_blocked_at_quorum<S, F>(fixture: F)
    where
        S: scheme::Scheme<Sha256Digest, PublicKey = commonware_cryptography::ed25519::PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = fixture(&mut context, b"aggregation-bad-signature", 4);
            let blocker = RecordingBlocker::default();
            let mut engine = test_engine(
                &context,
                WrappedScheme::new(schemes[0].clone(), Behavior::Honest),
                WrappedScheme::new(verifier, Behavior::Honest),
                blocker.clone(),
            )
            .await;
            let height = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            engine
                .pending
                .insert(height, Pending::new(Some(digest), BTreeMap::new()));

            // Peer 1 sends a corrupt signature; it is stored unverified like the others
            let behaviors = [
                Behavior::CorruptSignature,
                Behavior::Honest,
                Behavior::Honest,
            ];
            for (scheme, behavior) in schemes[1..].iter().zip(behaviors) {
                let scheme = WrappedScheme::new(scheme.clone(), behavior);
                (engine, _) = engine
                    .handle_ack(&signed(&scheme, EPOCH, height, digest), false)
                    .await;
            }

            // The quorum check failed: peer 1 is blocked and removed, the others kept
            assert_eq!(*blocker.0.lock(), vec![participants[1].clone()]);
            assert!(!engine.confirmed.contains_key(&height));
            let Some(Pending { epochs: acks, .. }) = engine.pending.get(&height) else {
                panic!("height must stay pending");
            };
            let acks = &acks[&EPOCH];
            assert!(acks.unverified.is_empty());
            assert_eq!(acks.verified.len(), 2);

            // Our own ack completes the quorum from verified acks alone
            let own = WrappedScheme::new(schemes[0].clone(), Behavior::Honest);
            (engine, _) = engine
                .handle_ack(&signed(&own, EPOCH, height, digest), true)
                .await;
            assert!(engine.confirmed.contains_key(&height));
            assert_eq!(blocker.0.lock().len(), 1);
        });
    }

    #[test]
    fn bad_signature_is_removed_and_blocked_at_quorum_ed25519() {
        bad_signature_is_removed_and_blocked_at_quorum(ed25519::fixture);
    }

    #[test]
    fn bad_signature_is_removed_and_blocked_at_quorum_threshold() {
        bad_signature_is_removed_and_blocked_at_quorum(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[test]
    fn invalid_signer_is_ignored_in_its_epoch_only() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, b"aggregation-invalid-signer", 4);
            let mut engine = test_engine(
                &context,
                WrappedScheme::new(schemes[0].clone(), Behavior::Honest),
                WrappedScheme::new(verifier, Behavior::Honest),
                RecordingBlocker::default(),
            )
            .await;
            let other = Epoch::new(112);
            assert!(engine.provider.register(
                other,
                WrappedScheme::new(schemes[0].clone(), Behavior::Honest)
            ));
            let height = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            engine
                .pending
                .insert(height, Pending::new(Some(digest), BTreeMap::new()));

            // Peer 1 also has an unchecked ack stored at the next height
            let next = Height::new(1);
            engine
                .pending
                .insert(next, Pending::new(Some(digest), BTreeMap::new()));
            let corrupt = WrappedScheme::new(schemes[1].clone(), Behavior::CorruptSignature);
            (engine, _) = engine
                .handle_ack(&signed(&corrupt, EPOCH, next, digest), false)
                .await;

            // Peer 1 is proven invalid when the quorum check fails
            let behaviors = [
                Behavior::CorruptSignature,
                Behavior::Honest,
                Behavior::Honest,
            ];
            for (scheme, behavior) in schemes[1..].iter().zip(behaviors) {
                let scheme = WrappedScheme::new(scheme.clone(), behavior);
                (engine, _) = engine
                    .handle_ack(&signed(&scheme, EPOCH, height, digest), false)
                    .await;
            }

            // Proving peer 1 invalid dropped its unchecked ack at the next height
            let Some(Pending { epochs: acks, .. }) = engine.pending.get(&next) else {
                panic!("height must stay pending");
            };
            assert!(acks[&EPOCH].unverified.is_empty());

            // Its later ack is discarded in that epoch, but accepted in another one
            let scheme = WrappedScheme::new(schemes[1].clone(), Behavior::Honest);
            let ack = signed(&scheme, EPOCH, height, digest);
            assert!(matches!(
                engine.validate_ack(&ack, &participants[1]),
                Err(Error::AckSignerInvalid(EPOCH, _))
            ));
            let ack = signed(&scheme, other, height, digest);
            assert!(engine.validate_ack(&ack, &participants[1]).is_ok());
        });
    }

    #[test]
    fn acks_of_different_epochs_do_not_form_a_quorum() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, b"aggregation-epoch-mix", 4);
            let mut engine = test_engine(
                &context,
                WrappedScheme::new(schemes[0].clone(), Behavior::Honest),
                WrappedScheme::new(verifier, Behavior::Honest),
                RecordingBlocker::default(),
            )
            .await;
            let other = Epoch::new(112);
            assert!(engine.provider.register(
                other,
                WrappedScheme::new(schemes[0].clone(), Behavior::Honest)
            ));
            let height = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            engine
                .pending
                .insert(height, Pending::new(Some(digest), BTreeMap::new()));

            // Three acks in total (the quorum) but split across two epochs
            let epochs = [EPOCH, other, EPOCH];
            for (scheme, epoch) in schemes[1..].iter().zip(epochs) {
                let scheme = WrappedScheme::new(scheme.clone(), Behavior::Honest);
                (engine, _) = engine
                    .handle_ack(&signed(&scheme, epoch, height, digest), false)
                    .await;
            }
            assert!(!engine.confirmed.contains_key(&height));

            // A third ack in one epoch completes that epoch's quorum alone
            let own = WrappedScheme::new(schemes[0].clone(), Behavior::Honest);
            (engine, _) = engine
                .handle_ack(&signed(&own, EPOCH, height, digest), true)
                .await;
            assert_eq!(engine.confirmed[&height].item.height, height);
        });
    }

    #[test]
    fn journal_holds_only_own_acks_and_replays_them_verified() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, b"aggregation-journal", 4);
            let mut engine = test_engine(
                &context,
                WrappedScheme::new(schemes[0].clone(), Behavior::Honest),
                WrappedScheme::new(verifier, Behavior::Honest),
                RecordingBlocker::default(),
            )
            .await;

            // One unverified peer ack, then our own signed ack
            let height = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            engine
                .pending
                .insert(height, Pending::new(Some(digest), BTreeMap::new()));
            let peer = WrappedScheme::new(schemes[1].clone(), Behavior::Honest);
            (engine, _) = engine
                .handle_ack(&signed(&peer, EPOCH, height, digest), false)
                .await;
            let own;
            (engine, own) = engine.sign_ack(height, digest).await;
            let own = own.unwrap();
            (engine, _) = engine.handle_ack(&own, true).await;

            // Replay restores only our ack, as verified
            engine.pending.clear();
            let journal = engine.journal.take().unwrap();
            let (_, unverified) = engine.replay(journal).await;
            assert!(unverified.is_empty());
            let Some(Pending {
                digest: Some(replayed),
                epochs: acks,
            }) = engine.pending.get(&height)
            else {
                panic!("height must be replayed as verified");
            };
            assert_eq!(*replayed, digest);
            let acks = &acks[&EPOCH];
            assert!(acks.unverified.is_empty());
            assert_eq!(
                acks.verified.keys().copied().collect::<Vec<_>>(),
                vec![own.attestation.signer]
            );
        });
    }
}
