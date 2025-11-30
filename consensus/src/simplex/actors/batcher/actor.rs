use super::{BatcherOutput, Config, Mailbox, Message};
use crate::{
    simplex::{
        interesting,
        metrics::Inbound,
        signing_scheme::Scheme,
        types::{
            Activity, Attributable, BatchVerifier, ConflictingFinalize, ConflictingNotarize,
            Finalization, Notarization, Nullification, NullifyFinalize, Proposal, VoteTracker,
            Voter,
        },
    },
    types::{Epoch, View, ViewDelta},
    Epochable, Reporter, Viewable,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::histogram::{self, Buckets},
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::set::{Ordered, OrderedQuorum};
use futures::{channel::mpsc, SinkExt, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, trace, warn};

/// Per-view state for vote accumulation and certificate tracking.
struct Round<
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    participants: Ordered<P>,

    blocker: B,
    reporter: R,
    verifier: BatchVerifier<S, D>,
    votes: VoteTracker<S, D>,

    /// First proposal we observed for this view (from leader's notarize vote).
    /// Used to detect equivocation and to forward to voter for verification.
    proposal: Option<Proposal<D>>,
    /// Whether we've already sent the proposal to voter.
    proposal_sent: bool,

    /// Cached certificates for this view.
    /// Once a certificate exists, we stop accumulating votes of that type.
    notarization: Option<Notarization<S, D>>,
    nullification: Option<Nullification<S>>,
    finalization: Option<Finalization<S, D>>,

    inbound_messages: Family<Inbound, Counter>,
}

impl<
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > Round<P, S, B, D, R>
{
    fn new(
        participants: Ordered<P>,
        scheme: S,
        blocker: B,
        reporter: R,
        inbound_messages: Family<Inbound, Counter>,
        batch: bool,
    ) -> Self {
        // Configure quorum params
        let quorum = if batch {
            Some(participants.quorum())
        } else {
            None
        };

        let len = participants.len();
        // Initialize data structures
        Self {
            participants,

            blocker,
            reporter,
            verifier: BatchVerifier::new(scheme, quorum),

            votes: VoteTracker::new(len),

            proposal: None,
            proposal_sent: false,

            notarization: None,
            nullification: None,
            finalization: None,

            inbound_messages,
        }
    }

    /// Returns the proposal if it hasn't been sent to voter yet.
    fn take_proposal(&mut self) -> Option<Proposal<D>> {
        if self.proposal_sent {
            return None;
        }
        if let Some(proposal) = &self.proposal {
            self.proposal_sent = true;
            return Some(proposal.clone());
        }
        None
    }

    /// Returns true if we already have a notarization certificate for this view.
    fn has_notarization(&self) -> bool {
        self.notarization.is_some()
    }

    /// Returns true if we already have a nullification certificate for this view.
    fn has_nullification(&self) -> bool {
        self.nullification.is_some()
    }

    /// Returns true if we already have a finalization certificate for this view.
    fn has_finalization(&self) -> bool {
        self.finalization.is_some()
    }

    /// Stores a notarization certificate and extracts the proposal if not already set.
    fn set_notarization(&mut self, notarization: Notarization<S, D>) {
        // Extract proposal from certificate if we don't have one
        if self.proposal.is_none() {
            self.proposal = Some(notarization.proposal.clone());
        }
        self.notarization = Some(notarization);
    }

    /// Stores a nullification certificate.
    fn set_nullification(&mut self, nullification: Nullification<S>) {
        self.nullification = Some(nullification);
    }

    /// Stores a finalization certificate and extracts the proposal if not already set.
    fn set_finalization(&mut self, finalization: Finalization<S, D>) {
        // Extract proposal from certificate if we don't have one
        if self.proposal.is_none() {
            self.proposal = Some(finalization.proposal.clone());
        }
        self.finalization = Some(finalization);
    }

    /// Adds a vote from the network to this round's verifier.
    ///
    /// Returns true if the vote was added and needs verification.
    /// Skips votes if we already have the corresponding certificate.
    async fn add(&mut self, sender: P, message: Voter<S, D>, leader: u32) -> bool {
        // Check if sender is a participant
        let Some(index) = self.participants.index(&sender) else {
            warn!(?sender, "blocking peer");
            self.blocker.block(sender).await;
            return false;
        };

        // Attempt to reserve
        match message {
            Voter::Notarize(notarize) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::notarize(&sender))
                    .inc();

                // Skip if we already have a notarization or finalization certificate
                if self.has_notarization() || self.has_finalization() {
                    return false;
                }

                // Verify sender is signer
                if index != notarize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.votes.notarize(index) {
                    Some(previous) => {
                        if previous != &notarize {
                            let activity = ConflictingNotarize::new(previous.clone(), notarize);
                            self.reporter
                                .report(Activity::ConflictingNotarize(activity))
                                .await;
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        false
                    }
                    None => {
                        // If this is the leader's notarize vote, store the proposal
                        if index == leader && self.proposal.is_none() {
                            self.proposal = Some(notarize.proposal.clone());
                        }

                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        self.votes.insert_notarize(notarize.clone());
                        self.verifier.add(Voter::Notarize(notarize), false);
                        true
                    }
                }
            }
            Voter::Nullify(nullify) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::nullify(&sender))
                    .inc();

                // Skip if we already have a nullification certificate
                if self.has_nullification() {
                    return false;
                }

                // Verify sender is signer
                if index != nullify.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Check if finalized
                if let Some(previous) = self.votes.finalize(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.votes.nullify(index) {
                    Some(previous) => {
                        if previous != &nullify {
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        false
                    }
                    None => {
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        self.votes.insert_nullify(nullify.clone());
                        self.verifier.add(Voter::Nullify(nullify), false);
                        true
                    }
                }
            }
            Voter::Finalize(finalize) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::finalize(&sender))
                    .inc();

                // Skip if we already have a finalization certificate
                if self.has_finalization() {
                    return false;
                }

                // Verify sender is signer
                if index != finalize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Check if nullified
                if let Some(previous) = self.votes.nullify(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.votes.finalize(index) {
                    Some(previous) => {
                        if previous != &finalize {
                            let activity = ConflictingFinalize::new(previous.clone(), finalize);
                            self.reporter
                                .report(Activity::ConflictingFinalize(activity))
                                .await;
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        false
                    }
                    None => {
                        self.reporter
                            .report(Activity::Finalize(finalize.clone()))
                            .await;
                        self.votes.insert_finalize(finalize.clone());
                        self.verifier.add(Voter::Finalize(finalize), false);
                        true
                    }
                }
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                // Certificates should be handled separately, not through add()
                warn!(
                    ?sender,
                    "blocking peer for sending certificate on vote channel"
                );
                self.blocker.block(sender).await;
                false
            }
        }
    }

    /// Adds a vote that we constructed ourselves to the verifier.
    ///
    /// Returns true if the vote was added (may be needed for quorum).
    /// Skips votes if we already have the corresponding certificate.
    async fn add_constructed(&mut self, message: Voter<S, D>) -> bool {
        match &message {
            Voter::Notarize(notarize) => {
                // Skip if we already have a notarization or finalization certificate
                if self.has_notarization() || self.has_finalization() {
                    return false;
                }
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;
                self.votes.insert_notarize(notarize.clone());
            }
            Voter::Nullify(nullify) => {
                // Skip if we already have a nullification certificate
                if self.has_nullification() {
                    return false;
                }
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;
                self.votes.insert_nullify(nullify.clone());
            }
            Voter::Finalize(finalize) => {
                // Skip if we already have a finalization certificate
                if self.has_finalization() {
                    return false;
                }
                self.reporter
                    .report(Activity::Finalize(finalize.clone()))
                    .await;
                self.votes.insert_finalize(finalize.clone());
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                unreachable!("certificates should not be sent via add_constructed");
            }
        }
        self.verifier.add(message, true);
        true
    }

    fn set_leader(&mut self, leader: u32) {
        self.verifier.set_leader(leader);
    }

    fn ready_notarizes(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_notarization() || self.has_finalization() {
            return false;
        }
        self.verifier.ready_notarizes()
    }

    fn verify_notarizes<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_notarizes(rng, namespace)
    }

    fn ready_nullifies(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_nullification() {
            return false;
        }
        self.verifier.ready_nullifies()
    }

    fn verify_nullifies<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_nullifies(rng, namespace)
    }

    fn ready_finalizes(&self) -> bool {
        // Don't bother verifying if we already have a certificate
        if self.has_finalization() {
            return false;
        }
        self.verifier.ready_finalizes()
    }

    fn verify_finalizes<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_finalizes(rng, namespace)
    }

    fn is_active(&self, leader: u32) -> Option<bool> {
        Some(self.votes.has_notarize(leader) || self.votes.has_nullify(leader))
    }

    /// Attempts to construct a notarization certificate from accumulated votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    fn try_construct_notarization(&mut self, scheme: &S) -> Option<Notarization<S, D>> {
        if self.has_notarization() || self.has_finalization() {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.votes.len_notarizes() < quorum {
            return None;
        }
        let notarization = Notarization::from_notarizes(scheme, self.votes.iter_notarizes())?;
        self.set_notarization(notarization.clone());
        Some(notarization)
    }

    /// Attempts to construct a nullification certificate from accumulated votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    fn try_construct_nullification(&mut self, scheme: &S) -> Option<Nullification<S>> {
        if self.has_nullification() {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.votes.len_nullifies() < quorum {
            return None;
        }
        let nullification = Nullification::from_nullifies(scheme, self.votes.iter_nullifies())?;
        self.set_nullification(nullification.clone());
        Some(nullification)
    }

    /// Attempts to construct a finalization certificate from accumulated votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    fn try_construct_finalization(&mut self, scheme: &S) -> Option<Finalization<S, D>> {
        if self.has_finalization() {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.votes.len_finalizes() < quorum {
            return None;
        }
        let finalization = Finalization::from_finalizes(scheme, self.votes.iter_finalizes())?;
        self.set_finalization(finalization.clone());
        Some(finalization)
    }
}

pub struct Actor<
    E: Spawner + Metrics + Clock + Rng + CryptoRng,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,

    participants: Ordered<P>,
    scheme: S,

    blocker: B,
    reporter: R,

    activity_timeout: ViewDelta,
    skip_timeout: ViewDelta,
    epoch: Epoch,
    namespace: Vec<u8>,
    mailbox_size: usize,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    added: Counter,
    verified: Counter,
    inbound_messages: Family<Inbound, Counter>,
    batch_size: Histogram,
    verify_latency: histogram::Timed<E>,
}

impl<
        E: Spawner + Metrics + Clock + Rng + CryptoRng,
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > Actor<E, P, S, B, D, R>
{
    pub fn new(context: E, cfg: Config<S, B, R>) -> (Self, Mailbox<S, D>) {
        let added = Counter::default();
        let verified = Counter::default();
        let inbound_messages = Family::<Inbound, Counter>::default();
        let batch_size =
            Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0]);
        context.register(
            "added",
            "number of messages added to the verifier",
            added.clone(),
        );
        context.register("verified", "number of messages verified", verified.clone());
        context.register(
            "inbound_messages",
            "number of inbound messages",
            inbound_messages.clone(),
        );
        context.register(
            "batch_size",
            "number of messages in a partial signature verification batch",
            batch_size.clone(),
        );
        let verify_latency = Histogram::new(Buckets::CRYPTOGRAPHY);
        context.register(
            "verify_latency",
            "latency of partial signature verification",
            verify_latency.clone(),
        );
        // TODO(#1833): Metrics should use the post-start context
        let clock = Arc::new(context.clone());
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let participants = cfg.scheme.participants().clone();
        (
            Self {
                context: ContextCell::new(context),

                participants,
                scheme: cfg.scheme,

                blocker: cfg.blocker,
                reporter: cfg.reporter,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                epoch: cfg.epoch,
                namespace: cfg.namespace,
                mailbox_size: cfg.mailbox_size,

                mailbox_receiver: receiver,

                added,
                verified,
                inbound_messages,
                batch_size,
                verify_latency: histogram::Timed::new(verify_latency, clock),
            },
            Mailbox::new(sender),
        )
    }

    pub fn mailbox_size(&self) -> usize {
        self.mailbox_size
    }

    fn new_round(&self, batch: bool) -> Round<P, S, B, D, R> {
        Round::new(
            self.participants.clone(),
            self.scheme.clone(),
            self.blocker.clone(),
            self.reporter.clone(),
            self.inbound_messages.clone(),
            batch,
        )
    }

    pub fn start(
        mut self,
        voter_sender: mpsc::Sender<BatcherOutput<S, D>>,
        pending_receiver: impl Receiver<PublicKey = P>,
        recovered_receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter_sender, pending_receiver, recovered_receiver)
                .await
        )
    }

    pub async fn run(
        mut self,
        mut voter_sender: mpsc::Sender<BatcherOutput<S, D>>,
        pending_receiver: impl Receiver<PublicKey = P>,
        recovered_receiver: impl Receiver<PublicKey = P>,
    ) {
        // Wrap channels
        //
        // pending_receiver: receives votes from network
        // recovered_receiver: receives certificates from network
        let mut pending_receiver: WrappedReceiver<_, Voter<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), pending_receiver);
        let mut recovered_receiver: WrappedReceiver<_, Voter<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), recovered_receiver);

        // Initialize view data structures
        let mut current = View::zero();
        let mut finalized = View::zero();
        let mut leader = 0u32;
        #[allow(clippy::type_complexity)]
        let mut work: BTreeMap<View, Round<P, S, B, D, R>> = BTreeMap::new();
        let mut initialized = false;

        let mut shutdown = self.context.stopped();
        loop {
            // Handle next message
            select! {
                _ = &mut shutdown => {
                    debug!("context shutdown, stopping batcher");
                    break;
                },
                message = self.mailbox_receiver.next() => {
                    match message {
                        Some(Message::Update {
                            current: new_current,
                            leader: new_leader,
                            finalized: new_finalized,
                            active,
                        }) => {
                            current = new_current;
                            finalized = new_finalized;
                            leader = new_leader;
                            work.entry(current)
                                .or_insert_with(|| self.new_round(initialized))
                                .set_leader(leader);
                            initialized = true;

                            // If we haven't seen enough rounds yet, assume active
                            if current < View::new(self.skip_timeout.get())
                                || (work.len() as u64) < self.skip_timeout.get()
                            {
                                active.send(true).unwrap();
                                continue;
                            }
                            let min_view = current.saturating_sub(self.skip_timeout);

                            // Check if the leader is active within the views we know about
                            let mut is_active = false;
                            for (view, round) in work.iter().rev() {
                                // If we haven't seen activity within the skip timeout, break
                                if *view < min_view {
                                    break;
                                }

                                // Don't penalize leader for not being a participant
                                let Some(active) = round.is_active(leader) else {
                                    is_active = true;
                                    break;
                                };

                                // If the leader is explicitly active, we can stop
                                if active {
                                    is_active = true;
                                    break;
                                }
                            }
                            active.send(is_active).unwrap();
                        }
                        Some(Message::Constructed(message)) => {
                            // If the view isn't interesting, we can skip
                            let view = message.view();
                            if !interesting(
                                self.activity_timeout,
                                finalized,
                                current,
                                view,
                                false,
                            ) {
                                continue;
                            }

                            // Add the message to the verifier
                            let added = work.entry(view)
                                .or_insert_with(|| self.new_round(initialized))
                                .add_constructed(message)
                                .await;
                            if added {
                                self.added.inc();
                            }
                        }
                        None => {
                            break;
                        }
                    }
                },
                // Handle votes from the network
                message = pending_receiver.recv() => {
                    // If the channel is closed, we should exit
                    let Ok((sender, message)) = message else {
                        break;
                    };

                    // If there is a decoding error, block
                    let Ok(message) = message else {
                        warn!(?sender, "blocking peer for decoding error");
                        self.blocker.block(sender).await;
                        continue;
                    };

                    // If the epoch is not the current epoch, block
                    if message.epoch() != self.epoch {
                        warn!(?sender, "blocking peer for epoch mismatch");
                        self.blocker.block(sender).await;
                        continue;
                    }

                    // If the view isn't interesting, we can skip
                    let view = message.view();
                    if !interesting(
                        self.activity_timeout,
                        finalized,
                        current,
                        view,
                        false,
                    ) {
                        continue;
                    }

                    // Add the vote to the verifier
                    let added = work
                        .entry(view)
                        .or_insert_with(|| self.new_round(initialized))
                        .add(sender, message, leader)
                        .await;
                    if added {
                        self.added.inc();
                    }
                },
                // Handle certificates from the network
                message = recovered_receiver.recv() => {
                    // If the channel is closed, we should exit
                    let Ok((sender, message)) = message else {
                        break;
                    };

                    // If there is a decoding error, block
                    let Ok(message) = message else {
                        warn!(?sender, "blocking peer for decoding error");
                        self.blocker.block(sender).await;
                        continue;
                    };

                    // If the epoch is not the current epoch, block
                    if message.epoch() != self.epoch {
                        warn!(?sender, "blocking peer for epoch mismatch");
                        self.blocker.block(sender).await;
                        continue;
                    }

                    // Handle certificate based on type
                    let view = message.view();

                    // Allow future certificates (they advance our view)
                    if !interesting(
                        self.activity_timeout,
                        finalized,
                        current,
                        view,
                        true, // allow future
                    ) {
                        continue;
                    }

                    // Get or create the round
                    let round = work
                        .entry(view)
                        .or_insert_with(|| self.new_round(initialized));

                    match message {
                        Voter::Notarization(notarization) => {
                            // Skip if we already have a notarization for this view
                            if round.has_notarization() {
                                trace!(%view, "skipping duplicate notarization");
                                continue;
                            }

                            // Verify the certificate
                            if !notarization.verify(
                                &mut self.context,
                                &self.scheme,
                                &self.namespace,
                            ) {
                                warn!(?sender, %view, "blocking peer for invalid notarization");
                                self.blocker.block(sender).await;
                                continue;
                            }

                            // Store and forward to voter
                            round.set_notarization(notarization.clone());
                            if voter_sender
                                .send(BatcherOutput::Notarization(notarization))
                                .await
                                .is_err()
                            {
                                debug!("voter channel closed");
                                break;
                            }
                        }
                        Voter::Nullification(nullification) => {
                            // Skip if we already have a nullification for this view
                            if round.has_nullification() {
                                trace!(%view, "skipping duplicate nullification");
                                continue;
                            }

                            // Verify the certificate
                            if !nullification.verify::<_, D>(
                                &mut self.context,
                                &self.scheme,
                                &self.namespace,
                            ) {
                                warn!(?sender, %view, "blocking peer for invalid nullification");
                                self.blocker.block(sender).await;
                                continue;
                            }

                            // Store and forward to voter
                            round.set_nullification(nullification.clone());
                            if voter_sender
                                .send(BatcherOutput::Nullification(nullification))
                                .await
                                .is_err()
                            {
                                debug!("voter channel closed");
                                break;
                            }
                        }
                        Voter::Finalization(finalization) => {
                            // Skip if we already have a finalization for this view
                            if round.has_finalization() {
                                trace!(%view, "skipping duplicate finalization");
                                continue;
                            }

                            // Verify the certificate
                            if !finalization.verify(
                                &mut self.context,
                                &self.scheme,
                                &self.namespace,
                            ) {
                                warn!(?sender, %view, "blocking peer for invalid finalization");
                                self.blocker.block(sender).await;
                                continue;
                            }

                            // Store and forward to voter
                            round.set_finalization(finalization.clone());
                            if voter_sender
                                .send(BatcherOutput::Finalization(finalization))
                                .await
                                .is_err()
                            {
                                debug!("voter channel closed");
                                break;
                            }
                        }
                        Voter::Notarize(_) | Voter::Nullify(_) | Voter::Finalize(_) => {
                            // Votes should come through pending_receiver, not recovered_receiver
                            warn!(?sender, "blocking peer for sending vote on certificate channel");
                            self.blocker.block(sender).await;
                            continue;
                        }
                    }
                }
            }

            // Look for a ready verifier (prioritizing the current view)
            let mut timer = self.verify_latency.timer();
            #[allow(clippy::type_complexity)]
            let mut selected: Option<(View, Vec<Voter<S, D>>, Vec<u32>)> = None;
            if let Some(round) = work.get_mut(&current) {
                if round.ready_notarizes() {
                    let (voters, failed) =
                        round.verify_notarizes(&mut self.context, &self.namespace);
                    selected = Some((current, voters, failed));
                } else if round.ready_nullifies() {
                    let (voters, failed) =
                        round.verify_nullifies(&mut self.context, &self.namespace);
                    selected = Some((current, voters, failed));
                }
            }
            if selected.is_none() {
                let potential = work
                    .iter_mut()
                    .rev()
                    .find(|(view, round)| {
                        **view != current && **view >= finalized && round.ready_finalizes()
                    })
                    .map(|(view, round)| (*view, round));
                if let Some((view, round)) = potential {
                    let (voters, failed) =
                        round.verify_finalizes(&mut self.context, &self.namespace);
                    selected = Some((view, voters, failed));
                }
            }
            let Some((view, voters, failed)) = selected else {
                trace!(
                    %current,
                    %finalized,
                    waiting = work.len(),
                    "no verifier ready"
                );
                continue;
            };
            timer.observe();

            // Process verified votes
            let batch = voters.len() + failed.len();
            trace!(%view, batch, "batch verified votes");
            self.verified.inc_by(batch as u64);
            self.batch_size.observe(batch as f64);

            // Block invalid signers
            for invalid in failed {
                if let Some(signer) = self.participants.key(invalid) {
                    warn!(?signer, "blocking peer for invalid signature");
                    self.blocker.block(signer.clone()).await;
                }
            }

            // Get the round for this view to construct certificates
            let Some(round) = work.get_mut(&view) else {
                continue;
            };

            // Check if we should send the proposal to voter (first valid leader notarize)
            if let Some(proposal) = round.take_proposal() {
                debug!(%view, ?proposal, "forwarding proposal to voter");
                if voter_sender
                    .send(BatcherOutput::Proposal { view, proposal })
                    .await
                    .is_err()
                {
                    debug!("voter channel closed");
                    break;
                }
            }

            // Try to construct and forward certificates
            if let Some(notarization) = round.try_construct_notarization(&self.scheme) {
                debug!(%view, "constructed notarization, forwarding to voter");
                if voter_sender
                    .send(BatcherOutput::Notarization(notarization))
                    .await
                    .is_err()
                {
                    debug!("voter channel closed");
                    break;
                }
            }

            if let Some(nullification) = round.try_construct_nullification(&self.scheme) {
                debug!(%view, "constructed nullification, forwarding to voter");
                if voter_sender
                    .send(BatcherOutput::Nullification(nullification))
                    .await
                    .is_err()
                {
                    debug!("voter channel closed");
                    break;
                }
            }

            if let Some(finalization) = round.try_construct_finalization(&self.scheme) {
                debug!(%view, "constructed finalization, forwarding to voter");
                if voter_sender
                    .send(BatcherOutput::Finalization(finalization))
                    .await
                    .is_err()
                {
                    debug!("voter channel closed");
                    break;
                }
            }

            // Drop any rounds that are no longer interesting
            loop {
                let Some((view, _)) = work.first_key_value() else {
                    break;
                };
                let view = *view;
                if interesting(self.activity_timeout, finalized, current, view, false) {
                    break;
                }
                work.remove(&view);
            }
        }
    }
}
