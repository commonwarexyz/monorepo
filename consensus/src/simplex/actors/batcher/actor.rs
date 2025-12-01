use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::voter,
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
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, trace, warn};

/// Action to take after adding a vote to a round.
enum Action<D: Digest> {
    /// Vote was not added (duplicate, invalid, or certificate already exists).
    Skip,
    /// Vote was added and needs verification.
    Verify,
    /// Vote was added and this is the leader's first notarize vote (forward proposal immediately).
    VerifyAndForward(Proposal<D>),
}

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
    /// Votes received from network (may not be verified yet).
    /// Used for duplicate detection and conflict reporting.
    votes: VoteTracker<S, D>,
    /// Votes that have been verified through batch verification.
    /// Only these votes are used for certificate construction.
    verified_votes: VoteTracker<S, D>,

    /// Whether we've already received and forwarded the leader's proposal.
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
            verified_votes: VoteTracker::new(len),

            proposal_sent: false,

            notarization: None,
            nullification: None,
            finalization: None,

            inbound_messages,
        }
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

    /// Stores a notarization certificate.
    fn set_notarization(&mut self, notarization: Notarization<S, D>) {
        self.notarization = Some(notarization);
    }

    /// Stores a nullification certificate.
    fn set_nullification(&mut self, nullification: Nullification<S>) {
        self.nullification = Some(nullification);
    }

    /// Stores a finalization certificate.
    fn set_finalization(&mut self, finalization: Finalization<S, D>) {
        self.finalization = Some(finalization);
    }

    /// Adds a vote from the network to this round's verifier.
    ///
    /// Returns `AddResult` indicating whether the vote was added and if a proposal
    /// should be forwarded to voter.
    /// Skips votes if we already have the corresponding certificate.
    async fn add(&mut self, sender: P, message: Voter<S, D>, leader: u32) -> Action<D> {
        // Check if sender is a participant
        let Some(index) = self.participants.index(&sender) else {
            warn!(?sender, "blocking peer");
            self.blocker.block(sender).await;
            return Action::Skip;
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
                    return Action::Skip;
                }

                // Verify sender is signer
                if index != notarize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
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
                        Action::Skip
                    }
                    None => {
                        // Check if this is the leader's first notarize vote
                        let is_leader_proposal = index == leader && !self.proposal_sent;
                        let action = if is_leader_proposal {
                            self.proposal_sent = true;
                            Action::VerifyAndForward(notarize.proposal.clone())
                        } else {
                            Action::Verify
                        };

                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        self.votes.insert_notarize(notarize.clone());
                        self.verifier.add(Voter::Notarize(notarize), false);

                        action
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
                    return Action::Skip;
                }

                // Verify sender is signer
                if index != nullify.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
                }

                // Check if finalized
                if let Some(previous) = self.votes.finalize(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
                }

                // Try to reserve
                match self.votes.nullify(index) {
                    Some(previous) => {
                        if previous != &nullify {
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        Action::Skip
                    }
                    None => {
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        self.votes.insert_nullify(nullify.clone());
                        self.verifier.add(Voter::Nullify(nullify), false);
                        Action::Verify
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
                    return Action::Skip;
                }

                // Verify sender is signer
                if index != finalize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
                }

                // Check if nullified
                if let Some(previous) = self.votes.nullify(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return Action::Skip;
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
                        Action::Skip
                    }
                    None => {
                        self.reporter
                            .report(Activity::Finalize(finalize.clone()))
                            .await;
                        self.votes.insert_finalize(finalize.clone());
                        self.verifier.add(Voter::Finalize(finalize), false);
                        Action::Verify
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
                Action::Skip
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
                // Our own votes are already verified
                self.verified_votes.insert_notarize(notarize.clone());
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
                // Our own votes are already verified
                self.verified_votes.insert_nullify(nullify.clone());
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
                // Our own votes are already verified
                self.verified_votes.insert_finalize(finalize.clone());
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

    /// Stores a verified vote for certificate construction.
    fn add_verified(&mut self, vote: Voter<S, D>) {
        match vote {
            Voter::Notarize(n) => {
                self.verified_votes.insert_notarize(n);
            }
            Voter::Nullify(n) => {
                self.verified_votes.insert_nullify(n);
            }
            Voter::Finalize(f) => {
                self.verified_votes.insert_finalize(f);
            }
            _ => {}
        }
    }

    /// Attempts to construct a notarization certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    fn try_construct_notarization(&mut self, scheme: &S) -> Option<Notarization<S, D>> {
        if self.has_notarization() || self.has_finalization() {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_notarizes() < quorum {
            return None;
        }
        let notarization =
            Notarization::from_notarizes(scheme, self.verified_votes.iter_notarizes())?;
        self.set_notarization(notarization.clone());
        Some(notarization)
    }

    /// Attempts to construct a nullification certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    fn try_construct_nullification(&mut self, scheme: &S) -> Option<Nullification<S>> {
        if self.has_nullification() {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_nullifies() < quorum {
            return None;
        }
        let nullification =
            Nullification::from_nullifies(scheme, self.verified_votes.iter_nullifies())?;
        self.set_nullification(nullification.clone());
        Some(nullification)
    }

    /// Attempts to construct a finalization certificate from verified votes.
    ///
    /// Returns the certificate if we have quorum and haven't already constructed one.
    fn try_construct_finalization(&mut self, scheme: &S) -> Option<Finalization<S, D>> {
        if self.has_finalization() {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_finalizes() < quorum {
            return None;
        }
        let finalization =
            Finalization::from_finalizes(scheme, self.verified_votes.iter_finalizes())?;
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
        voter_mailbox: voter::Mailbox<S, D>,
        pending_receiver: impl Receiver<PublicKey = P>,
        recovered_receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter_mailbox, pending_receiver, recovered_receiver)
                .await
        )
    }

    pub async fn run(
        mut self,
        mut voter_mailbox: voter::Mailbox<S, D>,
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
                    let result = work
                        .entry(view)
                        .or_insert_with(|| self.new_round(initialized))
                        .add(sender, message, leader)
                        .await;
                    match result {
                        Action::Skip => {}
                        Action::Verify => {
                            self.added.inc();
                        }
                        Action::VerifyAndForward(proposal) => {
                            self.added.inc();
                            // Forward leader's proposal immediately so voter can start verification
                            debug!(%view, ?proposal, "forwarding leader proposal to voter");
                            voter_mailbox.proposal(proposal).await;
                        }
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
                            // Update metrics
                            self.inbound_messages
                                .get_or_create(&Inbound::notarization(&sender))
                                .inc();

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
                            voter_mailbox
                                .verified(Voter::Notarization(notarization))
                                .await;
                        }
                        Voter::Nullification(nullification) => {
                            // Update metrics
                            self.inbound_messages
                                .get_or_create(&Inbound::nullification(&sender))
                                .inc();

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
                            voter_mailbox
                                .verified(Voter::Nullification(nullification))
                                .await;
                        }
                        Voter::Finalization(finalization) => {
                            // Update metrics
                            self.inbound_messages
                                .get_or_create(&Inbound::finalization(&sender))
                                .inc();

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
                            voter_mailbox
                                .verified(Voter::Finalization(finalization))
                                .await;
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

            // Store verified votes for certificate construction
            for voter in voters {
                round.add_verified(voter);
            }

            // Try to construct and forward certificates
            if let Some(notarization) = round.try_construct_notarization(&self.scheme) {
                debug!(%view, "constructed notarization, forwarding to voter");
                voter_mailbox
                    .verified(Voter::Notarization(notarization))
                    .await;
            }
            if let Some(nullification) = round.try_construct_nullification(&self.scheme) {
                debug!(%view, "constructed nullification, forwarding to voter");
                voter_mailbox
                    .verified(Voter::Nullification(nullification))
                    .await;
            }
            if let Some(finalization) = round.try_construct_finalization(&self.scheme) {
                debug!(%view, "constructed finalization, forwarding to voter");
                voter_mailbox
                    .verified(Voter::Finalization(finalization))
                    .await;
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
