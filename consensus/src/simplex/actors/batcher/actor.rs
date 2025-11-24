use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::voter,
        interesting,
        metrics::Inbound,
        signing_scheme::Scheme,
        types::{
            Activity, Attributable, BatchVerifier, ConflictingFinalize, ConflictingNotarize,
            Finalization, Notarization, Nullification, NullifyFinalize, OrderedExt, VoteTracker,
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
use commonware_utils::set::Ordered;
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{trace, warn};

struct Round<
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    participants: Ordered<P>,
    scheme: S,

    blocker: B,
    reporter: R,
    verifier: BatchVerifier<S, D>,
    votes: VoteTracker<S, D>,
    verified_votes: VoteTracker<S, D>,

    sent_leader_notarize: bool,
    sent_leader_nullify: bool,
    sent_leader_finalize: bool,

    sent_notarization: bool,
    sent_nullification: bool,
    sent_finalization: bool,

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
            scheme: scheme.clone(),

            blocker,
            reporter,
            verifier: BatchVerifier::new(scheme, quorum),

            votes: VoteTracker::new(len),
            verified_votes: VoteTracker::new(len),

            sent_leader_notarize: false,
            sent_leader_nullify: false,
            sent_leader_finalize: false,

            sent_notarization: false,
            sent_nullification: false,
            sent_finalization: false,

            inbound_messages,
        }
    }

    pub async fn add<C: Rng + CryptoRng>(
        &mut self,
        context: &mut C,
        namespace: &[u8],
        sender: P,
        message: Voter<S, D>,
    ) -> (bool, Option<Voter<S, D>>) {
        let index = match self.participants.index(&sender) {
            Some(index) => index,
            None => {
                warn!(?sender, "blocking peer");
                self.blocker.block(sender).await;
                return (false, None);
            }
        };

        match message {
            Voter::Notarize(notarize) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::notarize(&sender))
                    .inc();

                // Verify sender is signer
                if index != notarize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return (false, None);
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
                        (false, None)
                    }
                    None => {
                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        self.votes.insert_notarize(notarize.clone());
                        self.verifier.add(Voter::Notarize(notarize), false);
                        (true, None)
                    }
                }
            }
            Voter::Nullify(nullify) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::nullify(&sender))
                    .inc();

                // Verify sender is signer
                if index != nullify.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return (false, None);
                }

                // Check if finalized
                if let Some(previous) = self.votes.finalize(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return (false, None);
                }

                // Try to reserve
                match self.votes.nullify(index) {
                    Some(previous) => {
                        if previous != &nullify {
                            warn!(?sender, "blocking peer");
                            self.blocker.block(sender).await;
                        }
                        (false, None)
                    }
                    None => {
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        self.votes.insert_nullify(nullify.clone());
                        self.verifier.add(Voter::Nullify(nullify), false);
                        (true, None)
                    }
                }
            }
            Voter::Finalize(finalize) => {
                // Update metrics
                self.inbound_messages
                    .get_or_create(&Inbound::finalize(&sender))
                    .inc();

                // Verify sender is signer
                if index != finalize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return (false, None);
                }

                // Check if nullified
                if let Some(previous) = self.votes.nullify(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return (false, None);
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
                        (false, None)
                    }
                    None => {
                        self.reporter
                            .report(Activity::Finalize(finalize.clone()))
                            .await;
                        self.votes.insert_finalize(finalize.clone());
                        self.verifier.add(Voter::Finalize(finalize), false);
                        (true, None)
                    }
                }
            }
            Voter::Notarization(notarization) => {
                if notarization.verify(context, &self.scheme, namespace) {
                    self.sent_notarization = true;
                    (true, Some(Voter::Notarization(notarization)))
                } else {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    (false, None)
                }
            }
            Voter::Nullification(nullification) => {
                if nullification.verify::<C, D>(context, &self.scheme, namespace) {
                    self.sent_nullification = true;
                    (true, Some(Voter::Nullification(nullification)))
                } else {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    (false, None)
                }
            }
            Voter::Finalization(finalization) => {
                if finalization.verify(context, &self.scheme, namespace) {
                    self.sent_finalization = true;
                    (true, Some(Voter::Finalization(finalization)))
                } else {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    (false, None)
                }
            }
        }
    }

    async fn add_constructed(&mut self, message: Voter<S, D>) {
        match &message {
            Voter::Notarize(notarize) => {
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;
                self.votes.insert_notarize(notarize.clone());
                self.verified_votes.insert_notarize(notarize.clone());
            }
            Voter::Nullify(nullify) => {
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;
                self.votes.insert_nullify(nullify.clone());
                self.verified_votes.insert_nullify(nullify.clone());
            }
            Voter::Finalize(finalize) => {
                self.reporter
                    .report(Activity::Finalize(finalize.clone()))
                    .await;
                self.votes.insert_finalize(finalize.clone());
                self.verified_votes.insert_finalize(finalize.clone());
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                unreachable!("recovered messages should be sent to batcher");
            }
        }
        self.verifier.add(message, true);
    }

    fn add_verified(&mut self, voters: Vec<Voter<S, D>>) -> Vec<Voter<S, D>> {
        let mut output = Vec::new();
        let leader = self.verifier.leader();
        for voter in voters {
            match voter {
                Voter::Notarize(notarize) => {
                    if Some(notarize.signer()) == leader && !self.sent_leader_notarize {
                        self.sent_leader_notarize = true;
                        output.push(Voter::Notarize(notarize.clone()));
                    }
                    self.verified_votes.insert_notarize(notarize);
                }
                Voter::Nullify(nullify) => {
                    if Some(nullify.signer()) == leader && !self.sent_leader_nullify {
                        self.sent_leader_nullify = true;
                        output.push(Voter::Nullify(nullify.clone()));
                    }
                    self.verified_votes.insert_nullify(nullify);
                }
                Voter::Finalize(finalize) => {
                    if Some(finalize.signer()) == leader && !self.sent_leader_finalize {
                        self.sent_leader_finalize = true;
                        output.push(Voter::Finalize(finalize.clone()));
                    }
                    self.verified_votes.insert_finalize(finalize);
                }
                _ => unreachable!("batch verifier should only return votes"),
            }
        }
        output
    }

    fn construct_notarization(&mut self) -> Option<Notarization<S, D>> {
        if self.sent_notarization {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_notarizes() < quorum {
            return None;
        }
        let notarization =
            Notarization::from_notarizes(&self.scheme, self.verified_votes.iter_notarizes())?;
        self.sent_notarization = true;
        Some(notarization)
    }

    fn construct_nullification(&mut self) -> Option<Nullification<S>> {
        if self.sent_nullification {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_nullifies() < quorum {
            return None;
        }
        let nullification =
            Nullification::from_nullifies(&self.scheme, self.verified_votes.iter_nullifies())?;
        self.sent_nullification = true;
        Some(nullification)
    }

    fn construct_finalization(&mut self) -> Option<Finalization<S, D>> {
        if self.sent_finalization {
            return None;
        }
        let quorum = self.participants.quorum() as usize;
        if self.verified_votes.len_finalizes() < quorum {
            return None;
        }
        let finalization =
            Finalization::from_finalizes(&self.scheme, self.verified_votes.iter_finalizes())?;
        self.sent_finalization = true;
        Some(finalization)
    }

    fn set_leader(&mut self, leader: u32) {
        self.verifier.set_leader(leader);
    }

    fn ready_notarizes(&self) -> bool {
        !self.sent_notarization && self.verifier.ready_notarizes()
    }

    fn verify_notarizes<E: Rng + CryptoRng>(
        &mut self,
        context: &mut E,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_notarizes(context, namespace)
    }

    fn ready_nullifies(&self) -> bool {
        !self.sent_nullification && self.verifier.ready_nullifies()
    }

    fn verify_nullifies<E: Rng + CryptoRng>(
        &mut self,
        context: &mut E,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_nullifies(context, namespace)
    }

    fn ready_finalizes(&self) -> bool {
        !self.sent_finalization && self.verifier.ready_finalizes()
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
        consensus: voter::Mailbox<S, D>,
        receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(consensus, receiver).await)
    }

    pub async fn run(
        mut self,
        mut consensus: voter::Mailbox<S, D>,
        receiver: impl Receiver<PublicKey = P>,
    ) {
        // Wrap channel
        let mut receiver: WrappedReceiver<_, Voter<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), receiver);

        // Initialize view data structures
        let mut current = View::zero();
        let mut finalized = View::zero();
        #[allow(clippy::type_complexity)]
        let mut work: BTreeMap<View, Round<P, S, B, D, R>> = BTreeMap::new();
        let mut initialized = false;

        loop {
            // Handle next message
            select! {
                message = self.mailbox_receiver.next() => {
                    match message {
                        Some(Message::Update {
                            current: new_current,
                            leader,
                            finalized: new_finalized,
                            active,
                        }) => {
                            current = new_current;
                            finalized = new_finalized;
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
                            let round = work.entry(view)
                                .or_insert_with(|| self.new_round(initialized));
                            round.add_constructed(message).await;

                            // Check if we can construct any certificates (from our own vote)
                            if let Some(notarization) = round.construct_notarization() {
                                let mut consensus = consensus.clone();
                                self.context.clone().spawn(move |_| async move {
                                    consensus.verified(Voter::Notarization(notarization)).await;
                                });
                            }
                            if let Some(nullification) = round.construct_nullification() {
                                let mut consensus = consensus.clone();
                                self.context.clone().spawn(move |_| async move {
                                    consensus.verified(Voter::Nullification(nullification)).await;
                                });
                            }
                            if let Some(finalization) = round.construct_finalization() {
                                let mut consensus = consensus.clone();
                                self.context.clone().spawn(move |_| async move {
                                    consensus.verified(Voter::Finalization(finalization)).await;
                                });
                            }
                            self.added.inc();
                        }
                        None => {
                            break;
                        }
                    }
                },
                message = receiver.recv() => {
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

                    // Add the message to the verifier
                    let (added, certificate) = work
                        .entry(view)
                        .or_insert_with(|| self.new_round(initialized))
                        .add(&mut self.context, &self.namespace, sender, message)
                        .await;
                    if added {
                        self.added.inc();
                    }
                    if let Some(certificate) = certificate {
                        let mut consensus = consensus.clone();
                        self.context.clone().spawn(move |_| async move {
                            consensus.verified(certificate).await;
                        });
                    }
                }
            }

            // Look for a ready verifier (prioritizing the current view)
            let mut timer = self.verify_latency.timer();
            let mut selected = None;
            if let Some(verifier) = work.get_mut(&current) {
                if verifier.ready_notarizes() {
                    let (voters, failed) =
                        verifier.verify_notarizes(&mut self.context, &self.namespace);
                    selected = Some((current, voters, failed));
                } else if verifier.ready_nullifies() {
                    let (voters, failed) =
                        verifier.verify_nullifies(&mut self.context, &self.namespace);
                    selected = Some((current, voters, failed));
                }
            }
            if selected.is_none() {
                let potential = work
                    .iter_mut()
                    .rev()
                    .find(|(view, verifier)| {
                        **view != current && **view >= finalized && verifier.ready_finalizes()
                    })
                    .map(|(view, verifier)| (*view, verifier));
                if let Some((view, verifier)) = potential {
                    let (voters, failed) =
                        verifier.verify_finalizes(&mut self.context, &self.namespace);
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

            // Send messages to voter
            let batch = voters.len() + failed.len();
            trace!(%view, batch, "batch verified messages");
            self.verified.inc_by(batch as u64);
            self.batch_size.observe(batch as f64);

            // Process verified votes
            let round = work.get_mut(&view).expect("round must exist");
            let to_send = round.add_verified(voters);
            for msg in to_send {
                let mut consensus = consensus.clone();
                self.context.clone().spawn(move |_| async move {
                    consensus.verified(msg).await;
                });
            }
            if let Some(notarization) = round.construct_notarization() {
                let mut consensus = consensus.clone();
                self.context.clone().spawn(move |_| async move {
                    consensus.verified(Voter::Notarization(notarization)).await;
                });
            }
            if let Some(nullification) = round.construct_nullification() {
                let mut consensus = consensus.clone();
                self.context.clone().spawn(move |_| async move {
                    consensus
                        .verified(Voter::Nullification(nullification))
                        .await;
                });
            }
            if let Some(finalization) = round.construct_finalization() {
                let mut consensus = consensus.clone();
                self.context.clone().spawn(move |_| async move {
                    consensus.verified(Voter::Finalization(finalization)).await;
                });
            }

            // Check for certificates
            if let Some(notarization) = round.construct_notarization() {
                consensus.verified(Voter::Notarization(notarization)).await;
            }
            if let Some(nullification) = round.construct_nullification() {
                consensus
                    .verified(Voter::Nullification(nullification))
                    .await;
            }
            if let Some(finalization) = round.construct_finalization() {
                consensus.verified(Voter::Finalization(finalization)).await;
            }

            // Block invalid signers
            if !failed.is_empty() {
                for invalid in failed {
                    if let Some(signer) = self.participants.key(invalid) {
                        warn!(?signer, "blocking peer");
                        self.blocker.block(signer.clone()).await;
                    }
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
