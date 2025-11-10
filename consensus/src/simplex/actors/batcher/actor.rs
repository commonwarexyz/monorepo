use super::{Config, Mailbox, Message};
use crate::{
    simplex::{
        actors::voter,
        interesting,
        metrics::Inbound,
        signing_scheme::Scheme,
        types::{
            Activity, Attributable, AttributableMap, BatchVerifier, ConflictingFinalize,
            ConflictingNotarize, Finalization, Finalize, Notarization, Notarize, Nullification,
            Nullify, NullifyFinalize, OrderedExt, Voter,
        },
    },
    types::{Epoch, View},
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
use commonware_utils::{max_faults, set::Ordered};
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, convert::TryFrom, sync::Arc};
use tracing::{trace, warn};

struct Round<
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    participants: Ordered<P>,
    quorum: usize,

    blocker: B,
    reporter: R,
    verifier: BatchVerifier<S, D>,
    scheme: S,
    notarizes: AttributableMap<Notarize<S, D>>,
    nullifies: AttributableMap<Nullify<S>>,
    finalizes: AttributableMap<Finalize<S, D>>,
    notarize_verified: Vec<bool>,
    notarize_verified_count: usize,
    notarize_support_threshold: usize,
    notarize_support_ready: bool,
    notarize_support_notified: bool,
    nullify_verified: Vec<bool>,
    nullify_verified_count: usize,
    finalize_verified: Vec<bool>,
    finalize_verified_count: usize,

    leader: Option<u32>,
    leader_proposal_sent: bool,
    notarization_sent: bool,
    nullification_sent: bool,
    finalization_sent: bool,

    inbound_messages: Family<Inbound, Counter>,
}

enum Event<S: Scheme, D: Digest> {
    LeaderProposal(Notarize<S, D>),
    NotarizeSupport,
    Notarization(Notarization<S, D>),
    Nullification(Nullification<S>),
    Finalization(Finalization<S, D>),
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
        let quorum = participants.quorum() as usize;
        let verifier_quorum = if batch {
            Some(u32::try_from(quorum).expect("quorum should fit in u32 for batch verification"))
        } else {
            None
        };

        let notarizes = AttributableMap::new(participants.len());
        let nullifies = AttributableMap::new(participants.len());
        let finalizes = AttributableMap::new(participants.len());
        let notarize_verified = vec![false; participants.len()];
        let nullify_verified = vec![false; participants.len()];
        let finalize_verified = vec![false; participants.len()];
        let support_threshold =
            max_faults(u32::try_from(participants.len()).expect("participant count fits in u32"))
                as usize
                + 1;

        // Initialize data structures
        Self {
            participants,
            quorum,

            blocker,
            reporter,
            verifier: BatchVerifier::new(scheme.clone(), verifier_quorum),
            scheme,

            notarizes,
            nullifies,
            finalizes,
            notarize_verified,
            notarize_verified_count: 0,
            notarize_support_threshold: support_threshold,
            notarize_support_ready: false,
            notarize_support_notified: false,
            nullify_verified,
            nullify_verified_count: 0,
            finalize_verified,
            finalize_verified_count: 0,

            leader: None,
            leader_proposal_sent: false,
            notarization_sent: false,
            nullification_sent: false,
            finalization_sent: false,

            inbound_messages,
        }
    }

    fn mark_notarize_verified(&mut self, signer: u32) -> bool {
        let idx = signer as usize;
        if self.notarize_verified.get(idx).copied().unwrap_or(false) {
            return false;
        }
        if let Some(entry) = self.notarize_verified.get_mut(idx) {
            *entry = true;
            self.notarize_verified_count += 1;
            if self.notarize_verified_count >= self.notarize_support_threshold {
                self.notarize_support_ready = true;
            }
            return true;
        }
        false
    }

    fn mark_nullify_verified(&mut self, signer: u32) -> bool {
        let idx = signer as usize;
        if self.nullify_verified.get(idx).copied().unwrap_or(false) {
            return false;
        }
        if let Some(entry) = self.nullify_verified.get_mut(idx) {
            *entry = true;
            self.nullify_verified_count += 1;
            return true;
        }
        false
    }

    fn mark_finalize_verified(&mut self, signer: u32) -> bool {
        let idx = signer as usize;
        if self.finalize_verified.get(idx).copied().unwrap_or(false) {
            return false;
        }
        if let Some(entry) = self.finalize_verified.get_mut(idx) {
            *entry = true;
            self.finalize_verified_count += 1;
            return true;
        }
        false
    }

    fn leader_notarize(&self) -> Option<Notarize<S, D>> {
        let leader = self.leader?;
        self.notarizes.get(leader).cloned()
    }

    fn collect_verified<T: Attributable + Clone>(
        map: &AttributableMap<T>,
        verified: &[bool],
    ) -> Vec<T> {
        verified
            .iter()
            .enumerate()
            .filter_map(|(idx, ok)| {
                if *ok {
                    map.get(idx as u32).cloned()
                } else {
                    None
                }
            })
            .collect()
    }

    fn collect_verified_notarizes(&self) -> Vec<Notarize<S, D>> {
        Self::collect_verified(&self.notarizes, &self.notarize_verified)
    }

    fn collect_verified_nullifies(&self) -> Vec<Nullify<S>> {
        Self::collect_verified(&self.nullifies, &self.nullify_verified)
    }

    fn collect_verified_finalizes(&self) -> Vec<Finalize<S, D>> {
        Self::collect_verified(&self.finalizes, &self.finalize_verified)
    }

    fn build_notarization(&mut self) -> Option<Notarization<S, D>> {
        if self.notarization_sent || self.notarize_verified_count < self.quorum {
            return None;
        }
        let votes = self.collect_verified_notarizes();
        if votes.len() < self.quorum {
            return None;
        }
        let notarization = Notarization::from_notarizes(&self.scheme, &votes)?;
        self.notarization_sent = true;
        Some(notarization)
    }

    fn build_nullification(&mut self) -> Option<Nullification<S>> {
        if self.nullification_sent || self.nullify_verified_count < self.quorum {
            return None;
        }
        let votes = self.collect_verified_nullifies();
        if votes.len() < self.quorum {
            return None;
        }
        let nullification = Nullification::from_nullifies(&self.scheme, &votes)?;
        self.nullification_sent = true;
        Some(nullification)
    }

    fn build_finalization(&mut self) -> Option<Finalization<S, D>> {
        if self.finalization_sent || self.finalize_verified_count < self.quorum {
            return None;
        }
        let votes = self.collect_verified_finalizes();
        if votes.len() < self.quorum {
            return None;
        }
        let finalization = Finalization::from_finalizes(&self.scheme, &votes)?;
        self.finalization_sent = true;
        Some(finalization)
    }

    async fn add(&mut self, sender: P, message: Voter<S, D>) -> bool {
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

                // Verify sender is signer
                if index != notarize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.notarizes.get(index) {
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
                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        self.notarizes.insert(notarize.clone());
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

                // Verify sender is signer
                if index != nullify.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Check if finalized
                if let Some(previous) = self.finalizes.get(index) {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.nullifies.get(index) {
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
                        self.nullifies.insert(nullify.clone());
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

                // Verify sender is signer
                if index != finalize.signer() {
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Check if nullified
                if let Some(previous) = self.nullifies.get(index) {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.finalizes.get(index) {
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
                        self.finalizes.insert(finalize.clone());
                        self.verifier.add(Voter::Finalize(finalize), false);
                        true
                    }
                }
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                warn!(?sender, "blocking peer");
                self.blocker.block(sender).await;
                false
            }
        }
    }

    async fn add_constructed(&mut self, message: Voter<S, D>) -> Vec<Event<S, D>> {
        match &message {
            Voter::Notarize(notarize) => {
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;
                self.notarizes.insert(notarize.clone());
            }
            Voter::Nullify(nullify) => {
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;
                self.nullifies.insert(nullify.clone());
            }
            Voter::Finalize(finalize) => {
                self.reporter
                    .report(Activity::Finalize(finalize.clone()))
                    .await;
                self.finalizes.insert(finalize.clone());
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                unreachable!("recovered messages should be sent to batcher");
            }
        }
        let cloned = message.clone();
        self.verifier.add(message, true);
        self.on_verified(cloned)
    }

    fn set_leader(&mut self, leader: u32) -> Option<Notarize<S, D>> {
        self.verifier.set_leader(leader);
        self.leader = Some(leader);

        if self.leader_proposal_sent {
            return None;
        }
        if self
            .notarize_verified
            .get(leader as usize)
            .copied()
            .unwrap_or(false)
        {
            if let Some(notarize) = self.leader_notarize() {
                self.leader_proposal_sent = true;
                return Some(notarize);
            }
        }
        None
    }

    fn ready_notarizes(&self) -> bool {
        self.verifier.ready_notarizes()
            || (self.notarize_support_ready && self.leader_proposal_sent)
    }

    fn verify_notarizes<E: Rng + CryptoRng>(
        &mut self,
        rng: &mut E,
        namespace: &[u8],
    ) -> (Vec<Voter<S, D>>, Vec<u32>) {
        self.verifier.verify_notarizes(rng, namespace)
    }

    fn ready_nullifies(&self) -> bool {
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
        Some(self.notarizes.get(leader).is_some() || self.nullifies.get(leader).is_some())
    }

    fn on_verified(&mut self, message: Voter<S, D>) -> Vec<Event<S, D>> {
        let mut events = Vec::new();
        match message {
            Voter::Notarize(notarize) => {
                let signer = notarize.signer();
                if self.mark_notarize_verified(signer) {
                    if self.notarize_support_ready && !self.notarize_support_notified {
                        self.notarize_support_notified = true;
                        events.push(Event::NotarizeSupport);
                    }
                    if self.leader == Some(signer) && !self.leader_proposal_sent {
                        self.leader_proposal_sent = true;
                        events.push(Event::LeaderProposal(notarize.clone()));
                    }
                    if let Some(notarization) = self.build_notarization() {
                        events.push(Event::Notarization(notarization));
                    }
                }
            }
            Voter::Nullify(nullify) => {
                let signer = nullify.signer();
                if self.mark_nullify_verified(signer) {
                    if let Some(nullification) = self.build_nullification() {
                        events.push(Event::Nullification(nullification));
                    }
                }
            }
            Voter::Finalize(finalize) => {
                let signer = finalize.signer();
                if self.mark_finalize_verified(signer) {
                    if let Some(finalization) = self.build_finalization() {
                        events.push(Event::Finalization(finalization));
                    }
                }
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                unreachable!()
            }
        }
        events
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

    activity_timeout: View,
    skip_timeout: View,
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
            Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0].into_iter());
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
        let verify_latency = Histogram::new(Buckets::CRYPTOGRAPHY.into_iter());
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
        let mut current: View = 0;
        let mut finalized: View = 0;
        #[allow(clippy::type_complexity)]
        let mut work: BTreeMap<u64, Round<P, S, B, D, R>> = BTreeMap::new();
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
                            let events = work
                                .entry(current)
                                .or_insert_with(|| self.new_round(initialized))
                                .set_leader(leader)
                                .into_iter()
                                .map(Event::LeaderProposal)
                                .collect::<Vec<_>>();
                            if !events.is_empty() {
                                Self::dispatch_events(&mut consensus, current, events).await;
                            }
                            initialized = true;

                            // If we haven't seen enough rounds yet, assume active
                            if current < self.skip_timeout || (work.len() as u64) < self.skip_timeout {
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
                            let events = work
                                .entry(view)
                                .or_insert_with(|| self.new_round(initialized))
                                .add_constructed(message)
                                .await;
                            Self::dispatch_events(&mut consensus, view, events).await;
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
                    let added = work
                        .entry(view)
                        .or_insert_with(|| self.new_round(initialized))
                        .add(sender, message)
                        .await;
                    if added {
                        self.added.inc();
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
                    current,
                    finalized,
                    waiting = work.len(),
                    "no verifier ready"
                );
                continue;
            };
            timer.observe();

            // Send messages to voter
            let batch = voters.len() + failed.len();
            trace!(view, batch, "batch verified messages");
            self.verified.inc_by(batch as u64);
            self.batch_size.observe(batch as f64);
            if let Some(round) = work.get_mut(&view) {
                let mut events = Vec::new();
                for voter in voters {
                    events.extend(round.on_verified(voter));
                }
                let _ = round;
                Self::dispatch_events(&mut consensus, view, events).await;
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

    async fn dispatch_events(
        consensus: &mut voter::Mailbox<S, D>,
        view: View,
        events: Vec<Event<S, D>>,
    ) {
        for event in events {
            match event {
                Event::LeaderProposal(notarize) => {
                    consensus
                        .send(voter::Message::LeaderNotarize(notarize))
                        .await
                }
                Event::NotarizeSupport => {
                    consensus
                        .send(voter::Message::NotarizeSupport { view })
                        .await
                }
                Event::Notarization(notarization) => {
                    consensus
                        .send(voter::Message::Notarization(notarization))
                        .await
                }
                Event::Nullification(nullification) => {
                    consensus
                        .send(voter::Message::Nullification(nullification))
                        .await
                }
                Event::Finalization(finalization) => {
                    consensus
                        .send(voter::Message::Finalization(finalization))
                        .await
                }
            }
        }
    }
}
