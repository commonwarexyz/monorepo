use super::{Config, Mailbox, Message};
use crate::{
    threshold_simplex::{
        actors::voter,
        interesting,
        metrics::Inbound,
        types::{
            Activity, Attributable, BatchVerifier, ConflictingFinalize, ConflictingNotarize,
            Finalize, Notarize, Nullify, NullifyFinalize, View, Viewable, Voter,
        },
    },
    Reporter, ThresholdSupervisor,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest, Verifier};
use commonware_macros::select;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver};
use commonware_runtime::{
    telemetry::metrics::histogram::{self, Buckets},
    Clock, Handle, Metrics, Spawner,
};
use commonware_utils::quorum;
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, family::Family, histogram::Histogram};
use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};
use tracing::{trace, warn};

struct Round<
    C: Verifier,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    D: Digest,
    R: Reporter<Activity = Activity<V, D>>,
    S: ThresholdSupervisor<
        Index = View,
        Polynomial = Vec<V::Public>,
        PublicKey = C::PublicKey,
        Identity = V::Public,
    >,
> {
    view: View,

    blocker: B,
    reporter: R,
    supervisor: S,
    verifier: BatchVerifier<V, D>,
    notarizes: Vec<Option<Notarize<V, D>>>,
    nullifies: Vec<Option<Nullify<V>>>,
    finalizes: Vec<Option<Finalize<V, D>>>,

    inbound_messages: Family<Inbound, Counter>,

    _phantom: PhantomData<C>,
}

impl<
        C: Verifier,
        B: Blocker<PublicKey = C::PublicKey>,
        V: Variant,
        D: Digest,
        R: Reporter<Activity = Activity<V, D>>,
        S: ThresholdSupervisor<
            Index = View,
            Polynomial = Vec<V::Public>,
            PublicKey = C::PublicKey,
            Identity = V::Public,
        >,
    > Round<C, B, V, D, R, S>
{
    fn new(
        blocker: B,
        reporter: R,
        supervisor: S,
        inbound_messages: Family<Inbound, Counter>,
        view: View,
        batch: bool,
    ) -> Self {
        // Configure quorum params
        let participants = supervisor.participants(view).unwrap().len();
        let quorum = if batch {
            Some(quorum(participants as u32))
        } else {
            None
        };

        // Initialize data structures
        Self {
            view,

            blocker,
            reporter,
            supervisor,
            verifier: BatchVerifier::new(quorum),

            notarizes: vec![None; participants],
            nullifies: vec![None; participants],
            finalizes: vec![None; participants],

            inbound_messages,

            _phantom: PhantomData,
        }
    }

    async fn add(&mut self, sender: C::PublicKey, message: Voter<V, D>) -> bool {
        // Check if sender is a participant
        let Some(index) = self.supervisor.is_participant(self.view, &sender) else {
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
                match self.notarizes[index as usize] {
                    Some(ref previous) => {
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
                        self.notarizes[index as usize] = Some(notarize.clone());
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
                if let Some(ref previous) = self.finalizes[index as usize] {
                    let activity = NullifyFinalize::new(nullify, previous.clone());
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.nullifies[index as usize] {
                    Some(ref previous) => {
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
                        self.nullifies[index as usize] = Some(nullify.clone());
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
                if let Some(ref previous) = self.nullifies[index as usize] {
                    let activity = NullifyFinalize::new(previous.clone(), finalize);
                    self.reporter
                        .report(Activity::NullifyFinalize(activity))
                        .await;
                    warn!(?sender, "blocking peer");
                    self.blocker.block(sender).await;
                    return false;
                }

                // Try to reserve
                match self.finalizes[index as usize] {
                    Some(ref previous) => {
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
                        self.finalizes[index as usize] = Some(finalize.clone());
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

    async fn add_constructed(&mut self, message: Voter<V, D>) {
        match &message {
            Voter::Notarize(notarize) => {
                let signer = notarize.signer() as usize;
                self.reporter
                    .report(Activity::Notarize(notarize.clone()))
                    .await;
                self.notarizes[signer] = Some(notarize.clone());
            }
            Voter::Nullify(nullify) => {
                let signer = nullify.signer() as usize;
                self.reporter
                    .report(Activity::Nullify(nullify.clone()))
                    .await;
                self.nullifies[signer] = Some(nullify.clone());
            }
            Voter::Finalize(finalize) => {
                let signer = finalize.signer() as usize;
                self.reporter
                    .report(Activity::Finalize(finalize.clone()))
                    .await;
                self.finalizes[signer] = Some(finalize.clone());
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                unreachable!("recovered messages should be sent to batcher");
            }
        }
        self.verifier.add(message, true);
    }

    fn set_leader(&mut self, leader: u32) {
        self.verifier.set_leader(leader);
    }

    fn ready_notarizes(&self) -> bool {
        self.verifier.ready_notarizes()
    }

    fn verify_notarizes(&mut self, namespace: &[u8]) -> (Vec<Voter<V, D>>, Vec<u32>) {
        let polynomial = self.supervisor.polynomial(self.view).unwrap();
        self.verifier.verify_notarizes(namespace, polynomial)
    }

    fn ready_nullifies(&self) -> bool {
        self.verifier.ready_nullifies()
    }

    fn verify_nullifies(&mut self, namespace: &[u8]) -> (Vec<Voter<V, D>>, Vec<u32>) {
        let polynomial = self.supervisor.polynomial(self.view).unwrap();
        self.verifier.verify_nullifies(namespace, polynomial)
    }

    fn ready_finalizes(&self) -> bool {
        self.verifier.ready_finalizes()
    }

    fn verify_finalizes(&mut self, namespace: &[u8]) -> (Vec<Voter<V, D>>, Vec<u32>) {
        let polynomial = self.supervisor.polynomial(self.view).unwrap();
        self.verifier.verify_finalizes(namespace, polynomial)
    }

    fn is_active(&self, leader: &C::PublicKey) -> Option<bool> {
        let leader_index = self.supervisor.is_participant(self.view, leader)?;
        Some(
            self.notarizes[leader_index as usize].is_some()
                || self.nullifies[leader_index as usize].is_some(),
        )
    }
}

pub struct Actor<
    E: Spawner + Metrics + Clock,
    C: Verifier,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    D: Digest,
    R: Reporter<Activity = Activity<V, D>>,
    S: ThresholdSupervisor<
        Index = View,
        PublicKey = C::PublicKey,
        Identity = V::Public,
        Polynomial = Vec<V::Public>,
    >,
> {
    context: E,
    blocker: B,
    reporter: R,
    supervisor: S,

    activity_timeout: View,
    skip_timeout: View,
    namespace: Vec<u8>,

    mailbox_receiver: mpsc::Receiver<Message<C::PublicKey, V, D>>,

    added: Counter,
    verified: Counter,
    inbound_messages: Family<Inbound, Counter>,
    batch_size: Histogram,
    verify_latency: histogram::Timed<E>,

    _phantom: PhantomData<C>,
}

impl<
        E: Spawner + Metrics + Clock,
        C: Verifier,
        B: Blocker<PublicKey = C::PublicKey>,
        V: Variant,
        D: Digest,
        R: Reporter<Activity = Activity<V, D>>,
        S: ThresholdSupervisor<
            Index = View,
            PublicKey = C::PublicKey,
            Identity = V::Public,
            Polynomial = Vec<V::Public>,
        >,
    > Actor<E, C, B, V, D, R, S>
{
    pub fn new(context: E, cfg: Config<B, R, S>) -> (Self, Mailbox<C::PublicKey, V, D>) {
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
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: context.clone(),
                blocker: cfg.blocker,
                reporter: cfg.reporter,
                supervisor: cfg.supervisor,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                namespace: cfg.namespace,

                mailbox_receiver: receiver,

                added,
                verified,
                inbound_messages,
                batch_size,
                verify_latency: histogram::Timed::new(verify_latency, Arc::new(context)),
                _phantom: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        consensus: voter::Mailbox<V, D>,
        receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(consensus, receiver))
    }

    pub async fn run(
        mut self,
        mut consensus: voter::Mailbox<V, D>,
        receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) {
        // Wrap channel
        let mut receiver: WrappedReceiver<_, Voter<V, D>> = WrappedReceiver::new((), receiver);

        // Initialize view data structures
        let mut current: View = 0;
        let mut finalized: View = 0;
        let mut work: BTreeMap<u64, Round<C, B, V, D, R, S>> = BTreeMap::new();
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
                            let leader_index = self.supervisor.is_participant(current, &leader).unwrap();
                            work.entry(current)
                                .or_insert(Round::new(self.blocker.clone(), self.reporter.clone(), self.supervisor.clone(), self.inbound_messages.clone(), current, initialized))
                                .set_leader(leader_index);
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
                                let Some(active) = round.is_active(&leader) else {
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
                            work.entry(view).or_insert(
                                Round::new(self.blocker.clone(), self.reporter.clone(), self.supervisor.clone(), self.inbound_messages.clone(), view, initialized)
                            ).add_constructed(message).await;
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
                        warn!(?sender, "blocking peer");
                        self.blocker.block(sender).await;
                        continue;
                    };

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
                    let added = work.entry(view).or_insert(
                        Round::new(self.blocker.clone(), self.reporter.clone(), self.supervisor.clone(), self.inbound_messages.clone(), view, initialized)
                    ).add(sender, message).await;
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
                    let (voters, failed) = verifier.verify_notarizes(&self.namespace);
                    selected = Some((current, voters, failed));
                } else if verifier.ready_nullifies() {
                    let (voters, failed) = verifier.verify_nullifies(&self.namespace);
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
                    let (voters, failed) = verifier.verify_finalizes(&self.namespace);
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
            consensus.verified(voters).await;

            // Block invalid signers
            if !failed.is_empty() {
                let participants = self.supervisor.participants(view).unwrap();
                for invalid in failed {
                    let signer = participants[invalid as usize].clone();
                    warn!(?signer, "blocking peer");
                    self.blocker.block(signer).await;
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
