use super::{Config, Mailbox, Message};
use crate::{
    threshold_simplex::{
        actors::voter,
        types::{
            Activity, Attributable, ConflictingFinalize, ConflictingNotarize, Finalize, Notarize,
            Nullify, NullifyFinalize, PartialVerifier, View, Viewable, Voter,
        },
    },
    Reporter, ThresholdSupervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{poly, variant::Variant},
    Digest, Scheme, Verifier,
};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{Handle, Metrics, Spawner};
use commonware_utils::quorum;
use futures::{channel::mpsc, StreamExt};
use prometheus_client::metrics::{counter::Counter, histogram::Histogram};
use std::{collections::BTreeMap, marker::PhantomData};
use tracing::{trace, warn};

async fn recv_batch<T, F>(rx: &mut mpsc::Receiver<T>, block: bool, mut f: F) -> bool
where
    F: FnMut(T),
{
    if block {
        match rx.next().await {
            Some(first) => {
                f(first);
                while let Ok(Some(item)) = rx.try_next() {
                    f(item);
                }
                true // processed at least one item
            }
            None => false, // channel closed
        }
    } else {
        while let Ok(Some(item)) = rx.try_next() {
            f(item);
        }
        true
    }
}

struct Round<
    C: Verifier,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    D: Digest,
    R: Reporter<Activity = Activity<V, D>>,
    S: ThresholdSupervisor<
        Index = View,
        Identity = poly::Public<V>,
        PublicKey = C::PublicKey,
        Public = V::Public,
    >,
> {
    view: View,

    blocker: B,
    reporter: R,
    supervisor: S,
    verifier: PartialVerifier<V, D>,
    notarizes: Vec<Option<Notarize<V, D>>>,
    nullifies: Vec<Option<Nullify<V>>>,
    finalizes: Vec<Option<Finalize<V, D>>>,

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
            Identity = poly::Public<V>,
            PublicKey = C::PublicKey,
            Public = V::Public,
        >,
    > Round<C, B, V, D, R, S>
{
    fn new(blocker: B, reporter: R, supervisor: S, view: View, batch: bool) -> Self {
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
            verifier: PartialVerifier::new(quorum),

            notarizes: vec![None; participants],
            nullifies: vec![None; participants],
            finalizes: vec![None; participants],

            _phantom: PhantomData,
        }
    }

    async fn add(&mut self, sender: C::PublicKey, message: Voter<V, D>) {
        // Check if sender is a participant
        let Some(index) = self.supervisor.is_participant(self.view, &sender) else {
            self.blocker.block(sender).await;
            return;
        };

        // Attempt to reserve
        match message {
            Voter::Notarize(notarize) => {
                // Verify sender is signer
                if index != notarize.signer() {
                    self.blocker.block(sender).await;
                    return;
                }

                // Try to reserve
                match self.notarizes[index as usize] {
                    Some(ref previous) => {
                        if previous != &notarize {
                            let activity = ConflictingNotarize::new(previous.clone(), notarize);
                            self.reporter
                                .report(Activity::ConflictingNotarize(activity))
                                .await;
                            self.blocker.block(sender).await;
                        }
                    }
                    None => {
                        self.reporter
                            .report(Activity::Notarize(notarize.clone()))
                            .await;
                        self.notarizes[index as usize] = Some(notarize.clone());
                        self.verifier.add(Voter::Notarize(notarize), false);
                    }
                }
            }
            Voter::Nullify(nullify) => {
                // Verify sender is signer
                if index != nullify.signer() {
                    self.blocker.block(sender).await;
                    return;
                }

                // Check if finalized
                match self.finalizes[index as usize] {
                    None => {}
                    Some(ref previous) => {
                        let activity = NullifyFinalize::new(nullify, previous.clone());
                        self.reporter
                            .report(Activity::NullifyFinalize(activity))
                            .await;
                        self.blocker.block(sender).await;
                        return;
                    }
                }

                // Try to reserve
                match self.nullifies[index as usize] {
                    Some(ref previous) => {
                        if previous != &nullify {
                            self.blocker.block(sender).await;
                        }
                    }
                    None => {
                        self.reporter
                            .report(Activity::Nullify(nullify.clone()))
                            .await;
                        self.nullifies[index as usize] = Some(nullify.clone());
                        self.verifier.add(Voter::Nullify(nullify), false);
                    }
                }
            }
            Voter::Finalize(finalize) => {
                // Verify sender is signer
                if index != finalize.signer() {
                    self.blocker.block(sender).await;
                    return;
                }

                // Check if nullified
                match self.nullifies[index as usize] {
                    Some(ref previous) => {
                        let activity = NullifyFinalize::new(previous.clone(), finalize);
                        self.reporter
                            .report(Activity::NullifyFinalize(activity))
                            .await;
                        self.blocker.block(sender).await;
                        return;
                    }
                    None => {}
                }

                // Try to reserve
                match self.finalizes[index as usize] {
                    Some(ref previous) => {
                        if previous != &finalize {
                            let activity = ConflictingFinalize::new(previous.clone(), finalize);
                            self.reporter
                                .report(Activity::ConflictingFinalize(activity))
                                .await;
                            self.blocker.block(sender).await;
                        }
                    }
                    None => {
                        self.reporter
                            .report(Activity::Finalize(finalize.clone()))
                            .await;
                        self.finalizes[index as usize] = Some(finalize.clone());
                        self.verifier.add(Voter::Finalize(finalize), false);
                    }
                }
            }
            Voter::Notarization(_) | Voter::Finalization(_) | Voter::Nullification(_) => {
                self.blocker.block(sender).await;
            }
        }
    }

    fn add_verified(&mut self, message: Voter<V, D>) {
        match &message {
            Voter::Notarize(notarize) => {
                let signer = notarize.signer() as usize;
                self.notarizes[signer] = Some(notarize.clone());
            }
            Voter::Nullify(nullify) => {
                let signer = nullify.signer() as usize;
                self.nullifies[signer] = Some(nullify.clone());
            }
            Voter::Finalize(finalize) => {
                let signer = finalize.signer() as usize;
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
}

pub struct Actor<
    E: Spawner + Metrics,
    C: Verifier,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    D: Digest,
    R: Reporter<Activity = Activity<V, D>>,
    S: ThresholdSupervisor<
        Index = View,
        Identity = poly::Public<V>,
        PublicKey = C::PublicKey,
        Public = V::Public,
    >,
> {
    context: E,
    blocker: B,
    supervisor: S,

    namespace: Vec<u8>,

    mailbox_receiver: mpsc::Receiver<Message<V, D>>,

    added: Counter,
    verified: Counter,
    batch_size: Histogram,

    _phantom_verifier: PhantomData<C>,
    _phantom_reporter: PhantomData<R>,
}

impl<
        E: Spawner + Metrics,
        C: Verifier,
        B: Blocker<PublicKey = C::PublicKey>,
        V: Variant,
        D: Digest,
        R: Reporter<Activity = Activity<V, D>>,
        S: ThresholdSupervisor<
            Index = View,
            Identity = poly::Public<V>,
            PublicKey = C::PublicKey,
            Public = V::Public,
        >,
    > Actor<E, C, B, V, D, R, S>
{
    pub fn new(context: E, cfg: Config<B, S>) -> (Self, Mailbox<V, D>) {
        let added = Counter::default();
        let verified = Counter::default();
        let batch_size =
            Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0].into_iter());
        context.register(
            "added",
            "number of messages added to the verifier",
            added.clone(),
        );
        context.register("verified", "number of messages verified", verified.clone());
        context.register(
            "batch_size",
            "number of messages in a partial signature verification batch",
            batch_size.clone(),
        );
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                blocker: cfg.blocker,
                supervisor: cfg.supervisor,

                namespace: cfg.namespace,

                mailbox_receiver: receiver,

                added,
                verified,
                batch_size,

                _phantom_verifier: PhantomData,
                _phantom_reporter: PhantomData,
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
        // Initialize view data structures
        let mut current: View = 0;
        let mut finalized: View = 0;
        let mut work: BTreeMap<u64, Round<C, B, V, D, R, S>> = BTreeMap::new();
        let mut blocking = true;
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
                            }) => {
                                current = new_current;
                                finalized = new_finalized;

                                // If this is our first item, we may have some previous work completed
                                // from before restart. We should just verify everything (may just be
                                // nullifies) as soon as we can.
                                if initialized {
                                    let quorum = Some(self.supervisor.identity(current).unwrap().required());
                                    work.entry(current)
                                        .or_insert(PartialVerifier::new(quorum))
                                        .set_leader(leader);
                                }
                            }
                            Some(Message::Verified(message)) => {
                                self.added.inc();

                                // Only add messages if the view matters to us
                                if message.view() >= finalized {

                            }
                        },
                        None => {
                            break;
                        }
                    }
                },
                message = receiver.next() => {
                    match message {
                        Some(message) => {

                        }
                    }
                },
            }

            // Look for a ready verifier (prioritizing the current view)
            let mut selected = None;
            if let Some(verifier) = work.get_mut(&current) {
                if verifier.ready_notarizes() {
                    let identity = self.supervisor.identity(current).unwrap();
                    let (voters, failed) = verifier.verify_notarizes(&self.namespace, identity);
                    selected = Some((current, voters, failed));
                } else if verifier.ready_nullifies() {
                    let identity = self.supervisor.identity(current).unwrap();
                    let (voters, failed) = verifier.verify_nullifies(&self.namespace, identity);
                    selected = Some((current, voters, failed));
                }
            }
            if selected.is_none() {
                let potential = work
                    .iter_mut()
                    .rev()
                    .find(|(view, verifier)| {
                        *view != &current && *view >= finalized && verifier.ready_finalizes()
                    })
                    .map(|(view, verifier)| (*view, verifier));
                if let Some((view, verifier)) = potential {
                    let identity = self.supervisor.identity(view).unwrap();
                    let (voters, failed) = verifier.verify_finalizes(&self.namespace, identity);
                    selected = Some((view, voters, failed));
                }
            }
            let Some((view, voters, failed)) = selected else {
                blocking = true;
                trace!(
                    current,
                    finalized,
                    waiting = work.len(),
                    "no verifier ready"
                );
                continue;
            };
            blocking = false;

            // Send messages
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

            // TODO: Drop any rounds that are no longer interesting
            work.retain(|view, _| *view >= finalized);
        }
    }
}
