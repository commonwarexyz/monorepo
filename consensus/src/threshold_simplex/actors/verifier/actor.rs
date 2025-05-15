use super::{Config, Mailbox, Message};
use crate::{
    threshold_simplex::{
        actors::voter,
        types::{PartialVerifier, View, Viewable},
    },
    ThresholdSupervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{poly, variant::Variant},
    Digest, Scheme,
};
use commonware_p2p::Blocker;
use commonware_runtime::{Handle, Metrics, Spawner};
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

pub struct Actor<
    E: Spawner + Metrics,
    C: Scheme,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    D: Digest,
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

    _phantom: PhantomData<C>,
}

impl<
        E: Spawner + Metrics,
        C: Scheme,
        B: Blocker<PublicKey = C::PublicKey>,
        V: Variant,
        D: Digest,
        S: ThresholdSupervisor<
            Index = View,
            Identity = poly::Public<V>,
            PublicKey = C::PublicKey,
            Public = V::Public,
        >,
    > Actor<E, C, B, V, D, S>
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

                _phantom: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(mut self, consensus: voter::Mailbox<V, D>) -> Handle<()> {
        self.context.spawn_ref()(self.run(consensus))
    }

    pub async fn run(mut self, mut consensus: voter::Mailbox<V, D>) {
        // Initialize view data structures
        let mut current: View = 0;
        let mut finalized: View = 0;
        let mut work: BTreeMap<u64, PartialVerifier<V, D>> = BTreeMap::new();
        let mut blocking = true;
        let mut initialized = false;

        loop {
            // Read at least one message (if there doesn't already exist a backlog)
            if !recv_batch(&mut self.mailbox_receiver, blocking, |message| {
                match message {
                    Message::Update {
                        current: new_current,
                        leader,
                        finalized: new_finalized,
                    } => {
                        current = new_current;
                        finalized = new_finalized;

                        // If this is our first item, we may have some previous work completed
                        // from before restart. We should just verify everything (may just be
                        // nullifies) as soon as we can.
                        let quorum = if initialized {
                            Some(self.supervisor.identity(current).unwrap().required())
                        } else {
                            initialized = true;
                            None
                        };
                        work.entry(current)
                            .or_insert(PartialVerifier::new(quorum))
                            .set_leader(leader);
                    }
                    Message::Untrusted(message) => {
                        self.added.inc();

                        // Only add messages if the view matters to us
                        if message.view() >= finalized {
                            assert!(initialized);
                            let view = message.view();
                            let quorum = Some(self.supervisor.identity(view).unwrap().required());
                            work.entry(view)
                                .or_insert(PartialVerifier::new(quorum))
                                .add(message, false);
                        }
                    }
                    Message::Trusted(message) => {
                        // Only add messages if the view matters to us
                        if message.view() >= finalized {
                            assert!(initialized);
                            let view = message.view();
                            let quorum = Some(self.supervisor.identity(view).unwrap().required());
                            work.entry(message.view())
                                .or_insert(PartialVerifier::new(quorum))
                                .add(message, true);
                        }
                    }
                }
            })
            .await
            {
                return;
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
                    .find(|(view, verifier)| *view != &current && verifier.ready_finalizes())
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
            for msg in voters {
                consensus.voter(msg).await;
            }

            // Block invalid signers
            if !failed.is_empty() {
                let participants = self.supervisor.participants(view).unwrap();
                for invalid in failed {
                    let signer = participants[invalid as usize].clone();
                    warn!(?signer, "blocking peer");
                    self.blocker.block(signer).await;
                }
            }

            // Drop any verifiers lower than the last finalized view
            work.retain(|view, _| *view >= finalized);
        }
    }
}
