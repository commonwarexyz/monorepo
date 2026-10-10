//! Notifications from the catalog and the router to delivery.

use super::batch::DurableBatch;
use crate::{
    multimmit::{
        actors::util::Completion,
        marshal::actors::catalog,
        types::{Body, FinalityFact},
    },
    types::OutputIndex,
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::Hasher;
use commonware_runtime::Metrics as RuntimeMetrics;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, num::NonZeroUsize};

/// A notification from the catalog or the router.
pub(crate) enum Message<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// A published commit made these outputs deliverable.
    Committed(DurableBatch<H, B>),
    /// Consensus reported a leader finality fact.
    Finality(FinalityFact<H::Digest>),
    /// Custody admitted blocks on these producer chains, sorted and distinct.
    Admitted(Vec<u32>),
    /// A floor installation replaced the delivery generation.
    Reset {
        floor_generation: u64,
        /// Output the new generation starts after.
        acknowledged: OutputIndex,
        /// Resolved once delivery has applied the reset.
        waiters: Vec<oneshot::Sender<Result<(), catalog::Error>>>,
    },
}

/// Coalesces committed batches between resets, keeps only the latest finality fact, and merges
/// admission notices; the newest reset supersedes every queued batch and reset and inherits the
/// waiters of older resets.
impl<H, B> Policy for Message<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Committed(batch) => {
                let after_reset = overflow
                    .iter()
                    .rposition(|message| matches!(message, Self::Reset { .. }))
                    .map_or(0, |index| index + 1);
                if let Some(Self::Committed(pending)) = overflow
                    .range_mut(after_reset..)
                    .find(|message| matches!(message, Self::Committed(_)))
                {
                    pending.coalesce(batch);
                } else {
                    overflow.push_back(Self::Committed(batch));
                }
            }
            Self::Finality(fact) => {
                // A later view, or the same view with more votes, names final tips no lower.
                let rank = |fact: &FinalityFact<H::Digest>| (fact.round().view(), fact.votes());
                if let Some(index) = overflow
                    .iter()
                    .position(|message| matches!(message, Self::Finality(_)))
                {
                    let Self::Finality(queued) = &overflow[index] else {
                        unreachable!("the position matched a finality fact");
                    };
                    if rank(queued) >= rank(&fact) {
                        return;
                    }
                    overflow.remove(index);
                }
                overflow.push_back(Self::Finality(fact));
            }
            Self::Admitted(chains) => {
                if let Some(Self::Admitted(queued)) = overflow
                    .iter_mut()
                    .find(|message| matches!(message, Self::Admitted(_)))
                {
                    merge(queued, chains);
                } else {
                    overflow.push_back(Self::Admitted(chains));
                }
            }
            Self::Reset {
                floor_generation,
                acknowledged,
                mut waiters,
            } => {
                let mut finality = None;
                let mut admitted = None;
                for message in overflow.drain(..) {
                    match message {
                        Self::Reset { waiters: older, .. } => waiters.extend(older),
                        Self::Finality(fact) => finality = Some(fact),
                        Self::Admitted(chains) => admitted = Some(chains),
                        Self::Committed(_) => {}
                    }
                }
                overflow.push_back(Self::Reset {
                    floor_generation,
                    acknowledged,
                    waiters,
                });
                // Delivery applies the fact and the notice to the new generation.
                overflow.extend(finality.map(Self::Finality));
                overflow.extend(admitted.map(Self::Admitted));
            }
        }
    }
}

/// Merges the sorted, distinct `chains` into the sorted, distinct `into`.
fn merge(into: &mut Vec<u32>, chains: Vec<u32>) {
    into.extend(chains);
    into.sort_unstable();
    into.dedup();
}

/// Resolved once delivery has applied a generation reset.
///
/// If delivery stops first, it resolves to [`catalog::Error::DeliveryClosed`].
pub(crate) type ResetWaiter = Completion<catalog::Error>;

/// The receiving half of the delivery mailbox.
pub(crate) type Receiver<H, B> = mailbox::Receiver<Message<H, B>>;

/// The client for delivery: the catalog offers commits, resets and admission notices, the router
/// finality facts.
///
/// Complete batches keep the normal path in memory. Under pressure, queued batches coalesce into
/// a byte-bounded set of outputs and the newest committed output; delivery reads omitted outputs
/// from custody.
pub(crate) struct Mailbox<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    sender: mailbox::Sender<Message<H, B>>,
}

impl<H, B> Clone for Mailbox<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<H, B> Mailbox<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Offers the outputs a published commit made deliverable.
    pub(crate) fn committed(&self, batch: DurableBatch<H, B>) -> Feedback {
        self.sender.enqueue(Message::Committed(batch))
    }

    /// Offers a leader finality fact, whose final blocks delivery reports before they are
    /// ordered.
    pub(crate) fn finality(&self, fact: FinalityFact<H::Digest>) -> Feedback {
        self.sender.enqueue(Message::Finality(fact))
    }

    /// Tells delivery that custody admitted blocks on `chains`, sorted and distinct.
    pub(crate) fn admitted(&self, chains: Vec<u32>) -> Feedback {
        self.sender.enqueue(Message::Admitted(chains))
    }

    /// Resets delivery to a newly installed generation, returning `None` if delivery stopped.
    pub(crate) fn reset(
        &self,
        floor_generation: u64,
        acknowledged: OutputIndex,
    ) -> Option<ResetWaiter> {
        let (acknowledgement, waiter) = Completion::channel(|| catalog::Error::DeliveryClosed);
        (self.sender.enqueue(Message::Reset {
            floor_generation,
            acknowledged,
            waiters: vec![acknowledgement],
        }) != Feedback::Closed)
            .then_some(waiter)
    }
}

/// Creates the delivery mailbox.
///
/// The catalog needs this mailbox before delivery exists, and delivery needs the catalog's, so
/// the channel is created first and its receiver is passed to [`super::Actor::new`].
pub(crate) fn channel<H, B>(metrics: impl RuntimeMetrics) -> (Mailbox<H, B>, Receiver<H, B>)
where
    H: Hasher,
    B: Body<H>,
{
    let (sender, receiver) = mailbox::new(metrics, NonZeroUsize::MIN);
    (Mailbox { sender }, receiver)
}
