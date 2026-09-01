//! Notifications from the catalog to delivery.

use super::batch::DurableBatch;
use crate::multimmit::{
    actors::util::Completion,
    marshal::{actors::catalog, types::OutputIndex},
    types::Body,
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::Hasher;
use commonware_runtime::Metrics as RuntimeMetrics;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, num::NonZeroUsize};

/// A notification from the catalog.
pub(crate) enum Message<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// A published commit made these outputs deliverable.
    Committed(DurableBatch<H, B>),
    /// A floor installation replaced the delivery generation.
    Reset {
        floor_generation: u64,
        /// Output the new generation starts after.
        acknowledged: Option<OutputIndex>,
        /// Resolved once delivery has applied the reset.
        waiters: Vec<oneshot::Sender<Result<(), catalog::Error>>>,
    },
}

/// Coalesces committed batches between resets; the newest reset supersedes every queued message
/// and inherits the waiters of older resets.
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
            Self::Reset {
                floor_generation,
                acknowledged,
                mut waiters,
            } => {
                for message in overflow.drain(..) {
                    if let Self::Reset { waiters: older, .. } = message {
                        waiters.extend(older);
                    }
                }
                overflow.push_back(Self::Reset {
                    floor_generation,
                    acknowledged,
                    waiters,
                });
            }
        }
    }
}

/// Resolved once delivery has applied a generation reset.
///
/// If delivery stops first, it resolves to [`catalog::Error::DeliveryClosed`].
pub(crate) type ResetWaiter = Completion<catalog::Error>;

/// The receiving half of the delivery mailbox.
pub(crate) type Receiver<H, B> = mailbox::Receiver<Message<H, B>>;

/// The catalog's client for delivery.
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

    /// Resets delivery to a newly installed generation, returning `None` if delivery stopped.
    pub(crate) fn reset(
        &self,
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
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
