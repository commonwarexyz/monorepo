//! Ingress for the application actor.

use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_consensus::{
    Automaton, Reporter,
    multimmit::{
        FinalityFact,
        types::{Activity, BlockRef, ChainId, Context},
    },
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_runtime::Clock;
use commonware_utils::channel::oneshot;
use std::{
    collections::VecDeque,
    future::{Future, ready},
    sync::Arc,
    time::SystemTime,
};

/// Work sent to the application actor.
pub(super) enum Message {
    /// Build and stage a block for `context`, answering with its body digest.
    Propose {
        context: Context<Sha256Digest>,
        response: oneshot::Sender<Sha256Digest>,
    },
    /// Answer whether the block for `context` with body digest `body` is available and durable.
    Verify {
        context: Context<Sha256Digest>,
        body: Sha256Digest,
        response: oneshot::Sender<bool>,
    },
    /// Consensus finalized a leader at `at`.
    Finalized {
        fact: FinalityFact<Sha256Digest>,
        at: SystemTime,
    },
    /// Marshal delivered one of this node's blocks in the total order at `at`.
    Ordered {
        block: BlockRef<Sha256Digest>,
        at: SystemTime,
    },
}

impl Message {
    /// Returns whether the requester stopped waiting for the answer.
    fn is_obsolete(&self) -> bool {
        match self {
            Self::Propose { response, .. } => response.is_closed(),
            Self::Verify { response, .. } => response.is_closed(),
            Self::Finalized { .. } | Self::Ordered { .. } => false,
        }
    }
}

/// Messages that did not fit in the bounded mailbox, in arrival order.
///
/// Requests whose requester stopped waiting are discarded.
#[derive(Default)]
pub(super) struct Backlog(VecDeque<Message>);

impl Overflow<Message> for Backlog {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message) -> Option<Message>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.is_obsolete() {
                continue;
            }
            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl Policy for Message {
    type Overflow = Backlog;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.is_obsolete() {
            return;
        }
        overflow.0.push_back(message);
    }
}

/// Handle consensus and marshal use to reach the application actor.
///
/// It implements the consensus [`Automaton`] and [`Reporter`]. The reporter forwards only
/// finality facts; consensus reports every activity to marshal separately. Finality and ordered
/// delivery are timestamped here, when they are reported, so latency samples exclude time spent
/// in the actor's queue.
pub struct Mailbox<C> {
    sender: Sender<Message>,
    clock: Arc<C>,
    producer_chain: Option<ChainId>,
}

impl<C> Clone for Mailbox<C> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            clock: Arc::clone(&self.clock),
            producer_chain: self.producer_chain,
        }
    }
}

impl<C: Clock> Mailbox<C> {
    pub(super) const fn new(
        sender: Sender<Message>,
        clock: Arc<C>,
        producer_chain: Option<ChainId>,
    ) -> Self {
        Self {
            sender,
            clock,
            producer_chain,
        }
    }

    /// Records that marshal delivered `block` in the total order.
    ///
    /// Blocks from other producers are ignored.
    pub(super) fn ordered(&self, block: BlockRef<Sha256Digest>) {
        if Some(block.chain()) == self.producer_chain {
            let _ = self.sender.enqueue(Message::Ordered {
                block,
                at: self.clock.current(),
            });
        }
    }
}

impl<C: Clock> Automaton for Mailbox<C> {
    type Context = Context<Sha256Digest>;
    type Digest = Sha256Digest;

    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Propose { context, response });
        ready(receiver)
    }

    fn verify(
        &mut self,
        context: Self::Context,
        body: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Verify {
            context,
            body,
            response,
        });
        ready(receiver)
    }
}

impl<C: Clock> Reporter for Mailbox<C> {
    type Activity = Activity<MinPk, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = match activity {
            Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } => {
                Message::Finalized {
                    fact,
                    at: self.clock.current(),
                }
            }
            Activity::ProtocolAccepted { .. }
            | Activity::TransactionProposed { .. }
            | Activity::CommitmentsAccepted { .. }
            | Activity::HistoryAccepted { .. } => return Feedback::Ok,
        };
        self.sender.enqueue(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::{Epoch, Height};
    use commonware_cryptography::{Hasher as _, Sha256};

    fn propose() -> (Message, oneshot::Receiver<Sha256Digest>) {
        let (response, receiver) = oneshot::channel();
        let context = Context::new(
            Epoch::new(1),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"parent"]),
        )
        .unwrap();
        (Message::Propose { context, response }, receiver)
    }

    #[test]
    fn backlog_discards_requests_nobody_awaits() {
        let mut backlog = Backlog::default();
        let (abandoned, receiver) = propose();
        drop(receiver);
        Message::handle(&mut backlog, abandoned);
        assert!(backlog.is_empty());

        let (kept, receiver) = propose();
        Message::handle(&mut backlog, kept);
        let (later, _waiting) = propose();
        Message::handle(&mut backlog, later);
        Message::handle(
            &mut backlog,
            Message::Ordered {
                block: BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"block"])),
                at: SystemTime::UNIX_EPOCH,
            },
        );
        assert_eq!(backlog.0.len(), 3);

        // A request abandoned while retained is skipped when the backlog drains.
        drop(receiver);
        let mut drained = Vec::new();
        backlog.drain(|message| {
            drained.push(message);
            None
        });
        assert_eq!(drained.len(), 2);
        assert!(matches!(drained[0], Message::Propose { .. }));
        assert!(matches!(drained[1], Message::Ordered { .. }));
    }
}
