//! Control messages accepted by the ingress actor.

use crate::multimmit::actors::util::reliable_policy;
use commonware_actor::{Feedback, mailbox};

/// Control messages accepted by the ingress actor.
pub(crate) enum Message {
    /// Return observation credits after the voter consumes that many cohorts.
    Consumed(usize),
}

// The voter returns at most one credit per forwarded cohort, so the observation capacity bounds
// retention.
reliable_policy!(impl for Message);

/// Typed endpoint of the ingress actor.
#[derive(Clone)]
pub(crate) struct Mailbox {
    sender: mailbox::Sender<Message>,
}

impl Mailbox {
    /// Wraps the sending half of the ingress control queue.
    pub(crate) const fn new(sender: mailbox::Sender<Message>) -> Self {
        Self { sender }
    }

    /// Returns observation credits after the voter consumes `cohorts` cohorts.
    pub(crate) fn consumed(&self, cohorts: usize) -> Feedback {
        self.sender.enqueue(Message::Consumed(cohorts))
    }
}
