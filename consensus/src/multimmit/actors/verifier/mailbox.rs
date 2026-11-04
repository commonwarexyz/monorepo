//! Verification jobs accepted by the verifier actor.

use crate::{
    multimmit::{actors::util::reliable_policy, machine::VerifyJob, scheme::Scheme},
    types::Round,
};
use commonware_actor::{Feedback, mailbox};
use commonware_cryptography::Digest;
use std::time::SystemTime;
use tracing::Span;

/// Messages accepted by the verifier actor.
pub(crate) enum Message<S: Scheme, D: Digest> {
    /// Execute one machine-issued verification job.
    Verify {
        /// When the voter reserved this job's execution permit.
        issued_at: SystemTime,
        /// The caller's tracing span for this job.
        span: Span,
        /// The round that issued the job.
        round: Round,
        /// The machine-issued job.
        job: VerifyJob<S, D>,
    },
}

// The voter reserves an execution permit for every job before sending it, so the in-flight job
// ceiling bounds retention.
reliable_policy!(impl<S: Scheme, D: Digest> for Message<S, D>);

/// Typed endpoint of the verifier actor.
pub(crate) struct Mailbox<S: Scheme, D: Digest> {
    sender: mailbox::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Clone for Mailbox<S, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Wraps the sending half of the verifier's job queue.
    pub(crate) const fn new(sender: mailbox::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Submits one machine-issued job whose permit the voter reserved at `issued_at`.
    pub(crate) fn verify(
        &self,
        span: Span,
        round: Round,
        job: VerifyJob<S, D>,
        issued_at: SystemTime,
    ) -> Feedback {
        self.sender.enqueue(Message::Verify {
            issued_at,
            span,
            round,
            job,
        })
    }
}
