//! [`Syncer`](super::Syncer) actor ingress.

use crate::stateful::{
    Application,
    actor::{BlockDigest, SyncTargets},
    db::{Anchor, TipUpdate},
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::oneshot;
use rand_core::Rng;

/// Reply to [`Mailbox::retarget`].
#[derive(Debug, PartialEq)]
pub(crate) enum UpdateOutcome {
    /// The live sync coordinator recorded the update, so the eventual sync
    /// artifact reflects this target or a newer one.
    Observed,
    /// State sync already completed, so no coordinator remains to record the
    /// update. The artifact is on the completion channel.
    SyncCompleted,
}

pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    Retarget {
        update: TipUpdate<BlockDigest<A, E>, SyncTargets<A, E>>,
        /// Reports whether the update was recorded or sync already completed.
        response: oneshot::Sender<UpdateOutcome>,
    },
}

impl<E, A> Overflow<Message<E, A>> for Option<Message<E, A>>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn is_empty(&self) -> bool {
        self.is_none()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<E, A>) -> Self,
    {
        if let Some(message) = self.take()
            && let Some(message) = push(message)
        {
            *self = Some(message);
        }
    }
}

// Replacing a queued update drops its response sender. `Mailbox::retarget` has one caller, which
// awaits each update before sending the next, so a live response is never dropped.
impl<E, A> Policy for Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type Overflow = Option<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        *overflow = Some(message);
    }
}

/// Ingress mailbox for the [`Syncer`](super::Syncer) actor.
pub struct Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    sender: Sender<Message<E, A>>,
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub const fn new(sender: Sender<Message<E, A>>) -> Self {
        Self { sender }
    }

    /// Sends a target update and waits until the sync coordinator records it.
    ///
    /// Returns [`UpdateOutcome::Observed`] once the update is recorded, or
    /// [`UpdateOutcome::SyncCompleted`] if state sync finished first. The converged artifact then
    /// arrives on the completion channel. Returns `None` if the syncer has stopped.
    pub async fn retarget(
        &self,
        anchor: Anchor<BlockDigest<A, E>>,
        targets: SyncTargets<A, E>,
    ) -> Option<UpdateOutcome> {
        loop {
            let (update, observed) = TipUpdate::with_observation(anchor, targets.clone());
            let (response, receiver) = oneshot::channel();
            let feedback = self.sender.enqueue(Message::Retarget { update, response });
            if !feedback.accepted() {
                return None;
            }

            // The syncer answers every message it handles. With one sequential caller no newer
            // update can displace this one, so a dropped response means the syncer stopped.
            let outcome = receiver.await.ok()?;
            if outcome == UpdateOutcome::SyncCompleted {
                return Some(outcome);
            }

            // Wait until the live sync coordinator has recorded the new tip update.
            // Enqueueing it into Syncer is not enough to prove the eventual sync
            // artifact includes the target or to discard its handoff state.
            if observed.await.is_ok() {
                return Some(UpdateOutcome::Observed);
            }

            // The active coordinator dropped before recording this update.
            // Retry so Syncer can either hand the update to the next coordinator
            // or report the completed sync.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Message, UpdateOutcome};
    use crate::stateful::tests::mocks::{TestApp, anchor};
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use futures::FutureExt;

    #[test]
    fn retarget_retries_when_observation_is_dropped() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut retarget = Box::pin(mailbox.retarget(anchor(7, 9), 7));

            assert!(retarget.as_mut().now_or_never().is_none());

            let Some(Message::Retarget { update, response }) = receiver.recv().await else {
                panic!("first update should be sent");
            };
            assert!(
                response.send(UpdateOutcome::Observed).is_ok(),
                "response receiver should be alive"
            );
            drop(update);

            assert!(retarget.as_mut().now_or_never().is_none());

            let Some(Message::Retarget { response, .. }) = receiver.recv().await else {
                panic!("dropped observation should trigger a retry");
            };
            assert!(
                response.send(UpdateOutcome::SyncCompleted).is_ok(),
                "response receiver should be alive"
            );

            assert_eq!(
                retarget.await,
                Some(UpdateOutcome::SyncCompleted),
                "retry should report the completed sync"
            );
        });
    }

    #[test]
    fn retarget_reports_stopped_syncer_when_response_is_dropped() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut retarget = Box::pin(mailbox.retarget(anchor(7, 9), 7));

            assert!(retarget.as_mut().now_or_never().is_none());

            // A stopping syncer drops the message it was handling without responding.
            let Some(message) = receiver.recv().await else {
                panic!("first update should be sent");
            };
            drop(message);

            assert_eq!(retarget.await, None);
            assert!(
                receiver.try_recv().is_err(),
                "a stopped syncer gets no retry"
            );
        });
    }

    #[test]
    fn retarget_reports_stopped_syncer_when_mailbox_is_closed() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            drop(receiver);

            assert_eq!(mailbox.retarget(anchor(7, 9), 7).await, None);
        });
    }

    #[test]
    fn retarget_resolves_only_after_observation_is_recorded() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut retarget = Box::pin(mailbox.retarget(anchor(7, 9), 7));

            assert!(retarget.as_mut().now_or_never().is_none());

            let Some(Message::Retarget { update, response }) = receiver.recv().await else {
                panic!("update should be sent");
            };
            assert!(
                response.send(UpdateOutcome::Observed).is_ok(),
                "response receiver should be alive"
            );

            assert!(retarget.as_mut().now_or_never().is_none());

            update.record(|_, _| {});

            assert_eq!(
                retarget.await,
                Some(UpdateOutcome::Observed),
                "recorded update should report observation"
            );
        });
    }
}
