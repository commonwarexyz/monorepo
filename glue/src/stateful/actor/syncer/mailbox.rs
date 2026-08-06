//! [`Syncer`](super::Syncer) actor ingress.

use crate::stateful::{
    Application,
    db::{Anchor, DatabaseSet, TipUpdate},
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::oneshot;
use rand_core::Rng;

type SyncTargets<E, A> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type BlockDigest<E, A> = <<A as Application<E>>::Block as Digestible>::Digest;

pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    UpdateTargets {
        update: TipUpdate<BlockDigest<E, A>, SyncTargets<E, A>>,
        /// Resolves `true` once sync has completed (the artifact travels on the
        /// completion channel), `false` when the update was accepted instead.
        response: oneshot::Sender<bool>,
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

    /// Sends a target update and waits until the live sync coordinator records it.
    ///
    /// Returns `true` if sync already completed; the artifact arrives on the
    /// completion channel.
    pub async fn update_targets(
        &self,
        anchor: Anchor<BlockDigest<E, A>>,
        targets: SyncTargets<E, A>,
    ) -> bool {
        loop {
            let (update, observed) = TipUpdate::with_observation(anchor, targets.clone());
            let (response, receiver) = oneshot::channel();
            let feedback = self
                .sender
                .enqueue(Message::UpdateTargets { update, response });
            assert!(
                feedback.accepted(),
                "syncer must outlive update_targets callers",
            );

            let Ok(completed) = receiver.await else {
                // A newer queued update displaced this one before the syncer saw it.
                continue;
            };
            if completed {
                return true;
            }

            // Wait until the live sync coordinator has recorded the new tip update.
            // Enqueueing it into Syncer is not enough to prove the eventual sync
            // artifact includes the target or to discard its handoff state.
            if observed.await.is_ok() {
                return false;
            }

            // The active coordinator dropped before recording this update.
            // Retry so Syncer can either hand the update to the next coordinator
            // or report the completed sync.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Message};
    use crate::stateful::tests::mocks::{TestApp, anchor};
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use futures::FutureExt;

    #[test]
    fn update_targets_retries_when_observation_is_dropped() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut update_targets = Box::pin(mailbox.update_targets(anchor(7, 9), 7));

            assert!(update_targets.as_mut().now_or_never().is_none());

            let Some(Message::UpdateTargets { update, response }) = receiver.recv().await else {
                panic!("first update should be sent");
            };
            assert!(
                response.send(false).is_ok(),
                "response receiver should be alive"
            );
            drop(update);

            assert!(update_targets.as_mut().now_or_never().is_none());

            let Some(Message::UpdateTargets { response, .. }) = receiver.recv().await else {
                panic!("dropped observation should trigger a retry");
            };
            assert!(
                response.send(true).is_ok(),
                "response receiver should be alive"
            );

            assert!(
                update_targets.await,
                "retry should report the completed sync",
            );
        });
    }

    #[test]
    fn update_targets_retries_when_response_is_displaced() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut update_targets = Box::pin(mailbox.update_targets(anchor(7, 9), 7));

            assert!(update_targets.as_mut().now_or_never().is_none());

            // Drop the message without responding, as overflow displacement does.
            let Some(message) = receiver.recv().await else {
                panic!("first update should be sent");
            };
            drop(message);

            assert!(update_targets.as_mut().now_or_never().is_none());

            let Some(Message::UpdateTargets { response, .. }) = receiver.recv().await else {
                panic!("displaced response should trigger a retry");
            };
            assert!(
                response.send(true).is_ok(),
                "response receiver should be alive"
            );

            assert!(
                update_targets.await,
                "retry should report the completed sync",
            );
        });
    }

    #[test]
    fn update_targets_resolves_only_after_observation_is_recorded() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut update_targets = Box::pin(mailbox.update_targets(anchor(7, 9), 7));

            assert!(update_targets.as_mut().now_or_never().is_none());

            let Some(Message::UpdateTargets { update, response }) = receiver.recv().await else {
                panic!("update should be sent");
            };
            assert!(
                response.send(false).is_ok(),
                "response receiver should be alive"
            );

            assert!(update_targets.as_mut().now_or_never().is_none());

            update.record(|_, _| {});

            assert!(!update_targets.await, "recorded update completes nothing");
        });
    }
}
