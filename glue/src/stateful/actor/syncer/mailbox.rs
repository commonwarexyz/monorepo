//! [`Syncer`](super::Syncer) actor ingress.

use super::SyncResult;
use crate::stateful::{
    db::{Anchor, DatabaseSet, TipUpdate},
    Application,
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::oneshot;
use rand::Rng;

type SyncTargets<E, A> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type BlockDigest<E, A> = <<A as Application<E>>::Block as Digestible>::Digest;

pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    UpdateTargets {
        update: TipUpdate<BlockDigest<E, A>, SyncTargets<E, A>>,
        response: oneshot::Sender<Option<SyncResult<E, A>>>,
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
        if let Some(message) = self.take() {
            if let Some(message) = push(message) {
                *self = Some(message);
            }
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
    /// If sync already completed before the update could be observed, returns the
    /// completed artifact instead.
    pub async fn update_targets(
        &self,
        anchor: Anchor<BlockDigest<E, A>>,
        targets: SyncTargets<E, A>,
    ) -> Option<SyncResult<E, A>> {
        loop {
            let (update, observed) = TipUpdate::with_observation(anchor, targets.clone());
            let (response, receiver) = oneshot::channel();
            let _ = self
                .sender
                .enqueue(Message::UpdateTargets { update, response });

            match receiver
                .await
                .expect("Syncer should respond to update_targets")
            {
                Some(artifact) => return Some(artifact),
                None => {
                    // The caller acknowledges marshal after this returns. Wait until the
                    // live sync coordinator has actually recorded the new tip update;
                    // enqueueing it into Syncer is not enough to prove the eventual sync
                    // artifact includes this finalized block.
                    if observed.await.is_ok() {
                        return None;
                    }

                    // The active coordinator dropped before recording this update.
                    // Retry so Syncer can either hand the update to the next coordinator
                    // or report the completed sync artifact.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Message};
    use crate::stateful::{
        actor::syncer::SyncResult,
        tests::mocks::{anchor, test_databases, TestApp},
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
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
                response.send(None).is_ok(),
                "response receiver should be alive"
            );
            drop(update);

            assert!(update_targets.as_mut().now_or_never().is_none());

            let expected = SyncResult::<deterministic::Context, TestApp> {
                databases: test_databases(),
                serving_resolvers: (),
                anchor: anchor(8, 10),
            };
            let Some(Message::UpdateTargets { response, .. }) = receiver.recv().await else {
                panic!("dropped observation should trigger a retry");
            };
            assert!(
                response.send(Some(expected.clone())).is_ok(),
                "response receiver should be alive"
            );

            let result = update_targets.await;
            assert_eq!(
                result.expect("retry should return artifact").anchor,
                expected.anchor
            );
        });
    }

    #[test]
    fn update_targets_returns_none_only_after_observation_is_recorded() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut update_targets = Box::pin(mailbox.update_targets(anchor(7, 9), 7));

            assert!(update_targets.as_mut().now_or_never().is_none());

            let Some(Message::UpdateTargets { update, response }) = receiver.recv().await else {
                panic!("update should be sent");
            };
            assert!(
                response.send(None).is_ok(),
                "response receiver should be alive"
            );

            assert!(update_targets.as_mut().now_or_never().is_none());

            let _ = update.record();

            assert!(update_targets.await.is_none());
        });
    }
}
