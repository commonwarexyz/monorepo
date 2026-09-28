//! [`Syncer`](super::Syncer) actor ingress.

use super::Artifact;
use crate::stateful::{
    Application,
    actor::{BlockDigest, SyncTargets},
    db::{Anchor, TipUpdate},
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::oneshot;
use rand_core::Rng;

pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    Retarget {
        update: TipUpdate<BlockDigest<A, E>, SyncTargets<A, E>>,
        response: oneshot::Sender<Option<Artifact<E, A>>>,
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
    /// If sync already completed before the update could be observed, returns the
    /// completed artifact instead.
    pub async fn retarget(
        &self,
        anchor: Anchor<BlockDigest<A, E>>,
        targets: SyncTargets<A, E>,
    ) -> Option<Artifact<E, A>> {
        loop {
            let (update, observed) = TipUpdate::with_observation(anchor, targets.clone());
            let (response, receiver) = oneshot::channel();
            let _ = self.sender.enqueue(Message::Retarget { update, response });

            match receiver.await.expect("Syncer should respond to retarget") {
                Some(artifact) => return Some(artifact),
                None => {
                    // Wait until the live sync coordinator has recorded the new tip update.
                    // Enqueueing it into Syncer is not enough to prove the eventual sync
                    // artifact includes the target or to discard its handoff state.
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
        actor::syncer::Artifact,
        tests::mocks::{TestApp, anchor, test_databases},
    };
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
                response.send(None).is_ok(),
                "response receiver should be alive"
            );
            drop(update);

            assert!(retarget.as_mut().now_or_never().is_none());

            let expected = Artifact::<deterministic::Context, TestApp> {
                databases: test_databases(),
                anchor: anchor(8, 10),
            };
            let Some(Message::Retarget { response, .. }) = receiver.recv().await else {
                panic!("dropped observation should trigger a retry");
            };
            assert!(
                response.send(Some(expected.clone())).is_ok(),
                "response receiver should be alive"
            );

            let result = retarget.await;
            assert_eq!(
                result.expect("retry should return artifact").anchor,
                expected.anchor
            );
        });
    }

    #[test]
    fn retarget_returns_none_only_after_observation_is_recorded() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let mut retarget = Box::pin(mailbox.retarget(anchor(7, 9), 7));

            assert!(retarget.as_mut().now_or_never().is_none());

            let Some(Message::Retarget { update, response }) = receiver.recv().await else {
                panic!("update should be sent");
            };
            assert!(
                response.send(None).is_ok(),
                "response receiver should be alive"
            );

            assert!(retarget.as_mut().now_or_never().is_none());

            update.record(|_, _| {});

            assert!(retarget.await.is_none());
        });
    }
}
