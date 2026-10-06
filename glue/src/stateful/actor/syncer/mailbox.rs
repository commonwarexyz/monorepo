//! [`Syncer`](super::Syncer) actor ingress.

use super::Artifact;
use crate::stateful::{
    Application,
    actor::{BlockDigest, SyncTargets},
    db::{Anchor, Observation, TipUpdate},
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

/// The outcome of a target update sent to the [`Syncer`](super::Syncer).
pub(crate) enum Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The sync coordinator recorded the target.
    Recorded,
    /// The sync coordinator accepts no more targets until a forced update releases its hold. The
    /// converged [`Artifact`] follows on completion.
    Refused,
    /// State sync converged.
    Converged(Artifact<E, A>),
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

    /// Sends a target update and waits until the sync coordinator handles it.
    ///
    /// Returns [`Outcome::Recorded`] once the update is recorded, [`Outcome::Refused`] once it is
    /// refused, or [`Outcome::Converged`] with the converged [`Artifact`] if state sync finished
    /// first.
    ///
    /// Panics if the syncer stops without responding.
    pub async fn retarget(
        &self,
        anchor: Anchor<BlockDigest<A, E>>,
        targets: SyncTargets<A, E>,
    ) -> Outcome<E, A> {
        self.send(anchor, targets, false).await
    }

    /// Sends a target update that a holding sync coordinator records instead of refusing, which
    /// releases the hold, and waits until the coordinator handles it.
    ///
    /// Returns as [`Self::retarget`] does.
    pub async fn release(
        &self,
        anchor: Anchor<BlockDigest<A, E>>,
        targets: SyncTargets<A, E>,
    ) -> Outcome<E, A> {
        self.send(anchor, targets, true).await
    }

    async fn send(
        &self,
        anchor: Anchor<BlockDigest<A, E>>,
        targets: SyncTargets<A, E>,
        forced: bool,
    ) -> Outcome<E, A> {
        loop {
            let (update, observed) = if forced {
                TipUpdate::forced_with_observation(anchor, targets.clone())
            } else {
                TipUpdate::with_observation(anchor, targets.clone())
            };
            let (response, receiver) = oneshot::channel();
            let _ = self.sender.enqueue(Message::Retarget { update, response });

            match receiver.await.expect("Syncer should respond to retarget") {
                Some(artifact) => return Outcome::Converged(artifact),
                None => {
                    // Enqueueing can race with convergence, so wait for the coordinator to handle
                    // the update.
                    match observed.await {
                        Ok(Observation::Recorded) => return Outcome::Recorded,
                        Ok(Observation::Refused) => return Outcome::Refused,

                        // The update was dropped unhandled. Retry until it is handled or the
                        // converged artifact is returned.
                        Err(_) => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Message, Outcome};
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

            let Outcome::Converged(result) = retarget.await else {
                panic!("retry should return artifact");
            };
            assert_eq!(result.anchor, expected.anchor);
        });
    }

    #[test]
    fn retarget_returns_recorded_only_after_observation_is_recorded() {
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

            assert!(matches!(retarget.await, Outcome::Recorded));
        });
    }

    #[test]
    fn retarget_returns_refused_once_observation_is_refused() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let retarget = mailbox.retarget(anchor(7, 9), 7);
            let respond = async {
                let Some(Message::Retarget { update, response }) = receiver.recv().await else {
                    panic!("update should be sent");
                };
                assert!(!update.forced());
                assert!(response.send(None).is_ok());
                update.refuse();
            };
            let (outcome, ()) = futures::join!(retarget, respond);
            assert!(matches!(outcome, Outcome::Refused));
        });
    }

    #[test]
    fn release_sends_forced_update() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let release = mailbox.release(anchor(7, 9), 7);
            let respond = async {
                let Some(Message::Retarget { update, response }) = receiver.recv().await else {
                    panic!("update should be sent");
                };
                assert!(update.forced());
                assert!(response.send(None).is_ok());
                update.record(|_, _| {});
            };
            let (outcome, ()) = futures::join!(release, respond);
            assert!(matches!(outcome, Outcome::Recorded));
        });
    }
}
