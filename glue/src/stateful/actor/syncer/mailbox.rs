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
    TakeDatabases {
        response: oneshot::Sender<Option<SyncResult<E, A>>>,
    },
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
        F: FnMut(Message<E, A>) -> Option<Message<E, A>>,
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
    type Overflow = Option<Message<E, A>>;

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
    pub fn new(sender: Sender<Message<E, A>>) -> Self {
        Self { sender }
    }

    /// Attempts to collect the complete artifact of the state sync operation.
    ///
    /// If the process is still ongoing, returns [`None`].
    pub async fn try_finish(&self) -> Option<SyncResult<E, A>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::TakeDatabases { response });
        receiver
            .await
            .expect("Syncer should respond to take_databases")
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
        let (update, observed) = TipUpdate::with_observation(anchor, targets);
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::UpdateTargets { update, response });

        match receiver
            .await
            .expect("Syncer should respond to update_targets")
        {
            Some(artifact) => Some(artifact),
            None => {
                // The caller acknowledges marshal after this returns. Wait until the
                // live sync coordinator has actually recorded the new tip update;
                // enqueueing it into Syncer is not enough to prove the eventual sync
                // artifact includes this finalized block.
                observed
                    .await
                    .expect("state sync coordinator should observe target update");
                None
            }
        }
    }
}
