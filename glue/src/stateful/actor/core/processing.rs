use crate::stateful::{
    actor::{
        core::mailbox::Message,
        processor::{run_maintenance, FinalizeStatus, MaintenanceAction, Processor},
    },
    Application,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    types::Height,
    Heightable,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{channel::fallible::OneshotExt, Acknowledgement};
use futures::future::{self, Either};
use rand::Rng;
use std::collections::VecDeque;
use tracing::{debug, warn};

pub(super) struct Processing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,

    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub(super) input_provider: A::InputProvider,

    /// Marshal mailbox used for lazy block lookup.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// State sync resolvers stay alive here so peers can keep syncing from us.
    #[expect(
        dead_code,
        reason = "processing keeps resolver handles alive for peer state sync"
    )]
    pub(super) resolvers: R,

    /// The processing state of the actor.
    pub(super) processor: Processor<E, A>,

    /// Finalized marshal blocks at or below this height were already reflected
    /// in the selected database anchor and should be acknowledged only.
    pub(super) skip_finalized_until: Option<Height>,
}

impl<E, A, S, V, R> Processing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        let mut pending_maintenance = VecDeque::new();
        let mut maintenance_task: Option<Handle<()>> = None;

        select_loop! {
            self.context,
            on_start => {
                let start_maintenance = if maintenance_task.is_none() && !pending_maintenance.is_empty() {
                    Either::Left(future::ready(()))
                } else {
                    Either::Right(future::pending())
                };
                let maintenance_complete = maintenance_task.as_mut().map_or_else(
                    || Either::Right(future::pending()),
                    Either::Left,
                );
            },
            on_stopped => {
                debug!("processor received shutdown signal");
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down processor");
                break;
            } => match message {
                Message::Propose {
                    context,
                    ancestry,
                    response,
                } => {
                    self.processor
                        .propose(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            &mut self.input_provider,
                            response,
                        )
                        .await;
                }
                Message::Verify {
                    context,
                    ancestry,
                    response,
                } => {
                    self.processor
                        .verify(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            response,
                        )
                        .await;
                }
                Message::Finalized {
                    block,
                    acknowledgement,
                } => {
                    if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                        acknowledgement.acknowledge();
                        continue;
                    }
                    let (status, maintenance) = self.processor.finalize(&self.context, block).await;
                    queue_maintenance(
                        &mut pending_maintenance,
                        maintenance_task.is_some(),
                        maintenance,
                    );
                    if let FinalizeStatus::Applied { height } = status {
                        debug!(height = height.get(), "applied finalized database batch");
                    }
                    acknowledgement.acknowledge();
                }
                Message::SubscribeDatabases { response } => {
                    response.send_lossy(self.processor.databases().clone());
                }
            },
            _ = start_maintenance => {
                let maintenance = pending_maintenance
                    .pop_front()
                    .expect("start_maintenance should only run when work is queued");
                let databases = self.processor.databases().clone();
                let marshal = self.marshal.clone();
                maintenance_task = Some(
                    self.context.child("maintenance").spawn(|_| async move {
                        run_maintenance::<E, _, _, _>(databases, marshal, maintenance).await
                    })
                );
            },
            result = maintenance_complete => {
                if let Err(err) = result {
                    warn!(?err, "maintenance task exited before completion");
                }
                maintenance_task = None;
            }
        }
    }
}

fn queue_maintenance<T>(
    pending: &mut VecDeque<MaintenanceAction<T>>,
    task_active: bool,
    maintenance: MaintenanceAction<T>,
) {
    match maintenance {
        MaintenanceAction::None => {}
        MaintenanceAction::Preflush => {
            if !task_active && pending.is_empty() {
                pending.push_back(MaintenanceAction::Preflush);
            }
        }
        MaintenanceAction::Prune { .. } => {
            pending.retain(|queued| !matches!(queued, MaintenanceAction::Preflush));
            pending.push_back(maintenance);
        }
    }
}

fn skip_finalized_block(skip_until: &mut Option<Height>, height: Height) -> bool {
    let Some(target) = *skip_until else {
        return false;
    };
    if height > target {
        *skip_until = None;
        return false;
    }
    if height == target {
        *skip_until = None;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{queue_maintenance, skip_finalized_block};
    use crate::stateful::actor::processor::MaintenanceAction;
    use commonware_consensus::types::Height;
    use std::collections::VecDeque;

    #[test]
    fn skip_finalized_block_skips_through_target_height() {
        let mut skip_until = Some(Height::new(3));

        assert!(skip_finalized_block(&mut skip_until, Height::new(1)));
        assert_eq!(skip_until, Some(Height::new(3)));
        assert!(skip_finalized_block(&mut skip_until, Height::new(3)));
        assert_eq!(skip_until, None);
        assert!(!skip_finalized_block(&mut skip_until, Height::new(4)));
    }

    #[test]
    fn skip_finalized_block_clears_stale_target() {
        let mut skip_until = Some(Height::new(3));

        assert!(!skip_finalized_block(&mut skip_until, Height::new(4)));
        assert_eq!(skip_until, None);
    }

    #[test]
    fn queue_maintenance_coalesces_preflush() {
        let mut pending = VecDeque::new();
        queue_maintenance::<u64>(&mut pending, false, MaintenanceAction::Preflush);
        queue_maintenance::<u64>(&mut pending, false, MaintenanceAction::Preflush);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.pop_front(), Some(MaintenanceAction::Preflush));

        queue_maintenance::<u64>(&mut pending, true, MaintenanceAction::Preflush);
        assert!(pending.is_empty());
    }

    #[test]
    fn queue_maintenance_keeps_prune_boundaries() {
        let mut pending = VecDeque::new();
        queue_maintenance(&mut pending, false, MaintenanceAction::Preflush);
        queue_maintenance(
            &mut pending,
            true,
            MaintenanceAction::Prune {
                height: Height::new(7),
                targets: 11_u64,
            },
        );

        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending.pop_front(),
            Some(MaintenanceAction::Prune {
                height: Height::new(7),
                targets: 11,
            }),
        );
    }
}
