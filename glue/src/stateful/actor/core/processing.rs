use crate::stateful::{
    actor::{
        core::mailbox::Message,
        processor::{
            run_maintenance, FinalizeStatus, MaintenanceAction, MaintenanceResult, Processor,
        },
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

struct ActiveMaintenance {
    handle: Handle<MaintenanceResult>,
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
        let mut maintenance_task: Option<ActiveMaintenance> = None;

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
                    |task| Either::Left(&mut task.handle),
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
                    queue_maintenance(&mut pending_maintenance, maintenance);
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
                let handle = self.context.child("maintenance").spawn(|_| async move {
                    run_maintenance::<E, _, _, _>(databases, marshal, maintenance).await
                });
                maintenance_task = Some(ActiveMaintenance { handle });
            },
            result = maintenance_complete => {
                match result {
                    Ok(MaintenanceResult::PreflushStarted { height }) => {
                        self.processor.mark_preflush_started(height);
                        pending_maintenance.retain(|queued| {
                            !matches!(
                                queued,
                                MaintenanceAction::Preflush {
                                    height: queued_height,
                                    ..
                                } if *queued_height == height
                            )
                        });
                    }
                    Ok(MaintenanceResult::None) => {}
                    Err(err) => {
                        warn!(?err, "maintenance task exited before completion");
                    }
                }
                maintenance_task = None;
            }
        }
    }
}

fn queue_maintenance<T>(
    pending: &mut VecDeque<MaintenanceAction<T>>,
    maintenance: MaintenanceAction<T>,
) {
    match maintenance {
        MaintenanceAction::None => {}
        MaintenanceAction::Preflush { .. } => {
            pending.retain(|queued| !matches!(queued, MaintenanceAction::Preflush { .. }));
            pending.push_back(maintenance);
        }
        MaintenanceAction::Prune { .. } => {
            pending.retain(|queued| !matches!(queued, MaintenanceAction::Preflush { .. }));
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
        queue_maintenance::<u64>(
            &mut pending,
            MaintenanceAction::Preflush {
                height: Height::new(1),
                targets: 1,
            },
        );
        queue_maintenance::<u64>(
            &mut pending,
            MaintenanceAction::Preflush {
                height: Height::new(2),
                targets: 2,
            },
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending.pop_front(),
            Some(MaintenanceAction::Preflush {
                height: Height::new(2),
                targets: 2,
            })
        );

        queue_maintenance::<u64>(
            &mut pending,
            MaintenanceAction::Preflush {
                height: Height::new(3),
                targets: 3,
            },
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending.pop_front(),
            Some(MaintenanceAction::Preflush {
                height: Height::new(3),
                targets: 3,
            })
        );
    }

    #[test]
    fn queue_maintenance_keeps_prune_boundaries() {
        let mut pending = VecDeque::new();
        queue_maintenance(
            &mut pending,
            MaintenanceAction::Preflush {
                height: Height::new(8),
                targets: 1,
            },
        );
        queue_maintenance(
            &mut pending,
            MaintenanceAction::Prune {
                height: Height::new(7),
                targets: 11_u64,
                next_preflush: None,
            },
        );

        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending.pop_front(),
            Some(MaintenanceAction::Prune {
                height: Height::new(7),
                targets: 11,
                next_preflush: None,
            }),
        );
    }

    #[test]
    fn queue_maintenance_places_preflush_after_pending_prune() {
        let mut pending = VecDeque::new();
        queue_maintenance(
            &mut pending,
            MaintenanceAction::Prune {
                height: Height::new(7),
                targets: 11_u64,
                next_preflush: None,
            },
        );
        queue_maintenance(
            &mut pending,
            MaintenanceAction::Preflush {
                height: Height::new(8),
                targets: 12,
            },
        );

        assert_eq!(pending.len(), 2);
        assert_eq!(
            pending.pop_front(),
            Some(MaintenanceAction::Prune {
                height: Height::new(7),
                targets: 11,
                next_preflush: None,
            }),
        );
        assert_eq!(
            pending.pop_front(),
            Some(MaintenanceAction::Preflush {
                height: Height::new(8),
                targets: 12,
            })
        );
    }
}
