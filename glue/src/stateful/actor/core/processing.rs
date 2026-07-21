use crate::stateful::{
    actor::{
        core::mailbox::Message,
        processor::{FinalizeStatus, Processor},
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
use commonware_runtime::{Clock, ContextCell, Error as RuntimeError, Handle, Metrics, Spawner};
use commonware_utils::{acknowledgement::Exact, channel::fallible::OneshotExt, Acknowledgement};
use futures::{
    future::{pending, ready, Either},
    FutureExt,
};
use rand_core::Rng;
use std::sync::{mpsc::TryRecvError, Arc};
use tracing::{debug, info_span, Instrument as _};

/// A single unit of work for the processing loop: either a mailbox message to
/// handle or a deferred prune to run while the mailbox is idle.
enum Step<M, P> {
    Message(M),
    Prune(P),
}

/// A finalized block whose database sync is in flight: the external effects
/// that gate on durability — the application's finalized notification and
/// the marshal acknowledgement — held until the sync's handle resolves.
struct InflightFinalize<B> {
    /// Durability handle returned by [`Processor::finalize`].
    durability: Handle<()>,
    /// The finalized block, kept for the deferred notification.
    block: Arc<B>,
    /// Marshal acknowledgement, sent only once the applied state is durable.
    acknowledgement: Exact,
}

/// Wait for the in-flight finalize's durability handle, pending forever when
/// none is in flight. Cancel-safe: losing a select race neither consumes the
/// entry nor loses the handle's progress.
async fn wait_durable<B>(
    inflight: &mut Option<InflightFinalize<B>>,
    enabled: bool,
) -> Result<(), RuntimeError> {
    if !enabled {
        return pending().await;
    }
    match inflight {
        Some(entry) => (&mut entry.durability).await,
        None => pending().await,
    }
}

pub(super) struct Processing<E, A, S, V>
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

    /// The processing state of the actor.
    pub(super) processor: Processor<E, A>,

    /// Finalized marshal blocks at or below this height were already reflected
    /// in the selected database anchor and should be acknowledged only.
    pub(super) skip_finalized_until: Option<Height>,
}

impl<E, A, S, V> Processing<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        let mut pending_prune = None;
        // At most ONE finalized block's database sync is in flight: its
        // deferred effects live here until the durability arm (or the next
        // finalize) settles it.
        let mut inflight: Option<InflightFinalize<A::Block>> = None;
        select_loop! {
            self.context,
            on_start => {
                // Pruning is non-critical work. We only run it when the mailbox is idle, and
                // it is never raced against the mailbox due to its internal lock acquisition.
                // If a message is ready, it is always processed immediately.
                let (next, poll_durable) = match self.mailbox.try_recv() {
                    // A message is ready: handle it now, regardless of any queued prune.
                    Ok(message) => (
                        Either::Left(ready(Some(Step::Message(message)))),
                        false,
                    ),
                    Err(TryRecvError::Empty) => match pending_prune.take() {
                        // No message, but a prune is queued: run it.
                        Some(prune) => (
                            Either::Left(ready(Some(Step::Prune(prune)))),
                            false,
                        ),
                        // No message and nothing to prune: wait on the mailbox as normal.
                        None => (
                            Either::Right(self.mailbox.recv().map(|m| m.map(Step::Message))),
                            true,
                        ),
                    },
                    // Flow through the refutable arm's else so the exit
                    // shares the post-loop drain below.
                    Err(TryRecvError::Disconnected) => (Either::Left(ready(None)), false),
                };
            },
            on_stopped => {
                debug!("shutdown signal received, stopping processing");
            },
            // The in-flight finalize's sync completed: release the effects
            // that were gated on durability and observe any sync failure.
            // A ready message or prune was moved into `next` above. Do not
            // race and drop that owned work if durability is also ready.
            result = wait_durable(&mut inflight, poll_durable) => {
                let entry = inflight.take().expect("durability arm requires an in-flight finalize");
                self.settle(entry, result).await;
            },
            Some(step) = next else {
                debug!("mailbox closed, stopping processing");
                break;
            } => match step {
                Step::Message(Message::Propose {
                    span,
                    context,
                    ancestry,
                    response,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.propose");
                    self.processor
                        .propose(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            &mut self.input_provider,
                            response,
                        )
                        .instrument(process)
                        .await;
                }
                Step::Message(Message::Verify {
                    span,
                    context,
                    ancestry,
                    response,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.verify");
                    self.processor
                        .verify(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            response,
                        )
                        .instrument(process)
                        .await;
                }
                Step::Message(Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.finalized");
                    let prune = async {
                        if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                            self.processor
                                .notify_finalized(self.context.as_present(), block.as_ref())
                                .await;
                            acknowledgement.acknowledge();
                            return None;
                        }
                        // Execute and publish the block, STARTING its
                        // database sync: the previous block's fsync (if one
                        // is in flight) overlaps this work.
                        let (status, prune, durability) = self
                            .processor
                            .finalize(&self.context, block.as_ref())
                            .await;
                        // Settle the previous in-flight finalize before
                        // tracking (or acknowledging) this one: effects stay
                        // in block order, and the pipeline is bounded at one
                        // in-flight sync.
                        let mut previous_released = true;
                        if let Some(mut previous) = inflight.take() {
                            let result = (&mut previous.durability).await;
                            previous_released = self.settle(previous, result).await;
                        }
                        match (status, durability) {
                            (FinalizeStatus::Persisted { height }, Some(durability)) => {
                                debug!(height = height.get(), "started finalized database sync");
                                inflight = Some(InflightFinalize {
                                    durability,
                                    block,
                                    acknowledgement,
                                });
                            }
                            (FinalizeStatus::Duplicate, _) => {
                                // Already reflected in state, but durable only
                                // if the settle above released: a duplicate's
                                // durability may ride the very sync that was
                                // settled, and a shutdown settle released
                                // nothing. Acknowledging then would tell the
                                // marshal the height is durable when it is
                                // not, so leave it unacked for re-delivery.
                                if previous_released {
                                    acknowledgement.acknowledge();
                                } else {
                                    debug!("shutdown before duplicate's durability completed");
                                }
                            }
                            (FinalizeStatus::Persisted { .. }, None) => {
                                unreachable!("persisted finalize must return its durability handle")
                            }
                        }
                        prune
                    }
                    .instrument(process)
                    .await;
                    if let Some(prune) = prune {
                        pending_prune = Some(prune);
                    }
                }
                Step::Message(Message::SubscribeDatabases { response }) => {
                    response.send_lossy(self.processor.databases().clone());
                }
                Step::Prune(prune) => {
                    prune
                        .run(self.processor.databases_mut(), &self.marshal)
                        .await;
                }
            },
        }
        // Every exit path settles the in-flight finalize rather than
        // dropping its handle: a start_sync failure is reported only
        // through the handle, so an unobserved drop would silence a
        // fatal sync failure. A shutdown result releases nothing and
        // the block is re-delivered after restart.
        if let Some(mut entry) = inflight.take() {
            let result = (&mut entry.durability).await;
            self.settle(entry, result).await;
        }
    }

    /// Release a resolved in-flight finalize's deferred effects: once the
    /// applied state is durable, deliver the finalized notification and the
    /// marshal acknowledgement. A real sync failure is fatal (panic). A
    /// shutdown result releases nothing (returning false), so a restart
    /// re-delivers the block.
    async fn settle(
        &mut self,
        entry: InflightFinalize<A::Block>,
        result: Result<(), RuntimeError>,
    ) -> bool {
        if !crate::stateful::db::finalize_durable(result) {
            debug!("runtime shutdown before finalized database sync completed");
            return false;
        }
        debug!(
            height = entry.block.height().get(),
            "persisted finalized database batch"
        );
        self.processor
            .notify_finalized(self.context.as_present(), entry.block.as_ref())
            .await;
        entry.acknowledgement.acknowledge();
        true
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
    use super::skip_finalized_block;
    use commonware_consensus::types::Height;

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
}
