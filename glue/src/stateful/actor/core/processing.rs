use crate::stateful::{
    actor::{
        core::mailbox::Message,
        processor::{FinalizeStatus, Processor},
    },
    Application, Input,
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
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{channel::fallible::OneshotExt, Acknowledgement};
use futures::{
    future::{ready, Either},
    FutureExt,
};
use rand::Rng;
use std::sync::mpsc::TryRecvError;
use tracing::{debug, info_span, Instrument as _};

/// A single unit of work for the processing loop: either a mailbox message to
/// handle or a deferred prune to run while the mailbox is idle.
enum Step<M, P> {
    Message(M),
    Prune(P),
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

    /// Provider cloned into each proposal.
    pub(super) provider: A::Provider,

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
        select_loop! {
            self.context,
            on_start => {
                // Pruning is non-critical work. We only run it when the mailbox is idle, and
                // it is never raced against the mailbox due to its internal lock acquisition.
                // If a message is ready, it is always processed immediately.
                let next = match self.mailbox.try_recv() {
                    // A message is ready: handle it now, regardless of any queued prune.
                    Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                    Err(TryRecvError::Empty) => match pending_prune.take() {
                        // No message, but a prune is queued: run it.
                        Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                        // No message and nothing to prune: wait on the mailbox as normal.
                        None => Either::Right(self.mailbox.recv().map(|m| m.map(Step::Message))),
                    },
                    Err(TryRecvError::Disconnected) => {
                        debug!("mailbox closed, stopping processing");
                        return;
                    }
                };
            },
            on_stopped => {
                debug!("shutdown signal received, stopping processing");
            },
            Some(step) = next else {
                debug!("mailbox closed, stopping processing");
                break;
            } => match step {
                Step::Message(Message::Propose {
                    span,
                    context,
                    ancestry,
                    parent,
                    response,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.propose");
                    let input = Input {
                        parent,
                        provider: self.provider.clone(),
                    };
                    self.processor
                        .propose(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            input,
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
                                .notify_finalized(self.context.as_present(), &block)
                                .await;
                            acknowledgement.acknowledge();
                            return None;
                        }
                        let (status, prune) = self.processor.finalize(&self.context, block).await;
                        if let FinalizeStatus::Persisted { height } = status {
                            debug!(height = height.get(), "persisted finalized database batch");
                        }
                        acknowledgement.acknowledge();
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
