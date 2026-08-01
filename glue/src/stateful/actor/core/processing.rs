use crate::stateful::{
    Application, Input,
    actor::{
        core::mailbox::{Message, Verification},
        processor::{FinalizeStatus, Processor},
    },
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    Heightable,
    marshal::{
        ancestry::{BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant},
    },
    types::Height,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::{select, select_loop};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    Acknowledgement,
    channel::{fallible::OneshotExt, oneshot},
    futures::Pool,
};
use futures::{
    future::{Either, ready},
    poll,
};
use rand_core::Rng;
use std::{collections::BTreeMap, sync::mpsc::TryRecvError, task::Poll};
use tracing::{Instrument as _, Span, debug, info_span};

/// Verification work retained across actor state transitions.
pub(super) struct VerificationRequest<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: (E, A::Context),
    pub(super) ancestry: BoxedAncestry<A::Block>,
    pub(super) verification: Verification,
}

/// A single unit of work for the processing loop: either a mailbox message to
/// handle or a deferred prune to run while the mailbox is idle.
enum Step<M, P, J> {
    Message(M),
    Prune(P),
    Verification(J),
}

enum VerificationResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    Finished {
        id: u64,
    },
    Invalidated {
        id: u64,
        request: VerificationRequest<E, A>,
    },
}

impl<E, A> VerificationResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    const fn id(&self) -> u64 {
        match self {
            Self::Finished { id } | Self::Invalidated { id, .. } => *id,
        }
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

    /// Provider cloned into each proposal.
    pub(super) provider: A::Provider,

    /// Marshal mailbox used for lazy block lookup.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// The processing state of the actor.
    pub(super) processor: Processor<E, A>,

    /// Verify requests collected before the processor became available.
    pub(super) initial_verifications: Vec<VerificationRequest<E, A>>,

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
        let mut verifications = Pool::default();
        let mut invalidations = BTreeMap::new();
        let mut next_verification_id = 0u64;
        for request in std::mem::take(&mut self.initial_verifications) {
            self.schedule_verification(
                &mut verifications,
                &mut invalidations,
                &mut next_verification_id,
                request,
            );
        }
        select_loop! {
            self.context,
            on_start => {
                while let Poll::Ready(result) = poll!(verifications.next_completed()) {
                    invalidations.remove(&result.id());
                    if let VerificationResult::Invalidated { request, .. } = result {
                        self.schedule_verification(
                            &mut verifications,
                            &mut invalidations,
                            &mut next_verification_id,
                            request,
                        );
                    }
                }

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
                        None => {
                            let mailbox = &mut self.mailbox;
                            let verifications = &mut verifications;
                            Either::Right(async move {
                                select! {
                                    message = mailbox.recv() => message.map(Step::Message),
                                    result = verifications.next_completed() => Some(Step::Verification(result)),
                                }
                            })
                        },
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
                    upstream,
                    response,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.propose");
                    let input = Input {
                        upstream,
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
                    verification,
                }) => {
                    self.schedule_verification(
                        &mut verifications,
                        &mut invalidations,
                        &mut next_verification_id,
                        VerificationRequest {
                            span,
                            context,
                            ancestry,
                            verification,
                        },
                    );
                }
                Step::Message(Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                }) => {
                    let retry = Self::quiesce_verifications(
                        &mut verifications,
                        &mut invalidations,
                    )
                    .await;
                    let process = info_span!(parent: &span, "stateful.actor.finalized");
                    let prune = async {
                        if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                            self.processor
                                .notify_finalized(self.context.as_present(), block.as_ref())
                                .await;
                            acknowledgement.acknowledge();
                            return None;
                        }
                        let (status, prune) =
                            self.processor.finalize(&self.context, block.as_ref()).await;
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
                    for request in retry {
                        self.schedule_verification(
                            &mut verifications,
                            &mut invalidations,
                            &mut next_verification_id,
                            request,
                        );
                    }
                }
                Step::Message(Message::SubscribeDatabases { response }) => {
                    response.send_lossy(self.processor.databases().clone());
                }
                Step::Prune(prune) => {
                    let retry = Self::quiesce_verifications(
                        &mut verifications,
                        &mut invalidations,
                    )
                    .await;
                    prune
                        .run(self.processor.databases_mut(), &self.marshal)
                        .await;
                    for request in retry {
                        self.schedule_verification(
                            &mut verifications,
                            &mut invalidations,
                            &mut next_verification_id,
                            request,
                        );
                    }
                }
                Step::Verification(result) => {
                    invalidations.remove(&result.id());
                    if let VerificationResult::Invalidated { request, .. } = result {
                        self.schedule_verification(
                            &mut verifications,
                            &mut invalidations,
                            &mut next_verification_id,
                            request,
                        );
                    }
                }
            },
        }
    }

    fn schedule_verification(
        &self,
        verifications: &mut Pool<VerificationResult<E, A>>,
        invalidations: &mut BTreeMap<u64, oneshot::Sender<()>>,
        next_id: &mut u64,
        mut request: VerificationRequest<E, A>,
    ) {
        let id = *next_id;
        *next_id = next_id
            .checked_add(1)
            .expect("verification request ID overflowed");
        let (invalidate, invalidated) = oneshot::channel();
        assert!(invalidations.insert(id, invalidate).is_none());

        // Abandoned verification can outlive its caller, so application work remains under the
        // actor's supervision tree.
        let process = info_span!(parent: &request.span, "stateful.actor.verify");
        let mut verifier = self.processor.verifier();
        let actor_context = self.context.as_present().child("verify");
        let marshal = self.marshal.clone();
        verifications.push(
            async move {
                let ancestry = request.ancestry.clone();
                let attempt_context = (
                    actor_context.child("application"),
                    request.context.1.clone(),
                );
                let result = select! {
                    _ = invalidated => None,
                    result = verifier.verify(
                        &actor_context,
                        marshal,
                        attempt_context,
                        ancestry,
                        &mut request.verification,
                    ) => Some(result),
                };
                match result {
                    Some(Some(valid)) => {
                        request.verification.respond(valid);
                        VerificationResult::Finished { id }
                    }
                    Some(None) => VerificationResult::Finished { id },
                    None => VerificationResult::Invalidated { id, request },
                }
            }
            .instrument(process),
        );
    }

    async fn quiesce_verifications(
        verifications: &mut Pool<VerificationResult<E, A>>,
        invalidations: &mut BTreeMap<u64, oneshot::Sender<()>>,
    ) -> Vec<VerificationRequest<E, A>> {
        invalidations.clear();
        let mut retry = Vec::with_capacity(verifications.len());
        while !verifications.is_empty() {
            if let VerificationResult::Invalidated { request, .. } =
                verifications.next_completed().await
                && !request.verification.is_cancelled()
            {
                retry.push(request);
            }
        }
        retry
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
