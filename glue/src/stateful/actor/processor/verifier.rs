use super::{Application, Execution, ExecutionStep, PrepareBatchesError, ReplayPath};
use commonware_consensus::{
    Block, CertifiableBlock, Heightable, Roundable,
    marshal::{
        Identifier,
        ancestry::{self as marshal_ancestry, Ancestry, BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_runtime::{
    Clock, Supervisor,
    telemetry::{metrics::histogram::Timer, traces::TracedExt as _},
};
use futures::StreamExt;
use std::future::{Future, pending};
use tracing::{Instrument as _, debug, info_span, warn};

type PreparedStep<B> = (ExecutionStep<<B as Digestible>::Digest>, BoxedAncestry<B>);

/// Materialized inputs and the remaining work for one caller.
///
/// Parent state is checked again when each execution step forks its batches.
pub(in crate::stateful::actor) struct Prepared<B: Block> {
    ancestry: BoxedAncestry<B>,
    replay: Option<ReplayPath<B>>,
    verify: bool,
    timer: Option<Timer>,
}

impl<B: Block> Prepared<B> {
    pub(in crate::stateful::actor) fn finish(self, context: &impl Clock) -> BoxedAncestry<B> {
        if let Some(timer) = self.timer {
            timer.observe(context);
        }
        self.ancestry
    }
}

/// Processes candidates for verification and parent recovery against shared speculative state.
pub(in crate::stateful::actor) struct Verifier<E, A>
where
    A: Application<E>,
{
    pub(super) app: A,
    pub(super) execution: Execution<E, A>,
}

impl<E, A> Clone for Verifier<E, A>
where
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            execution: self.execution.clone(),
        }
    }
}

impl<E, A> Verifier<E, A>
where
    E: Supervisor + Clock,
    A: Application<E>,
{
    /// Acquires a caller's block and the missing path to known state without borrowing the
    /// application or forking database batches.
    pub(in crate::stateful::actor) fn prepare<S, V>(
        &self,
        context: E,
        marshal: MarshalMailbox<S, V>,
        mut ancestry: BoxedAncestry<A::Block>,
        verify: bool,
    ) -> impl Future<Output = Result<Prepared<A::Block>, PrepareBatchesError>> + Send + use<E, A, S, V>
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let execution = self.execution.clone();
        async move {
            let timer = verify.then(|| execution.metrics.verify_duration.timer(&context));

            // Availability is caller-scoped even when subsequent execution is shared by digest.
            let Some(block) = ancestry.next().await else {
                if verify {
                    debug!("verification waiting on incomplete block ancestry");
                    return pending().await;
                }
                return Err(PrepareBatchesError::Incomplete);
            };
            let digest = block.digest();

            if verify {
                let cached = execution.pending_contains(&digest);
                let anchor = execution.branch_anchor();
                if cached || block.height() <= anchor.height {
                    let valid = if cached {
                        true
                    } else {
                        async {
                            if block.height() == anchor.height {
                                return digest == anchor.digest;
                            }
                            let Some(canonical) =
                                marshal.get_block(Identifier::Height(block.height())).await
                            else {
                                warn!(
                                    target_height = block.height().get(),
                                    anchor_height = anchor.height.get(),
                                    "verification waiting on missing canonical block"
                                );
                                return pending().await;
                            };
                            canonical.digest() == digest
                        }
                        .instrument(info_span!(
                            "stateful.processor.is_already_processed",
                            height = block.height().traced(),
                            digest = %digest,
                        ))
                        .await
                    };
                    return if valid {
                        Ok(Prepared {
                            ancestry: BoxedAncestry::new(marshal_ancestry::with_prefix(
                                [block],
                                ancestry,
                            )),
                            replay: None,
                            verify: false,
                            timer,
                        })
                    } else {
                        Err(PrepareBatchesError::Invalid)
                    };
                }
            }

            let (parent, ancestry) = if verify {
                let Some(parent) = ancestry.next().await else {
                    debug!(
                        ?digest,
                        "verification waiting on incomplete parent ancestry"
                    );
                    return pending().await;
                };
                (
                    parent.clone(),
                    BoxedAncestry::new(marshal_ancestry::with_prefix([block, parent], ancestry)),
                )
            } else {
                (
                    block.clone(),
                    BoxedAncestry::new(marshal_ancestry::with_prefix([block], ancestry)),
                )
            };

            let replay = if execution.pending_contains(&parent.digest())
                || execution.branch_anchor().digest == parent.digest()
            {
                None
            } else {
                match execution.prepare_replay(&context, marshal, parent).await {
                    Ok(path) => Some(path),
                    Err(PrepareBatchesError::Incomplete) if verify => {
                        debug!(
                            ?digest,
                            "verification waiting on incomplete recovery ancestry"
                        );
                        return pending().await;
                    }
                    Err(error) => return Err(error),
                }
            };

            Ok(Prepared {
                ancestry,
                replay,
                verify,
                timer,
            })
        }
    }

    /// Selects one block whose parent state has been recovered by the preceding steps.
    pub(in crate::stateful::actor) fn next<P>(
        &self,
        context: &E,
        provider: P,
        prepared: &mut Prepared<A::Block>,
    ) -> Option<PreparedStep<A::Block>>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        let ancestry = match prepared
            .replay
            .as_mut()
            .and_then(|path| self.execution.next_replay(context, provider, path))
        {
            Some(ancestry) => ancestry,
            None => {
                prepared.replay = None;
                if !std::mem::take(&mut prepared.verify) {
                    return None;
                }
                prepared.ancestry.clone()
            }
        };
        let block = ancestry
            .peek()
            .expect("prepared execution must have its block");
        let step = ExecutionStep {
            digest: block.digest(),
            parent: block.parent(),
            round: block.context().round(),
        };
        Some((step, ancestry))
    }

    /// Executes one prepared block, including all permanent checks and shared-result publication.
    pub(in crate::stateful::actor) async fn process(
        &mut self,
        context: &E,
        ancestry: BoxedAncestry<A::Block>,
    ) -> Result<(), PrepareBatchesError> {
        let digest = ancestry
            .peek()
            .expect("prepared execution must have its block")
            .digest();
        self.execution
            .replay_shared(&mut self.app, context, digest, ancestry)
            .await
            .inspect_err(|error| {
                warn!(?digest, ?error, "candidate processing failed");
            })
    }

    #[cfg(test)]
    pub(in crate::stateful::actor) async fn run<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        ancestry: impl Ancestry<A::Block>,
    ) -> bool
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let Ok(mut prepared) = self
            .prepare(
                context.child("verify"),
                marshal.clone(),
                BoxedAncestry::new(ancestry),
                true,
            )
            .await
        else {
            return false;
        };
        while let Some((_, ancestry)) = self.next(context, marshal.clone(), &mut prepared) {
            if self.process(context, ancestry).await.is_err() {
                return false;
            }
        }
        prepared.finish(context);
        true
    }
}
