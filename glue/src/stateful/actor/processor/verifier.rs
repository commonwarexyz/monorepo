//! Acquisition and execution steps for speculative requests.
//!
//! A [`Verifier`] turns a verification or a proposal's parent recovery into work the actor can
//! interleave with maintenance: [`Verifier::prepare`] finds where recovery starts without touching
//! the application, [`Verifier::next`] selects one block to acquire or process at a time,
//! [`Verifier::acquire`] acquires the next missing block below the target from the selected
//! branch, and [`Verifier::process`] processes a block once for all concurrent requests that
//! need it.

use super::{Application, Execution, ExecutionStep, PrepareBatchesError, ReplayPath};
use commonware_consensus::{
    Block, CertifiableBlock, Heightable, Roundable,
    marshal::{
        Identifier,
        blocks::Blocks,
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
};
use commonware_cryptography::{Digested, Digestible, certificate::Scheme};
use commonware_runtime::{
    Clock, Supervisor,
    telemetry::{metrics::histogram::Timer, traces::TracedExt as _},
};
use std::future::{Future, pending};
use tracing::{Instrument as _, debug, info_span, warn};

/// A request's recovery path and the execution steps that remain before it completes.
///
/// Each step checks its parent's state again when it forks batches.
pub(in crate::stateful::actor) struct Prepared<B: Block> {
    /// The verification's own block, processed once the path is done. The final verification
    /// step takes it.
    block: Option<Digested<B>>,
    /// The selected branch ending at the request's parent.
    blocks: Blocks<B>,
    /// Missing blocks still to acquire or process before the request's own block, if any.
    replay: Option<ReplayPath<B>>,
    /// Verification timer, observed only when the verification accepts its block.
    timer: Option<Timer>,
}

impl<B: Block> Prepared<B> {
    /// Records the verification latency, if timed.
    pub(in crate::stateful::actor) fn finish(self, context: &impl Clock) {
        if let Some(timer) = self.timer {
            timer.observe(context);
        }
    }
}

/// The next action for a [`Prepared`] request.
pub(in crate::stateful::actor) enum Next<B: Block> {
    /// Acquire the next missing block below the recovery target with [`Verifier::acquire`].
    Acquire,
    /// Process `block` on the selected branch ending at its parent.
    Process {
        step: ExecutionStep<B::Digest>,
        block: Digested<B>,
        blocks: Blocks<B>,
    },
    /// The request has no step left.
    Done,
}

/// Processes candidates for verification and parent recovery against shared speculative state.
pub(in crate::stateful::actor) struct Verifier<E, A>
where
    A: Application<E>,
{
    pub(super) app: A,
    pub(super) execution: Execution<E, A>,
}

impl<E, A> Verifier<E, A>
where
    E: Supervisor + Clock,
    A: Application<E>,
{
    /// Finds the missing path from cached or applied state to `parent` on the selected branch
    /// `blocks`, without borrowing the application or forking database batches.
    ///
    /// `block` is the verification's own block and must extend `parent`. It is `None` when
    /// recovering a proposal's parent. The request holds both bodies, so the missing path
    /// excludes them.
    ///
    /// A verification of a cached block, or of a block at or below the branch anchor's height,
    /// needs no execution and is answered from the cache or the canonical block at that height.
    /// Unavailable selected history leaves a verification pending, so it abstains, and makes
    /// recovery return [`PrepareBatchesError::Incomplete`].
    pub(in crate::stateful::actor) fn prepare<S, V>(
        &self,
        context: E,
        marshal: MarshalMailbox<S, V>,
        block: Option<Digested<A::Block>>,
        parent: Digested<A::Block>,
        blocks: Blocks<A::Block>,
    ) -> impl Future<Output = Result<Prepared<A::Block>, PrepareBatchesError>> + Send + use<E, A, S, V>
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
    {
        let execution = self.execution.clone();
        async move {
            let verify = block.is_some();
            let timer = verify.then(|| execution.metrics.verify_duration.timer(&context));

            // A cached block was already processed, and a block at or below the branch anchor
            // cannot be processed on the applied state, so both are answered without execution:
            // the cached block is valid, and the other is valid only if it is the canonical block
            // at its height. A canonical block marshal cannot return yet leaves the verification
            // pending.
            if let Some(block) = &block {
                let digest = block.digest();
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
                            block: None,
                            blocks,
                            replay: None,
                            timer,
                        })
                    } else {
                        Err(PrepareBatchesError::Invalid)
                    };
                }
            }

            // Find the missing path unless the parent is already cached or the branch anchor. A
            // verification waits on unavailable history, since it can still become available, and
            // a proposal declines.
            let replay = match execution.prepare_replay(&context, &blocks, parent).await {
                Ok(path) => path,
                Err(PrepareBatchesError::Incomplete) if verify => {
                    debug!("verification waiting on unavailable selected history");
                    return pending().await;
                }
                Err(error) => return Err(error),
            };

            Ok(Prepared {
                block,
                blocks,
                replay,
                timer,
            })
        }
    }

    /// Returns the next action: acquiring or processing each block on the missing path in height
    /// order, then processing the block itself when verifying.
    ///
    /// Returns [`PrepareBatchesError::Invalid`] if the recovery target is not the selected block
    /// at its height or does not extend the acquired path.
    pub(in crate::stateful::actor) fn next(
        &self,
        context: &E,
        prepared: &mut Prepared<A::Block>,
    ) -> Result<Next<A::Block>, PrepareBatchesError> {
        // The missing path comes first. Once it is exhausted, the request's own block is the
        // last step.
        let (block, blocks) = match prepared.replay.as_mut() {
            Some(path) => match path.take()? {
                Some(next) => next,
                None if !path.exhausted() => return Ok(Next::Acquire),
                None => {
                    self.execution.finish_replay(context, path);
                    prepared.replay = None;
                    return self.next(context, prepared);
                }
            },
            None => match prepared.block.take() {
                Some(block) => (block, prepared.blocks.clone()),
                None => return Ok(Next::Done),
            },
        };

        // The step identifies the block for admission decisions, and the block and its branch
        // travel with the execution.
        let step = ExecutionStep {
            digest: block.digest(),
            parent: block.parent(),
            round: block.context().round(),
        };
        Ok(Next::Process {
            step,
            block,
            blocks,
        })
    }

    /// Acquires the next missing block for a request whose [`Self::next`] returned
    /// [`Next::Acquire`], without borrowing the application.
    ///
    /// Unavailable selected history leaves a verification pending, so it abstains, and makes
    /// recovery return [`PrepareBatchesError::Incomplete`]. Dropping the future releases the
    /// path's acquisitions.
    pub(in crate::stateful::actor) async fn acquire(
        mut prepared: Prepared<A::Block>,
    ) -> Result<Prepared<A::Block>, PrepareBatchesError> {
        let verify = prepared.block.is_some();
        let path = prepared
            .replay
            .as_mut()
            .expect("an acquiring request must have a replay path");
        match path.acquire().await {
            Ok(()) => Ok(prepared),
            Err(PrepareBatchesError::Incomplete) if verify => {
                debug!("verification waiting on unavailable recovery history");
                pending().await
            }
            Err(error) => Err(error),
        }
    }

    /// Processes one block from [`Self::next`] as a candidate, sharing the call with concurrent
    /// requests for the same block, and caches a valid result.
    ///
    /// The request joins the processing when this is called, so the returned future holds it
    /// before its first poll. Dropping that future leaves the processing running for any other
    /// request that holds the processing, and cancels it otherwise. `context` must outlive every
    /// request that may join the processing, so it is the actor's.
    pub(in crate::stateful::actor) fn process(
        &self,
        context: E,
        block: Digested<A::Block>,
        blocks: Blocks<A::Block>,
    ) -> impl Future<Output = Result<(), PrepareBatchesError>> + Send + use<E, A> {
        let digest = block.digest();
        let flight = self
            .execution
            .join_flight(&self.app, context, block, blocks);
        async move {
            let Some(flight) = flight else {
                return Ok(());
            };
            flight.await.inspect_err(|error| {
                warn!(?digest, ?error, "candidate processing failed");
            })
        }
    }
}
