//! Acquisition and execution steps for speculative requests.
//!
//! A [`Verifier`] turns a verification or a proposal's parent recovery into work the actor can
//! interleave with maintenance: [`Verifier::prepare`] acquires the blocks a request needs without
//! touching the application, [`Verifier::next`] selects one block to process at a time, and
//! [`Verifier::process`] processes that block once for all concurrent requests that need it.

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

/// A request's acquired ancestry and the execution steps that remain before it completes.
///
/// Each step checks its parent's state again when it forks batches.
pub(in crate::stateful::actor) struct Prepared<B: Block> {
    /// The request's block, or a proposal's parent, followed by its ancestors. The final
    /// verification step takes it, leaving an empty ancestry.
    ancestry: BoxedAncestry<B>,
    /// Missing blocks still to process before the request's own block, if any.
    replay: Option<ReplayPath<B>>,
    /// Whether the request's own block still needs processing once the path is done.
    verify: bool,
    /// Verification timer, observed when the request completes.
    timer: Option<Timer>,
}

impl<B: Block> Prepared<B> {
    /// Records the verification latency, if timed, and returns the ancestry a proposal builds on.
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
    /// Acquires a request's block, its parent when `verify` is set, and the missing path to
    /// cached or applied state, without borrowing the application or forking database batches.
    ///
    /// A verification of a cached block, or of a block at or below the branch anchor's height,
    /// needs no execution and is answered from the cache or the canonical block at that height.
    /// Ancestry that ends before known state leaves a verification pending, so it abstains, and
    /// makes recovery return [`PrepareBatchesError::Incomplete`].
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

            // Each request waits on its own ancestry, even though execution is shared by digest.
            let Some(block) = ancestry.next().await else {
                if verify {
                    debug!("verification waiting on incomplete block ancestry");
                    return pending().await;
                }
                return Err(PrepareBatchesError::Incomplete);
            };
            let digest = block.digest();

            // A cached block was already processed, and a block at or below the branch anchor
            // cannot be processed on the applied state, so both are answered without execution:
            // the cached block is valid, and the other is valid only if it is the canonical block
            // at its height. A canonical block marshal cannot return yet leaves the verification
            // pending.
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

            // A verification also acquires the block's parent and recovers state through it.
            // Recovery targets the first block itself: the parent a proposal builds on.
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

            // Collect the missing path unless that block is already cached or the branch anchor.
            // A verification waits for a path that ends before known state, since the missing
            // blocks can still arrive, and a proposal declines.
            let replay = if execution.pending_contains(&parent.digest())
                || execution.branch_anchor().digest == parent.digest()
            {
                None
            } else {
                match execution.prepare_replay(&context, &marshal, parent).await {
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

    /// Returns the next execution step: each block on the missing path in height order, then the
    /// block itself when verifying. Returns [`None`] once the request has no step left.
    pub(in crate::stateful::actor) fn next<P>(
        &self,
        context: &E,
        provider: &P,
        prepared: &mut Prepared<A::Block>,
    ) -> Option<PreparedStep<A::Block>>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        // The missing path comes first. Once it is exhausted, the request's own block is the
        // last step. That step takes the acquired ancestry: cloning a stream with a pending parent
        // fetch would subscribe to that parent again. Clearing the flag makes the following call
        // return no step.
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
                std::mem::replace(
                    &mut prepared.ancestry,
                    BoxedAncestry::new(marshal_ancestry::from_iter::<A::Block>([])),
                )
            }
        };

        // The step identifies the block for admission decisions while the ancestry travels with
        // the execution.
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

    /// Processes one step from [`Self::next`] as a candidate, sharing the call with concurrent
    /// requests for the same block, and caches a valid result.
    ///
    /// The request joins the processing when this is called, so the returned future holds it
    /// before its first poll. Dropping that future leaves the processing running for any other
    /// request that holds the processing, and cancels it otherwise. `context` must outlive every
    /// request that may join the processing, so it is the actor's.
    pub(in crate::stateful::actor) fn process(
        self,
        context: E,
        ancestry: BoxedAncestry<A::Block>,
    ) -> impl Future<Output = Result<(), PrepareBatchesError>> + Send {
        let digest = ancestry
            .peek()
            .expect("prepared execution must have its block")
            .digest();
        let flight = self.execution.join_replay(self.app, context, ancestry);
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
