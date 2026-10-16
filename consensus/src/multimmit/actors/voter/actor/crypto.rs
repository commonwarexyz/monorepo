//! Signing and certificate assembly on the critical pool.

use super::{DigestOf, Finished, VoterTypes};
use crate::{
    multimmit::{
        actors::{
            util::{WorkerPanicked, offload},
            voter::{
                tasks::TaskPermit,
                telemetry::{TraceContext, metrics::Metrics},
            },
        },
        machine::{Aggregated, CryptoCompletion, CryptoJob, EffectId, Generation, SignRequest},
        scheme::bls12381::{Error as SchemeError, Scheme, SignatureVerification},
        types::Artifact,
    },
    types::View,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy as _;
use commonware_runtime::{
    Clock, Supervisor as _,
    telemetry::metrics::{Histogram, HistogramExt as _},
};
use commonware_utils::futures::Pool;
use futures::FutureExt as _;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tracing::Span;

/// One completed signing choice or certificate assembly.
pub(crate) enum CryptoOutcome<V: Variant, D: Digest> {
    /// The artifacts of one signing effect, in request order.
    Signed {
        id: EffectId,
        generation: Generation,
        artifacts: Vec<Arc<Artifact<V, D>>>,
    },
    /// One assembled certificate for the view whose votes it aggregates.
    Aggregated {
        view: View,
        completion: CryptoCompletion<V, D>,
    },
}

/// An operation's result as it returns from the pool: its outcome, or a worker panic.
pub(crate) type CryptoResult<V, D> =
    Result<Result<CryptoOutcome<V, D>, SchemeError>, WorkerPanicked>;

/// Runs local cryptography on the critical pool and collects the results.
pub(crate) struct CryptoExecutor<T: VoterTypes> {
    scheme: Arc<Scheme<T::PublicKey, T::Variant>>,
    critical: T::CriticalStrategy,
    clock: Arc<T::Context>,
    pool: Pool<'static, Finished<CryptoResult<T::Variant, DigestOf<T>>>>,
    signing_wait: Histogram,
    aggregation_wait: Histogram,
}

impl<T: VoterTypes> CryptoExecutor<T> {
    pub(crate) fn new(
        scheme: Arc<Scheme<T::PublicKey, T::Variant>>,
        critical: T::CriticalStrategy,
        clock: T::Context,
        metrics: &Metrics,
    ) -> Self {
        Self {
            scheme,
            critical,
            clock: Arc::new(clock),
            pool: Pool::default(),
            signing_wait: metrics.crypto_submit_wait_signing.clone(),
            aggregation_wait: metrics.crypto_submit_wait_aggregation.clone(),
        }
    }

    /// Returns the scheme the executor signs and assembles with.
    pub(crate) const fn scheme(&self) -> &Arc<Scheme<T::PublicKey, T::Variant>> {
        &self.scheme
    }

    /// Signs every machine-authorized subject in `requests` across the pool, all or nothing and
    /// in order.
    pub(crate) fn sign(
        &mut self,
        permit: TaskPermit,
        id: EffectId,
        generation: Generation,
        requests: Arc<[SignRequest<T::Variant, DigestOf<T>>]>,
        span: Span,
        root: &Span,
    ) {
        let scheme = Arc::clone(&self.scheme);
        let wait = self.signing_wait.clone();
        self.submit(permit, wait, span, root, move |strategy| {
            let artifacts = match &*requests {
                [request] => vec![request.sign(&scheme)?],
                requests => strategy
                    .try_map_collect_vec(requests.iter(), |request| request.sign(&scheme))?,
            };
            Ok(CryptoOutcome::Signed {
                id,
                generation,
                artifacts: artifacts.into_iter().map(Arc::new).collect(),
            })
        });
    }

    /// Assembles one V-QC or L-QC from its preverified votes.
    ///
    /// Preverified assembly checks no signature, so it draws nothing from the runtime randomness
    /// it is handed.
    pub(crate) fn aggregate(
        &mut self,
        permit: TaskPermit,
        job: CryptoJob<T::Variant, DigestOf<T>>,
        span: Span,
        root: &Span,
    ) {
        let scheme = Arc::clone(&self.scheme);
        let wait = self.aggregation_wait.clone();
        let view = job.view();
        let mut rng = self.clock.child("aggregate");
        self.submit(permit, wait, span, root, move |strategy| {
            let completion = match job {
                CryptoJob::AggregateVqc(job) => {
                    let (issued, parent) = (job.issued(), job.parent());
                    let (votes, paths) = job.into_votes_and_paths();
                    let vqc = scheme.assemble_vqc(
                        &mut rng,
                        parent,
                        &votes,
                        paths,
                        SignatureVerification::Preverified,
                        &strategy,
                    )?;
                    CryptoCompletion::Vqc(Box::new(Aggregated::new(issued, vqc)))
                }
                CryptoJob::AggregateLqc(job) => {
                    let lqc = scheme.assemble_lqc::<_, T::Hasher, _>(
                        &mut rng,
                        job.leader().clone(),
                        job.votes(),
                        SignatureVerification::Preverified,
                        &strategy,
                    )?;
                    CryptoCompletion::Lqc(Box::new(Aggregated::new(job.issued(), lqc)))
                }
            };
            Ok(CryptoOutcome::Aggregated { view, completion })
        });
    }

    /// Runs `operation` on the critical pool while `permit` holds its capacity.
    ///
    /// `wait` observes the delay from submission to the start of the work. The operation receives
    /// the submission strategy so nested parallel work uses the same pool.
    fn submit(
        &mut self,
        permit: TaskPermit,
        wait: Histogram,
        span: Span,
        root: &Span,
        operation: impl FnOnce(
            T::CriticalStrategy,
        ) -> Result<CryptoOutcome<T::Variant, DigestOf<T>>, SchemeError>
        + Send
        + 'static,
    ) {
        let clock = Arc::clone(&self.clock);
        let submitted_at = clock.current();
        let operation = offload(self.critical.clone(), 1, span, move |strategy| {
            wait.observe_between(submitted_at, clock.current());
            operation(strategy)
        });
        let root = root.clone();
        self.pool.push(async move {
            let (span, outcome) = operation.await;
            Finished {
                permit,
                trace: TraceContext::new(span, root),
                outcome,
            }
        });
    }

    /// Polls for the next finished operation.
    pub(crate) fn poll_completed(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Finished<CryptoResult<T::Variant, DigestOf<T>>>> {
        self.pool.next_completed().poll_unpin(cx)
    }

    /// Cancels every operation in flight.
    pub(crate) fn cancel_all(&mut self) {
        self.pool.cancel_all();
    }
}
