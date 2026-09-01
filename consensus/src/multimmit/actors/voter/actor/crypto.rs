//! Signing, certificate assembly, and nullification recovery on the critical pool.

use super::{DigestOf, Finished, VoterTypes};
use crate::{
    Viewable as _,
    multimmit::{
        actors::{
            util::{WorkerPanicked, offload},
            voter::{
                tasks::TaskPermit,
                telemetry::{TraceContext, metrics::Metrics},
            },
        },
        machine::{
            EffectId, Generation, Issued, LqcAggregateCompletion, LqcAggregateJob,
            NullificationRecoveryCompletion, NullificationRecoveryJob, SignRequest,
            VqcAggregateCompletion, VqcAggregateJob,
        },
        scheme::bls12381_threshold::{Error as SchemeError, Scheme, SignatureVerification},
        types::Artifact,
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock,
    telemetry::metrics::{Histogram, HistogramExt as _},
};
use commonware_utils::futures::Pool;
use futures::FutureExt as _;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::SystemTime,
};
use tracing::Span;

/// One completed signature, certificate assembly, or recovery.
pub(crate) enum CryptoOutcome<V: Variant, D: Digest> {
    Signed {
        id: EffectId,
        generation: Generation,
        artifact: Arc<Artifact<V, D>>,
    },
    SignedBatch {
        id: EffectId,
        generation: Generation,
        artifacts: Vec<Artifact<V, D>>,
    },
    NullificationRecovered {
        started_at: SystemTime,
        completion: NullificationRecoveryCompletion<V>,
    },
    VqcAggregated {
        view: View,
        completion: Box<VqcAggregateCompletion<V, D>>,
    },
    LqcAggregated {
        view: View,
        completion: Box<LqcAggregateCompletion<V, D>>,
    },
}

/// An operation's result as it returns from the pool: its outcome, or a worker panic.
pub(crate) type CryptoResult<V, D> =
    Result<Result<CryptoOutcome<V, D>, SchemeError>, WorkerPanicked>;

/// A leader-path certificate assembled from a machine-selected, preverified quorum.
pub(crate) trait QuorumJob<H: Hasher, P: PublicKey, V: Variant>: Send + 'static {
    /// Returns the view whose leader the certificate names.
    fn view(&self) -> View;

    /// Assembles the certificate on `strategy`, checks it against this job, and wraps it.
    fn assemble<S: Strategy>(
        &self,
        scheme: &Scheme<P, V>,
        strategy: &S,
    ) -> Result<CryptoOutcome<V, H::Digest>, SchemeError>;
}

impl<H: Hasher, P: PublicKey, V: Variant> QuorumJob<H, P, V> for VqcAggregateJob<V, H::Digest> {
    fn view(&self) -> View {
        self.leader().view()
    }

    fn assemble<S: Strategy>(
        &self,
        scheme: &Scheme<P, V>,
        strategy: &S,
    ) -> Result<CryptoOutcome<V, H::Digest>, SchemeError> {
        let messages = self.messages().collect::<Vec<_>>();
        let certificate = scheme.assemble_vqc_with::<H, _>(
            self.leader().clone(),
            &messages,
            SignatureVerification::Preverified,
            strategy,
        )?;
        let completion =
            VqcAggregateCompletion::prepare::<H>(self, certificate, scheme.codec_config())?;
        Ok(CryptoOutcome::VqcAggregated {
            view: QuorumJob::<H, P, V>::view(self),
            completion: Box::new(completion),
        })
    }
}

impl<H: Hasher, P: PublicKey, V: Variant> QuorumJob<H, P, V> for LqcAggregateJob<V, H::Digest> {
    fn view(&self) -> View {
        self.leader().view()
    }

    fn assemble<S: Strategy>(
        &self,
        scheme: &Scheme<P, V>,
        strategy: &S,
    ) -> Result<CryptoOutcome<V, H::Digest>, SchemeError> {
        let votes = self.votes().cloned().collect::<Vec<_>>();
        let certificate = scheme.assemble_lqc_with::<H, _>(
            self.leader().clone(),
            &votes,
            SignatureVerification::Preverified,
            strategy,
        )?;
        let completion =
            LqcAggregateCompletion::prepare::<H>(self, certificate, scheme.codec_config())?;
        Ok(CryptoOutcome::LqcAggregated {
            view: QuorumJob::<H, P, V>::view(self),
            completion: Box::new(completion),
        })
    }
}

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

    /// Signs the one machine-authorized subject in `requests`.
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
        self.submit(permit, wait, span, root, move |_| {
            requests[0]
                .sign(&scheme)
                .map(|artifact| CryptoOutcome::Signed {
                    id,
                    generation,
                    artifact: Arc::new(artifact),
                })
        });
    }

    /// Signs a batch of subjects across the pool, all or nothing and in order.
    pub(crate) fn sign_batch(
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
            strategy
                .try_map_collect_vec(requests.iter(), |request| request.sign(&scheme))
                .map(|artifacts| CryptoOutcome::SignedBatch {
                    id,
                    generation,
                    artifacts,
                })
        });
    }

    /// Assembles one V-QC or L-QC from its preverified quorum.
    pub(crate) fn aggregate<Q: QuorumJob<T::Hasher, T::PublicKey, T::Variant>>(
        &mut self,
        permit: TaskPermit,
        job: Q,
        span: Span,
        root: &Span,
    ) {
        let scheme = Arc::clone(&self.scheme);
        let wait = self.aggregation_wait.clone();
        self.submit(permit, wait, span, root, move |strategy| {
            job.assemble(&scheme, &strategy)
        });
    }

    /// Recovers one nullification from its preverified shares.
    pub(crate) fn recover_nullification(
        &mut self,
        permit: TaskPermit,
        job: NullificationRecoveryJob<T::Variant>,
        span: Span,
        root: &Span,
    ) {
        let scheme = Arc::clone(&self.scheme);
        let wait = self.aggregation_wait.clone();
        let started_at = self.clock.current();
        let (id, generation) = (job.issued().id(), job.issued().generation());
        self.submit(permit, wait, span, root, move |strategy| {
            scheme
                .assemble_nullification_with(
                    job.shares(),
                    SignatureVerification::Preverified,
                    &strategy,
                )
                .map(|certificate| CryptoOutcome::NullificationRecovered {
                    started_at,
                    completion: NullificationRecoveryCompletion::new(
                        Issued::new(id, generation),
                        certificate,
                    ),
                })
        });
    }

    /// Runs `operation` on the critical pool while `permit` holds its capacity.
    ///
    /// `wait` observes the delay from submission to the start of the work. The operation receives
    /// the submission strategy so nested parallel work uses the same pool.
    pub(super) fn submit(
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

    /// Returns the number of operations in flight.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.pool.len()
    }

    /// Cancels every operation in flight.
    pub(crate) fn cancel_all(&mut self) {
        self.pool.cancel_all();
    }
}
