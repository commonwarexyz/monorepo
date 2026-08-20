use crate::stateful::{
    Application,
    actor::{
        core::mailbox::Verification,
        processor::{VerificationResult, Verifier},
    },
};
use commonware_consensus::marshal::{
    ancestry::{BlockProvider, BoxedAncestry},
    core::{Mailbox as MarshalMailbox, Variant},
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::futures::Pool;
use futures::FutureExt as _;
use rand_core::Rng;
use std::future::Future;
use tracing::{Instrument as _, Span, info_span};

/// A verification request handed to a job.
pub(super) struct Request<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: (E, A::Context),
    pub(super) ancestry: BoxedAncestry<A::Block>,
    pub(super) verification: Verification,
}

/// Owns independently-polled verification jobs.
///
/// A job runs to its own conclusion. The only thing that ends one early is
/// its request future being dropped.
pub(super) struct Handler<S: Scheme, V: Variant> {
    marshal: MarshalMailbox<S, V>,
    jobs: Pool<(Verification, VerificationResult)>,
}

impl<S, V> Handler<S, V>
where
    S: Scheme + 'static,
    V: Variant + 'static,
{
    pub(super) fn new(marshal: MarshalMailbox<S, V>) -> Self {
        Self {
            marshal,
            jobs: Pool::default(),
        }
    }

    /// Starts verifying a request as a job the actor loop polls alongside its
    /// own work.
    pub(super) fn schedule<E, A>(
        &mut self,
        mut verifier: Verifier<E, A>,
        mut request: Request<E, A>,
    ) where
        E: Rng + Spawner + Metrics + Clock + 'static,
        A: Application<E> + 'static,
        V: Variant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let marshal = self.marshal.clone();
        let process = info_span!(parent: &request.span, "stateful.actor.verify");
        self.jobs.push(
            async move {
                let outcome = verifier
                    .run(
                        &request.context.0,
                        marshal,
                        request.context.1,
                        request.ancestry,
                        &mut request.verification,
                    )
                    .await;
                (request.verification, outcome)
            }
            .instrument(process),
        );
    }

    /// Answers every job that has already finished, without waiting.
    pub(super) fn complete_ready(&mut self) {
        while let Some(result) = self.jobs.next_completed().now_or_never() {
            Self::respond(result);
        }
    }

    pub(super) async fn next_completed(&mut self) {
        let result = self.jobs.next_completed().await;
        Self::respond(result);
    }

    /// Runs `operation` while still answering verification jobs.
    pub(super) async fn drive<T>(&mut self, operation: impl Future<Output = T>) -> T {
        futures::pin_mut!(operation);
        loop {
            select! {
                output = &mut operation => break output,
                _ = self.next_completed() => {},
            }
        }
    }

    fn respond((verification, outcome): (Verification, VerificationResult)) {
        match outcome {
            VerificationResult::Decided(valid) => verification.respond(valid),
            VerificationResult::Cancelled => {}
        }
    }
}
