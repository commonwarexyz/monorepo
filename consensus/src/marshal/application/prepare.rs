//! The marshal's side of the [`Parent`] handle given to [`Application::prepare`].
//!
//! A prepare request hands the application a [`Lazy`] parent. The marshal's proposal checks
//! run only when the application asks for the ancestry, and their outcome reaches the marshal
//! through a report the handle sends when it resolves. [`drive`] then answers consensus from
//! that report and the application's response.
//!
//! [`Application::prepare`]: crate::Application::prepare

use crate::{
    Application, Block, Handoff, Roundable as _, Viewable,
    marshal::{
        ancestry::{Ancestry, Parent},
        application::gates::Gates,
    },
    types::Round,
};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::metrics::histogram::Timer};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use futures::FutureExt as _;
use rand_core::Rng;
use std::{future::Future, sync::Arc};
use tracing::{Instrument as _, Span, debug, warn};

/// The outcome of the marshal's proposal checks for a parent.
///
/// The handle reports the same outcome to the marshal with a unit ancestry.
pub(crate) enum Resolved<D, S, A, M = ()> {
    /// The marshal re-proposes the epoch boundary block, identified by the first field.
    Reuse(D, Arc<S>),
    /// The marshal cannot build on this parent.
    Skip,
    /// The parent is fetched and the application may build on its ancestry. The timer
    /// measures the application's build from this point; the metadata (the coding
    /// configuration, or unit for standard blocks) is passed to the sealing callback with
    /// the built block.
    Build(A, Timer, M),
}

/// The staging log name of a re-proposed epoch boundary block.
pub(crate) const BOUNDARY_BLOCK: &str = "re-proposed boundary block";

/// A parent the marshal fetches only when the application asks for its ancestry.
///
/// `resolve` holds the marshal's proposal checks. The handle reports their outcome to the
/// marshal before it answers the application, so the marshal can tell a block built on the
/// fetched ancestry from one built without it.
struct Lazy<F, D, S, M> {
    resolve: F,
    report: oneshot::Sender<Resolved<D, S, (), M>>,
}

impl<F, D, S, M> Lazy<F, D, S, M> {
    /// Creates a handle around `resolve` and the receiver of its report.
    fn new(resolve: F) -> (Self, oneshot::Receiver<Resolved<D, S, (), M>>) {
        let (report, resolution) = oneshot::channel();
        (Self { resolve, report }, resolution)
    }
}

impl<B, F, D, S, A, M> Parent<B> for Lazy<F, D, S, M>
where
    B: Block,
    F: Future<Output = Resolved<D, S, A, M>> + Send + 'static,
    D: Send + 'static,
    S: Send + Sync + 'static,
    A: Ancestry<B>,
    M: Send + 'static,
{
    async fn ancestry(self) -> Option<impl Ancestry<B>> {
        let (resolved, ancestry) = match self.resolve.await {
            Resolved::Reuse(id, block) => (Resolved::Reuse(id, block), None),
            Resolved::Skip => (Resolved::Skip, None),
            Resolved::Build(ancestry, timer, metadata) => {
                (Resolved::Build((), timer, metadata), Some(ancestry))
            }
        };
        self.report.send_lossy(resolved);
        ancestry
    }
}

/// Answers a prepare request for `consensus_context` through the application's build.
///
/// The application receives a [`Lazy`] parent that runs `checks` only when asked. The build is
/// instrumented with `span` and driven under a child of `context` named for the request, and
/// `seal` turns a block it built into the staged form and its identifier.
pub(crate) fn request<E, A, D, S, N, Fut, M>(
    context: &E,
    application: &A,
    gates: Gates<D, S>,
    consensus_context: A::Context,
    checks: Fut,
    span: Span,
    seal: impl FnOnce(A::Block, M) -> (D, Arc<S>) + Send + 'static,
) -> oneshot::Receiver<Handoff<D>>
where
    E: Rng + Clock + Spawner + Metrics,
    A: Application<E, Input = ()>,
    A::Context: Viewable + Send + 'static,
    D: Digest,
    S: Send + Sync + 'static,
    N: Ancestry<A::Block>,
    M: Send + 'static,
    Fut: Future<Output = Resolved<D, S, N, M>> + Send + 'static,
{
    let round = consensus_context.round();
    let (tx, rx) = oneshot::channel();
    let (parent, resolution) = Lazy::new(checks);
    let context = context.child("prepare").with_attribute("round", round);
    let mut application = application.clone();
    let application_context = context.child("app_prepare");
    let build = async move {
        application
            .prepare((application_context, consensus_context), parent, ())
            .await
    }
    .instrument(span);
    drive(context, build, tx, resolution, gates, round, seal);
    rx
}

/// Answers a prepare request on `tx` from the application's `build` future.
///
/// A build that completes on its first poll without asking for the parent, as the default
/// [`Application::prepare`] does, is answered [`Handoff::Wait`] on the caller's task without
/// spawning. A build that completes on its first poll after its parent resolved is answered
/// from a spawned task. Any other build is driven by a task spawned from `context` until it
/// completes or consensus drops the receiver, which cancels the build and its wait for the
/// parent.
///
/// `seal` turns a block the application built into the staged form and its identifier.
fn drive<E, B, D, S, Fut, M>(
    context: E,
    build: Fut,
    tx: oneshot::Sender<Handoff<D>>,
    mut resolution: oneshot::Receiver<Resolved<D, S, (), M>>,
    gates: Gates<D, S>,
    round: Round,
    seal: impl FnOnce(B, M) -> (D, Arc<S>) + Send + 'static,
) where
    E: Clock + Spawner + Metrics,
    B: Send + 'static,
    D: Digest,
    S: Send + Sync + 'static,
    Fut: Future<Output = Handoff<B>> + Send + 'static,
    M: Send + 'static,
{
    let mut build = Box::pin(build);
    if let Some(prepared) = (&mut build).now_or_never() {
        match resolution.try_recv() {
            Err(_) => decline(prepared, tx),
            Ok(resolved) => {
                context.spawn(move |context| {
                    answer(context, prepared, resolved, tx, gates, round, seal)
                });
            }
        }
        return;
    }
    context.spawn(move |context| async move {
        let mut tx = tx;
        let prepared = select! {
            _ = tx.closed() => {
                debug!(?round, reason = "consensus dropped receiver", "skipping prepare");
                return;
            },
            prepared = &mut build => prepared,
        };
        match resolution.try_recv() {
            Err(_) => decline(prepared, tx),
            Ok(resolved) => answer(context, prepared, resolved, tx, gates, round, seal).await,
        }
    });
}

/// Answers a prepare request whose parent handle was resolved.
///
/// A boundary block the marshal re-proposes or a parent it cannot build on decides the answer
/// regardless of what the application returned. Otherwise the application's block is sealed and
/// staged under its decision, and its build time is observed.
async fn answer<E, B, D, S, M>(
    context: E,
    prepared: Handoff<B>,
    resolved: Resolved<D, S, (), M>,
    tx: oneshot::Sender<Handoff<D>>,
    gates: Gates<D, S>,
    round: Round,
    seal: impl FnOnce(B, M) -> (D, Arc<S>),
) where
    E: Clock,
    D: Digest,
{
    match resolved {
        Resolved::Reuse(id, block) => {
            if !prepared.is_wait() {
                debug!(
                    ?round,
                    "discarding prepared block: marshal re-proposes the boundary block"
                );
            }
            gates
                .stage(
                    round,
                    id,
                    block,
                    |id| {
                        tx.send_lossy(Handoff::Stage(id));
                    },
                    BOUNDARY_BLOCK,
                )
                .await;
        }
        Resolved::Skip => {
            if !prepared.is_wait() {
                debug!(
                    ?round,
                    "discarding prepared block: marshal cannot build on the parent"
                );
            }
            tx.send_lossy(Handoff::Wait);
        }
        Resolved::Build((), timer, metadata) => {
            let (block, respond): (B, fn(D) -> Handoff<D>) = match prepared {
                Handoff::Vote(block) => (block, Handoff::Vote),
                Handoff::Stage(block) => (block, Handoff::Stage),
                Handoff::Wait => {
                    debug!(?round, reason = "block building failed", "skipping prepare");
                    tx.send_lossy(Handoff::Wait);
                    return;
                }
            };
            timer.observe(&context);
            let (id, block) = seal(block, metadata);
            gates
                .stage(
                    round,
                    id,
                    block,
                    |id| {
                        tx.send_lossy(respond(id));
                    },
                    "prepared block",
                )
                .await;
        }
    }
}

/// Answers [`Handoff::Wait`] for a response built without the parent handle.
fn decline<B, D>(prepared: Handoff<B>, tx: oneshot::Sender<Handoff<D>>) {
    if !prepared.is_wait() {
        warn!("discarding prepared block built without asking for the parent ancestry");
    }
    tx.send_lossy(Handoff::Wait);
}
