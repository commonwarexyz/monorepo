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
pub(crate) enum Resolved<D, S, A> {
    /// The marshal stages a block of its own under `id`, either a candidate recovered from
    /// before a restart or the epoch boundary block. The `&'static str` names the block in the
    /// staging logs.
    Reuse(D, Arc<S>, &'static str),
    /// The marshal cannot build on this parent.
    Skip,
    /// The parent is fetched and the application may build on its ancestry. The timer
    /// measures the application's build from this point.
    Build(A, Timer),
}

/// A parent the marshal fetches only when the application asks for it.
///
/// `resolve` runs the marshal's proposal checks. The handle reports their outcome to the
/// marshal before it answers the application, so the marshal can tell a block built on the
/// fetched ancestry from one built without it.
struct Lazy<F, D, S> {
    resolve: F,
    report: oneshot::Sender<Resolved<D, S, ()>>,
}

impl<F, D, S> Lazy<F, D, S> {
    /// Creates a handle around `resolve` and the receiver of its report.
    fn new(resolve: F) -> (Self, oneshot::Receiver<Resolved<D, S, ()>>) {
        let (report, resolution) = oneshot::channel();
        (Self { resolve, report }, resolution)
    }
}

impl<B, F, Fut, D, S, A> Parent<B> for Lazy<F, D, S>
where
    B: Block,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Resolved<D, S, A>> + Send,
    D: Send + 'static,
    S: Send + Sync + 'static,
    A: Ancestry<B>,
{
    async fn ancestry(self) -> Option<impl Ancestry<B>> {
        let (resolved, ancestry) = match (self.resolve)().await {
            Resolved::Reuse(id, block, name) => (Resolved::Reuse(id, block, name), None),
            Resolved::Skip => (Resolved::Skip, None),
            Resolved::Build(ancestry, timer) => (Resolved::Build((), timer), Some(ancestry)),
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
pub(crate) fn request<E, A, D, S, N, Fut>(
    context: &E,
    application: &A,
    gates: Gates<D, S>,
    consensus_context: A::Context,
    checks: Fut,
    span: Span,
    seal: impl FnOnce(A::Block) -> (D, Arc<S>) + Send + 'static,
) -> oneshot::Receiver<Handoff<D>>
where
    E: Rng + Clock + Spawner + Metrics,
    A: Application<E, Input = ()>,
    A::Context: Viewable + Send + 'static,
    D: Digest,
    S: Send + Sync + 'static,
    N: Ancestry<A::Block>,
    Fut: Future<Output = Resolved<D, S, N>> + Send + 'static,
{
    let round = consensus_context.round();
    let (tx, rx) = oneshot::channel();
    let (parent, resolution) = Lazy::new(move || checks);
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
/// spawning. Any other build is driven by a task spawned from `context` until it completes or
/// consensus drops the receiver, which cancels it along with any parent fetch in flight.
///
/// `seal` turns a block the application built into the staged form and its identifier.
fn drive<E, B, D, S, Fut>(
    context: E,
    build: Fut,
    tx: oneshot::Sender<Handoff<D>>,
    mut resolution: oneshot::Receiver<Resolved<D, S, ()>>,
    gates: Gates<D, S>,
    round: Round,
    seal: impl FnOnce(B) -> (D, Arc<S>) + Send + 'static,
) where
    E: Clock + Spawner + Metrics,
    B: Send + 'static,
    D: Digest,
    S: Send + Sync + 'static,
    Fut: Future<Output = Handoff<B>> + Send + 'static,
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
/// A block the marshal reuses or a parent it cannot build on decides the answer regardless of
/// what the application returned. Otherwise the application's block is sealed and staged under
/// its decision, and its build time is observed.
async fn answer<E, B, D, S>(
    context: E,
    prepared: Handoff<B>,
    resolved: Resolved<D, S, ()>,
    tx: oneshot::Sender<Handoff<D>>,
    gates: Gates<D, S>,
    round: Round,
    seal: impl FnOnce(B) -> (D, Arc<S>),
) where
    E: Clock,
    D: Digest,
{
    match resolved {
        Resolved::Reuse(id, block, name) => {
            if !prepared.is_wait() {
                debug!(
                    ?round,
                    "discarding prepared block: marshal reuses a block of its own"
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
                    name,
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
        Resolved::Build((), timer) => {
            let (block, respond): (B, fn(D) -> Handoff<D>) = match prepared {
                Handoff::Publish(block) => (block, Handoff::Publish),
                Handoff::Stage(block) => (block, Handoff::Stage),
                Handoff::Wait => {
                    debug!(?round, reason = "block building failed", "skipping prepare");
                    tx.send_lossy(Handoff::Wait);
                    return;
                }
            };
            timer.observe(&context);
            let (id, block) = seal(block);
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
