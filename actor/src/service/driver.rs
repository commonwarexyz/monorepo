use super::types::{LaneReceiver, LoopEvent};
use crate::{Actor, IngressEnvelope, IntoIngressEnvelope};
use commonware_macros::select;
use commonware_runtime::{signal::Signal, ContextCell, Error as RuntimeError, Handle, Spawner};
use futures::{future::FutureExt, stream::FuturesUnordered, StreamExt};
use std::{
    future::Future,
    num::NonZeroUsize,
    pin::{pin, Pin},
    task::{Context, Poll},
};
use tracing::{debug, error};

/// A future that polls all lanes in declaration order, returning the first
/// ready message or `None` if any lane closed.
///
/// Returns `Pending` when no lane is ready or `lanes` is empty.
struct Lanes<'a, I> {
    lanes: &'a mut [LaneReceiver<I>],
}

impl<I> Future for Lanes<'_, I> {
    type Output = Option<I>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.lanes.is_empty() {
            return Poll::Pending;
        }
        for lane in self.lanes.iter_mut() {
            match lane.poll_recv(cx) {
                Poll::Ready(Some(message)) => return Poll::Ready(Some(message)),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

/// In-flight read-only tasks with a bounded concurrency limit.
///
/// Before executing a read-write (mutation), all in-flight reads must
/// be drained. New reads are only accepted when the number of in-flight
/// reads is below `max_inflight`.
struct Reads<E: Spawner, A: Actor<E>> {
    inflight: FuturesUnordered<Handle<Result<(), A::Error>>>,
    max_inflight: usize,
}

impl<E: Spawner, A: Actor<E>> Reads<E, A> {
    fn new(max_inflight: NonZeroUsize) -> Self {
        Self {
            inflight: FuturesUnordered::new(),
            max_inflight: max_inflight.get(),
        }
    }

    fn is_full(&self) -> bool {
        self.inflight.len() >= self.max_inflight
    }

    fn is_empty(&self) -> bool {
        self.inflight.is_empty()
    }

    fn push(&mut self, handle: Handle<Result<(), A::Error>>) {
        self.inflight.push(handle);
    }

    /// Retire all immediately-ready reads without blocking.
    ///
    /// Returns `true` if any completed read was fatal, `false` otherwise.
    fn retire_ready(&mut self) -> bool {
        while let Some(result) = self.inflight.next().now_or_never().flatten() {
            if Self::is_fatal(result) {
                return true;
            }
        }
        false
    }

    /// Wait for the next in-flight read to complete.
    ///
    /// Returns `None` when there are no in-flight reads, or `Some(fatal)`
    /// where `fatal` is `true` if the completed read failed.
    async fn next(&mut self) -> Option<bool> {
        let result = self.inflight.next().await?;
        Some(Self::is_fatal(result))
    }

    /// Drain all remaining in-flight reads, logging results until the
    /// first fatal, then draining the rest silently.
    async fn drain(&mut self) {
        while let Some(result) = self.inflight.next().await {
            if Self::is_fatal(result) {
                while self.inflight.next().await.is_some() {}
                break;
            }
        }
    }

    fn is_fatal(result: Result<Result<(), A::Error>, RuntimeError>) -> bool {
        match result {
            Ok(Ok(())) => false,
            Ok(Err(err)) => {
                error!(%err, "actor failed");
                true
            }
            Err(err) => {
                error!(?err, "read-only task failed");
                true
            }
        }
    }
}

/// Framework-managed actor loop used by [`crate::service::ServiceBuilder`].
///
/// The loop dispatches incoming messages as either read-only (spawned
/// concurrently on a snapshot) or read-write (executed inline with
/// exclusive `&mut self` access). A fence ensures the two never overlap:
///
/// ```text
///   Timeline for a write arriving while reads are in flight:
///
///   --time-->
///
///   R0 ####..done
///   R1 ######..done
///   R2 ########.done     drain_reads_or_shutdown()
///                   |---- FENCE ----|
///   W0                              ######done  on_read_write()
///   R3                                    ######  (new reads ok)
///
///   # = executing   . = completing / being awaited
/// ```
///
/// Before any read-write handler runs, the service drains every in-flight
/// read task to completion. This fence guarantees that
/// `on_read_write(&mut self, ...)` never races with a concurrent
/// `on_read_only` snapshot task.
pub struct ActorService<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    pub(super) context: ContextCell<E>,
    pub(super) actor: A,
    pub(super) lanes: Vec<LaneReceiver<A::Ingress>>,
    pub(super) shutdown: Signal,
    pub(super) max_inflight_reads: NonZeroUsize,
}

impl<E, A> ActorService<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    /// Spawn the control loop, passing `args` data to [`Actor::on_startup`].
    ///
    /// The returned handle resolves when the actor loop exits.
    pub fn start_with(mut self, args: A::Args) -> Handle<()> {
        let context = self.context.take();
        context.spawn(move |context| async move {
            self.context.restore(context);
            self.enter(args).await
        })
    }

    /// read-only or read-write handlers, and exits on shutdown, lane
    /// closure, or fatal handler error.
    async fn enter(mut self, mut args: A::Args) {
        debug!(lanes = self.lanes.len(), "actor service started");
        self.actor
            .on_startup(self.context.as_present_mut(), &mut args)
            .await;

        let mut reads = Reads::<E, A>::new(self.max_inflight_reads);

        loop {
            if !reads.is_empty() && reads.retire_ready() {
                self.shutdown_gracefully(&mut args, &mut reads, "fatal read detected")
                    .await;
                return;
            }

            self.actor
                .preprocess(self.context.as_present_mut(), &mut args)
                .await;

            if reads.is_full() {
                if self.wait_for_read_capacity(&mut args, &mut reads).await {
                    return;
                }

                self.actor
                    .postprocess(self.context.as_present_mut(), &mut args)
                    .await;
                continue;
            }

            let event = {
                let external = self
                    .actor
                    .on_external(self.context.as_present_mut(), &mut args);
                Self::recv_event(&mut self.shutdown, &mut self.lanes, pin!(external)).await
            };
            match event {
                LoopEvent::Shutdown => {
                    self.shutdown_gracefully(&mut args, &mut reads, "shutdown signal received")
                        .await;
                    return;
                }
                LoopEvent::Mailbox(Some(message)) => match message.into_ingress_envelope() {
                    IngressEnvelope::ReadOnly(message) => {
                        self.handle_read_only(&args, &mut reads, message);
                    }
                    IngressEnvelope::ReadWrite(message) => {
                        if self.handle_read_write(&mut args, &mut reads, message).await {
                            return;
                        }
                    }
                },
                LoopEvent::External(Some(message)) => {
                    if self.handle_read_write(&mut args, &mut reads, message).await {
                        return;
                    }
                }
                LoopEvent::Mailbox(None) | LoopEvent::External(None) => {
                    self.shutdown_gracefully(
                        &mut args,
                        &mut reads,
                        "ingress source closed, shutting down actor",
                    )
                    .await;
                    return;
                }
            };

            self.actor
                .postprocess(self.context.as_present_mut(), &mut args)
                .await;
        }
    }

    /// Drain all in-flight reads, invoke [`Actor::on_shutdown`], and log
    /// service stop.
    async fn shutdown_gracefully(
        &mut self,
        args: &mut A::Args,
        reads: &mut Reads<E, A>,
        reason: &'static str,
    ) {
        debug!(reason, "actor shutting down");
        reads.drain().await;
        self.actor
            .on_shutdown(self.context.as_present_mut(), args)
            .await;
        debug!("actor service stopped");
    }

    /// Block until there is room for another read or a shutdown signal
    /// arrives. Returns `true` if the actor loop should exit.
    async fn wait_for_read_capacity(
        &mut self,
        args: &mut A::Args,
        reads: &mut Reads<E, A>,
    ) -> bool {
        debug_assert!(!reads.is_empty(), "wait requires in-flight reads");

        select! {
            _ = &mut self.shutdown => {
                self.shutdown_gracefully(args, reads, "shutdown signal received").await;
                true
            },
            result = reads.next() => {
                match result {
                    Some(true) => {
                        self.shutdown_gracefully(args, reads, "fatal read detected").await;
                        true
                    },
                    _ => false,
                }
            },
        }
    }

    /// Wait for all in-flight reads to complete, or exit early on
    /// shutdown or fatal read. Returns `true` if the actor loop should
    /// exit.
    async fn drain_reads_or_shutdown(
        &mut self,
        args: &mut A::Args,
        reads: &mut Reads<E, A>,
    ) -> bool {
        while !reads.is_empty() {
            select! {
                _ = &mut self.shutdown => {
                    self.shutdown_gracefully(args, reads, "shutdown signal received").await;
                    return true;
                },
                result = reads.next() => {
                    match result {
                        Some(true) => {
                            self.shutdown_gracefully(args, reads, "fatal read detected").await;
                            return true;
                        },
                        Some(false) => {},
                        None => return false,
                    }
                },
            }
        }
        false
    }

    /// Snapshot actor state and spawn a read-only handler.
    fn handle_read_only(
        &self,
        args: &A::Args,
        reads: &mut Reads<E, A>,
        message: <A::Ingress as IntoIngressEnvelope>::ReadOnlyIngress,
    ) {
        let snapshot = self.actor.snapshot(args);
        let context = self.context.as_present().clone();
        let handle = context
            .spawn(move |context| async move { A::on_read_only(context, snapshot, message).await });
        reads.push(handle);
    }

    /// Drain all in-flight reads, execute a read-write message, and
    /// handle errors. Returns `true` if the actor loop should exit.
    async fn handle_read_write(
        &mut self,
        args: &mut A::Args,
        reads: &mut Reads<E, A>,
        message: <A::Ingress as IntoIngressEnvelope>::ReadWriteIngress,
    ) -> bool {
        if self.drain_reads_or_shutdown(args, reads).await {
            return true;
        }

        if let Err(err) = self
            .actor
            .on_read_write(self.context.as_present_mut(), args, message)
            .await
        {
            error!(%err, "actor failed");
            self.shutdown_gracefully(args, reads, "fatal write detected")
                .await;
            return true;
        }

        false
    }

    /// Await the next event for the actor loop using biased `select!`.
    ///
    /// Priority order: shutdown signal, lane messages, then the actor-defined
    /// external future. At most one event is returned per call.
    async fn recv_event<W, F>(
        shutdown: &mut Signal,
        lanes: &mut [LaneReceiver<A::Ingress>],
        mut external: Pin<&mut F>,
    ) -> LoopEvent<A::Ingress, W>
    where
        W: Send + 'static,
        F: Future<Output = Option<W>> + Send,
    {
        let mut lane_recv = Lanes { lanes };
        select! {
            _ = &mut *shutdown => {
                LoopEvent::Shutdown
            },
            message = &mut lane_recv => {
                LoopEvent::Mailbox(message)
            },
            message = &mut external => {
                LoopEvent::External(message)
            },
        }
    }
}

impl<E, A> ActorService<E, A>
where
    E: Spawner,
    A: Actor<E, Args = ()>,
{
    /// Spawn the control loop for actors whose [`Actor::Args`] is `()`.
    ///
    /// The returned handle resolves when the actor loop exits.
    pub fn start(self) -> Handle<()> {
        self.start_with(())
    }
}
