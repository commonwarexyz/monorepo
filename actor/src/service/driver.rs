use super::types::{LaneReceiver, LoopEvent};
use crate::{Actor, IngressEnvelope, IntoIngressEnvelope};
use commonware_macros::select;
use commonware_runtime::{signal::Signal, ContextCell, Error as RuntimeError, Handle, Spawner};
use futures::{future::FutureExt, stream::FuturesUnordered, StreamExt};
use std::{
    collections::BTreeMap,
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

/// A read-only task handle tagged with the scheduler epoch at which it
/// was dispatched. Resolves to `(epoch, result)` so the scheduler can
/// track per-epoch completion counts.
struct EpochedRead<E: Spawner, A: Actor<E>> {
    epoch: u64,
    handle: Handle<Result<(), A::Error>>,
}

impl<E: Spawner, A: Actor<E>> Future for EpochedRead<E, A> {
    type Output = (u64, Result<Result<(), A::Error>, RuntimeError>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let epoch = self.epoch;
        Pin::new(&mut self.handle).poll(cx).map(|r| (epoch, r))
    }
}

/// Epoch-based read/write scheduler.
///
/// Manages concurrent read-only tasks tagged with monotonic epochs,
/// enforcing the invariant that a read-write (mutation) at epoch `e`
/// waits for all reads dispatched at epochs `<= e` to complete before
/// proceeding. Reads dispatched after the fence epoch are allowed to
/// remain in flight.
///
/// ```text
///  epoch 0          epoch 1          epoch 2
///  -------          -------          -------
///  R0a  R0b         R1a              R2a  R2b
///   |    |           |                |    |
///   |    |   W(fence=0)               |    |
///   |    |     |     |                |    |
///   v    v     |     |                |    |
///  (drain R0*) |     |  (R1a, R2* may continue)
///              v     |                |    |
///          execute   |                |    |
///              |     |   W(fence=1)   |    |
///              |     |     |          |    |
///              |     v     |          |    |
///              | (drain R1*)          |    |
///              |           v          |    |
///              |       execute        |    |
///              |                      v    v
/// ```
///
/// Each `push` tags a read with the current epoch. `begin_write`
/// snapshots the epoch as a fence and increments it. The caller then
/// drains reads at or before the fence before executing the write.
struct Scheduler<E: Spawner, A: Actor<E>> {
    inflight: FuturesUnordered<EpochedRead<E, A>>,
    epoch_counts: BTreeMap<u64, usize>,
    fence_epoch: Option<u64>,
    fence_count: usize,
    epoch: u64,
    max_inflight: usize,
}

impl<E: Spawner, A: Actor<E>> Scheduler<E, A> {
    /// Create a scheduler that allows up to `max_inflight` concurrent reads.
    fn new(max_inflight: NonZeroUsize) -> Self {
        Self {
            inflight: FuturesUnordered::new(),
            epoch_counts: BTreeMap::new(),
            fence_epoch: None,
            fence_count: 0,
            epoch: 0,
            max_inflight: max_inflight.get(),
        }
    }

    /// Returns `true` when the number of in-flight reads has reached capacity.
    fn is_full(&self) -> bool {
        self.inflight.len() >= self.max_inflight
    }

    /// Returns `true` when no reads are in flight.
    fn is_empty(&self) -> bool {
        self.inflight.is_empty()
    }

    /// Register a read-only task at the current epoch.
    fn push(&mut self, handle: Handle<Result<(), A::Error>>) {
        let epoch = self.epoch;
        *self.epoch_counts.entry(epoch).or_default() += 1;
        self.inflight.push(EpochedRead { epoch, handle });
    }

    /// Advance the epoch and snapshot how many reads must be drained
    /// before executing a write.
    fn begin_write(&mut self) {
        let fence = self.epoch;
        self.epoch += 1;

        self.fence_count = self
            .epoch_counts
            .range(..=fence)
            .map(|(_, count)| count)
            .sum();
        self.fence_epoch = (self.fence_count > 0).then_some(fence);
    }

    /// Returns `true` while reads at or before `fence` are still in flight.
    const fn has_fence_reads(&self) -> bool {
        self.fence_count > 0
    }

    /// Retire all immediately-ready reads without blocking.
    ///
    /// Returns `true` if any completed read was fatal, `false` otherwise.
    fn retire_ready(&mut self) -> bool {
        while let Some((completed_epoch, result)) = self.inflight.next().now_or_never().flatten() {
            self.complete_read(completed_epoch);
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
        let (completed_epoch, result) = self.inflight.next().await?;
        self.complete_read(completed_epoch);
        Some(Self::is_fatal(result))
    }

    /// Drain all remaining in-flight reads, logging results until the
    /// first fatal, then draining the rest silently.
    async fn drain(&mut self) {
        while let Some((_, result)) = self.inflight.next().await {
            if Self::is_fatal(result) {
                while let Some((_, _)) = self.inflight.next().await {}
                break;
            }
        }
        self.epoch_counts.clear();
        self.fence_epoch = None;
        self.fence_count = 0;
    }

    /// Decrement the read count for `epoch`, removing the entry when it
    /// reaches zero.
    fn complete_read(&mut self, epoch: u64) {
        if let Some(n) = self.epoch_counts.get_mut(&epoch) {
            *n -= 1;

            if let Some(fence) = self.fence_epoch {
                if epoch <= fence {
                    self.fence_count = self
                        .fence_count
                        .checked_sub(1)
                        .expect("fence_count underflow");
                    if self.fence_count == 0 {
                        self.fence_epoch = None;
                    }
                }
            }

            if *n == 0 {
                self.epoch_counts.remove(&epoch);
            }
        }
    }

    /// Returns `true` if the completed read result is fatal.
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

    /// Main control loop. Calls lifecycle hooks, dispatches ingress to
    /// read-only or read-write handlers, and exits on shutdown, lane
    /// closure, or fatal handler error.
    async fn enter(mut self, mut args: A::Args) {
        debug!(lanes = self.lanes.len(), "actor service started");
        self.actor
            .on_startup(self.context.as_present_mut(), &mut args)
            .await;

        let mut scheduler = Scheduler::<E, A>::new(self.max_inflight_reads);

        loop {
            // Drain any concurrent reads that finished since the last
            // iteration before doing anything else. Only check when there
            // are in-flight reads to avoid unnecessary overhead.
            if !scheduler.is_empty() && scheduler.retire_ready() {
                self.shutdown_gracefully(&mut args, &mut scheduler, "fatal read detected")
                    .await;
                return;
            }

            self.actor
                .preprocess(self.context.as_present_mut(), &mut args)
                .await;

            // Backpressure: limit in-flight concurrent reads to prevent
            // unbounded memory growth and ensure timely write processing.
            //
            // Before receiving the next event, check if we've hit the
            // concurrency limit. If so, wait for a read slot to free up.
            // This ensures:
            // - If the next event is a write, we need to drain
            // reads before the new epoch anyway. If it is a read, we need a
            // free slot before spawning. Either way, wait for capacity.
            if scheduler.is_full() {
                if self.wait_for_read_capacity(&mut args, &mut scheduler).await {
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
                    self.shutdown_gracefully(&mut args, &mut scheduler, "shutdown signal received")
                        .await;
                    return;
                }
                LoopEvent::Mailbox(Some(message)) => match message.into_ingress_envelope() {
                    IngressEnvelope::ReadOnly(message) => {
                        self.handle_read_only(&args, &mut scheduler, message);
                    }
                    IngressEnvelope::ReadWrite(message) => {
                        if self
                            .handle_read_write(&mut args, &mut scheduler, message)
                            .await
                        {
                            return;
                        }
                    }
                },
                LoopEvent::External(Some(message)) => {
                    if self
                        .handle_read_write(&mut args, &mut scheduler, message)
                        .await
                    {
                        return;
                    }
                }
                LoopEvent::Mailbox(None) | LoopEvent::External(None) => {
                    self.shutdown_gracefully(
                        &mut args,
                        &mut scheduler,
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
        scheduler: &mut Scheduler<E, A>,
        reason: &'static str,
    ) {
        debug!(reason, "actor shutting down");
        scheduler.drain().await;
        self.actor
            .on_shutdown(self.context.as_present_mut(), args)
            .await;
        debug!("actor service stopped");
    }

    /// Block until the scheduler has room for another read or a shutdown
    /// signal arrives. Returns `true` if the actor loop should exit.
    async fn wait_for_read_capacity(
        &mut self,
        args: &mut A::Args,
        scheduler: &mut Scheduler<E, A>,
    ) -> bool {
        debug_assert!(!scheduler.is_empty(), "wait requires in-flight reads");

        select! {
            _ = &mut self.shutdown => {
                self.shutdown_gracefully(args, scheduler, "shutdown signal received").await;
                true
            },
            result = scheduler.next() => {
                match result {
                    Some(true) => {
                        self.shutdown_gracefully(args, scheduler, "fatal read detected").await;
                        true
                    },
                    _ => false,
                }
            },
        }
    }

    /// Wait for all reads at or before `fence` to complete, or exit
    /// early on shutdown or fatal read. Returns `true` if the actor
    /// loop should exit.
    async fn drain_fence_or_shutdown(
        &mut self,
        args: &mut A::Args,
        scheduler: &mut Scheduler<E, A>,
    ) -> bool {
        while scheduler.has_fence_reads() {
            select! {
                _ = &mut self.shutdown => {
                    self.shutdown_gracefully(args, scheduler, "shutdown signal received").await;
                    return true;
                },
                result = scheduler.next() => {
                    match result {
                        Some(true) => {
                            self.shutdown_gracefully(args, scheduler, "fatal read detected").await;
                            return true;
                        },
                        Some(false) => {},
                        None => {
                            debug_assert!(!scheduler.has_fence_reads(), "fence_count > 0 with no in-flight reads");
                            return false;
                        },
                    }
                },
            }
        }
        false
    }

    /// Snapshot actor state and spawn a read-only handler on the scheduler.
    fn handle_read_only(
        &self,
        args: &A::Args,
        scheduler: &mut Scheduler<E, A>,
        message: <A::Ingress as IntoIngressEnvelope>::ReadOnlyIngress,
    ) {
        let snapshot = self.actor.snapshot(args);
        let context = self.context.as_present().clone();
        let handle = context
            .spawn(move |context| async move { A::on_readonly(context, snapshot, message).await });
        scheduler.push(handle);
    }

    /// Fence in-flight reads, execute a read-write message, and handle
    /// errors. Returns `true` if the actor loop should exit.
    async fn handle_read_write(
        &mut self,
        args: &mut A::Args,
        scheduler: &mut Scheduler<E, A>,
        message: <A::Ingress as IntoIngressEnvelope>::ReadWriteIngress,
    ) -> bool {
        scheduler.begin_write();

        if self.drain_fence_or_shutdown(args, scheduler).await {
            return true;
        }

        if let Err(err) = self
            .actor
            .on_read_write(self.context.as_present_mut(), args, message)
            .await
        {
            error!(%err, "actor failed");
            self.shutdown_gracefully(args, scheduler, "fatal write detected")
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
