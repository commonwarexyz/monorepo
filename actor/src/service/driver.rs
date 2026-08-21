use super::{
    FenceMode, metrics,
    types::{Event, Lane, LaneReceiver, LaneSet},
};
use crate::{
    Actor,
    ingress::{Envelope, IntoEnvelope},
};
use commonware_macros::select;
use commonware_runtime::{
    ContextCell, Error as RuntimeError, Handle, Metrics as RuntimeMetrics, Spawner,
    signal::{Signal, Signaler},
};
use commonware_utils::channel::mpsc;
use crossbeam_queue::ArrayQueue;
use futures_util::{StreamExt, future::FutureExt, stream::FuturesUnordered, task::AtomicWaker};
use std::{
    future::poll_fn,
    num::NonZeroUsize,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::TryRecvError,
    },
    task::Poll,
};
use thiserror::Error as ThisError;
use tracing::{Instrument as _, Span, debug, debug_span, error};

type ReadMessage<E, A> = <<A as Actor<E>>::Ingress as IntoEnvelope>::ReadOnlyMessage;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
enum Stop {
    #[error("shutdown signal received")]
    Shutdown,
    #[error("actor requested stop")]
    Actor,
    #[error(transparent)]
    Read(ReadStop),
    #[error(transparent)]
    Write(WriteStop),
    #[error(transparent)]
    Worker(WorkerStop),
    #[error(transparent)]
    Dispatch(DispatchStop),
}

impl Stop {
    const fn reason(self) -> metrics::StopReason {
        match self {
            Self::Shutdown => metrics::StopReason::Shutdown,
            Self::Actor => metrics::StopReason::Actor,
            Self::Read(_) => metrics::StopReason::Read,
            Self::Write(_) => metrics::StopReason::Write,
            Self::Worker(_) => metrics::StopReason::Worker,
            Self::Dispatch(_) => metrics::StopReason::Dispatch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
enum ReadStop {
    #[error("fatal read detected")]
    Fatal,
    #[error("read failure channel closed")]
    FailureChannelClosed,
    #[error("read workers exhausted")]
    WorkersExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
enum WriteStop {
    #[error("fatal write detected")]
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
enum WorkerStop {
    #[error("read worker stopped")]
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
enum DispatchStop {
    #[error("read dispatched without available worker")]
    ReadWithoutWorker,
    #[error("read worker unavailable")]
    ReadWorkerUnavailable,
}

struct ReadJob<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    snapshot: A::Snapshot,
    message: ReadMessage<E, A>,
    process: Span,
}

/// Coordination state shared between the control loop and read workers.
///
/// Workers retire their own completions: each returns itself to `idle`,
/// decrements `inflight`, and wakes any registered waiter. Successful reads
/// therefore never wake the control loop; it only hears about failures.
struct ReadShared {
    /// Workers ready to accept a job.
    idle: ArrayQueue<usize>,
    /// Reads dispatched but not yet completed.
    inflight: AtomicUsize,
    /// Woken when `inflight` reaches zero (write fence).
    drained: AtomicWaker,
    /// Woken when a worker becomes idle (capacity wait).
    capacity: AtomicWaker,
}

/// Pre-spawned read workers with a bounded number of active handlers.
struct ReadPool<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    workers: Vec<mpsc::Sender<ReadJob<E, A>>>,
    shared: Arc<ReadShared>,
    failures: mpsc::Receiver<A::Error>,
    handles: FuturesUnordered<Handle<()>>,
    shutdown: Option<Signaler>,
    metrics: metrics::Metrics,
}

impl<E, A> ReadPool<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    fn new(context: &E, max_inflight: NonZeroUsize, metrics: metrics::Metrics) -> Self {
        let max_inflight = max_inflight.get();
        let (failure_sender, failures) = mpsc::channel(max_inflight);
        let (signaler, signal) = Signaler::new();
        let shared = Arc::new(ReadShared {
            idle: ArrayQueue::new(max_inflight),
            inflight: AtomicUsize::new(0),
            drained: AtomicWaker::new(),
            capacity: AtomicWaker::new(),
        });
        let mut workers = Vec::with_capacity(max_inflight);
        let handles = FuturesUnordered::new();
        metrics.set_read_workers(max_inflight);
        metrics.set_inflight_reads(0);

        for worker in 0..max_inflight {
            let (sender, receiver) = mpsc::channel(1);
            let failures = failure_sender.clone();
            let signal = signal.clone();
            let worker_shared = shared.clone();
            let metrics = metrics.clone();
            let handle = context
                .child("read_worker")
                .with_attribute("worker", worker)
                .spawn(move |context| {
                    Self::run_worker(
                        worker,
                        context,
                        receiver,
                        worker_shared,
                        failures,
                        metrics,
                        signal,
                    )
                });
            workers.push(sender);
            let _ = shared.idle.push(worker);
            handles.push(handle);
        }

        Self {
            workers,
            shared,
            failures,
            handles,
            shutdown: Some(signaler),
            metrics,
        }
    }

    fn len(&self) -> usize {
        self.shared.inflight.load(Ordering::Acquire)
    }

    fn is_full(&self) -> bool {
        self.shared.idle.is_empty()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn dispatch(&mut self, job: ReadJob<E, A>) -> Result<(), DispatchStop> {
        let Some(worker) = self.shared.idle.pop() else {
            return Err(DispatchStop::ReadWithoutWorker);
        };

        // Count the read before handing it off so a completing worker can
        // never observe an in-flight read that was not yet counted.
        let inflight = self.shared.inflight.fetch_add(1, Ordering::AcqRel) + 1;
        self.metrics.set_inflight_reads(inflight);
        if self.workers[worker].try_send(job).is_err() {
            return Err(DispatchStop::ReadWorkerUnavailable);
        }
        Ok(())
    }

    /// Await a fatal read failure or an unexpected worker stop.
    ///
    /// Successful completions retire on the worker and never resolve this
    /// future.
    async fn failed(&mut self) -> Stop {
        select! {
            err = self.failures.recv() => {
                let Some(err) = err else {
                    return Stop::Read(ReadStop::FailureChannelClosed);
                };
                error!(%err, "actor failed");
                Stop::Read(ReadStop::Fatal)
            },
            result = self.handles.next() => {
                let Some(result) = result else {
                    return Stop::Read(ReadStop::WorkersExhausted);
                };
                self.metrics.read_worker_stops.inc();
                Self::worker_stopped(result)
            },
        }
    }

    /// Await a stop condition (shutdown, fatal read, or worker stop).
    async fn stop_or_shutdown(&mut self, shutdown: &mut Signal) -> Stop {
        select! {
            _ = shutdown => Stop::Shutdown,
            reason = self.failed() => reason,
        }
    }

    /// Await read capacity, returning a stop reason if one occurs first.
    async fn capacity_or_stop(&mut self, shutdown: &mut Signal) -> Option<Stop> {
        let shared = self.shared.clone();
        select! {
            _ = shutdown => Some(Stop::Shutdown),
            reason = self.failed() => Some(reason),
            _ = poll_fn(|cx| {
                // Register before checking so a worker that frees itself
                // between the check and the pending return still wakes us.
                shared.capacity.register(cx.waker());
                if shared.idle.is_empty() {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            }) => None,
        }
    }

    /// Await zero in-flight reads, returning a stop reason if one occurs first.
    async fn drained_or_stop(&mut self, shutdown: &mut Signal) -> Option<Stop> {
        let shared = self.shared.clone();
        select! {
            _ = shutdown => Some(Stop::Shutdown),
            reason = self.failed() => Some(reason),
            _ = poll_fn(|cx| {
                // Register before checking so a worker that retires between
                // the check and the pending return still wakes us.
                shared.drained.register(cx.waker());
                if shared.inflight.load(Ordering::Acquire) == 0 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }) => None,
        }
    }

    async fn shutdown(&mut self) {
        self.workers.clear();
        let shutdown = self.shutdown.take().map(|signaler| signaler.signal(0));
        while let Some(result) = self.handles.next().await {
            let _ = result;
        }
        if let Some(shutdown) = shutdown {
            let _ = shutdown.await;
        }
        self.shared.inflight.store(0, Ordering::Release);
        self.metrics.set_inflight_reads(0);
    }

    async fn run_worker(
        worker: usize,
        context: E,
        mut receiver: mpsc::Receiver<ReadJob<E, A>>,
        shared: Arc<ReadShared>,
        failures: mpsc::Sender<A::Error>,
        metrics: metrics::Metrics,
        mut shutdown: Signal,
    ) {
        loop {
            let job = select! {
                _ = &mut shutdown => return,
                job = receiver.recv() => {
                    let Some(job) = job else {
                        return;
                    };
                    job
                },
            };

            let read = A::on_read_only(context.child("read"), job.snapshot, job.message)
                .instrument(job.process);
            let read = pin!(read);
            let result = select! {
                _ = &mut shutdown => return,
                result = read => result,
            };

            // Publish any failure before retiring so a fence that observes
            // zero in-flight reads also observes the failure.
            if let Err(err) = result {
                metrics.read_failures.inc();
                if failures.try_send(err).is_err() {
                    return;
                }
            }
            metrics.reads.inc();
            if shared.idle.push(worker).is_err() {
                return;
            }
            let remaining = shared.inflight.fetch_sub(1, Ordering::AcqRel) - 1;
            metrics.set_inflight_reads(remaining);
            if remaining == 0 {
                shared.drained.wake();
            }
            shared.capacity.wake();
        }
    }

    fn worker_stopped(result: Result<(), RuntimeError>) -> Stop {
        match result {
            Ok(()) => error!("read worker exited"),
            Err(err) => error!(?err, "read worker failed"),
        }
        Stop::Worker(WorkerStop::Stopped)
    }
}

enum NextEvent<I, W> {
    Actor(Event<I, W>),
    Stop(Stop),
}

struct Batch {
    messages: usize,
    stopped: bool,
}

/// Framework-managed actor loop used by [`crate::service::Builder`].
///
/// The loop dispatches read-only ingress concurrently on snapshots and
/// read-write ingress serially on the control loop. Under
/// [`FenceMode::Linearizable`], every in-flight read-only handler is drained
/// to completion before a read-write handler runs; under
/// [`FenceMode::Snapshot`], read-write handlers run immediately.
///
/// Shutdown is prompt: in-flight read-only handlers are aborted before
/// [`Actor::on_shutdown`] runs.
pub struct Service<E, A, R>
where
    E: Spawner,
    A: Actor<E>,
    R: LaneReceiver<A::Ingress>,
{
    pub(super) context: ContextCell<E>,
    pub(super) actor: A,
    pub(super) lanes: Vec<Option<R>>,
    pub(super) shutdown: Signal,
    pub(super) max_inflight_reads: NonZeroUsize,
    pub(super) fence_mode: FenceMode,
    pub(super) cached_snapshot: Option<A::Snapshot>,
    pub(super) metrics: metrics::Metrics,
}

impl<E, A, R> Service<E, A, R>
where
    E: RuntimeMetrics + Spawner,
    A: Actor<E>,
    R: LaneReceiver<A::Ingress> + 'static,
{
    pub(super) fn new(
        context: E,
        actor: A,
        lanes: Vec<R>,
        max_inflight_reads: NonZeroUsize,
        fence_mode: FenceMode,
    ) -> Self {
        let shutdown = context.stopped();
        let metrics = metrics::Metrics::init(&context, lanes.len());
        Self {
            context: ContextCell::new(context),
            actor,
            lanes: lanes.into_iter().map(Some).collect(),
            shutdown,
            max_inflight_reads,
            fence_mode,
            cached_snapshot: None,
            metrics,
        }
    }
}

impl<E, A, R> Service<E, A, R>
where
    E: Spawner,
    A: Actor<E>,
    R: LaneReceiver<A::Ingress> + 'static,
{
    /// Spawn the control loop, passing `args` data to [`Actor::on_startup`].
    pub fn start_with(mut self, args: A::Args) -> Handle<()> {
        let context = self.context.take();
        context.spawn(move |context| async move {
            self.context.restore(context);
            self.enter(args).await
        })
    }

    /// Run the actor loop until shutdown, fatal handler failure, or [`Event::Stop`].
    async fn enter(mut self, mut args: A::Args) {
        debug!(lanes = self.lanes.len(), "actor service started");
        self.actor
            .on_startup(self.context.as_present_mut(), &mut args)
            .await;

        let mut reads = ReadPool::<E, A>::new(
            self.context.as_present(),
            self.max_inflight_reads,
            self.metrics.clone(),
        );

        loop {
            self.actor
                .preprocess(self.context.as_present_mut(), &mut args)
                .await;

            if reads.is_full() {
                if self.wait_for_read_capacity(&mut args, &mut reads).await {
                    return;
                }
                continue;
            }

            // When the failure or shutdown arm wins, `next` is dropped mid-poll.
            // This is the cancellation described in [`Actor::next_event`]'s
            // "Cancellation safety" contract: the actor must tolerate losing
            // the future here, and any state it mutated before the
            // cancellation point persists.
            let event = {
                let lanes = LaneSet::new(&mut self.lanes);
                let next = self
                    .actor
                    .next_event(self.context.as_present_mut(), &mut args, lanes);
                let next = pin!(next);
                select! {
                    reason = reads.stop_or_shutdown(&mut self.shutdown) => NextEvent::Stop(reason),
                    event = next => NextEvent::Actor(event),
                }
            };
            // Every `&mut` actor hook since the last dispatch (preprocess,
            // postprocess, next_event) has run by this point, and no read
            // dispatches before it in an iteration.
            self.cached_snapshot = None;
            match event {
                NextEvent::Stop(reason) => {
                    self.shutdown_gracefully(&mut args, &mut reads, reason)
                        .await;
                    return;
                }
                NextEvent::Actor(Event::Continue) => continue,
                NextEvent::Actor(Event::Stop) => {
                    self.shutdown_gracefully(&mut args, &mut reads, Stop::Actor)
                        .await;
                    return;
                }
                NextEvent::Actor(Event::Ingress { lane, message }) => {
                    self.metrics.record_lane_message(lane.index());
                    if self.dispatch_ingress(&mut args, &mut reads, message).await {
                        self.metrics.observe_lane_batch(1);
                        return;
                    }
                    let batch = self.drain_lane_batch(&mut args, &mut reads, lane).await;
                    self.metrics.observe_lane_batch(batch.messages);
                    if batch.stopped {
                        return;
                    }
                }
                NextEvent::Actor(Event::External(message)) => {
                    if self
                        .handle_read_write(&mut args, &mut reads, None, message)
                        .await
                    {
                        return;
                    }
                }
            }

            self.actor
                .postprocess(self.context.as_present_mut(), &mut args)
                .await;
        }
    }

    /// Close mailboxes, abort in-flight read-only handlers, run
    /// [`Actor::on_shutdown`], and exit promptly.
    ///
    /// Reads abort before the hook runs so no handler can respond with
    /// pre-shutdown state after the hook mutates the actor. Pending askers
    /// observe a cancelled response.
    async fn shutdown_gracefully(
        &mut self,
        args: &mut A::Args,
        reads: &mut ReadPool<E, A>,
        reason: Stop,
    ) {
        let inflight_reads = reads.len();
        self.metrics.record_stop(reason.reason());
        debug!(%reason, inflight_reads, "actor shutting down");
        self.lanes.clear();
        reads.shutdown().await;
        self.actor
            .on_shutdown(self.context.as_present_mut(), args)
            .await;
        debug!("actor service stopped");
    }

    /// Wait until read-only capacity is available or the service must stop.
    async fn wait_for_read_capacity(
        &mut self,
        args: &mut A::Args,
        reads: &mut ReadPool<E, A>,
    ) -> bool {
        debug_assert!(!reads.is_empty(), "wait requires in-flight reads");
        self.metrics.read_capacity_waits.inc();

        if let Some(reason) = reads.capacity_or_stop(&mut self.shutdown).await {
            self.shutdown_gracefully(args, reads, reason).await;
            return true;
        }

        false
    }

    /// Drain all reads that must complete before a read-write handler runs.
    async fn drain_reads_or_shutdown(
        &mut self,
        args: &mut A::Args,
        reads: &mut ReadPool<E, A>,
    ) -> bool {
        if reads.is_empty() {
            return false;
        }
        if let Some(reason) = reads.drained_or_stop(&mut self.shutdown).await {
            self.shutdown_gracefully(args, reads, reason).await;
            return true;
        }
        false
    }

    /// Dispatch one ingress message according to its read-only or read-write envelope.
    async fn dispatch_ingress(
        &mut self,
        args: &mut A::Args,
        reads: &mut ReadPool<E, A>,
        message: A::Ingress,
    ) -> bool {
        let (span, envelope) = message.into_envelope();
        match envelope {
            Envelope::ReadOnly(message) => {
                let process = debug_span!(parent: &span, "actor.process");
                if let Err(reason) = self.handle_read_only(args, reads, process, message) {
                    error!(%reason, "read dispatch failed");
                    self.shutdown_gracefully(args, reads, Stop::Dispatch(reason))
                        .await;
                    return true;
                }
                false
            }
            Envelope::ReadWrite(message) => {
                self.handle_read_write(args, reads, Some(span), message)
                    .await
            }
        }
    }

    /// Drain additional ready messages from the lane that won this iteration.
    ///
    /// The batch ends before [`Actor::max_lane_batch`] when the lane has no
    /// ready message or read capacity fills. Other lanes are not polled while
    /// the batch runs, which biases throughput toward the winning lane.
    async fn drain_lane_batch(
        &mut self,
        args: &mut A::Args,
        reads: &mut ReadPool<E, A>,
        lane: Lane,
    ) -> Batch {
        let mut remaining = self.actor.max_lane_batch(args).get().saturating_sub(1);
        let mut messages = 1;
        while remaining > 0 {
            if (&mut self.shutdown).now_or_never().is_some() {
                self.shutdown_gracefully(args, reads, Stop::Shutdown).await;
                return Batch {
                    messages,
                    stopped: true,
                };
            }

            if reads.is_full() {
                return Batch {
                    messages,
                    stopped: false,
                };
            }

            let next = self
                .lanes
                .get_mut(lane.index())
                .and_then(|slot| slot.as_mut())
                .map(|receiver| receiver.try_recv());
            match next {
                Some(Ok(message)) => {
                    self.metrics.record_lane_message(lane.index());
                    messages += 1;
                    if self.dispatch_ingress(args, reads, message).await {
                        return Batch {
                            messages,
                            stopped: true,
                        };
                    }
                    remaining -= 1;
                }
                Some(Err(TryRecvError::Empty | TryRecvError::Disconnected)) | None => {
                    return Batch {
                        messages,
                        stopped: false,
                    };
                }
            }
        }
        Batch {
            messages,
            stopped: false,
        }
    }

    /// Dispatch a read-only handler to an idle worker using the current actor snapshot.
    ///
    /// Consecutive read-only dispatches clone one cached snapshot instead of
    /// capturing a new one per message.
    fn handle_read_only(
        &mut self,
        args: &A::Args,
        reads: &mut ReadPool<E, A>,
        process: Span,
        message: <A::Ingress as IntoEnvelope>::ReadOnlyMessage,
    ) -> Result<(), DispatchStop> {
        let actor = &self.actor;
        let snapshot = self
            .cached_snapshot
            .get_or_insert_with(|| actor.snapshot(args))
            .clone();
        reads.dispatch(ReadJob {
            snapshot,
            message,
            process,
        })
    }

    /// Fence behind in-flight reads per [`FenceMode`], then run one
    /// read-write handler.
    ///
    /// `enqueue_span` is the span carried by a mailbox message; external
    /// events pass `None` and are processed under a distinct span name. The
    /// processing span is created after the read fence so the fence wait is
    /// not attributed to handler work.
    async fn handle_read_write(
        &mut self,
        args: &mut A::Args,
        reads: &mut ReadPool<E, A>,
        enqueue_span: Option<Span>,
        message: <A::Ingress as IntoEnvelope>::ReadWriteMessage,
    ) -> bool {
        if self.fence_mode == FenceMode::Linearizable
            && self.drain_reads_or_shutdown(args, reads).await
        {
            return true;
        }

        let process = enqueue_span.as_ref().map_or_else(
            || debug_span!("actor.process.external"),
            |span| debug_span!(parent: span, "actor.process"),
        );
        let result = self
            .actor
            .on_read_write(self.context.as_present_mut(), args, message)
            .instrument(process)
            .await;
        self.cached_snapshot = None;
        self.metrics.writes.inc();
        if let Err(err) = result {
            self.metrics.write_failures.inc();
            error!(%err, "actor failed");
            self.shutdown_gracefully(args, reads, Stop::Write(WriteStop::Fatal))
                .await;
            return true;
        }

        false
    }
}

impl<E, A, R> Service<E, A, R>
where
    E: Spawner,
    A: Actor<E, Args = ()>,
    R: LaneReceiver<A::Ingress> + 'static,
{
    /// Spawn the control loop for actors whose [`Actor::Args`] is `()`.
    pub fn start(self) -> Handle<()> {
        self.start_with(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_failure_channel_closed_records_read_stop() {
        assert_eq!(
            Stop::Read(ReadStop::FailureChannelClosed).reason(),
            metrics::StopReason::Read
        );
    }
}
