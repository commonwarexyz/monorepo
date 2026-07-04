use super::{
    metrics,
    types::{Event, Lane, LaneReceiver, LaneSet},
    FenceMode,
};
use crate::{
    ingress::{Envelope, IntoEnvelope},
    Actor,
};
use commonware_macros::select;
use commonware_runtime::{
    signal::{Signal, Signaler},
    ContextCell, Error as RuntimeError, Handle, Metrics as RuntimeMetrics, Spawner,
};
use commonware_utils::channel::mpsc;
use futures_util::{future::FutureExt, stream::FuturesUnordered, StreamExt};
use std::{future::pending, num::NonZeroUsize, pin::pin, sync::mpsc::TryRecvError};
use tracing::{debug, debug_span, error, Instrument as _, Span};

type ReadMessage<E, A> = <<A as Actor<E>>::Ingress as IntoEnvelope>::ReadOnlyMessage;

struct ReadJob<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    snapshot: A::Snapshot,
    message: ReadMessage<E, A>,
    process: Span,
}

struct ReadCompletion<T> {
    worker: usize,
    result: Result<(), T>,
}

/// Pre-spawned read workers with a bounded number of active handlers.
struct ReadPool<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    workers: Vec<mpsc::Sender<ReadJob<E, A>>>,
    idle: Vec<usize>,
    completed: mpsc::Receiver<ReadCompletion<A::Error>>,
    handles: FuturesUnordered<Handle<()>>,
    shutdown: Option<Signaler>,
    metrics: metrics::Metrics,
    inflight: usize,
}

impl<E, A> ReadPool<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    fn new(context: &E, max_inflight: NonZeroUsize, metrics: metrics::Metrics) -> Self {
        let max_inflight = max_inflight.get();
        let (completed_sender, completed) = mpsc::channel(max_inflight);
        let (signaler, signal) = Signaler::new();
        let mut workers = Vec::with_capacity(max_inflight);
        let mut idle = Vec::with_capacity(max_inflight);
        let handles = FuturesUnordered::new();
        metrics.set_read_workers(max_inflight);
        metrics.set_inflight_reads(0);

        for worker in 0..max_inflight {
            let (sender, receiver) = mpsc::channel(1);
            let completed = completed_sender.clone();
            let signal = signal.clone();
            let handle = context
                .child("read_worker")
                .with_attribute("worker", worker)
                .spawn(move |context| {
                    Self::run_worker(worker, context, receiver, completed, signal)
                });
            workers.push(sender);
            idle.push(worker);
            handles.push(handle);
        }

        Self {
            workers,
            idle,
            completed,
            handles,
            shutdown: Some(signaler),
            metrics,
            inflight: 0,
        }
    }

    const fn len(&self) -> usize {
        self.inflight
    }

    const fn is_full(&self) -> bool {
        self.idle.is_empty()
    }

    const fn is_empty(&self) -> bool {
        self.inflight == 0
    }

    fn dispatch(&mut self, job: ReadJob<E, A>) -> Result<(), &'static str> {
        let Some(worker) = self.idle.pop() else {
            return Err("read dispatched without available worker");
        };

        if self.workers[worker].try_send(job).is_err() {
            return Err("read worker unavailable");
        }

        self.inflight += 1;
        self.metrics.set_inflight_reads(self.inflight);
        Ok(())
    }

    /// Retire every read-only handler that is ready without blocking.
    fn retire_ready(&mut self) -> Option<&'static str> {
        while let Some(completion) = self.completed.recv().now_or_never().flatten() {
            if let Some(reason) = self.complete(completion) {
                return Some(reason);
            }
        }

        if let Some(result) = self.handles.next().now_or_never().flatten() {
            self.metrics.read_worker_stops.inc();
            return Some(Self::worker_stopped(result));
        }

        None
    }

    /// Await one read completion, worker failure, or pend forever when neither can happen.
    async fn next(&mut self) -> Option<&'static str> {
        if self.inflight == 0 {
            return pending().await;
        }

        select! {
            completion = self.completed.recv() => {
                let Some(completion) = completion else {
                    return Some("read completion channel closed");
                };
                self.complete(completion)
            },
            result = self.handles.next() => {
                let Some(result) = result else {
                    return Some("read workers exhausted");
                };
                self.metrics.read_worker_stops.inc();
                Some(Self::worker_stopped(result))
            },
        }
    }

    async fn next_or_shutdown(&mut self, shutdown: &mut Signal) -> Option<&'static str> {
        select! {
            _ = shutdown => Some("shutdown signal received"),
            reason = self.next() => reason,
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
        self.inflight = 0;
        self.metrics.set_inflight_reads(0);
    }

    async fn run_worker(
        worker: usize,
        context: E,
        mut receiver: mpsc::Receiver<ReadJob<E, A>>,
        completed: mpsc::Sender<ReadCompletion<A::Error>>,
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
            if completed
                .try_send(ReadCompletion { worker, result })
                .is_err()
            {
                return;
            }
        }
    }

    fn complete(&mut self, completion: ReadCompletion<A::Error>) -> Option<&'static str> {
        debug_assert!(self.inflight > 0, "read completion without in-flight read");
        self.inflight -= 1;
        self.idle.push(completion.worker);
        self.metrics.reads.inc();
        self.metrics.set_inflight_reads(self.inflight);

        if let Err(err) = completion.result {
            self.metrics.read_failures.inc();
            error!(%err, "actor failed");
            return Some("fatal read detected");
        }

        None
    }

    fn worker_stopped(result: Result<(), RuntimeError>) -> &'static str {
        match result {
            Ok(()) => error!("read worker exited"),
            Err(err) => error!(?err, "read worker failed"),
        }
        "read worker stopped"
    }
}

enum NextEvent<I, W> {
    Actor(Event<I, W>),
    Stop(&'static str),
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
        let metrics = metrics::Metrics::init(&context);
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
            if !reads.is_empty() {
                if let Some(reason) = reads.retire_ready() {
                    self.shutdown_gracefully(&mut args, &mut reads, reason)
                        .await;
                    return;
                }
            }

            self.actor
                .preprocess(self.context.as_present_mut(), &mut args)
                .await;

            if reads.is_full() {
                if self.wait_for_read_capacity(&mut args, &mut reads).await {
                    return;
                }
                continue;
            }

            // When the read or shutdown arm wins, `next` is dropped mid-poll.
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
                    event = next => NextEvent::Actor(event),
                    reason = reads.next_or_shutdown(&mut self.shutdown) => reason.map_or(
                        NextEvent::Actor(Event::Continue),
                        NextEvent::Stop,
                    ),
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
                    self.shutdown_gracefully(&mut args, &mut reads, "actor requested stop")
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

    /// Abort in-flight read-only handlers, run [`Actor::on_shutdown`], and
    /// exit promptly.
    ///
    /// Reads abort before the hook runs so no handler can respond with
    /// pre-shutdown state after the hook mutates the actor. Pending askers
    /// observe a cancelled response.
    async fn shutdown_gracefully(
        &mut self,
        args: &mut A::Args,
        reads: &mut ReadPool<E, A>,
        reason: &'static str,
    ) {
        let inflight_reads = reads.len();
        self.metrics.record_stop(reason);
        debug!(reason, inflight_reads, "actor shutting down");
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

        if let Some(reason) = reads.next_or_shutdown(&mut self.shutdown).await {
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
        while !reads.is_empty() {
            let Some(reason) = reads.next_or_shutdown(&mut self.shutdown).await else {
                continue;
            };
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
                    error!(reason, "read dispatch failed");
                    self.shutdown_gracefully(args, reads, reason).await;
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
                self.shutdown_gracefully(args, reads, "shutdown signal received")
                    .await;
                return Batch {
                    messages,
                    stopped: true,
                };
            }

            if !reads.is_empty() {
                if let Some(reason) = reads.retire_ready() {
                    self.shutdown_gracefully(args, reads, reason).await;
                    return Batch {
                        messages,
                        stopped: true,
                    };
                }
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
    ) -> Result<(), &'static str> {
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
            self.shutdown_gracefully(args, reads, "fatal write detected")
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
