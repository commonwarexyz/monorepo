use super::*;
use crate::{ingress, ingress::Cancelled, mocks::TraceRecorder, Actor, Feedback, Unreliable};
use commonware_runtime::{deterministic, Clock, Metrics, Runner as _, Spawner, Supervisor as _};
use commonware_utils::{
    channel::{mpsc, oneshot},
    futures::OptionFuture,
    sync::Mutex,
    NZUsize,
};
use futures_util::FutureExt as _;
use std::{
    collections::VecDeque,
    convert::Infallible,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};
use tracing::Instrument as _;

struct CounterActor {
    value: u64,
}

ingress! {
    CounterMailbox,

    pub tell Seed { value: u64 };
    pub ask read_write BumpAndGet { delta: u64 } -> u64;
    pub ask Get -> u64;
}

impl<E: Spawner> Actor<E> for CounterActor {
    type Mailbox = CounterMailbox;
    type Ingress = CounterMailboxMessage;
    type Error = Infallible;
    type Snapshot = u64;
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.value
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: CounterMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxReadOnlyMessage::Get { response } => {
                let _ = response.send(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: CounterMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxReadWriteMessage::Seed { value } => {
                self.value = value;
            }
            CounterMailboxReadWriteMessage::BumpAndGet { delta, response } => {
                self.value += delta;
                let _ = response.send(self.value);
            }
        }
        Ok(())
    }
}

/// Actor whose [`Actor::Args`] seeds the initial value on startup.
struct ArgsActor {
    value: u64,
}

impl<E: Spawner> Actor<E> for ArgsActor {
    type Mailbox = CounterMailbox;
    type Ingress = CounterMailboxMessage;
    type Error = Infallible;
    type Snapshot = u64;
    type Args = u64;

    async fn on_startup(&mut self, _context: &mut E, args: &mut Self::Args) {
        self.value = *args;
    }

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.value
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: CounterMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxReadOnlyMessage::Get { response } => {
                let _ = response.send(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: CounterMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxReadWriteMessage::Seed { value } => {
                self.value = value;
            }
            CounterMailboxReadWriteMessage::BumpAndGet { delta, response } => {
                self.value += delta;
                let _ = response.send(self.value);
            }
        }
        Ok(())
    }
}

ingress! {
    HookMailbox,

    pub tell Note { value: u64 };
    pub ask read_write Fence -> u64;
}

ingress! {
    unreliable,
    UnreliableHookMailbox,

    pub tell Hit;
    pub ask Count -> u64;
}

/// Actor recording hook activity and processed message order.
#[derive(Clone)]
struct HookActor {
    batch: NonZeroUsize,
    processed: Arc<Mutex<Vec<u64>>>,
    preprocess: Arc<AtomicUsize>,
    postprocess: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

impl HookActor {
    fn new(batch: NonZeroUsize) -> Self {
        Self {
            batch,
            processed: Arc::new(Mutex::new(Vec::new())),
            preprocess: Arc::new(AtomicUsize::new(0)),
            postprocess: Arc::new(AtomicUsize::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    fn apply(&self, message: HookMailboxReadWriteMessage) {
        match message {
            HookMailboxReadWriteMessage::Note { value } => {
                self.processed.lock().push(value);
            }
            HookMailboxReadWriteMessage::Fence { response } => {
                let _ = response.send(self.processed.lock().len() as u64);
            }
        }
    }
}

impl<E: Spawner> Actor<E> for HookActor {
    type Mailbox = HookMailbox;
    type Ingress = HookMailboxMessage;
    type Error = Infallible;
    type Snapshot = ();
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    fn max_lane_batch(&self, _args: &Self::Args) -> NonZeroUsize {
        self.batch
    }

    async fn preprocess(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.preprocess.fetch_add(1, Ordering::SeqCst);
    }

    async fn postprocess(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.postprocess.fetch_add(1, Ordering::SeqCst);
    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: HookMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        self.apply(message);
        Ok(())
    }
}

struct UnreliableHookActor {
    value: u64,
}

impl<E: Spawner> Actor<E> for UnreliableHookActor {
    type Mailbox = UnreliableHookMailbox;
    type Ingress = UnreliableHookMailboxMessage;
    type Error = Infallible;
    type Snapshot = u64;
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.value
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: UnreliableHookMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        let UnreliableHookMailboxReadOnlyMessage::Count { response } = message;
        let _ = response.send(snapshot);
        Ok(())
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: UnreliableHookMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        let UnreliableHookMailboxReadWriteMessage::Hit = message;
        self.value += 1;
        Ok(())
    }
}

struct StopBatchActor {
    processed: Arc<Mutex<Vec<u64>>>,
}

impl<E: Spawner> Actor<E> for StopBatchActor {
    type Mailbox = HookMailbox;
    type Ingress = HookMailboxMessage;
    type Error = Infallible;
    type Snapshot = ();
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    fn max_lane_batch(&self, _args: &Self::Args) -> NonZeroUsize {
        NZUsize!(8)
    }

    async fn on_read_write(
        &mut self,
        context: &mut E,
        _args: &mut Self::Args,
        message: HookMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        let HookMailboxReadWriteMessage::Note { value } = message else {
            return Ok(());
        };

        self.processed.lock().push(value);
        if value == 1 {
            let _ = context.child("stop").stop(0, None).now_or_never();
        }
        Ok(())
    }
}

/// Actor selecting pre-lane events, mailbox lanes, and post-lane p2p events
/// without driver-owned source policy.
struct SelectActor {
    pre: VecDeque<u64>,
    timeouts_remaining: usize,
    timeout_deadline: Option<SystemTime>,
    p2p_closed: bool,
    inner: HookActor,
}

impl SelectActor {
    fn new() -> Self {
        Self {
            pre: VecDeque::new(),
            timeouts_remaining: 0,
            timeout_deadline: None,
            p2p_closed: false,
            inner: HookActor::new(NonZeroUsize::MIN),
        }
    }
}

impl<E: Spawner + Clock> Actor<E> for SelectActor {
    type Mailbox = HookMailbox;
    type Ingress = HookMailboxMessage;
    type Error = Infallible;
    type Snapshot = ();
    type Args = mpsc::Receiver<u64>;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
    }

    async fn next_event<R>(
        &mut self,
        context: &mut E,
        args: &mut Self::Args,
        mut lanes: LaneSet<'_, Self::Ingress, R>,
    ) -> Event<Self::Ingress, HookMailboxReadWriteMessage>
    where
        R: LaneReceiver<Self::Ingress>,
    {
        if self.pre.is_empty()
            && self.timeouts_remaining == 0
            && self.p2p_closed
            && lanes.is_exhausted()
        {
            return Event::Stop;
        }

        if let Some(value) = self.pre.pop_front() {
            return Event::External(HookMailboxReadWriteMessage::Note { value });
        }

        let timeout = OptionFuture::from((self.timeouts_remaining > 0).then(|| {
            let deadline = *self
                .timeout_deadline
                .get_or_insert_with(|| context.current() + Duration::from_millis(1));
            context.sleep_until(deadline)
        }));
        let p2p = OptionFuture::from((!self.p2p_closed).then(|| args.recv()));

        commonware_macros::select! {
            _ = timeout => {
                self.timeouts_remaining -= 1;
                self.timeout_deadline = None;
                Event::External(HookMailboxReadWriteMessage::Note { value: 100 })
            },
            event = lanes.recv() => match event {
                LaneEvent::Message { lane, message } => Event::Ingress { lane, message },
                LaneEvent::Closed { .. } => Event::Continue,
            },
            value = p2p => match value {
                Some(value) => Event::External(HookMailboxReadWriteMessage::Note { value }),
                None => {
                    self.p2p_closed = true;
                    Event::Continue
                },
            },
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: HookMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        self.inner.apply(message);
        Ok(())
    }
}

ingress! {
    FailMailbox,

    pub ask read_write Halt -> ();
    pub ask Snap -> u64;
    pub ask Crash -> u64;
    pub ask Hang {
        release: commonware_utils::channel::oneshot::Receiver<()>,
    } -> u64;
}

/// Actor whose handlers fail or block to exercise the fatal shutdown paths.
struct FailingActor {
    shutdown: Arc<AtomicBool>,
    hanging: Arc<AtomicUsize>,
}

impl FailingActor {
    fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            hanging: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<E: Spawner> Actor<E> for FailingActor {
    type Mailbox = FailMailbox;
    type Ingress = FailMailboxMessage;
    type Error = &'static str;
    type Snapshot = Arc<AtomicUsize>;
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.hanging.clone()
    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: FailMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            FailMailboxReadOnlyMessage::Snap { .. } => Err("read failed"),
            FailMailboxReadOnlyMessage::Crash { .. } => panic!("read panicked"),
            FailMailboxReadOnlyMessage::Hang { release, response } => {
                snapshot.fetch_add(1, Ordering::SeqCst);
                let _ = release.await;
                let _ = response.send(1);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: FailMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            FailMailboxReadWriteMessage::Halt { .. } => Err("write failed"),
        }
    }
}

#[test]
fn routes_read_write_ask_and_read_only_ask() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mailbox, service) =
            Builder::new(CounterActor { value: 0 }).build(context.child("counter"));
        let handle = service.start();

        assert_eq!(mailbox.seed_internal(10), Feedback::Ok);
        assert_eq!(
            mailbox
                .bump_and_get_internal(5)
                .await
                .expect("bump response"),
            15
        );
        assert_eq!(mailbox.get_internal().await.expect("get response"), 15);

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn unreliable_service_routes_messages() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mailbox, service) = Builder::new(UnreliableHookActor { value: 0 })
            .build_unreliable(context.child("unreliable"));
        let handle = service.start();

        assert_eq!(mailbox.hit_internal(), Unreliable::new(Feedback::Ok));
        assert_eq!(mailbox.count_internal().await.expect("count response"), 1);

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn service_metrics_track_activity() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mailbox, service) =
            Builder::new(CounterActor { value: 0 }).build(context.child("metrics"));
        let handle = service.start();

        assert_eq!(mailbox.get_internal().await.expect("get response"), 0);
        assert_eq!(
            mailbox
                .bump_and_get_internal(1)
                .await
                .expect("bump response"),
            1
        );

        let buffer = context.encode();
        assert!(buffer.contains("metrics_reads_total 1"), "{buffer}");
        assert!(buffer.contains("metrics_writes_total 1"), "{buffer}");
        assert!(
            buffer.contains("metrics_lane_messages_total{lane=\"0\"} 2"),
            "{buffer}"
        );
        assert!(buffer.contains("metrics_inflight_reads 0"), "{buffer}");
        assert!(buffer.contains("metrics_read_workers 16"), "{buffer}");

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn start_with_seeds_args() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mailbox, service) = Builder::new(ArgsActor { value: 0 }).build(context.child("args"));
        let handle = service.start_with(41);

        assert_eq!(
            mailbox
                .bump_and_get_internal(1)
                .await
                .expect("bump response"),
            42
        );

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn spans_follow_messages_across_the_mailbox() {
    let (recorder, state) = TraceRecorder::new();
    tracing::subscriber::with_default(recorder, || {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (mailbox, service) =
                Builder::new(CounterActor { value: 0 }).build(context.child("spans"));
            let handle = service.start();

            let caller = tracing::info_span!("test.actor.caller");
            {
                let _guard = caller.enter();
                assert_eq!(mailbox.seed_internal(11), Feedback::Ok);
            }
            let bumped = mailbox
                .bump_and_get_internal(1)
                .instrument(caller.clone())
                .await
                .expect("bump response");
            assert_eq!(bumped, 12);

            drop(mailbox);
            handle.await.expect("service stopped cleanly");
        });
    });

    // Tells start a new root that follows from the caller, even while the
    // caller's span is active. This is what keeps tell ping/pong loops from
    // growing one trace without bound.
    let caller = state.span("test.actor.caller");
    let seed = state.span("actor.counter_mailbox.seed");
    assert_eq!(seed.parent, None);
    assert_eq!(seed.follows, vec![caller.id]);

    // Asks stay inside the caller's trace: depth is bounded by the request
    // chain because the caller awaits the response.
    let bump = state.span("actor.counter_mailbox.bump_and_get");
    assert_eq!(bump.parent, Some(caller.id));
    assert!(bump.follows.is_empty());

    // Dispatch re-enters the carried span via an `actor.process` child.
    let process = state.spans_named("actor.process");
    assert!(process.iter().any(|span| span.parent == Some(seed.id)));
    assert!(process.iter().any(|span| span.parent == Some(bump.id)));
}

#[test]
fn external_events_route_and_exhaustion_stops_actor() {
    let (recorder, state) = TraceRecorder::new();
    tracing::subscriber::with_default(recorder, || {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let actor = SelectActor::new();
            let processed = actor.inner.processed.clone();
            let shutdown = actor.inner.shutdown.clone();
            let (external, receiver) = mpsc::channel(8);
            let (mailbox, service) = Builder::new(actor).build(context.child("external"));
            let handle = service.start_with(receiver);

            external.send(7).await.expect("send external");
            external.send(8).await.expect("send external");
            while processed.lock().len() < 2 {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(*processed.lock(), vec![7, 8]);
            assert_eq!(mailbox.fence_internal().await.expect("fence response"), 2);

            // Closing the p2p source only disables that arm. The actor stops
            // after the mailbox lane also closes.
            drop(external);
            drop(mailbox);
            handle.await.expect("service stopped cleanly");
            assert!(shutdown.load(Ordering::SeqCst));
        });
    });

    // External events carry no enqueue span; they are processed under a
    // distinct root span name.
    assert!(!state.spans_named("actor.process.external").is_empty());
}

#[test]
fn actor_select_can_sandwich_lane_between_external_sources() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut actor = SelectActor::new();
        actor.pre = VecDeque::from([1]);
        let processed = actor.inner.processed.clone();
        let (external, receiver) = mpsc::channel(8);
        let (mailbox, service) = Builder::new(actor).build(context.child("sandwich"));

        // Every source is ready when the actor starts. The actor's select
        // places `pre` before lanes and p2p after lanes.
        assert_eq!(mailbox.note_internal(2), Feedback::Ok);
        external.send(3).await.expect("send external");
        let handle = service.start_with(receiver);

        while processed.lock().len() < 3 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(*processed.lock(), vec![1, 2, 3]);

        drop(external);
        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn lane_close_can_keep_serving_external_sources() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = SelectActor::new();
        let processed = actor.inner.processed.clone();
        let shutdown = actor.inner.shutdown.clone();
        let (external, receiver) = mpsc::channel(8);
        let (mailbox, service) = Builder::new(actor).build(context.child("disable"));

        // Drain and close the mailbox lane before the loop starts: the
        // actor disables the lane and keeps serving external events.
        assert_eq!(mailbox.note_internal(1), Feedback::Ok);
        drop(mailbox);
        let handle = service.start_with(receiver);

        external.send(2).await.expect("send external");
        while processed.lock().len() < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(*processed.lock(), vec![1, 2]);
        assert!(!shutdown.load(Ordering::SeqCst));

        // Exhausting the external source leaves no live source, so the actor
        // stops on the next iteration.
        drop(external);
        handle.await.expect("service stopped cleanly");
        assert!(shutdown.load(Ordering::SeqCst));
    });
}

#[test]
fn p2p_close_can_be_omitted_while_timeout_and_lane_continue() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut actor = SelectActor::new();
        actor.timeouts_remaining = 1;
        let processed = actor.inner.processed.clone();
        let shutdown = actor.inner.shutdown.clone();
        let (external, receiver) = mpsc::channel::<u64>(8);
        let (mailbox, service) = Builder::new(actor).build(context.child("p2p_closed"));

        // Closing p2p should only remove that arm. Timeout and lanes still
        // produce events.
        drop(external);
        assert_eq!(mailbox.note_internal(2), Feedback::Ok);
        let handle = service.start_with(receiver);

        while processed.lock().len() < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(*processed.lock(), vec![2, 100]);
        assert!(!shutdown.load(Ordering::SeqCst));

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
        assert!(shutdown.load(Ordering::SeqCst));
    });
}

#[test]
fn fatal_write_stops_actor() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = FailingActor::new();
        let shutdown = actor.shutdown.clone();
        let (mailbox, service) = Builder::new(actor).build(context.child("fatal_write"));
        let handle = service.start();

        assert_eq!(mailbox.halt_internal().await.unwrap_err(), Cancelled);
        handle.await.expect("service stopped cleanly");
        assert!(shutdown.load(Ordering::SeqCst));
    });
}

#[test]
fn fatal_read_stops_actor() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = FailingActor::new();
        let shutdown = actor.shutdown.clone();
        let (mailbox, service) = Builder::new(actor).build(context.child("fatal_read"));
        let handle = service.start();

        assert_eq!(mailbox.snap_internal().await.unwrap_err(), Cancelled);
        handle.await.expect("service stopped cleanly");
        assert!(shutdown.load(Ordering::SeqCst));
    });
}

#[test]
fn panic_read_stops_actor() {
    let cfg = deterministic::Config::default().with_catch_panics(true);
    let runner = deterministic::Runner::new(cfg);
    runner.start(|context| async move {
        let actor = FailingActor::new();
        let shutdown = actor.shutdown.clone();
        let (mailbox, service) = Builder::new(actor).build(context.child("panic_read"));
        let handle = service.start();

        assert_eq!(mailbox.crash_internal().await.unwrap_err(), Cancelled);
        handle.await.expect("service stopped cleanly");
        assert!(shutdown.load(Ordering::SeqCst));
    });
}

#[test]
fn fatal_read_aborts_blocked_reads() {
    let runner = deterministic::Runner::timed(Duration::from_secs(10));
    runner.start(|context| async move {
        let actor = FailingActor::new();
        let shutdown = actor.shutdown.clone();
        let hanging = actor.hanging.clone();
        let (mailbox, service) = Builder::new(actor).build(context.child("fatal_hang"));
        let handle = service.start();

        // Park one read on a channel that never releases.
        let (release, wait) = oneshot::channel();
        let hang_mailbox = mailbox.clone();
        let hang = context
            .child("hang")
            .spawn(move |_context| async move { hang_mailbox.hang_internal(wait).await });
        while hanging.load(Ordering::SeqCst) < 1 {
            context.sleep(Duration::from_millis(1)).await;
        }

        // A fatal read must stop the actor without draining the parked read.
        assert_eq!(mailbox.snap_internal().await.unwrap_err(), Cancelled);
        handle.await.expect("service stopped cleanly");
        assert!(shutdown.load(Ordering::SeqCst));
        assert_eq!(hang.await.expect("hang task joined"), Err(Cancelled));
        drop(release);
    });
}

#[test]
fn lane_batch_processes_up_to_cap_with_single_postprocess() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = HookActor::new(NZUsize!(4));
        let processed = actor.processed.clone();
        let postprocess = actor.postprocess.clone();
        let (mailbox, service) =
            Builder::new(actor.clone()).build_with_capacity(context.child("batch"), NZUsize!(8));

        // Buffer a full batch before the loop starts: one iteration should
        // drain all four messages and run postprocess once.
        for value in 1..=4 {
            assert_eq!(mailbox.note_internal(value), Feedback::Ok);
        }
        let handle = service.start();

        assert_eq!(mailbox.fence_internal().await.expect("fence response"), 4);
        assert_eq!(*processed.lock(), vec![1, 2, 3, 4]);
        // One postprocess for the batched notes, one for the fence. The
        // fence's postprocess runs after its response is delivered, so wait
        // for the loop to finish the iteration.
        while postprocess.load(Ordering::SeqCst) < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(postprocess.load(Ordering::SeqCst), 2);

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn overflow_messages_are_processed_in_order() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = HookActor::new(NonZeroUsize::MIN);
        let processed = actor.processed.clone();
        let (mailbox, service) =
            Builder::new(actor).build_with_capacity(context.child("overflow"), NZUsize!(1));

        // Only the first message fits the ready queue; the rest ride the
        // generated FIFO overflow policy and must still arrive in order.
        assert_eq!(mailbox.note_internal(1), Feedback::Ok);
        for value in 2..=10 {
            assert_eq!(mailbox.note_internal(value), Feedback::Backoff);
        }
        let handle = service.start();

        assert_eq!(mailbox.fence_internal().await.expect("fence response"), 10);
        assert_eq!(*processed.lock(), (1..=10).collect::<Vec<_>>());

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn lane_close_mid_batch_postprocesses_then_shuts_down() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = HookActor::new(NZUsize!(8));
        let processed = actor.processed.clone();
        let postprocess = actor.postprocess.clone();
        let shutdown = actor.shutdown.clone();
        let (mailbox, service) =
            Builder::new(actor).build_with_capacity(context.child("close"), NZUsize!(4));

        for value in 1..=3 {
            assert_eq!(mailbox.note_internal(value), Feedback::Ok);
        }
        drop(mailbox);
        let handle = service.start();
        handle.await.expect("service stopped cleanly");

        assert_eq!(*processed.lock(), vec![1, 2, 3]);
        assert_eq!(postprocess.load(Ordering::SeqCst), 1);
        assert!(shutdown.load(Ordering::SeqCst));
    });
}

#[test]
fn runtime_stop_interrupts_lane_batch() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let processed = Arc::new(Mutex::new(Vec::new()));
        let actor = StopBatchActor {
            processed: processed.clone(),
        };
        let (mailbox, service) =
            Builder::new(actor).build_with_capacity(context.child("stop_batch"), NZUsize!(4));

        for value in 1..=4 {
            assert_eq!(mailbox.note_internal(value), Feedback::Ok);
        }

        let handle = service.start();
        handle.await.expect("service stopped cleanly");
        assert_eq!(*processed.lock(), vec![1]);
        drop(mailbox);
    });
}

#[test]
fn runtime_stop_triggers_graceful_shutdown() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = HookActor::new(NonZeroUsize::MIN);
        let shutdown = actor.shutdown.clone();
        let (mailbox, service) = Builder::new(actor).build(context.child("stop"));
        let handle = service.start();

        assert_eq!(mailbox.fence_internal().await.expect("fence response"), 0);
        context
            .stop(0, None)
            .await
            .expect("runtime stopped cleanly");
        handle.await.expect("service stopped cleanly");
        assert!(shutdown.load(Ordering::SeqCst));
        drop(mailbox);
    });
}

#[test]
fn multi_lane_declaration_order_bias() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = HookActor::new(NonZeroUsize::MIN);
        let processed = actor.processed.clone();
        let (lanes, service) = Builder::new(actor)
            .with_lane("hi", NZUsize!(4))
            .with_lane("lo", NZUsize!(4))
            .build(context.child("lanes"))
            .expect("unique lanes");
        let mailboxes = lanes.into_inner();
        let hi = mailboxes.get(&"hi").expect("hi lane").clone();
        let lo = mailboxes.get(&"lo").expect("lo lane").clone();
        drop(mailboxes);

        // Enqueue on the later lane first: declaration order still wins.
        assert_eq!(lo.note_internal(2), Feedback::Ok);
        assert_eq!(hi.note_internal(1), Feedback::Ok);
        let handle = service.start();

        while processed.lock().len() < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(*processed.lock(), vec![1, 2]);

        drop(hi);
        drop(lo);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn duplicate_lanes_are_rejected() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let result = Builder::new(CounterActor { value: 0 })
            .with_lane("same", NZUsize!(1))
            .with_lane("same", NZUsize!(1))
            .build(context.child("duplicates"));

        assert!(matches!(result, Err(DuplicateLaneError)));
    });
}

struct FencedActor {
    value: u64,
    active_reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

ingress! {
    FencedMailbox,

    pub tell Bump;
    pub ask BlockOn {
        release: commonware_utils::channel::oneshot::Receiver<()>,
    } -> u64;
    pub ask GetFenced -> u64;
}

impl<E: Spawner> Actor<E> for FencedActor {
    type Mailbox = FencedMailbox;
    type Ingress = FencedMailboxMessage;
    type Error = Infallible;
    type Snapshot = (u64, Arc<AtomicUsize>);
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        (self.value, self.active_reads.clone())
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: FencedMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        let (value, active_reads) = snapshot;
        match message {
            FencedMailboxReadOnlyMessage::BlockOn { release, response } => {
                active_reads.fetch_add(1, Ordering::SeqCst);
                let _ = release.await;
                active_reads.fetch_sub(1, Ordering::SeqCst);
                let _ = response.send(value);
            }
            FencedMailboxReadOnlyMessage::GetFenced { response } => {
                let _ = response.send(value);
            }
        }
        Ok(())
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: FencedMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            FencedMailboxReadWriteMessage::Bump => {
                self.value += 1;
                self.writes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    }
}

#[test]
fn read_write_waits_for_inflight_reads() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let active_reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let actor = FencedActor {
            value: 7,
            active_reads: active_reads.clone(),
            writes: writes.clone(),
        };
        let (mailbox, service) = Builder::new(actor)
            .with_read_concurrency(NonZeroUsize::new(2).expect("non-zero"))
            .build(context.child("fenced"));
        let handle = service.start();

        let (release, wait) = oneshot::channel();
        let read_mailbox = mailbox.clone();
        let read = context.child("read").spawn(move |_context| async move {
            read_mailbox
                .block_on_internal(wait)
                .await
                .expect("read response")
        });

        for _ in 0..10 {
            if active_reads.load(Ordering::SeqCst) == 1 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(active_reads.load(Ordering::SeqCst), 1);

        assert_eq!(mailbox.bump_internal(), Feedback::Ok);
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert_eq!(active_reads.load(Ordering::SeqCst), 1);

        release.send(()).expect("release read");
        assert_eq!(read.await.expect("read task joined"), 7);

        for _ in 0..10 {
            if writes.load(Ordering::SeqCst) == 1 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            mailbox.get_fenced_internal().await.expect("get response"),
            8
        );

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn snapshot_fence_mode_runs_writes_during_reads() {
    let runner = deterministic::Runner::timed(Duration::from_secs(10));
    runner.start(|context| async move {
        let active_reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let actor = FencedActor {
            value: 7,
            active_reads: active_reads.clone(),
            writes: writes.clone(),
        };
        let (mailbox, service) = Builder::new(actor)
            .with_fence_mode(FenceMode::Snapshot)
            .build(context.child("unfenced"));
        let handle = service.start();

        // Park one read on a channel released only after the write lands.
        let (release, wait) = oneshot::channel();
        let read_mailbox = mailbox.clone();
        let read = context.child("read").spawn(move |_context| async move {
            read_mailbox
                .block_on_internal(wait)
                .await
                .expect("read response")
        });
        while active_reads.load(Ordering::SeqCst) < 1 {
            context.sleep(Duration::from_millis(1)).await;
        }

        // The write must complete while the read is still parked.
        assert_eq!(mailbox.bump_internal(), Feedback::Ok);
        while writes.load(Ordering::SeqCst) < 1 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(active_reads.load(Ordering::SeqCst), 1);

        // The read still responds with the snapshot captured at admission.
        release.send(()).expect("release read");
        assert_eq!(read.await.expect("read task joined"), 7);
        assert_eq!(
            mailbox.get_fenced_internal().await.expect("get response"),
            8
        );

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn runtime_stop_aborts_blocked_reads() {
    let runner = deterministic::Runner::timed(Duration::from_secs(10));
    runner.start(|context| async move {
        let active_reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let actor = FencedActor {
            value: 7,
            active_reads: active_reads.clone(),
            writes,
        };
        let (mailbox, service) = Builder::new(actor).build(context.child("stop_abort"));
        let handle = service.start();

        // Park one read on a channel that never releases.
        let (release, wait) = oneshot::channel();
        let read_mailbox = mailbox.clone();
        let read = context
            .child("read")
            .spawn(move |_context| async move { read_mailbox.block_on_internal(wait).await });
        while active_reads.load(Ordering::SeqCst) < 1 {
            context.sleep(Duration::from_millis(1)).await;
        }

        // Runtime shutdown must not wait for the parked read; supervision
        // aborts it and the asker observes a cancelled response.
        context
            .stop(0, None)
            .await
            .expect("runtime stopped cleanly");
        handle.await.expect("service stopped cleanly");
        assert_eq!(read.await.expect("read task joined"), Err(Cancelled));
        drop(release);
        drop(mailbox);
    });
}

ingress! {
    OrderedMailbox,

    pub ask Park {
        release: commonware_utils::channel::oneshot::Receiver<()>,
    } -> u64;
}

/// Records the drop of a parked read-only handler.
struct DropLog {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl Drop for DropLog {
    fn drop(&mut self) {
        self.events.lock().push("read_dropped");
    }
}

/// Actor recording the order of read aborts and the shutdown hook.
struct OrderedShutdownActor {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl<E: Spawner> Actor<E> for OrderedShutdownActor {
    type Mailbox = OrderedMailbox;
    type Ingress = OrderedMailboxMessage;
    type Error = Infallible;
    type Snapshot = Arc<Mutex<Vec<&'static str>>>;
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.events.clone()
    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.events.lock().push("on_shutdown");
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: OrderedMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        let OrderedMailboxReadOnlyMessage::Park { release, response } = message;
        let _guard = DropLog {
            events: snapshot.clone(),
        };
        snapshot.lock().push("read_parked");
        let _ = release.await;
        let _ = response.send(1);
        Ok(())
    }
}

#[test]
fn reads_abort_before_on_shutdown() {
    let runner = deterministic::Runner::timed(Duration::from_secs(10));
    runner.start(|context| async move {
        let events = Arc::new(Mutex::new(Vec::new()));
        let actor = OrderedShutdownActor {
            events: events.clone(),
        };
        let (mailbox, service) = Builder::new(actor).build(context.child("ordered"));
        let handle = service.start();

        // Park one read on a channel that never releases.
        let (release, wait) = oneshot::channel();
        let read_mailbox = mailbox.clone();
        let read = context
            .child("read")
            .spawn(move |_context| async move { read_mailbox.park_internal(wait).await });
        while events.lock().is_empty() {
            context.sleep(Duration::from_millis(1)).await;
        }

        // The parked read must be aborted before on_shutdown runs, so the
        // hook can never race a handler holding a pre-shutdown snapshot.
        context
            .stop(0, None)
            .await
            .expect("runtime stopped cleanly");
        handle.await.expect("service stopped cleanly");
        assert_eq!(
            *events.lock(),
            vec!["read_parked", "read_dropped", "on_shutdown"]
        );
        assert_eq!(read.await.expect("read task joined"), Err(Cancelled));
        drop(release);
        drop(mailbox);
    });
}

ingress! {
    CachedMailbox,

    pub tell Bump;
    pub subscribe Peek -> u64;
}

/// Actor counting how many snapshots the service captures.
struct CachingActor {
    value: u64,
    snapshots: Arc<AtomicUsize>,
}

impl<E: Spawner> Actor<E> for CachingActor {
    type Mailbox = CachedMailbox;
    type Ingress = CachedMailboxMessage;
    type Error = Infallible;
    type Snapshot = u64;
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        self.value
    }

    fn max_lane_batch(&self, _args: &Self::Args) -> NonZeroUsize {
        NZUsize!(8)
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: CachedMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        let CachedMailboxReadOnlyMessage::Peek { response } = message;
        let _ = response.send(snapshot);
        Ok(())
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: CachedMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        let CachedMailboxReadWriteMessage::Bump = message;
        self.value += 1;
        Ok(())
    }
}

#[test]
fn consecutive_reads_share_one_snapshot() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let snapshots = Arc::new(AtomicUsize::new(0));
        let actor = CachingActor {
            value: 3,
            snapshots: snapshots.clone(),
        };
        let (mailbox, service) = Builder::new(actor).build(context.child("cached"));

        // Buffer a full batch of reads before the loop starts: one snapshot
        // capture must serve the whole batch.
        let peeks: Vec<_> = (0..4).map(|_| mailbox.peek_internal()).collect();
        let handle = service.start();

        for peek in peeks {
            assert_eq!(peek.await.expect("peek response"), 3);
        }
        assert_eq!(snapshots.load(Ordering::SeqCst), 1);

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

#[test]
fn write_invalidates_cached_snapshot() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let snapshots = Arc::new(AtomicUsize::new(0));
        let actor = CachingActor {
            value: 0,
            snapshots: snapshots.clone(),
        };
        let (mailbox, service) = Builder::new(actor).build(context.child("invalidate"));

        // A write between two reads in one batch must split the cache: the
        // second read observes the write, not the first read's snapshot.
        let before = mailbox.peek_internal();
        assert_eq!(mailbox.bump_internal(), Feedback::Ok);
        let after = mailbox.peek_internal();
        let handle = service.start();

        assert_eq!(before.await.expect("peek response"), 0);
        assert_eq!(after.await.expect("peek response"), 1);
        assert_eq!(snapshots.load(Ordering::SeqCst), 2);

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
    });
}

/// Drive a mixed read/write workload and return the runtime auditor state.
fn mixed_workload_state(seed: u64) -> String {
    let runner = deterministic::Runner::seeded(seed);
    runner.start(|context| async move {
        let (mailbox, service) = Builder::new(CounterActor { value: 0 })
            .with_read_concurrency(NZUsize!(4))
            .build(context.child("determinism"));
        let handle = service.start();

        assert_eq!(mailbox.seed_internal(1), Feedback::Ok);
        let (a, b, c) = futures::join!(
            mailbox.get_internal(),
            mailbox.bump_and_get_internal(2),
            mailbox.get_internal()
        );
        a.expect("get response");
        b.expect("bump response");
        c.expect("get response");

        drop(mailbox);
        handle.await.expect("service stopped cleanly");
        context.auditor().state()
    })
}

#[test]
fn deterministic_across_identical_runs() {
    assert_eq!(mixed_workload_state(42), mixed_workload_state(42));
}
