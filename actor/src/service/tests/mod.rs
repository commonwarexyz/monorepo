use super::*;
use crate::{ingress, Actor};
use commonware_macros::select;
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, mpsc};
use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

mod concurrent_reads;
mod read_write_ask;

struct ExternalActor {
    n: u64,
}

ingress! {
    ExternalMailbox,

    pub tell TellMsg { n: u64 };
    pub ask AskMsg -> u64;
}

impl<E: Spawner + Clock> Actor<E> for ExternalActor {
    type Mailbox = ExternalMailbox;
    type Ingress = ExternalMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = mpsc::Receiver<u64>;
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.n
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: ExternalMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ExternalMailboxReadOnlyMessage::AskMsg { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: ExternalMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ExternalMailboxReadWriteMessage::TellMsg { n } => {
                self.n = n;
                Ok(())
            }
        }
    }

    async fn on_external(
        &mut self,
        context: &mut E,
        args: &mut Self::Args,
    ) -> Option<ExternalMailboxReadWriteMessage> {
        select! {
            _ = context.sleep(Duration::from_secs(1)) => {
                None
            },
            n = args.recv() => {
                n.map(|n| ExternalMailboxReadWriteMessage::TellMsg { n })
            },
        }
    }
}

#[test]
fn test_actor_on_external() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = ExternalActor { n: 0 };
        let (mailbox, service) =
            ServiceBuilder::new(actor).build(context.with_label("actor_on_external"));

        let (other_tx, other_rx) = mpsc::channel(8);
        service.start_with(other_rx);

        mailbox.tell_msg(42).await.expect("tell failed");
        context.sleep(Duration::from_millis(5)).await;
        assert_eq!(mailbox.ask_msg().await.expect("ask failed"), 42);

        other_tx.send(100).await.expect("send failed");
        context.sleep(Duration::from_millis(5)).await;
        assert_eq!(mailbox.ask_msg().await.expect("ask failed"), 100);

        context.sleep(Duration::from_secs(2)).await;
        assert!(mailbox.ask_msg().await.is_err());
    });
}

struct CounterActor {
    counter: u64,
    started: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
}

ingress! {
    CounterMailbox,

    pub tell Increment;
    pub ask GetCounter -> u64;
}

impl<E: Spawner> Actor<E> for CounterActor {
    type Mailbox = CounterMailbox;
    type Ingress = CounterMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.counter
    }

    async fn on_startup(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.started.store(true, Ordering::SeqCst);
    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: CounterMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxReadOnlyMessage::GetCounter { response } => {
                response.send_lossy(snapshot);
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
            CounterMailboxReadWriteMessage::Increment => Ok(()),
        }
    }

    async fn postprocess(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.counter += 1;
    }
}

#[test]
fn test_counter_actor_lifecycle() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let started = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));

        let actor = CounterActor {
            counter: 0,
            started: started.clone(),
            shutdown: shutdown.clone(),
        };
        let (mailbox, service) = ServiceBuilder::new(actor).build(context.with_label("counter"));
        let handle = service.start();

        mailbox.increment().await.expect("tell failed");
        mailbox.increment().await.expect("tell failed");
        mailbox.increment().await.expect("tell failed");

        let val = mailbox.get_counter().await.expect("ask failed");
        assert_eq!(val, 3);
        assert!(started.load(Ordering::SeqCst));

        drop(mailbox);
        let _ = handle.await;
        assert!(shutdown.load(Ordering::SeqCst));
    });
}

struct PreprocessActor {
    preprocess_count: u64,
}

ingress! {
    PreprocessMailbox,

    pub tell Bump;
    pub ask GetPreprocessCount -> u64;
}

impl<E: Spawner> Actor<E> for PreprocessActor {
    type Mailbox = PreprocessMailbox;
    type Ingress = PreprocessMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.preprocess_count
    }

    async fn preprocess(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.preprocess_count += 1;
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: PreprocessMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            PreprocessMailboxReadOnlyMessage::GetPreprocessCount { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: PreprocessMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            PreprocessMailboxReadWriteMessage::Bump => Ok(()),
        }
    }
}

#[test]
fn test_preprocess_runs_each_iteration() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = PreprocessActor {
            preprocess_count: 0,
        };
        let (mailbox, service) = ServiceBuilder::new(actor).build(context.with_label("preprocess"));
        service.start();

        mailbox.bump().await.expect("tell failed");
        mailbox.bump().await.expect("tell failed");
        mailbox.bump().await.expect("tell failed");

        let count = mailbox.get_preprocess_count().await.expect("ask failed");
        assert_eq!(count, 4);
    });
}

struct StopOnCommandActor {
    shutdown_called: Arc<AtomicBool>,
}

#[derive(Debug)]
struct PoisonError;

impl std::fmt::Display for PoisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "poisoned")
    }
}

ingress! {
    StopMailbox,

    pub tell Normal;
    pub tell Poison;
    pub ask IsAlive -> bool;
}

impl<E: Spawner> Actor<E> for StopOnCommandActor {
    type Mailbox = StopMailbox;
    type Ingress = StopMailboxMessage;
    type Error = PoisonError;
    type Args = ();
    type Snapshot = bool;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        true
    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.shutdown_called.store(true, Ordering::SeqCst);
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: StopMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            StopMailboxReadOnlyMessage::IsAlive { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: StopMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            StopMailboxReadWriteMessage::Normal => Ok(()),
            StopMailboxReadWriteMessage::Poison => Err(PoisonError),
        }
    }
}

#[test]
fn test_stop_on_error() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let actor = StopOnCommandActor {
            shutdown_called: shutdown_called.clone(),
        };
        let (mailbox, service) =
            ServiceBuilder::new(actor).build(context.with_label("stop_on_cmd"));
        let handle = service.start();

        mailbox.normal().await.expect("tell failed");
        context.sleep(Duration::from_millis(1)).await;
        assert!(mailbox.is_alive().await.expect("ask failed"));

        mailbox.poison().await.expect("tell failed");
        let _ = handle.await;

        assert!(shutdown_called.load(Ordering::SeqCst));
    });
}

struct UnboundedActor {
    sum: u64,
}

ingress! {
    unbounded UnboundedActorMailbox,

    pub tell AddVal { n: u64 };
    pub ask GetSum -> u64;
}

impl<E: Spawner> Actor<E> for UnboundedActor {
    type Mailbox = UnboundedActorMailbox;
    type Ingress = UnboundedActorMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.sum
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: UnboundedActorMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            UnboundedActorMailboxReadOnlyMessage::GetSum { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: UnboundedActorMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            UnboundedActorMailboxReadWriteMessage::AddVal { n } => {
                self.sum += n;
                Ok(())
            }
        }
    }
}

#[test]
fn test_unbounded_actor() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = UnboundedActor { sum: 0 };
        let (mailbox, service) =
            ServiceBuilder::new(actor).build_unbounded(context.with_label("unbounded"));
        service.start();

        mailbox.add_val(10).expect("tell failed");
        mailbox.add_val(20).expect("tell failed");
        mailbox.add_val(30).expect("tell failed");

        context.sleep(Duration::from_millis(1)).await;
        let total = mailbox.get_sum().await.expect("ask failed");
        assert_eq!(total, 60);
    });
}

struct MultiLaneActor {
    log: Vec<&'static str>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lane {
    Priority,
    Normal,
}

ingress! {
    MultiLaneMailbox,

    pub tell TagPriority;
    pub tell TagNormal;
    pub ask ReadLog -> Vec<&'static str>;
}

impl<E: Spawner> Actor<E> for MultiLaneActor {
    type Mailbox = MultiLaneMailbox;
    type Ingress = MultiLaneMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = Vec<&'static str>;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.log.clone()
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: MultiLaneMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            MultiLaneMailboxReadOnlyMessage::ReadLog { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: MultiLaneMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            MultiLaneMailboxReadWriteMessage::TagPriority => {
                self.log.push("priority");
                Ok(())
            }
            MultiLaneMailboxReadWriteMessage::TagNormal => {
                self.log.push("normal");
                Ok(())
            }
        }
    }
}

#[test]
fn test_multi_lane_actor() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = MultiLaneActor { log: Vec::new() };

        let (lanes, service) = ServiceBuilder::new(actor)
            .with_lane(Lane::Priority, NonZeroUsize::new(8).expect("non-zero"))
            .with_lane(Lane::Normal, NonZeroUsize::new(8).expect("non-zero"))
            .build(context.with_label("multi_lane"))
            .expect("build failed");
        service.start();

        let priority = lanes.lane(&Lane::Priority).expect("missing priority lane");
        let normal = lanes.lane(&Lane::Normal).expect("missing normal lane");

        normal.tag_normal().await.expect("tell normal failed");
        priority.tag_priority().await.expect("tell priority failed");

        context.sleep(Duration::from_millis(5)).await;

        let log = priority.read_log().await.expect("ask failed");
        assert_eq!(log, vec!["priority", "normal"]);
    });
}

#[test]
fn test_duplicate_lane_error() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = MultiLaneActor { log: Vec::new() };
        let result = ServiceBuilder::new(actor)
            .with_lane(0u8, NonZeroUsize::new(8).expect("non-zero"))
            .with_lane(0u8, NonZeroUsize::new(16).expect("non-zero"))
            .build(context.with_label("dup_lane"));

        assert!(result.is_err());
    });
}

#[test]
fn test_lane_closed_triggers_shutdown() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let actor = StopOnCommandActor {
            shutdown_called: shutdown_called.clone(),
        };
        let (mailbox, service) =
            ServiceBuilder::new(actor).build(context.with_label("lane_closed"));
        let handle = service.start();

        drop(mailbox);
        let _ = handle.await;
        assert!(shutdown_called.load(Ordering::SeqCst));
    });
}

trait Peer: Send + Clone + 'static {}
impl Peer for String {}

struct GenericActor<P: Peer> {
    peer: Option<P>,
}

ingress! {
    GenericMailbox<P: Peer>,

    pub tell Ping;
    pub tell Connect { peer: P };
    pub ask GetPeer -> Option<P>;
    pub ask GetPeerById { id: u64 } -> Option<P>;
    pub ask IsConnected -> bool;
}

impl<E: Spawner, P: Peer> Actor<E> for GenericActor<P> {
    type Mailbox = GenericMailbox<P>;
    type Ingress = GenericMailboxMessage<P>;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = Option<P>;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.peer.clone()
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: GenericMailboxReadOnlyMessage<P>,
    ) -> Result<(), Self::Error> {
        match message {
            GenericMailboxReadOnlyMessage::GetPeer { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
            GenericMailboxReadOnlyMessage::GetPeerById { id: _, response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
            GenericMailboxReadOnlyMessage::IsConnected { response } => {
                response.send_lossy(snapshot.is_some());
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: GenericMailboxReadWriteMessage<P>,
    ) -> Result<(), Self::Error> {
        match message {
            GenericMailboxReadWriteMessage::Ping => Ok(()),
            GenericMailboxReadWriteMessage::Connect { peer } => {
                self.peer = Some(peer);
                Ok(())
            }
        }
    }
}

#[test]
fn test_generic_mailbox_actor() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor: GenericActor<String> = GenericActor { peer: None };
        let (mailbox, service) = ServiceBuilder::new(actor).build(context.with_label("generic"));
        service.start();

        mailbox.ping().await.expect("ping failed");
        context.sleep(Duration::from_millis(1)).await;

        assert!(!mailbox.is_connected().await.expect("ask failed"));

        mailbox
            .connect("alice".to_string())
            .await
            .expect("connect failed");
        context.sleep(Duration::from_millis(1)).await;

        let peer = mailbox.get_peer().await.expect("ask failed");
        assert_eq!(peer, Some("alice".to_string()));
    });
}

struct SubscribeActor {
    pending: Option<commonware_utils::channel::oneshot::Sender<String>>,
}

ingress! {
    SubscribeMailbox,

    pub subscribe WaitForValue -> String;
    pub tell Resolve { value: String };
}

impl<E: Spawner> Actor<E> for SubscribeActor {
    type Mailbox = SubscribeMailbox;
    type Ingress = SubscribeMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_readonly(
        _context: E,
        _snapshot: Self::Snapshot,
        _message: SubscribeMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        unreachable!("subscribe mailbox has no read-only ingress")
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: SubscribeMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            SubscribeMailboxReadWriteMessage::WaitForValue { response } => {
                self.pending = Some(response);
            }
            SubscribeMailboxReadWriteMessage::Resolve { value } => {
                if let Some(tx) = self.pending.take() {
                    tx.send_lossy(value);
                }
            }
        }
        Ok(())
    }
}

#[test]
fn test_subscribe_returns_receiver() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = SubscribeActor { pending: None };
        let (mailbox, service) = ServiceBuilder::new(actor).build(context.with_label("subscribe"));
        service.start();

        let rx = mailbox.wait_for_value().await;

        mailbox
            .resolve("hello".to_string())
            .await
            .expect("resolve failed");

        let val = rx.await.expect("subscribe receiver failed");
        assert_eq!(val, "hello");
    });
}

#[test]
fn test_try_subscribe_reports_delivery_error() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = SubscribeActor { pending: None };
        let (mailbox, service) =
            ServiceBuilder::new(actor).build(context.with_label("subscribe_try"));

        drop(service);

        let err = mailbox
            .try_wait_for_value()
            .await
            .expect_err("try_subscribe should fail when mailbox is closed");
        assert_eq!(err, crate::mailbox::MailboxError::Closed);
    });
}

#[test]
fn test_build_with_capacity_works_with_non_zero_capacity() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = CounterActor {
            counter: 0,
            started: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
        };
        let (mailbox, service) = ServiceBuilder::new(actor).build_with_capacity(
            context.with_label("non_zero_capacity"),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        service.start();

        mailbox.increment().await.expect("tell failed");
        context.sleep(Duration::from_millis(1)).await;
        let val = mailbox.get_counter().await.expect("ask failed");
        assert_eq!(val, 1);
    });
}

struct ShutdownDrainActor {
    read_started: Arc<AtomicBool>,
    read_finished: Arc<AtomicBool>,
    shutdown_saw_finished_read: Arc<AtomicBool>,
}

ingress! {
    ShutdownDrainMailbox,

    pub tell Nop;
    pub ask BlockUntil {
        release: commonware_utils::channel::oneshot::Receiver<()>,
    } -> u64;
}

impl<E: Spawner> Actor<E> for ShutdownDrainActor {
    type Mailbox = ShutdownDrainMailbox;
    type Ingress = ShutdownDrainMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = commonware_utils::channel::oneshot::Receiver<()>;
    type Snapshot = (Arc<AtomicBool>, Arc<AtomicBool>);

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        (self.read_started.clone(), self.read_finished.clone())
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: ShutdownDrainMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ShutdownDrainMailboxReadOnlyMessage::BlockUntil { release, response } => {
                let (read_started, read_finished) = snapshot;
                read_started.store(true, Ordering::SeqCst);
                let _ = release.await;
                read_finished.store(true, Ordering::SeqCst);
                response.send_lossy(7);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: ShutdownDrainMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ShutdownDrainMailboxReadWriteMessage::Nop => Ok(()),
        }
    }

    async fn on_external(
        &mut self,
        _context: &mut E,
        args: &mut Self::Args,
    ) -> Option<ShutdownDrainMailboxReadWriteMessage> {
        let _ = args.await;
        None
    }

    async fn on_shutdown(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.shutdown_saw_finished_read
            .store(self.read_finished.load(Ordering::SeqCst), Ordering::SeqCst);
    }
}

#[test]
fn test_shutdown_waits_for_inflight_reads() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let read_started = Arc::new(AtomicBool::new(false));
        let read_finished = Arc::new(AtomicBool::new(false));
        let shutdown_saw_finished_read = Arc::new(AtomicBool::new(false));

        let actor = ShutdownDrainActor {
            read_started: read_started.clone(),
            read_finished: read_finished.clone(),
            shutdown_saw_finished_read: shutdown_saw_finished_read.clone(),
        };
        let (mailbox, service) = ServiceBuilder::new(actor)
            .with_read_concurrency(NonZeroUsize::new(2).expect("non-zero"))
            .build(context.with_label("shutdown_drain"));

        let (shutdown_tx, shutdown_rx) = commonware_utils::channel::oneshot::channel();
        let service_handle = service.start_with(shutdown_rx);

        mailbox.nop().await.expect("nop failed");

        let (release_tx, release_rx) = commonware_utils::channel::oneshot::channel();
        let read_mailbox = mailbox.clone();
        let read_handle = context
            .with_label("inflight_read")
            .spawn(move |_context| async move {
                read_mailbox
                    .block_until(release_rx)
                    .await
                    .expect("read failed")
            });

        for _ in 0..10 {
            if read_started.load(Ordering::SeqCst) {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        assert!(read_started.load(Ordering::SeqCst));

        shutdown_tx.send_lossy(());
        context.sleep(Duration::from_millis(1)).await;
        assert!(!read_finished.load(Ordering::SeqCst));

        release_tx.send_lossy(());
        assert_eq!(read_handle.await.expect("read task join failed"), 7);
        service_handle.await.expect("service join failed");

        assert!(read_finished.load(Ordering::SeqCst));
        assert!(shutdown_saw_finished_read.load(Ordering::SeqCst));
    });
}

#[test]
fn test_try_tell_and_ask_timeout() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = CounterActor {
            counter: 0,
            started: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
        };
        let (mailbox, service) = ServiceBuilder::new(actor).build(context.with_label("try_ask"));
        service.start();

        mailbox.try_increment().expect("try_tell failed");
        context.sleep(Duration::from_millis(1)).await;
        let val = mailbox.get_counter().await.expect("ask failed");
        assert_eq!(val, 1);

        let val = mailbox
            .get_counter_timeout(context.sleep(Duration::from_secs(5)))
            .await
            .expect("ask_timeout failed");
        assert_eq!(val, 2);

        let err = mailbox
            .get_counter_timeout(futures::future::ready(()))
            .await
            .unwrap_err();
        assert_eq!(err, crate::mailbox::MailboxError::Timeout);
    });
}
