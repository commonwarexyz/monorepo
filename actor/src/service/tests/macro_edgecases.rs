use super::*;
use crate::{ingress, Actor};
use commonware_runtime::{deterministic, Clock, Runner, Spawner};
use commonware_utils::channel::fallible::OneshotExt;
use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct BatchClosePostprocessActor {
    handled: Arc<AtomicUsize>,
    postprocess: Arc<AtomicUsize>,
    batch: NonZeroUsize,
}

ingress! {
    BatchClosePostprocessMailbox,

    pub tell Work;
}

impl<E: Spawner> Actor<E> for BatchClosePostprocessActor {
    type Mailbox = BatchClosePostprocessMailbox;
    type Ingress = BatchClosePostprocessMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    fn max_lane_batch(&self, _args: &Self::Args) -> NonZeroUsize {
        self.batch
    }

    async fn on_read_only(
        _context: E,
        _snapshot: Self::Snapshot,
        _message: BatchClosePostprocessMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        unreachable!("batch close mailbox has no read-only ingress")
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: BatchClosePostprocessMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            BatchClosePostprocessMailboxReadWriteMessage::Work => {
                self.handled.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    }

    async fn postprocess(&mut self, _context: &mut E, _args: &mut Self::Args) {
        self.postprocess.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_postprocess_runs_when_batched_lane_closes() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let handled = Arc::new(AtomicUsize::new(0));
        let postprocess = Arc::new(AtomicUsize::new(0));
        let actor = BatchClosePostprocessActor {
            handled: handled.clone(),
            postprocess: postprocess.clone(),
            batch: NonZeroUsize::new(8).expect("non-zero"),
        };
        let (mailbox, service) = ServiceBuilder::new(actor).build_with_capacity(
            context.with_label("batched_lane_close"),
            NonZeroUsize::new(8).expect("non-zero"),
        );

        mailbox.work().await.expect("work 1 failed");
        mailbox.work().await.expect("work 2 failed");

        let handle = service.start();
        drop(mailbox);
        handle.await.expect("service join failed");

        assert_eq!(handled.load(Ordering::SeqCst), 2);
        assert_eq!(postprocess.load(Ordering::SeqCst), 1);
    });
}

struct TimeoutFieldAskActor;

ingress! {
    TimeoutFieldAskMailbox,

    pub ask Echo { timeout: u64 } -> u64;
}

impl<E: Spawner> Actor<E> for TimeoutFieldAskActor {
    type Mailbox = TimeoutFieldAskMailbox;
    type Ingress = TimeoutFieldAskMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_read_only(
        _context: E,
        _snapshot: Self::Snapshot,
        message: TimeoutFieldAskMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            TimeoutFieldAskMailboxReadOnlyMessage::Echo { timeout, response } => {
                response.send_lossy(timeout);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: TimeoutFieldAskMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {}
    }
}

#[test]
fn test_non_unit_ask_timeout_field_name_timeout() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = TimeoutFieldAskActor;
        let (mailbox, service) = ServiceBuilder::new(actor).build(context.with_label("timeout"));
        service.start();

        assert_eq!(mailbox.echo(7).await.expect("ask failed"), 7);
        assert_eq!(
            mailbox
                .echo_timeout(11, context.sleep(Duration::from_secs(1)))
                .await
                .expect("ask timeout failed"),
            11,
        );
    });
}

struct SubscribeFieldCollisionActor;

ingress! {
    SubscribeFieldCollisionMailbox,

    pub subscribe Wait { tx: u64, rx: u64 } -> (u64, u64);
}

impl<E: Spawner> Actor<E> for SubscribeFieldCollisionActor {
    type Mailbox = SubscribeFieldCollisionMailbox;
    type Ingress = SubscribeFieldCollisionMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_read_only(
        _context: E,
        _snapshot: Self::Snapshot,
        _message: SubscribeFieldCollisionMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        unreachable!("subscribe collision mailbox has no read-only ingress")
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: SubscribeFieldCollisionMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            SubscribeFieldCollisionMailboxReadWriteMessage::Wait { tx, rx, response } => {
                response.send_lossy((tx, rx));
                Ok(())
            }
        }
    }
}

#[test]
fn test_subscribe_field_names_tx_rx() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = SubscribeFieldCollisionActor;
        let (mailbox, service) =
            ServiceBuilder::new(actor).build(context.with_label("subscribe_collision"));
        service.start();

        let first = mailbox.wait(5, 9);
        assert_eq!(first.await.expect("subscribe failed"), (5, 9));

        let second = mailbox.try_wait(11, 15).expect("try_subscribe failed");
        assert_eq!(
            second.await.expect("try_subscribe receiver failed"),
            (11, 15)
        );
    });
}

struct ConstBoolActor<const FLAG: bool>;

ingress! {
    ConstBoolMailbox<const FLAG: bool>,

    pub ask Flag -> bool;
}

impl<E: Spawner, const FLAG: bool> Actor<E> for ConstBoolActor<FLAG> {
    type Mailbox = ConstBoolMailbox<FLAG>;
    type Ingress = ConstBoolMailboxMessage<FLAG>;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_read_only(
        _context: E,
        _snapshot: Self::Snapshot,
        message: ConstBoolMailboxReadOnlyMessage<FLAG>,
    ) -> Result<(), Self::Error> {
        match message {
            ConstBoolMailboxReadOnlyMessage::Flag { response } => {
                response.send_lossy(FLAG);
                Ok(())
            }
            ConstBoolMailboxReadOnlyMessage::_Phantom(_) => unreachable!(),
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: ConstBoolMailboxReadWriteMessage<FLAG>,
    ) -> Result<(), Self::Error> {
        match message {
            ConstBoolMailboxReadWriteMessage::_Phantom(_) => unreachable!(),
        }
    }
}

#[test]
fn test_const_bool_generic_with_phantom_variant() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mailbox_true, service_true) =
            ServiceBuilder::new(ConstBoolActor::<true>).build(context.with_label("const_true"));
        service_true.start();

        let (mailbox_false, service_false) =
            ServiceBuilder::new(ConstBoolActor::<false>).build(context.with_label("const_false"));
        service_false.start();

        assert!(mailbox_true.flag().await.expect("true ask failed"));
        assert!(!mailbox_false.flag().await.expect("false ask failed"));
    });
}

struct CfgAskActor;

ingress! {
    CfgAskMailbox,

    #[cfg(any())]
    pub ask Hidden -> u64;
    pub ask Visible -> u64;
}

impl<E: Spawner> Actor<E> for CfgAskActor {
    type Mailbox = CfgAskMailbox;
    type Ingress = CfgAskMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        99
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: CfgAskMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CfgAskMailboxReadOnlyMessage::Visible { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: CfgAskMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {}
    }
}

#[test]
fn test_cfg_gated_ask_item_timeout_helper_is_absent() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = CfgAskActor;
        let (mailbox, service) =
            ServiceBuilder::new(actor).build(context.with_label("cfg_gated_ask"));
        service.start();

        assert_eq!(mailbox.visible().await.expect("visible ask failed"), 99);
        assert_eq!(
            mailbox
                .visible_timeout(context.sleep(Duration::from_secs(1)))
                .await
                .expect("visible ask timeout failed"),
            99,
        );
    });
}

struct CfgFieldActor;

ingress! {
    CfgFieldMailbox,

    pub ask Value {
        visible: u64,
        #[cfg(any())]
        hidden: u64,
    } -> u64;
}

impl<E: Spawner> Actor<E> for CfgFieldActor {
    type Mailbox = CfgFieldMailbox;
    type Ingress = CfgFieldMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_read_only(
        _context: E,
        _snapshot: Self::Snapshot,
        message: CfgFieldMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CfgFieldMailboxReadOnlyMessage::Value { visible, response } => {
                response.send_lossy(visible);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: CfgFieldMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {}
    }
}

#[test]
fn test_cfg_gated_fields_in_wrapper_args_and_assignments() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = CfgFieldActor;
        let (mailbox, service) = ServiceBuilder::new(actor).build(context.with_label("cfg_field"));
        service.start();

        assert_eq!(mailbox.value(17).await.expect("ask failed"), 17);
        assert_eq!(
            mailbox
                .value_timeout(21, context.sleep(Duration::from_secs(1)))
                .await
                .expect("ask timeout failed"),
            21,
        );
    });
}
