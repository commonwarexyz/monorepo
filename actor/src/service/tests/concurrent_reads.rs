use super::*;
use crate::{ingress, Actor};
use commonware_runtime::{deterministic, Runner, Spawner};
use commonware_utils::channel::fallible::OneshotExt;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct ConcurrentReadActor {
    value: u64,
    active_reads: Arc<AtomicUsize>,
    max_active_reads: Arc<AtomicUsize>,
    read_write_count: Arc<AtomicUsize>,
}

ingress! {
    ConcurrentReadMailbox,

    pub tell Bump;
    pub ask BlockOn {
        release: commonware_utils::channel::oneshot::Receiver<()>,
    } -> u64;
}

impl<E: Spawner> Actor<E> for ConcurrentReadActor {
    type Mailbox = ConcurrentReadMailbox;
    type Ingress = ConcurrentReadMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = (u64, Arc<AtomicUsize>, Arc<AtomicUsize>);

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        (
            self.value,
            self.active_reads.clone(),
            self.max_active_reads.clone(),
        )
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: ConcurrentReadMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ConcurrentReadMailboxReadOnlyMessage::BlockOn { release, response } => {
                let (value, active_reads, max_active_reads) = snapshot;
                let active = active_reads.fetch_add(1, Ordering::SeqCst) + 1;

                loop {
                    let observed = max_active_reads.load(Ordering::SeqCst);
                    if observed >= active {
                        break;
                    }
                    if max_active_reads
                        .compare_exchange(observed, active, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        break;
                    }
                }

                let _ = release.await;

                active_reads.fetch_sub(1, Ordering::SeqCst);
                response.send_lossy(value);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: ConcurrentReadMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ConcurrentReadMailboxReadWriteMessage::Bump => {
                self.value += 1;
                self.read_write_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    }
}

#[test]
fn test_readonly_asks_run_concurrently() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let active_reads = Arc::new(AtomicUsize::new(0));
        let max_active_reads = Arc::new(AtomicUsize::new(0));
        let read_write_count = Arc::new(AtomicUsize::new(0));

        let actor = ConcurrentReadActor {
            value: 7,
            active_reads: active_reads.clone(),
            max_active_reads: max_active_reads.clone(),
            read_write_count,
        };

        let (mailbox, service) = ServiceBuilder::new(actor)
            .with_read_concurrency(std::num::NonZeroUsize::new(2).expect("non-zero"))
            .build(context.with_label("concurrent_reads"));
        service.start();

        let (tx1, rx1) = commonware_utils::channel::oneshot::channel();
        let (tx2, rx2) = commonware_utils::channel::oneshot::channel();

        let mailbox1 = mailbox.clone();
        let mailbox2 = mailbox;

        let read1 = context
            .with_label("read1")
            .spawn(
                move |_context| async move { mailbox1.block_on(rx1).await.expect("read1 failed") },
            );
        let read2 = context
            .with_label("read2")
            .spawn(
                move |_context| async move { mailbox2.block_on(rx2).await.expect("read2 failed") },
            );

        for _ in 0..10 {
            if active_reads.load(Ordering::SeqCst) == 2 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }

        assert_eq!(active_reads.load(Ordering::SeqCst), 2);
        assert_eq!(max_active_reads.load(Ordering::SeqCst), 2);

        tx1.send_lossy(());
        tx2.send_lossy(());

        assert_eq!(read1.await.expect("join1 failed"), 7);
        assert_eq!(read2.await.expect("join2 failed"), 7);
    });
}

#[test]
fn test_read_write_is_fenced_by_readonly_inflight() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let active_reads = Arc::new(AtomicUsize::new(0));
        let max_active_reads = Arc::new(AtomicUsize::new(0));
        let read_write_count = Arc::new(AtomicUsize::new(0));

        let actor = ConcurrentReadActor {
            value: 7,
            active_reads: active_reads.clone(),
            max_active_reads,
            read_write_count: read_write_count.clone(),
        };

        let (mailbox, service) = ServiceBuilder::new(actor)
            .with_read_concurrency(std::num::NonZeroUsize::new(2).expect("non-zero"))
            .build(context.with_label("read_write_fenced_by_reads"));
        service.start();

        let (tx1, rx1) = commonware_utils::channel::oneshot::channel();
        let (tx2, rx2) = commonware_utils::channel::oneshot::channel();

        let mailbox_read1 = mailbox.clone();
        let mailbox_write = mailbox.clone();
        let mailbox_read2 = mailbox;

        let read1 = context
            .with_label("fenced_read1")
            .spawn(move |_context| async move {
                mailbox_read1.block_on(rx1).await.expect("read1 failed")
            });

        for _ in 0..10 {
            if active_reads.load(Ordering::SeqCst) == 1 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(active_reads.load(Ordering::SeqCst), 1);

        mailbox_write.bump().await.expect("bump tell failed");

        let read2 = context
            .with_label("fenced_read2")
            .spawn(move |_context| async move {
                mailbox_read2.block_on(rx2).await.expect("read2 failed")
            });

        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(read_write_count.load(Ordering::SeqCst), 0);
        assert_eq!(active_reads.load(Ordering::SeqCst), 1);

        tx1.send_lossy(());
        assert_eq!(read1.await.expect("join1 failed"), 7);

        for _ in 0..10 {
            if read_write_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(read_write_count.load(Ordering::SeqCst), 1);

        for _ in 0..10 {
            if active_reads.load(Ordering::SeqCst) == 1 {
                break;
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(active_reads.load(Ordering::SeqCst), 1);

        tx2.send_lossy(());
        assert_eq!(read2.await.expect("join2 failed"), 8);
    });
}
