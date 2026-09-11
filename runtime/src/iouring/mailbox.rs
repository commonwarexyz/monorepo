//! Delivery of owned work to a worker from other threads.
//!
//! A mailbox holds no pointer into the worker's local state. Producers hand
//! over owned messages, and the worker applies them on its own thread.
//! Producers append under the inbox mutex, publish to the waker once per
//! empty-to-nonempty transition, and signal after unlocking if needed. The
//! worker swaps the whole batch into its scratch buffer and applies it outside
//! the lock. A closed mailbox returns messages to the sender, so no payload is
//! ever destroyed under the lock.

use super::{
    sleep::TimerId,
    task::{BoxedTask, Target},
    waiter::WaiterId,
    waker::Waker,
};
use commonware_utils::sync::Mutex;
use std::mem;

/// Owned work delivered to the worker without borrowing its local state.
pub enum Message {
    /// Wake the root future or a task.
    Wake(Target),
    /// Place a spawned task on this worker.
    Spawn(BoxedTask),
    /// Stop observing an admitted operation or retained result.
    Orphan(WaiterId),
    /// Cancel a timer whose sleep future was dropped.
    CancelTimer(TimerId),
}

/// Queue state synchronized between producers and the owning worker.
struct Inbox {
    /// Whether producers may still append.
    open: bool,
    /// Pending batch. Transfer swaps it with the worker's drained scratch, so
    /// both buffers keep their capacity.
    messages: Vec<Message>,
}

/// A worker's shared entry point: its inbox and its waker.
pub struct Mailbox {
    /// Wake source used after publication when signaling is needed. Owned here
    /// so producers can signal after unlocking.
    pub waker: Waker,
    /// Pending messages. No user code runs under this mutex.
    inbox: Mutex<Inbox>,
}

impl Mailbox {
    /// Create an open mailbox with a fresh waker.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            waker: Waker::new()?,
            inbox: Mutex::new(Inbox {
                open: true,
                messages: Vec::new(),
            }),
        })
    }

    /// Deliver a message, or return it if the mailbox is closed.
    pub fn send(&self, message: Message) -> Result<(), Message> {
        let signal = {
            let mut inbox = self.inbox.lock();
            if !inbox.open {
                return Err(message);
            }

            let first = inbox.messages.is_empty();
            inbox.messages.push(message);

            // Publish once per batch to match the worker's transfer count.
            first && self.waker.publish()
        };

        if signal {
            self.waker.wake();
        }

        Ok(())
    }

    /// Swap the pending batch into `scratch`, returning whether anything was
    /// transferred. `scratch` must be empty.
    ///
    /// Each `true` is one published batch, so the caller advances its processed
    /// sequence once per transfer.
    pub fn take(&self, scratch: &mut Vec<Message>) -> bool {
        assert!(
            scratch.is_empty(),
            "mailbox scratch must be drained before transfer"
        );

        let mut inbox = self.inbox.lock();
        if inbox.messages.is_empty() {
            return false;
        }
        mem::swap(&mut inbox.messages, scratch);

        true
    }

    /// Close the mailbox and return the pending messages for cleanup outside
    /// the lock.
    pub fn close(&self) -> Vec<Message> {
        let mut inbox = self.inbox.lock();
        inbox.open = false;
        mem::take(&mut inbox.messages)
    }

    /// Whether the mailbox still accepts messages.
    pub fn is_open(&self) -> bool {
        self.inbox.lock().open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::{task::Task, waker::tests::eventfd_count};
    use std::{
        future::pending,
        sync::{
            Arc, Barrier, Weak,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    struct Reentrant {
        mailbox: Weak<Mailbox>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for Reentrant {
        fn drop(&mut self) {
            let mailbox = self.mailbox.upgrade().unwrap();

            // Fail immediately if destruction runs under the inbox lock.
            let inbox = mailbox
                .inbox
                .try_lock()
                .expect("task dropped under inbox lock");
            assert!(!inbox.open);

            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    fn spawn_message(mailbox: &Arc<Mailbox>) -> (Message, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Reentrant {
            mailbox: Arc::downgrade(mailbox),
            dropped: dropped.clone(),
        };
        let task = Task::boxed(async move {
            let _guard = guard;
            pending::<()>().await;
        });

        (Message::Spawn(task), dropped)
    }

    #[test]
    fn test_messages_publish_once_per_batch() {
        let mailbox = Mailbox::new().unwrap();
        let mut scratch = Vec::new();
        assert!(mailbox.is_open());
        assert!(!mailbox.take(&mut scratch));
        assert!(!mailbox.waker.pending(0));

        // Multiple messages share one publication and retain their send order.
        assert!(mailbox.send(Message::Wake(Target::Root)).is_ok());
        assert!(mailbox.send(Message::Spawn(Task::boxed(pending()))).is_ok());
        assert!(mailbox.waker.pending(0));
        assert!(mailbox.take(&mut scratch));
        assert!(!mailbox.waker.pending(1));
        assert!(matches!(
            scratch.as_slice(),
            [Message::Wake(Target::Root), Message::Spawn(_)]
        ));

        // A new batch remains pending while the worker drains its scratch.
        assert!(mailbox.send(Message::Wake(Target::Root)).is_ok());
        assert!(mailbox.waker.pending(1));

        scratch.clear();
        assert!(mailbox.take(&mut scratch));
        assert!(!mailbox.waker.pending(2));
        assert!(matches!(scratch.as_slice(), [Message::Wake(Target::Root)]));

        scratch.clear();
        assert!(!mailbox.take(&mut scratch));
        assert!(!mailbox.waker.pending(2));
    }

    #[test]
    fn test_send_signals_armed_worker() {
        let mailbox = Mailbox::new().unwrap();
        let arm = mailbox.waker.arm(0);
        assert!(arm.still_idle());

        // Sending to an armed worker must also signal its eventfd.
        assert!(mailbox.send(Message::Wake(Target::Root)).is_ok());
        assert!(mailbox.waker.pending(0));
        assert_eq!(eventfd_count(&mailbox.waker), 1);
    }

    #[test]
    #[should_panic(expected = "mailbox scratch must be drained before transfer")]
    fn test_take_requires_empty_scratch() {
        let mailbox = Mailbox::new().unwrap();
        let mut scratch = vec![Message::Wake(Target::Root)];

        mailbox.take(&mut scratch);
    }

    #[test]
    fn test_close_returns_tasks_and_rejects_new_messages() {
        let mailbox = Arc::new(Mailbox::new().unwrap());
        let (message, dropped) = spawn_message(&mailbox);
        assert!(mailbox.send(message).is_ok());

        // Closing transfers queued tasks to the caller for destruction.
        let queued = mailbox.close();
        assert!(!mailbox.is_open());
        assert!(matches!(queued.as_slice(), [Message::Spawn(_)]));
        assert!(!dropped.load(Ordering::Relaxed));

        drop(queued);
        assert!(dropped.load(Ordering::Relaxed));

        // Rejected tasks also reach the caller, without another publication.
        let (message, dropped) = spawn_message(&mailbox);
        let rejected = mailbox.send(message);
        assert!(matches!(rejected, Err(Message::Spawn(_))));
        assert!(!dropped.load(Ordering::Relaxed));
        assert!(mailbox.waker.pending(0));
        assert!(!mailbox.waker.pending(1));

        drop(rejected);
        assert!(dropped.load(Ordering::Relaxed));

        let mut scratch = Vec::new();
        assert!(!mailbox.take(&mut scratch));
        assert!(mailbox.close().is_empty());
    }

    #[test]
    fn test_send_racing_close_preserves_payload_ownership() {
        let mailbox = Arc::new(Mailbox::new().unwrap());
        let gate = Arc::new(Barrier::new(2));
        let (message, dropped) = spawn_message(&mailbox);

        let producer = thread::spawn({
            let mailbox = mailbox.clone();
            let gate = gate.clone();
            move || {
                gate.wait();
                mailbox.send(message)
            }
        });

        gate.wait();
        let queued = mailbox.close();
        let result = producer.join().unwrap();

        // Either send or close must return the task, whichever wins the race.
        assert_eq!(queued.len(), usize::from(result.is_ok()));
        assert!(!mailbox.is_open());
        assert!(!dropped.load(Ordering::Relaxed));

        drop(queued);
        drop(result);
        assert!(dropped.load(Ordering::Relaxed));
    }
}
