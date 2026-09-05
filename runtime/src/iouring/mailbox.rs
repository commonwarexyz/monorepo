//! Foreign publication into an owning worker's local state.
//!
//! A mailbox contains no pointer to the worker's local arena or ring. Producers
//! append owned messages under an inbox mutex and publish once when an empty
//! inbox becomes nonempty. They signal the retained hybrid waker after unlocking.
//!
//! ```text
//! producer: lock -> append -> publish batch -> unlock -> signal
//! owner:    lock -> swap into scratch       -> unlock -> apply bounded batch
//! ```
//!
//! The owner increments its processed sequence once per nonempty transfer,
//! independently of the number of messages it applies in a turn. Scratch work
//! prevents parking. A newer shared batch remains visible while scratch drains.
//! Rejected and closed messages leave the lock before payload destruction.

use super::{
    admission::AdmissionId,
    operation::OperationId,
    sleep::TimerId,
    task::{Runnable, Target},
    waker::Waker,
};
use commonware_utils::sync::Mutex;
use std::{mem, pin::Pin};

/// Owned work delivered to the worker without borrowing its local state.
pub(super) enum Message {
    /// Notify the root or a generational task entry.
    Wake(Target),
    /// Register a concrete wrapped task on its selected worker.
    Spawn(Pin<Box<dyn Runnable>>),
    /// Release a queued or granted admission reservation.
    CancelAdmission(AdmissionId),
    /// Stop observing an admitted operation or retained result.
    OrphanOperation(OperationId),
    /// Remove a sleeper registration after foreign destruction.
    CancelTimer(TimerId),
}

/// Queue state synchronized between producers and the owning worker.
struct Inbox {
    /// Whether a producer may append another message.
    open: bool,
    /// One published batch, with capacity reused after the owner's transfer.
    messages: Vec<Message>,
}

/// Shared ingress and kernel wake resources retained through delayed signaling.
pub(super) struct Mailbox {
    /// Hybrid wake state whose descriptor outlives every publishing call.
    pub(super) waker: Waker,
    /// Foreign messages. Arbitrary callbacks never run under this mutex.
    inbox: Mutex<Inbox>,
}

impl Mailbox {
    /// Create ingress on the worker before exposing any weak references.
    pub(super) fn new() -> std::io::Result<Self> {
        Ok(Self {
            waker: Waker::new()?,
            inbox: Mutex::new(Inbox {
                open: true,
                messages: Vec::new(),
            }),
        })
    }

    /// Publish owned work, returning rejected payloads without destroying them.
    pub(super) fn send(&self, message: Message) -> Result<(), Message> {
        let signal = {
            let mut inbox = self.inbox.lock();
            if !inbox.open {
                return Err(message);
            }
            let first = inbox.messages.is_empty();
            inbox.messages.push(message);
            first && self.waker.publish_deferred()
        };
        if signal {
            self.waker.wake();
        }
        Ok(())
    }

    /// Transfer one whole shared batch into empty owner-local scratch.
    ///
    /// A true result requires exactly one processed-sequence increment. The
    /// caller must finish its retained scratch before transferring another batch.
    pub(super) fn take(&self, scratch: &mut Vec<Message>) -> bool {
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

    /// Close ingress and detach every queued message for cleanup outside locks.
    pub(super) fn close(&self) -> Vec<Message> {
        let mut inbox = self.inbox.lock();
        inbox.open = false;
        mem::take(&mut inbox.messages)
    }

    /// Distinguish a closed worker from an invalid poll on another live worker.
    pub(super) fn is_open(&self) -> bool {
        self.inbox.lock().open
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;
    use crate::iouring::task::Task;
    use std::sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn messages_publish_once_per_nonempty_batch() {
        let mailbox = Mailbox::new().unwrap();
        assert!(mailbox.send(Message::Wake(Target::Root)).is_ok());
        assert!(mailbox.send(Message::Wake(Target::Root)).is_ok());
        assert!(mailbox.waker.pending(0));
        assert!(!mailbox.waker.pending(1));
        let mut scratch = Vec::new();
        assert!(mailbox.take(&mut scratch));
        assert_eq!(scratch.len(), 2);
        assert!(mailbox.send(Message::Wake(Target::Root)).is_ok());
        assert!(mailbox.waker.pending(1));
        assert!(!mailbox.waker.pending(2));
        scratch.clear();
        assert!(mailbox.take(&mut scratch));
        scratch.clear();
        assert!(!mailbox.take(&mut scratch));
    }

    #[test]
    fn rejected_spawn_destruction_can_reenter_mailbox() {
        struct Reentrant {
            mailbox: Weak<Mailbox>,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for Reentrant {
            fn drop(&mut self) {
                assert!(!self.mailbox.upgrade().unwrap().is_open());
                self.dropped.store(true, Ordering::Relaxed);
            }
        }
        let mailbox = Arc::new(Mailbox::new().unwrap());
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Reentrant {
            mailbox: Arc::downgrade(&mailbox),
            dropped: dropped.clone(),
        };
        let task = Task::boxed(async move {
            let _guard = guard;
            std::future::pending::<()>().await
        });
        drop(mailbox.close());
        let rejected = mailbox.send(Message::Spawn(task));
        assert!(rejected.is_err());
        assert!(!dropped.load(Ordering::Relaxed));
        drop(rejected);
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[test]
    fn enqueue_racing_close_preserves_payload_ownership() {
        let mailbox = Arc::new(Mailbox::new().unwrap());
        let gate = Arc::new(std::sync::Barrier::new(2));
        let producer = std::thread::spawn({
            let mailbox = mailbox.clone();
            let gate = gate.clone();
            move || {
                gate.wait();
                mailbox.send(Message::Wake(Target::Root))
            }
        });
        gate.wait();
        let queued = mailbox.close();
        let accepted = producer.join().unwrap().is_ok();
        assert_eq!(queued.len(), usize::from(accepted));
        assert!(!mailbox.is_open());
    }
}
