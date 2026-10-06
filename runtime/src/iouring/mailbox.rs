//! Delivery of owned work to a worker from other threads.
//!
//! A mailbox holds no pointer into the worker's local state. Producers hand
//! over owned messages, and the worker applies them on its own thread.
//! Producers append under the inbox mutex, publish to the waker once per
//! empty-to-nonempty transition, and signal after unlocking if needed. The
//! worker swaps the whole batch into its scratch buffer and applies it outside
//! the lock. A closed mailbox returns messages to the sender, so no payload is
//! ever destroyed under the lock.

use super::{request::RequestOutput, sleep::TimerId, waiter::WaiterId, waker::Waker};
use crate::Error;
use commonware_utils::channel::oneshot;
use std::mem;

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{Mutex, MutexGuard};
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
    }
}

/// Owned work delivered to the worker without borrowing its local state.
pub enum Message {
    /// Wake the root future.
    WakeRoot,
    /// Transfer observation of an operation or timer to a channel.
    Forward(Forward),
    /// Release observation of an operation or timer.
    Cancel(Cancel),
}

/// Registration and channel used to forward completion to another thread.
pub enum Forward {
    /// Deliver an operation's result through a thread-safe channel.
    Waiter(WaiterId, oneshot::Sender<Result<RequestOutput, Error>>),
    /// Deliver a timer's result through a thread-safe channel.
    Timer(TimerId, oneshot::Sender<Result<(), Error>>),
}

/// Registration whose observer is being released.
pub enum Cancel {
    /// Stop observing an admitted operation or retained result.
    Waiter(WaiterId),
    /// Cancel a timer whose sleep future was dropped.
    Timer(TimerId),
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
    /// so producers can signal after unlocking. The pool also wakes a parked
    /// worker through it, without a message.
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

    /// Lock the inbox.
    fn lock(&self) -> MutexGuard<'_, Inbox> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let inbox = self.inbox.lock().unwrap();
            } else {
                let inbox = self.inbox.lock();
            }
        }
        inbox
    }

    /// Deliver a message, or return it if the mailbox is closed.
    pub fn send(&self, message: Message) -> Result<(), Message> {
        let signal = {
            let mut inbox = self.lock();
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

        let mut inbox = self.lock();
        if inbox.messages.is_empty() {
            return false;
        }
        mem::swap(&mut inbox.messages, scratch);

        true
    }

    /// Close the mailbox and return the pending messages for cleanup outside
    /// the lock.
    pub fn close(&self) -> Vec<Message> {
        let mut inbox = self.lock();
        inbox.open = false;
        mem::take(&mut inbox.messages)
    }

    /// Whether the mailbox still accepts messages.
    #[cfg(test)]
    pub fn is_open(&self) -> bool {
        self.lock().open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::{slab::Id, waker::tests::eventfd_count};
    use futures::task::{ArcWake, waker};
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc, Barrier, Weak,
            atomic::{AtomicBool, Ordering},
        },
        task::Context,
        thread,
    };

    /// Wakes when its forwarded result's sender is dropped, failing if that
    /// happens under the inbox lock, since a waker runs user code.
    struct Reentrant {
        mailbox: Weak<Mailbox>,
        woken: AtomicBool,
    }

    impl ArcWake for Reentrant {
        fn wake_by_ref(this: &Arc<Self>) {
            let mailbox = this.mailbox.upgrade().unwrap();

            // Fail immediately if the wake runs under the inbox lock.
            let inbox = mailbox
                .inbox
                .try_lock()
                .expect("message dropped under inbox lock");
            assert!(!inbox.open);

            this.woken.store(true, Ordering::Relaxed);
        }
    }

    /// A forwarded result whose receiver waits with a [`Reentrant`] waker, so
    /// dropping the message wakes it. Returns the message, its receiver, which
    /// the caller keeps alive, and the waker's state.
    fn forward_message(
        mailbox: &Arc<Mailbox>,
    ) -> (
        Message,
        oneshot::Receiver<Result<RequestOutput, Error>>,
        Arc<Reentrant>,
    ) {
        let (sender, mut receiver) = oneshot::channel();
        let reentrant = Arc::new(Reentrant {
            mailbox: Arc::downgrade(mailbox),
            woken: AtomicBool::new(false),
        });
        let waker = waker(reentrant.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut receiver).poll(&mut cx).is_pending());

        let id = WaiterId(Id {
            index: 0,
            generation: 0,
        });
        (
            Message::Forward(Forward::Waiter(id, sender)),
            receiver,
            reentrant,
        )
    }

    /// A message with no payload to release.
    const fn cancel_message() -> Message {
        Message::Cancel(Cancel::Waiter(WaiterId(Id {
            index: 0,
            generation: 0,
        })))
    }

    #[test]
    fn test_messages_publish_once_per_batch() {
        let mailbox = Mailbox::new().unwrap();
        let mut scratch = Vec::new();
        assert!(mailbox.is_open());
        assert!(!mailbox.take(&mut scratch));
        assert!(!mailbox.waker.pending(0));

        // Multiple messages share one publication and retain their send order.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.send(cancel_message()).is_ok());
        assert!(mailbox.waker.pending(0));
        assert!(mailbox.take(&mut scratch));
        assert!(!mailbox.waker.pending(1));
        assert!(matches!(
            scratch.as_slice(),
            [Message::WakeRoot, Message::Cancel(_)]
        ));

        // A new batch remains pending while the worker drains its scratch.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.waker.pending(1));

        scratch.clear();
        assert!(mailbox.take(&mut scratch));
        assert!(!mailbox.waker.pending(2));
        assert!(matches!(scratch.as_slice(), [Message::WakeRoot]));

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
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.waker.pending(0));
        assert_eq!(eventfd_count(&mailbox.waker), 1);
    }

    #[test]
    #[should_panic(expected = "mailbox scratch must be drained before transfer")]
    fn test_take_requires_empty_scratch() {
        let mailbox = Mailbox::new().unwrap();
        let mut scratch = vec![Message::WakeRoot];

        mailbox.take(&mut scratch);
    }

    #[test]
    fn test_close_returns_messages_and_rejects_new_ones() {
        let mailbox = Arc::new(Mailbox::new().unwrap());
        let (message, _receiver, reentrant) = forward_message(&mailbox);
        assert!(mailbox.send(message).is_ok());

        // Closing transfers queued messages to the caller for disposal.
        let queued = mailbox.close();
        assert!(!mailbox.is_open());
        assert!(matches!(queued.as_slice(), [Message::Forward(_)]));
        assert!(!reentrant.woken.load(Ordering::Relaxed));

        drop(queued);
        assert!(reentrant.woken.load(Ordering::Relaxed));

        // Rejected messages also reach the caller, without another publication.
        let (message, _receiver, reentrant) = forward_message(&mailbox);
        let rejected = mailbox.send(message);
        assert!(matches!(rejected, Err(Message::Forward(_))));
        assert!(!reentrant.woken.load(Ordering::Relaxed));
        assert!(mailbox.waker.pending(0));
        assert!(!mailbox.waker.pending(1));

        drop(rejected);
        assert!(reentrant.woken.load(Ordering::Relaxed));

        let mut scratch = Vec::new();
        assert!(!mailbox.take(&mut scratch));
        assert!(mailbox.close().is_empty());
    }

    #[test]
    fn test_send_racing_close_preserves_payload_ownership() {
        let mailbox = Arc::new(Mailbox::new().unwrap());
        let gate = Arc::new(Barrier::new(2));
        let (message, _receiver, reentrant) = forward_message(&mailbox);

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

        // Either send or close must return the message, whichever wins the race.
        assert_eq!(queued.len(), usize::from(result.is_ok()));
        assert!(!mailbox.is_open());
        assert!(!reentrant.woken.load(Ordering::Relaxed));

        drop(queued);
        drop(result);
        assert!(reentrant.woken.load(Ordering::Relaxed));
    }
}
