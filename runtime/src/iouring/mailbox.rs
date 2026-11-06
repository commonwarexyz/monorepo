//! Delivery of owned work to a worker from other threads.
//!
//! A mailbox holds no pointer into the worker's local state. Producers hand
//! over owned messages, and the worker applies them on its own thread.
//! Producers append under the inbox mutex and, after unlocking, notify the
//! waker once per empty-to-nonempty transition. The worker swaps the whole
//! batch into its scratch buffer and applies it outside the lock. A closed
//! mailbox returns messages to the sender, so no payload is ever destroyed
//! under the lock.
//!
//! The waker's sequence also moves for pool claims and permit grants, which
//! carry no message. So the inbox keeps a mail flag, set by the send that
//! starts a batch and cleared by the take or close that empties the inbox,
//! both under the lock. The worker checks the flag without locking and takes
//! only when it is set, so a notification without mail costs no lock.
//!
//! A relaxed load of the flag suffices once the worker has observed the waker.
//! The send stores the flag before it unlocks and notifies with release
//! ordering, and the worker observes with acquire ordering before it checks the
//! flag. If that observation includes the notification, the flag store happens
//! before the check, and only the worker's own take or close clears it later.
//! Otherwise the notification moves the sequence after the observation, so the
//! worker's recheck before blocking, or the wake of its wait, sends it round
//! again, and its next observation includes the notification.
//!
//! The pool's idle state also notifies a selected worker through its mailbox's
//! [`Waker`], without a message. See [`super::idle`] for parking order.

use super::{request::RequestOutput, sleep::TimerId, waiter::WaiterId, waker::Waker};
use crate::Error;
use commonware_utils::channel::oneshot;
use std::mem;

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            Mutex, MutexGuard,
            atomic::{AtomicBool, Ordering},
        };
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
        use std::sync::atomic::{AtomicBool, Ordering};
    }
}

/// Owned work delivered to the worker without borrowing its local state.
pub enum Message {
    /// Wake the root future. The root is pinned on its worker and has no
    /// runnable, so unlike a task it cannot move to the waking worker or the
    /// global queue, and wakes from other threads reach it here.
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
    /// Eventcount notified after a send that starts a batch. Owned here so
    /// producers can notify after unlocking. The pool and the driver also
    /// notify the worker through it, without a message.
    pub waker: Waker,
    /// Whether the inbox holds a batch. Written only under the inbox lock and
    /// read without it.
    mail: AtomicBool,
    /// Pending messages. No user code runs under this mutex.
    inbox: Mutex<Inbox>,
}

impl Mailbox {
    /// Create an open mailbox with a fresh waker.
    pub fn new() -> Self {
        Self {
            waker: Waker::new(),
            mail: AtomicBool::new(false),
            inbox: Mutex::new(Inbox {
                open: true,
                messages: Vec::new(),
            }),
        }
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
        let first = {
            let mut inbox = self.lock();
            if !inbox.open {
                return Err(message);
            }

            let first = inbox.messages.is_empty();
            inbox.messages.push(message);

            // The lock orders this store with the take that clears it, and the
            // notification below publishes it to the worker's observation.
            if first {
                self.mail.store(true, Ordering::Relaxed);
            }
            first
        };

        // A later message of the batch needs no notification: the worker takes
        // the whole batch once the first one's notification moves the word.
        if first {
            self.waker.notify();
        }

        Ok(())
    }

    /// Swap the pending batch into `scratch`, returning whether anything was
    /// transferred. `scratch` must be empty.
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
        self.mail.store(false, Ordering::Relaxed);

        true
    }

    /// Whether a batch may be waiting, without locking the inbox.
    ///
    /// A batch whose notification the caller's last [`Waker::observe`] included
    /// is reported, unless the caller took it since. See the module docs.
    #[inline]
    pub fn has_mail(&self) -> bool {
        self.mail.load(Ordering::Relaxed)
    }

    /// Close the mailbox and return the pending messages for cleanup outside
    /// the lock.
    pub fn close(&self) -> Vec<Message> {
        let mut inbox = self.lock();
        inbox.open = false;
        self.mail.store(false, Ordering::Relaxed);
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
    use crate::iouring::{
        slab::Id,
        waker::tests::{notifications, wait_until_armed},
    };
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
        time::{Duration, Instant},
    };

    /// Waker state that records a wake and fails if the wake runs under the
    /// inbox lock, since a waker can run user code.
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
                .expect("messages must be dropped outside the inbox lock");
            assert!(!inbox.open);

            this.woken.store(true, Ordering::Relaxed);
        }
    }

    /// A forwarded result whose receiver waits with a [`Reentrant`] waker, so
    /// dropping the message wakes it. Returns the message, the receiver for the
    /// caller to keep alive, and the waker's state.
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
    fn test_messages_notify_once_per_batch() {
        let mailbox = Mailbox::new();
        let mut scratch = Vec::new();
        assert!(mailbox.is_open());
        assert!(!mailbox.take(&mut scratch));
        assert_eq!(notifications(&mailbox.waker), 0);
        assert!(!mailbox.has_mail());

        // Multiple messages share one notification and retain their send order.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.send(cancel_message()).is_ok());
        assert_eq!(notifications(&mailbox.waker), 1);
        assert!(mailbox.has_mail());
        assert!(mailbox.take(&mut scratch));
        assert!(!mailbox.has_mail());
        assert!(matches!(
            scratch.as_slice(),
            [Message::WakeRoot, Message::Cancel(_)]
        ));

        // A new batch notifies again while the worker drains its scratch.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert_eq!(notifications(&mailbox.waker), 2);
        assert!(mailbox.has_mail());

        scratch.clear();
        assert!(mailbox.take(&mut scratch));
        assert!(matches!(scratch.as_slice(), [Message::WakeRoot]));

        scratch.clear();
        assert!(!mailbox.take(&mut scratch));
        assert_eq!(notifications(&mailbox.waker), 2);
        assert!(!mailbox.has_mail());
    }

    #[test]
    fn test_notification_without_message_is_not_mail() {
        // A pool claim or a permit grant notifies the waker without a message.
        let mailbox = Mailbox::new();
        mailbox.waker.notify();

        // The word moved, but the mailbox reports no mail, so the worker skips
        // the take.
        assert!(mailbox.waker.moved(0));
        assert!(!mailbox.has_mail());

        // A message sent after the notification still reports mail.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.has_mail());
        assert_eq!(notifications(&mailbox.waker), 2);
    }

    #[test]
    fn test_send_wakes_armed_worker() {
        let mailbox = Arc::new(Mailbox::new());
        let deadline = Instant::now() + Duration::from_secs(10);
        let parked = thread::spawn({
            let mailbox = mailbox.clone();
            move || mailbox.waker.park_idle(0, Some(deadline))
        });

        // Sending to an armed worker must also wake its wait.
        wait_until_armed(&mailbox.waker, deadline);
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        parked.join().unwrap();
        assert!(Instant::now() < deadline, "send did not wake the worker");
        assert_eq!(notifications(&mailbox.waker), 1);
    }

    #[test]
    #[should_panic(expected = "mailbox scratch must be drained before transfer")]
    fn test_take_requires_empty_scratch() {
        let mailbox = Mailbox::new();
        let mut scratch = vec![Message::WakeRoot];

        mailbox.take(&mut scratch);
    }

    #[test]
    fn test_close_returns_messages_and_rejects_new_ones() {
        let mailbox = Arc::new(Mailbox::new());
        let (message, _receiver, reentrant) = forward_message(&mailbox);
        assert!(mailbox.send(message).is_ok());

        // Closing transfers queued messages to the caller for disposal.
        assert!(mailbox.has_mail());
        let queued = mailbox.close();
        assert!(!mailbox.is_open());
        assert!(!mailbox.has_mail());
        assert!(matches!(queued.as_slice(), [Message::Forward(_)]));
        assert!(!reentrant.woken.load(Ordering::Relaxed));

        drop(queued);
        assert!(reentrant.woken.load(Ordering::Relaxed));

        // Rejected messages also reach the caller, without another notification.
        let (message, _receiver, reentrant) = forward_message(&mailbox);
        let rejected = mailbox.send(message);
        assert!(matches!(rejected, Err(Message::Forward(_))));
        assert!(!reentrant.woken.load(Ordering::Relaxed));
        assert_eq!(notifications(&mailbox.waker), 1);
        assert!(!mailbox.has_mail());

        drop(rejected);
        assert!(reentrant.woken.load(Ordering::Relaxed));

        let mut scratch = Vec::new();
        assert!(!mailbox.take(&mut scratch));
        assert!(mailbox.close().is_empty());
    }

    #[test]
    fn test_send_racing_close_preserves_payload_ownership() {
        let mailbox = Arc::new(Mailbox::new());
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
