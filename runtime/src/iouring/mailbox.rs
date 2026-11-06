//! Delivery of owned work to a worker from other threads.
//!
//! A mailbox holds no pointer into the worker's local state. Producers hand
//! over owned messages, and the worker applies them on its own thread.
//! Producers append under the inbox mutex and, after unlocking, unpark the
//! worker once per empty-to-nonempty transition. The worker swaps the whole
//! batch into its scratch buffer and applies it outside the lock. A closed
//! mailbox returns messages to the sender, so no payload is ever destroyed
//! under the lock.
//!
//! The sequence of the worker's futex word (see [`super::park`]) also moves
//! for pool claims and permit grants, which carry no message. So the inbox
//! keeps a mail flag, set by the send that starts a batch and cleared by the
//! take or close that empties the inbox, both under the lock. The worker
//! checks the flag without locking and takes only when it is set, so a
//! notification without mail costs no lock.
//!
//! A relaxed load of the flag suffices once the worker has observed the word.
//! The send stores the flag before it unlocks and notifies with release
//! ordering, and the worker observes with acquire ordering before it checks the
//! flag. If that observation includes the notification, the flag store happens
//! before the check, and only the worker's own take or close clears it later.
//! Otherwise the notification moves the sequence after the observation, so the
//! worker's recheck before blocking, or the wake of its wait, sends it round
//! again, and its next observation includes the notification.
//!
//! The mailbox also holds the worker's [`Parker`] until the worker takes it at
//! startup, so the word has one parker. The pool's idle state unparks a
//! selected worker through its mailbox's [`Unparker`], without a message. See
//! [`super::idle`] for parking order.

use super::{
    park::{Parker, Unparker},
    request::RequestOutput,
    sleep::TimerId,
    waiter::WaiterId,
};
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
    /// The parker of the word until its worker takes it.
    parker: Option<Parker>,
}

/// A worker's shared entry point: its inbox and the unparker of its word.
pub struct Mailbox {
    /// Unparks the worker after a send that starts a batch. Owned here so
    /// producers can unpark after unlocking. The pool and the driver also
    /// unpark the worker through it, without a message.
    pub unparker: Unparker,
    /// Whether the inbox holds a batch. Written only under the inbox lock and
    /// read without it.
    mail: AtomicBool,
    /// Pending messages. No user code runs under this mutex.
    inbox: Mutex<Inbox>,
}

impl Mailbox {
    /// Create an open mailbox with a fresh word, holding its parker for the
    /// worker.
    pub fn new() -> Self {
        let parker = Parker::new();
        Self {
            unparker: parker.unparker(),
            mail: AtomicBool::new(false),
            inbox: Mutex::new(Inbox {
                open: true,
                messages: Vec::new(),
                parker: Some(parker),
            }),
        }
    }

    /// Take the parker of this mailbox's word, panicking if it was already
    /// taken, even if it has since been dropped.
    pub fn parker(&self) -> Parker {
        self.lock()
            .parker
            .take()
            .expect("mailbox parker must be taken at most once")
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

        // A later message of the batch needs no notification, since the
        // worker takes the whole batch once the first one's notification
        // moves the word.
        if first {
            self.unparker.unpark();
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
    /// A batch whose notification the caller's last [`Parker::observe`] included
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
        park::tests::{notifications, wait_until_armed},
        slab::Id,
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

    /// Messages sent while a batch is pending share its one notification and
    /// keep their send order, and the mail flag stays set until a take
    /// empties the inbox.
    #[test]
    fn test_messages_notify_once_per_batch() {
        // A fresh mailbox has no batch, no notification, and no mail.
        let mailbox = Mailbox::new();
        let mut scratch = Vec::new();
        assert!(mailbox.is_open());
        assert!(!mailbox.take(&mut scratch));
        assert_eq!(notifications(&mailbox.unparker), 0);
        assert!(!mailbox.has_mail());

        // Multiple messages share one notification and retain their send order.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.send(cancel_message()).is_ok());
        assert_eq!(notifications(&mailbox.unparker), 1);
        assert!(mailbox.has_mail());
        assert!(mailbox.take(&mut scratch));
        assert!(!mailbox.has_mail());
        assert!(matches!(
            scratch.as_slice(),
            [Message::WakeRoot, Message::Cancel(_)]
        ));

        // A new batch notifies again while the worker drains its scratch.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert_eq!(notifications(&mailbox.unparker), 2);
        assert!(mailbox.has_mail());

        // The worker takes the new batch once it has drained its scratch.
        scratch.clear();
        assert!(mailbox.take(&mut scratch));
        assert!(matches!(scratch.as_slice(), [Message::WakeRoot]));

        // An empty inbox has nothing to take and no new notification.
        scratch.clear();
        assert!(!mailbox.take(&mut scratch));
        assert_eq!(notifications(&mailbox.unparker), 2);
        assert!(!mailbox.has_mail());
    }

    /// Notifications without messages leave the mail flag clear.
    #[test]
    fn test_notification_without_message_is_not_mail() {
        // A pool claim or a permit grant unparks the worker without a message.
        let mailbox = Mailbox::new();
        let parker = mailbox.parker();
        mailbox.unparker.unpark();

        // The word moved, but the mailbox reports no mail, so the worker skips
        // the take.
        assert!(parker.moved(0));
        assert!(!mailbox.has_mail());

        // A message sent after the notification still reports mail.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.has_mail());
        assert_eq!(notifications(&mailbox.unparker), 2);
    }

    /// Sending a message ends the worker's armed wait.
    #[test]
    fn test_send_wakes_armed_worker() {
        // The worker parks on its word with a bounded deadline.
        let mailbox = Mailbox::new();
        let parker = mailbox.parker();
        let deadline = Instant::now() + Duration::from_secs(10);
        let parked = thread::spawn(move || parker.park(0, Some(deadline)));

        // Send to the armed worker.
        wait_until_armed(&mailbox.unparker, deadline);
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        parked.join().unwrap();

        // The send woke the wait well before the deadline, with one
        // notification.
        assert!(Instant::now() < deadline, "send did not wake the worker");
        assert_eq!(notifications(&mailbox.unparker), 1);
    }

    /// A mailbox hands out the parker of its word once, so one worker waits on
    /// it, while its unparker keeps working after that parker is dropped.
    #[test]
    #[should_panic(expected = "mailbox parker must be taken at most once")]
    fn test_parker_is_taken_at_most_once() {
        // The worker takes the parker and drops it, which leaves the word to
        // its unparkers.
        let mailbox = Mailbox::new();
        drop(mailbox.parker());
        mailbox.unparker.unpark();
        assert_eq!(notifications(&mailbox.unparker), 1);

        // Another take panics, even after the first parker is gone.
        mailbox.parker();
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
        assert_eq!(notifications(&mailbox.unparker), 1);
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
