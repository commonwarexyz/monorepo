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
//! for pool claims and permit grants, which carry no message. So the mailbox
//! keeps a mail flag beside the word, set by the send that starts a batch and
//! cleared by the take or close that empties the inbox, both under the lock.
//! The worker checks the flag through its [`Parker`] without locking and takes
//! only when it is set, so a notification without mail costs no lock.
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
//! The worker takes only into an empty scratch and applies a bounded share of
//! it each turn, so a turn can observe a batch's notification and still leave
//! that batch in the inbox. No later send of the batch notifies, so the worker
//! reads the flag again after it applies messages and blocks only while the
//! flag is clear.
//!
//! [`Mailbox::new`] returns the word's only [`Parker`] beside the mailbox, for
//! the worker that drains it. The pool's idle state unparks a selected worker
//! through its mailbox's [`Unparker`], without a message. See [`super::idle`]
//! for parking order.

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
        use loom::sync::{Mutex, MutexGuard};
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
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

/// A worker's shared entry point: its inbox and the unparker of its word.
pub struct Mailbox {
    /// Unparks the worker after a send that starts a batch, and holds the mail
    /// flag beside the word. Owned here so producers can unpark after
    /// unlocking. The pool unparks the worker through it, and the driver
    /// through a clone, both without a message.
    pub unparker: Unparker,
    /// Pending messages. No user code runs under this mutex.
    inbox: Mutex<Inbox>,
    /// Calls to [`Self::take`], each of which locks the inbox.
    #[cfg(test)]
    takes: std::sync::atomic::AtomicUsize,
}

impl Mailbox {
    /// Create an open mailbox with a fresh word, and return it with the word's
    /// only parker, which belongs to the worker that drains the mailbox.
    pub fn new() -> (Self, Parker) {
        let parker = Parker::new();
        let mailbox = Self {
            unparker: parker.unparker(),
            inbox: Mutex::new(Inbox {
                open: true,
                messages: Vec::new(),
            }),
            #[cfg(test)]
            takes: std::sync::atomic::AtomicUsize::new(0),
        };
        (mailbox, parker)
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
                self.unparker.set_mail(true);
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
        #[cfg(test)]
        self.takes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut inbox = self.lock();
        if inbox.messages.is_empty() {
            return false;
        }
        mem::swap(&mut inbox.messages, scratch);
        self.unparker.set_mail(false);

        true
    }

    /// Close the mailbox and return the pending messages for cleanup outside
    /// the lock.
    pub fn close(&self) -> Vec<Message> {
        let mut inbox = self.lock();
        inbox.open = false;
        self.unparker.set_mail(false);
        mem::take(&mut inbox.messages)
    }

    /// Whether the mailbox still accepts messages.
    #[cfg(test)]
    pub fn is_open(&self) -> bool {
        self.lock().open
    }

    /// Calls to [`Self::take`] so far.
    #[cfg(test)]
    pub fn takes(&self) -> usize {
        self.takes.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::{
        park::tests::{has_mail, notifications, wait_until_armed},
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
        let (mailbox, _parker) = Mailbox::new();
        let mut scratch = Vec::new();
        assert!(mailbox.is_open());
        assert!(!mailbox.take(&mut scratch));
        assert_eq!(notifications(&mailbox.unparker), 0);
        assert!(!has_mail(&mailbox.unparker));

        // Multiple messages share one notification and retain their send order.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(mailbox.send(cancel_message()).is_ok());
        assert_eq!(notifications(&mailbox.unparker), 1);
        assert!(has_mail(&mailbox.unparker));
        assert!(mailbox.take(&mut scratch));
        assert!(!has_mail(&mailbox.unparker));
        assert!(matches!(
            scratch.as_slice(),
            [Message::WakeRoot, Message::Cancel(_)]
        ));

        // A new batch notifies again while the worker drains its scratch.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert_eq!(notifications(&mailbox.unparker), 2);
        assert!(has_mail(&mailbox.unparker));

        // The worker takes the new batch once it has drained its scratch.
        scratch.clear();
        assert!(mailbox.take(&mut scratch));
        assert!(matches!(scratch.as_slice(), [Message::WakeRoot]));

        // An empty inbox has nothing to take and no new notification.
        scratch.clear();
        assert!(!mailbox.take(&mut scratch));
        assert_eq!(notifications(&mailbox.unparker), 2);
        assert!(!has_mail(&mailbox.unparker));
    }

    /// Notifications without messages leave the mail flag clear.
    #[test]
    fn test_notification_without_message_is_not_mail() {
        // A pool claim or a permit grant unparks the worker without a message.
        let (mailbox, parker) = Mailbox::new();
        mailbox.unparker.unpark();

        // The word moved, but the worker's parker reports no mail, so the
        // worker skips the take.
        assert!(parker.moved(0));
        assert!(!parker.has_mail());

        // A message sent after the notification still reports mail.
        assert!(mailbox.send(Message::WakeRoot).is_ok());
        assert!(parker.has_mail());
        assert_eq!(notifications(&mailbox.unparker), 2);
    }

    /// Sending a message ends the worker's armed wait.
    #[test]
    fn test_send_wakes_armed_worker() {
        // The worker parks on its word with a bounded deadline.
        let (mailbox, parker) = Mailbox::new();
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

    #[test]
    #[should_panic(expected = "mailbox scratch must be drained before transfer")]
    fn test_take_requires_empty_scratch() {
        let (mailbox, _parker) = Mailbox::new();
        let mut scratch = vec![Message::WakeRoot];

        mailbox.take(&mut scratch);
    }

    #[test]
    fn test_close_returns_messages_and_rejects_new_ones() {
        let mailbox = Arc::new(Mailbox::new().0);
        let (message, _receiver, reentrant) = forward_message(&mailbox);
        assert!(mailbox.send(message).is_ok());

        // Closing transfers queued messages to the caller for disposal.
        assert!(has_mail(&mailbox.unparker));
        let queued = mailbox.close();
        assert!(!mailbox.is_open());
        assert!(!has_mail(&mailbox.unparker));
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
        assert!(!has_mail(&mailbox.unparker));

        drop(rejected);
        assert!(reentrant.woken.load(Ordering::Relaxed));

        let mut scratch = Vec::new();
        assert!(!mailbox.take(&mut scratch));
        assert!(mailbox.close().is_empty());
    }

    #[test]
    fn test_send_racing_close_preserves_payload_ownership() {
        let mailbox = Arc::new(Mailbox::new().0);
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
