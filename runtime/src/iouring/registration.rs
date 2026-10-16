//! Observation of work that stays on its original worker.
//!
//! Local polls access the worker directly. The first foreign poll installs a
//! completion channel, which all subsequent polls use. The original identity
//! remains available for cancellation until observation ends.

use super::{
    mailbox::{Cancel, Forward, Mailbox, Message},
    runtime::Local,
};
use crate::Error;
use commonware_utils::channel::oneshot;
use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::Weak,
    task::{Context, Poll, Waker},
};

/// Inspection without cloning or invoking the observer's waker.
pub enum Observation<T> {
    /// The registration has completed and relinquished its output.
    Ready(T),
    /// The installed waker already matches the current task.
    Pending,
    /// A new waker must be cloned outside the worker borrow.
    Refresh,
}

/// Worker-owned operations needed by a movable observer.
pub trait Key: Copy + Unpin {
    /// Terminal value produced by the owning subsystem.
    type Output;

    /// Inspect completion without running callbacks under the worker borrow.
    fn observe(self, local: &mut Local, waker: &Waker) -> Observation<Self::Output>;

    /// Replace the observer and return its displaced waker for deferred destruction.
    fn refresh(self, local: &mut Local, waker: Waker) -> Option<Waker>;

    /// Transfer observation to a completion channel on the owning worker.
    fn forward(self, sender: oneshot::Sender<Result<Self::Output, Error>>) -> Forward;

    /// Release observation, leaving retirement policy to the owning subsystem.
    fn cancel(self) -> Cancel;
}

/// Registration ownership retained between polls.
enum State<K: Key> {
    /// Registration awaiting observation, directly or through a forwarding channel.
    Waiting {
        /// Owning worker, without extending its lifetime.
        mailbox: Weak<Mailbox>,
        /// Identity retained until completion or cancellation.
        key: K,
        /// Permanent observation path once forwarding is requested.
        receiver: Option<oneshot::Receiver<Result<K::Output, Error>>>,
    },
    /// Registration rejected by a closing worker, with closure not yet observed.
    Closed,
    /// Observation completed or released, with no cancellation identity retained.
    Done,
}

/// A movable observer of one registration on its original worker.
pub struct Registration<K: Key> {
    /// Retains the cancellation identity until observation completes or is released.
    state: State<K>,
}

impl<K: Key> Registration<K> {
    /// Observe work already registered with this worker.
    pub const fn new(mailbox: Weak<Mailbox>, key: K) -> Self {
        Self {
            state: State::Waiting {
                mailbox,
                key,
                receiver: None,
            },
        }
    }

    /// Report that the worker rejected registration during shutdown.
    pub const fn closed() -> Self {
        Self {
            state: State::Closed,
        }
    }

    /// Return the identity of a waiting registration.
    #[cfg(test)]
    pub fn key(&self) -> K {
        let State::Waiting { key, .. } = self.state else {
            panic!("registration already completed");
        };
        key
    }

    /// Release the registration before destroying a channel's observer waker.
    fn release(&mut self) {
        // Consume the identity before cleanup can unwind. Publish cancellation
        // before dropping the receiver, whose waker destructor may run user code.
        if let State::Waiting {
            mailbox,
            key,
            receiver,
        } = mem::replace(&mut self.state, State::Done)
        {
            Local::cancel(&mailbox, key.cancel());
            drop(receiver);
        }
    }
}

impl<K: Key> Future for Registration<K> {
    type Output = Result<K::Output, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Pending polls retain the owner and key so Drop can still release the
        // registration if polling unwinds.
        let this = self.get_mut();
        let (mailbox, key, receiver) = match &mut this.state {
            State::Waiting {
                mailbox,
                key,
                receiver,
            } => (mailbox, *key, receiver),
            State::Closed => {
                this.state = State::Done;
                return Poll::Ready(Err(Error::Closed));
            }
            State::Done => panic!("io_uring registration polled after completion"),
        };

        // Direct access requires the owning worker and an unforwarded registration.
        // Once installed, the channel remains the observation path even on that worker.
        let owner = receiver.is_none().then(|| Local::owner(mailbox)).flatten();
        let Some(owner) = owner else {
            // A missing or closed worker drops the sender, allowing the receiver
            // to report closure without retaining the worker.
            let receiver = receiver.get_or_insert_with(|| {
                let (sender, receiver) = oneshot::channel();
                if let Some(mailbox) = mailbox.upgrade() {
                    let _ = mailbox.send(Message::Forward(key.forward(sender)));
                }
                receiver
            });

            let result = std::task::ready!(Pin::new(receiver).poll(cx));
            this.state = State::Done;
            return Poll::Ready(result.unwrap_or(Err(Error::Closed)));
        };

        // A closing worker owns cleanup. Release observation after ending this
        // borrow because cancellation reenters the worker.
        let mut local = owner.borrow_mut();
        if local.closing {
            drop(local);
            this.release();
            return Poll::Ready(Err(Error::Closed));
        }

        // Only a changed pending waker needs a refresh. Ready results and matching
        // wakers return without invoking observer callbacks.
        match key.observe(&mut local, cx.waker()) {
            Observation::Ready(output) => {
                this.state = State::Done;
                return Poll::Ready(Ok(output));
            }
            Observation::Pending => return Poll::Pending,
            Observation::Refresh => {}
        }

        // Waker callbacks may reenter the runtime, so clone outside the borrow
        // and defer destruction of the displaced waker. Worker service cannot
        // advance during this poll, and a clone panic leaves the registration
        // identity available for cancellation.
        drop(local);
        let waker = cx.waker().clone();
        let mut local = owner.borrow_mut();
        let old = key.refresh(&mut local, waker);
        local.deferred.drops.extend(old);
        Poll::Pending
    }
}

impl<K: Key> Drop for Registration<K> {
    fn drop(&mut self) {
        self.release();
    }
}
