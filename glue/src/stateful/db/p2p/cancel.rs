//! Cancellation of an in-flight resolver request.

use commonware_actor::mailbox::{Policy, Sender};

/// Sends its message on drop, unless [`Guard::disarm`] ran first.
pub(super) struct Guard<T: Policy> {
    sender: Sender<T>,
    cancel: Option<T>,
}

impl<T: Policy> Guard<T> {
    pub(super) const fn new(sender: Sender<T>, cancel: T) -> Self {
        Self {
            sender,
            cancel: Some(cancel),
        }
    }

    /// Suppresses the drop-time cancel; call once the fetch has completed.
    pub(super) fn disarm(&mut self) {
        self.cancel = None;
    }
}

impl<T: Policy> Drop for Guard<T> {
    fn drop(&mut self) {
        let Some(cancel) = self.cancel.take() else {
            return;
        };
        let _ = self.sender.enqueue(cancel);
    }
}
