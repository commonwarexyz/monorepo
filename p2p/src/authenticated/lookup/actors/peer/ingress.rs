use commonware_utils::{NZUsize, channel::ring};
use std::fmt;

/// Handle to the connection of a peer [super::Actor].
///
/// The connection ends once any clone calls [Mailbox::kill] or every clone is dropped.
pub struct Mailbox(ring::Sender<()>);

impl Mailbox {
    pub fn new() -> (Self, ring::Receiver<()>) {
        let (sender, receiver) = ring::channel(NZUsize!(1));
        (Self(sender), receiver)
    }

    /// Ends the connection without blocking.
    pub fn kill(&self) {
        let _ = self.0.send_lossy(());
    }
}

impl Clone for Mailbox {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Mailbox").finish()
    }
}
