pub mod discovery;
pub mod lookup;
mod peer_info;
use futures::channel::mpsc;
use peer_info::PeerInfo;

// TODO danlaine: remove this and just use sender directly
/// A mailbox for sending messages to an actor.
#[derive(Clone, Debug)]
pub struct Mailbox<T>(mpsc::Sender<T>);

impl<T> Mailbox<T> {
    fn new(sender: mpsc::Sender<T>) -> Self {
        Self(sender)
    }

    /// Returns a new mailbox and a receiver for testing purposes.
    /// The capacity of the channel is 1.
    #[cfg(test)]
    pub fn test() -> (Self, mpsc::Receiver<T>) {
        let (sender, receiver) = mpsc::channel(1);
        (Self(sender), receiver)
    }
}
