use super::{ingress::Mailbox, Message};
use futures::channel::mpsc;

pub struct Actor {
    mailbox_receiver: mpsc::Receiver<Message>,
}

impl Actor {
    pub fn new() -> (Self, Mailbox) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Self {
                mailbox_receiver: receiver,
            },
            Mailbox::new(sender),
        )
    }
}
