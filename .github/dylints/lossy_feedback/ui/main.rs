enum Feedback {
    Ok,
    Backoff,
    Closed,
}

enum Lossy<T> {
    Handled(T),
    Rejected,
}

mod mailbox {
    use super::{Feedback, Lossy};
    use std::marker::PhantomData;

    pub trait Policy: Sized {
        type Overflow;

        fn handle(overflow: &mut Self::Overflow, message: Self) -> bool;
    }

    pub struct Sender<T>(PhantomData<T>);

    impl<T> Sender<T> {
        pub fn enqueue(&self, _message: T) -> Feedback {
            Feedback::Ok
        }

        pub fn enqueue_lossy(&self, _message: T) -> Lossy<Feedback> {
            Lossy::Handled(Feedback::Ok)
        }
    }
}

struct ReliableMessage;

impl mailbox::Policy for ReliableMessage {
    type Overflow = ();

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        true
    }
}

struct LossyMessage;

impl mailbox::Policy for LossyMessage {
    type Overflow = ();

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

enum MixedMessage {
    Content,
    Release,
}

impl mailbox::Policy for MixedMessage {
    type Overflow = Vec<MixedMessage>;

    fn handle(overflow: &mut Self::Overflow, message: Self) -> bool {
        match message {
            Self::Content => false,
            message => {
                overflow.push(message);
                true
            }
        }
    }
}

struct Mailbox {
    reliable: mailbox::Sender<ReliableMessage>,
    lossy: mailbox::Sender<LossyMessage>,
    mixed: mailbox::Sender<MixedMessage>,
}

impl Mailbox {
    fn allowed_reliable(&self, message: ReliableMessage) -> Feedback {
        self.reliable.enqueue(message)
    }

    fn bad_lossy(&self, message: LossyMessage) -> Feedback {
        self.lossy.enqueue(message)
    }

    fn good_lossy(&self, message: LossyMessage) -> Lossy<Feedback> {
        self.lossy.enqueue_lossy(message)
    }

    fn bad_content(&self) -> Feedback {
        self.mixed.enqueue(MixedMessage::Content)
    }

    fn allowed_release(&self) -> Feedback {
        self.mixed.enqueue(MixedMessage::Release)
    }

    fn ignored(&self, message: LossyMessage) {
        let _ = self.lossy.enqueue(message);
    }
}

fn main() {}
