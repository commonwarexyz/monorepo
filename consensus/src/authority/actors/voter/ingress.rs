use crate::authority::{wire, Context, View};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    Proposed {
        context: Context,
        payload: Digest,
    },
    Verified {
        context: Context,
        result: bool,
    },
    Backfilled {
        notarizations: Vec<wire::Notarization>,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn proposed(&mut self, context: Context, payload: Digest) {
        self.sender
            .send(Message::Proposed { context, payload })
            .await
            .unwrap();
    }

    pub async fn verified(&mut self, context: Context, result: bool) {
        self.sender
            .send(Message::Verified { context, result })
            .await
            .unwrap();
    }

    pub(crate) async fn backfilled(&mut self, notarizations: Vec<wire::Notarization>) {
        self.sender
            .send(Message::Backfilled { notarizations })
            .await
            .unwrap();
    }
}

pub enum ApplicationMessage {
    Propose { context: Context },
    Verify { context: Context, payload: Digest },
}

pub struct Application {
    sender: mpsc::Sender<ApplicationMessage>,
}

impl Application {
    pub(super) fn new(sender: mpsc::Sender<ApplicationMessage>) -> Self {
        Self { sender }
    }

    pub async fn propose(&mut self, context: Context) {
        self.sender
            .send(ApplicationMessage::Propose { context })
            .await
            .unwrap();
    }

    pub async fn verify(&mut self, context: Context, payload: Digest) {
        self.sender
            .send(ApplicationMessage::Verify { context, payload })
            .await
            .unwrap();
    }
}
