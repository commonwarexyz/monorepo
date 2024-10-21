use crate::{Hash, Height, View};
use bytes::Bytes;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    Proposal {
        view: View,
        parent: Hash,
        height: Height,
        payload: Bytes,
        payload_hash: Hash,
    },
    ProposalFailed {
        view: View,
    },
    Verified {
        view: View,
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

    pub async fn proposal(
        &mut self,
        view: View,
        parent: Hash,
        height: Height,
        payload: Bytes,
        payload_hash: Hash,
    ) {
        self.sender
            .send(Message::Proposal {
                view,
                parent,
                height,
                payload,
                payload_hash,
            })
            .await
            .unwrap();
    }

    pub async fn proposal_failed(&mut self, view: View) {
        self.sender
            .send(Message::ProposalFailed { view })
            .await
            .unwrap();
    }

    pub async fn verified(&mut self, view: View) {
        self.sender.send(Message::Verified { view }).await.unwrap();
    }
}
