use crate::{authority::wire, Hash, Height, View};
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
        votes: Vec<wire::Vote>,
        finalizes: Vec<wire::Finalize>,
        faults: Vec<wire::Fault>,
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
        votes: Vec<wire::Vote>,
        finalizes: Vec<wire::Finalize>,
        faults: Vec<wire::Fault>,
    ) {
        self.sender
            .send(Message::Proposal {
                view,
                parent,
                height,
                payload,
                payload_hash,
                votes,
                finalizes,
                faults,
            })
            .await
            .unwrap();
    }

    pub async fn verified(&mut self, view: View) {
        self.sender.send(Message::Verified { view }).await.unwrap();
    }
}
