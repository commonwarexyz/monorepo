use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Notarization, Nullification},
    },
    types::View,
};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

pub enum Message<S: Scheme, D: Digest> {
    Fetch {
        notarizations: Vec<View>,
        nullifications: Vec<View>,
    },
    Notarized {
        notarization: Notarization<S, D>,
    },
    Nullified {
        nullification: Nullification<S>,
    },
    Finalized {
        // Used to indicate when to prune old notarizations/nullifications.
        view: View,
    },
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn fetch(&mut self, notarizations: Vec<View>, nullifications: Vec<View>) {
        if let Err(e) = self
            .sender
            .send(Message::Fetch {
                notarizations,
                nullifications,
            })
            .await
        {
            error!(error = %e, "failed to send fetch message");
        }
    }

    pub async fn notarized(&mut self, notarization: Notarization<S, D>) {
        if let Err(e) = self.sender.send(Message::Notarized { notarization }).await {
            error!(error = %e, "failed to send notarization message");
        }
    }

    pub async fn nullified(&mut self, nullification: Nullification<S>) {
        if let Err(e) = self.sender.send(Message::Nullified { nullification }).await {
            error!(error = %e, "failed to send nullification message");
        }
    }

    pub async fn finalized(&mut self, view: View) {
        if let Err(e) = self.sender.send(Message::Finalized { view }).await {
            error!(error = %e, "failed to send finalized view message");
        }
    }
}
