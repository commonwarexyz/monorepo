use super::{Channel, Error, Link, Receiver, Sender};
use commonware_cryptography::PublicKey;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};

pub enum Message {
    Register {
        public_key: PublicKey,
        channel: Channel,
        max_size: usize,
        result: oneshot::Sender<Result<(Sender, Receiver), Error>>,
    },
    Deregister {
        public_key: PublicKey,
        result: oneshot::Sender<Result<(), Error>>,
    },
    AddLink {
        sender: PublicKey,
        receiver: PublicKey,
        config: Link,
        result: oneshot::Sender<()>,
    },
    RemoveLink {
        sender: PublicKey,
        receiver: PublicKey,
        result: oneshot::Sender<Result<(), Error>>,
    },
}

pub struct Oracle {
    sender: mpsc::UnboundedSender<Message>,
}

impl Oracle {
    pub(crate) fn new(sender: mpsc::UnboundedSender<Message>) -> Self {
        Self { sender }
    }

    /// Register a new peer with the network that can interact over a given channel.
    ///
    /// By default, the peer will not be linked to any other peers. If a peer is already
    /// registered on a given channel, it will return an error.
    pub async fn register(
        &mut self,
        public_key: PublicKey,
        channel: Channel,
        max_size: usize,
    ) -> Result<(Sender, Receiver), Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Register {
                public_key,
                channel,
                max_size,
                result: sender,
            })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)?
    }

    /// Deregister a peer from the network.
    ///
    /// If the peer is not registered, this will return an error.
    pub async fn deregister(&mut self, public_key: PublicKey) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Deregister {
                public_key,
                result: sender,
            })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)?
    }

    /// Create a unidirectional link between two peers.
    ///
    /// Link can be called multiple times for the same sender/receiver. The latest
    /// setting will be used.
    pub async fn add_link(
        &mut self,
        sender: PublicKey,
        receiver: PublicKey,
        config: Link,
    ) -> Result<(), Error> {
        // Sanity checks
        if sender == receiver {
            return Err(Error::LinkingSelf);
        }
        if config.success_rate < 0.0 || config.success_rate > 1.0 {
            return Err(Error::InvalidSuccessRate(config.success_rate));
        }

        // Wait for update to complete
        let (s, r) = oneshot::channel();
        self.sender
            .send(Message::AddLink {
                sender,
                receiver,
                config,
                result: s,
            })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        r.await.map_err(|_| Error::NetworkClosed)
    }

    /// Remove a unidirectional link between two peers.
    ///
    /// If no link exists, this will return an error.
    pub async fn remove_link(
        &mut self,
        sender: PublicKey,
        receiver: PublicKey,
    ) -> Result<(), Error> {
        // Sanity checks
        if sender == receiver {
            return Err(Error::LinkingSelf);
        }

        // Wait for update to complete
        let (s, r) = oneshot::channel();
        self.sender
            .send(Message::RemoveLink {
                sender,
                receiver,
                result: s,
            })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        r.await.map_err(|_| Error::NetworkClosed)?
    }
}
