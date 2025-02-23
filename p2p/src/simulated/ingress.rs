use super::{Error, Receiver, Sender};
use crate::Channel;
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use rand_distr::Normal;

pub enum Message<P: Array> {
    Register {
        public_key: P,
        channel: Channel,
        #[allow(clippy::type_complexity)]
        result: oneshot::Sender<Result<(Sender<P>, Receiver<P>), Error>>,
    },
    AddLink {
        sender: P,
        receiver: P,
        sampler: Normal<f64>,
        success_rate: f64,
        result: oneshot::Sender<Result<(), Error>>,
    },
    RemoveLink {
        sender: P,
        receiver: P,
        result: oneshot::Sender<Result<(), Error>>,
    },
}

/// Describes a connection between two peers.
///
/// Links are unidirectional (and must be set up in both directions
/// for a bidirectional connection).
#[derive(Clone)]
pub struct Link {
    /// Mean latency for the delivery of a message in milliseconds.
    pub latency: f64,

    /// Standard deviation of the latency for the delivery of a message in milliseconds.
    pub jitter: f64,

    /// Probability of a message being delivered successfully (in range \[0,1\]).
    pub success_rate: f64,
}

/// Interface for modifying the simulated network.
///
/// At any point, peers can be added/removed and links
/// between said peers can be modified.
#[derive(Clone)]
pub struct Oracle<P: Array> {
    sender: mpsc::UnboundedSender<Message<P>>,
}

impl<P: Array> Oracle<P> {
    pub(crate) fn new(sender: mpsc::UnboundedSender<Message<P>>) -> Self {
        Self { sender }
    }

    /// Register a new peer with the network that can interact over a given channel.
    ///
    /// By default, the peer will not be linked to any other peers. If a peer is already
    /// registered on a given channel, it will return an error.
    pub async fn register(
        &mut self,
        public_key: P,
        channel: Channel,
    ) -> Result<(Sender<P>, Receiver<P>), Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Register {
                public_key,
                channel,
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
    pub async fn add_link(&mut self, sender: P, receiver: P, config: Link) -> Result<(), Error> {
        // Sanity checks
        if sender == receiver {
            return Err(Error::LinkingSelf);
        }
        if config.success_rate < 0.0 || config.success_rate > 1.0 {
            return Err(Error::InvalidSuccessRate(config.success_rate));
        }
        if config.latency < 0.0 || config.jitter < 0.0 {
            return Err(Error::InvalidBehavior(config.latency, config.jitter));
        }

        // Create distribution
        let sampler = Normal::new(config.latency, config.jitter)
            .map_err(|_| Error::InvalidBehavior(config.latency, config.jitter))?;

        // Wait for update to complete
        let (s, r) = oneshot::channel();
        self.sender
            .send(Message::AddLink {
                sender,
                receiver,
                sampler,
                success_rate: config.success_rate,
                result: s,
            })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        r.await.map_err(|_| Error::NetworkClosed)?
    }

    /// Remove a unidirectional link between two peers.
    ///
    /// If no link exists, this will return an error.
    pub async fn remove_link(&mut self, sender: P, receiver: P) -> Result<(), Error> {
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
