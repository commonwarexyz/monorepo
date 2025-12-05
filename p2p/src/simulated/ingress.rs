use super::{Error, Receiver, Sender};
use crate::Channel;
use commonware_cryptography::PublicKey;
use commonware_utils::ordered::{Map, Set};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use rand_distr::Normal;
use std::{net::SocketAddr, time::Duration};

pub enum Message<P: PublicKey> {
    Register {
        channel: Channel,
        public_key: P,
        #[allow(clippy::type_complexity)]
        result: oneshot::Sender<Result<(Sender<P>, Receiver<P>), Error>>,
    },
    Update {
        id: u64,
        peers: Set<P>,
    },
    PeerSet {
        id: u64,
        response: oneshot::Sender<Option<Set<P>>>,
    },
    Subscribe {
        sender: mpsc::UnboundedSender<(u64, Set<P>, Set<P>)>,
    },
    LimitBandwidth {
        public_key: P,
        egress_cap: Option<usize>,
        ingress_cap: Option<usize>,
        result: oneshot::Sender<()>,
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
    Block {
        /// The public key of the peer sending the block request.
        from: P,
        /// The public key of the peer to block.
        to: P,
    },
    Blocked {
        result: oneshot::Sender<Result<Vec<(P, P)>, Error>>,
    },
}

/// Describes a connection between two peers.
///
/// Links are unidirectional (and must be set up in both directions
/// for a bidirectional connection).
#[derive(Clone)]
pub struct Link {
    /// Mean latency for the delivery of a message.
    pub latency: Duration,

    /// Standard deviation of the latency for the delivery of a message.
    pub jitter: Duration,

    /// Probability of a message being delivered successfully (in range \[0,1\]).
    pub success_rate: f64,
}

/// Interface for modifying the simulated network.
///
/// At any point, peers can be added/removed and links
/// between said peers can be modified.
#[derive(Debug, Clone)]
pub struct Oracle<P: PublicKey> {
    sender: mpsc::UnboundedSender<Message<P>>,
}

impl<P: PublicKey> Oracle<P> {
    /// Create a new instance of the oracle.
    pub(crate) const fn new(sender: mpsc::UnboundedSender<Message<P>>) -> Self {
        Self { sender }
    }

    /// Create a new [Control] interface for some peer.
    pub fn control(&self, me: P) -> Control<P> {
        Control {
            me,
            sender: self.sender.clone(),
        }
    }

    /// Create a new [Manager].
    ///
    /// Useful for mocking [crate::authenticated::discovery].
    pub fn manager(&self) -> Manager<P> {
        Manager {
            oracle: self.clone(),
        }
    }

    /// Create a new [SocketManager].
    ///
    /// Useful for mocking [crate::authenticated::lookup].
    pub fn socket_manager(&self) -> SocketManager<P> {
        SocketManager {
            oracle: self.clone(),
        }
    }

    /// Return a list of all blocked peers.
    pub async fn blocked(&mut self) -> Result<Vec<(P, P)>, Error> {
        let (s, r) = oneshot::channel();
        self.sender
            .send(Message::Blocked { result: s })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        r.await.map_err(|_| Error::NetworkClosed)?
    }

    /// Set bandwidth limits for a peer.
    ///
    /// Bandwidth is specified for the peer's egress (upload) and ingress (download)
    /// rates in bytes per second. Use `None` for unlimited bandwidth.
    ///
    /// Bandwidth can be specified before a peer is registered or linked.
    pub async fn limit_bandwidth(
        &mut self,
        public_key: P,
        egress_cap: Option<usize>,
        ingress_cap: Option<usize>,
    ) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::LimitBandwidth {
                public_key,
                egress_cap,
                ingress_cap,
                result: sender,
            })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        receiver.await.map_err(|_| Error::NetworkClosed)
    }

    /// Create a unidirectional link between two peers.
    ///
    /// Link can be called multiple times for the same sender/receiver. The latest
    /// setting will be used.
    ///
    /// Link can be called before a peer is registered or bandwidth is specified.
    pub async fn add_link(&mut self, sender: P, receiver: P, config: Link) -> Result<(), Error> {
        // Sanity checks
        if sender == receiver {
            return Err(Error::LinkingSelf);
        }
        if config.success_rate < 0.0 || config.success_rate > 1.0 {
            return Err(Error::InvalidSuccessRate(config.success_rate));
        }

        // Convert Duration to milliseconds as f64 for the Normal distribution
        let latency_ms = config.latency.as_secs_f64() * 1000.0;
        let jitter_ms = config.jitter.as_secs_f64() * 1000.0;

        // Create distribution
        let sampler = Normal::new(latency_ms, jitter_ms).unwrap();

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

    /// Set the peers for a given id.
    async fn update(&mut self, id: u64, peers: Set<P>) {
        let _ = self.sender.send(Message::Update { id, peers }).await;
    }

    /// Get the peers for a given id.
    async fn peer_set(&mut self, id: u64) -> Option<Set<P>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::PeerSet {
                id,
                response: sender,
            })
            .await
            .ok()?;
        receiver.await.ok().flatten()
    }

    /// Subscribe to notifications when new peer sets are added.
    async fn subscribe(&mut self) -> mpsc::UnboundedReceiver<(u64, Set<P>, Set<P>)> {
        let (sender, receiver) = mpsc::unbounded();
        let _ = self.sender.send(Message::Subscribe { sender }).await;
        receiver
    }
}

/// Implementation of [crate::Manager] for peers.
///
/// Useful for mocking [crate::authenticated::discovery].
#[derive(Debug, Clone)]
pub struct Manager<P: PublicKey> {
    /// The oracle to send messages to.
    oracle: Oracle<P>,
}

impl<P: PublicKey> crate::Manager for Manager<P> {
    type PublicKey = P;
    type Peers = Set<Self::PublicKey>;

    async fn update(&mut self, id: u64, peers: Self::Peers) {
        self.oracle.update(id, peers).await;
    }

    async fn peer_set(&mut self, id: u64) -> Option<Set<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(
        &mut self,
    ) -> mpsc::UnboundedReceiver<(u64, Set<Self::PublicKey>, Set<Self::PublicKey>)> {
        self.oracle.subscribe().await
    }
}

/// Implementation of [crate::Manager] for peers with [SocketAddr]s.
///
/// Useful for mocking [crate::authenticated::lookup].
///
/// # Note on [SocketAddr]
///
/// Because [SocketAddr]s are never exposed in [crate::simulated],
/// there is nothing to assert submitted data against. We thus consider
/// all [SocketAddr]s to be valid.
#[derive(Debug, Clone)]
pub struct SocketManager<P: PublicKey> {
    /// The oracle to send messages to.
    oracle: Oracle<P>,
}

impl<P: PublicKey> crate::Manager for SocketManager<P> {
    type PublicKey = P;
    type Peers = Map<Self::PublicKey, SocketAddr>;

    async fn update(&mut self, id: u64, peers: Self::Peers) {
        // Ignore all SocketAddrs
        self.oracle.update(id, peers.into_keys()).await;
    }

    async fn peer_set(&mut self, id: u64) -> Option<Set<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(
        &mut self,
    ) -> mpsc::UnboundedReceiver<(u64, Set<Self::PublicKey>, Set<Self::PublicKey>)> {
        self.oracle.subscribe().await
    }
}

/// Individual control interface for a peer in the simulated network.
#[derive(Debug, Clone)]
pub struct Control<P: PublicKey> {
    /// The public key of the peer this control interface is for.
    me: P,

    /// Sender for messages to the oracle.
    sender: mpsc::UnboundedSender<Message<P>>,
}

impl<P: PublicKey> Control<P> {
    /// Register the communication interfaces for the peer over a given [Channel].
    pub async fn register(&mut self, channel: Channel) -> Result<(Sender<P>, Receiver<P>), Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Message::Register {
                channel,
                public_key: self.me.clone(),
                result: tx,
            })
            .await
            .map_err(|_| Error::NetworkClosed)?;
        rx.await.map_err(|_| Error::NetworkClosed)?
    }
}

impl<P: PublicKey> crate::Blocker for Control<P> {
    type PublicKey = P;

    async fn block(&mut self, public_key: P) {
        let _ = self
            .sender
            .send(Message::Block {
                from: self.me.clone(),
                to: public_key,
            })
            .await;
    }
}
