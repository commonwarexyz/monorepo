use super::{Error, Receiver, Sender};
use crate::{authenticated::UnboundedMailbox, Address, Channel};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Quota};
use commonware_utils::{
    channel::{fallible::FallibleExt, mpsc, oneshot, ring},
    ordered::{Map, Set},
};
use rand_distr::Normal;
use std::time::Duration;

pub enum Message<P: PublicKey, E: Clock> {
    Register {
        channel: Channel,
        public_key: P,
        quota: Quota,
        #[allow(clippy::type_complexity)]
        result: oneshot::Sender<Result<(Sender<P, E>, Receiver<P>), Error>>,
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
    SubscribeConnected {
        response: oneshot::Sender<ring::Receiver<Vec<P>>>,
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

impl<P: PublicKey, E: Clock> std::fmt::Debug for Message<P, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register { .. } => f.debug_struct("Register").finish_non_exhaustive(),
            Self::Update { id, .. } => f
                .debug_struct("Update")
                .field("id", id)
                .finish_non_exhaustive(),
            Self::PeerSet { id, .. } => f
                .debug_struct("PeerSet")
                .field("id", id)
                .finish_non_exhaustive(),
            Self::Subscribe { .. } => f.debug_struct("Subscribe").finish_non_exhaustive(),
            Self::SubscribeConnected { .. } => {
                f.debug_struct("SubscribeConnected").finish_non_exhaustive()
            }
            Self::LimitBandwidth { .. } => f.debug_struct("LimitBandwidth").finish_non_exhaustive(),
            Self::AddLink { .. } => f.debug_struct("AddLink").finish_non_exhaustive(),
            Self::RemoveLink { .. } => f.debug_struct("RemoveLink").finish_non_exhaustive(),
            Self::Block { from, to } => f
                .debug_struct("Block")
                .field("from", from)
                .field("to", to)
                .finish(),
            Self::Blocked { .. } => f.debug_struct("Blocked").finish_non_exhaustive(),
        }
    }
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
#[derive(Debug)]
pub struct Oracle<P: PublicKey, E: Clock> {
    sender: UnboundedMailbox<Message<P, E>>,
}

impl<P: PublicKey, E: Clock> Clone for Oracle<P, E> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<P: PublicKey, E: Clock> Oracle<P, E> {
    /// Create a new instance of the oracle.
    pub(crate) const fn new(sender: UnboundedMailbox<Message<P, E>>) -> Self {
        Self { sender }
    }

    /// Create a new [Control] interface for some peer.
    pub fn control(&self, me: P) -> Control<P, E> {
        Control {
            me,
            sender: self.sender.clone(),
        }
    }

    /// Create a new [Manager].
    ///
    /// Useful for mocking [crate::authenticated::discovery].
    pub fn manager(&self) -> Manager<P, E> {
        Manager {
            oracle: self.clone(),
        }
    }

    /// Create a new [SocketManager].
    ///
    /// Useful for mocking [crate::authenticated::lookup].
    pub fn socket_manager(&self) -> SocketManager<P, E> {
        SocketManager {
            oracle: self.clone(),
        }
    }

    /// Return a list of all blocked peers.
    pub async fn blocked(&self) -> Result<Vec<(P, P)>, Error> {
        self.sender
            .0
            .request(|result| Message::Blocked { result })
            .await
            .ok_or(Error::NetworkClosed)?
    }

    /// Set bandwidth limits for a peer.
    ///
    /// Bandwidth is specified for the peer's egress (upload) and ingress (download)
    /// rates in bytes per second. Use `None` for unlimited bandwidth.
    ///
    /// Bandwidth can be specified before a peer is registered or linked.
    pub async fn limit_bandwidth(
        &self,
        public_key: P,
        egress_cap: Option<usize>,
        ingress_cap: Option<usize>,
    ) -> Result<(), Error> {
        self.sender
            .0
            .request(|result| Message::LimitBandwidth {
                public_key,
                egress_cap,
                ingress_cap,
                result,
            })
            .await
            .ok_or(Error::NetworkClosed)
    }

    /// Create a unidirectional link between two peers.
    ///
    /// Link can be called multiple times for the same sender/receiver. The latest
    /// setting will be used.
    ///
    /// Link can be called before a peer is registered or bandwidth is specified.
    pub async fn add_link(&self, sender: P, receiver: P, config: Link) -> Result<(), Error> {
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

        self.sender
            .0
            .request(|result| Message::AddLink {
                sender,
                receiver,
                sampler,
                success_rate: config.success_rate,
                result,
            })
            .await
            .ok_or(Error::NetworkClosed)?
    }

    /// Remove a unidirectional link between two peers.
    ///
    /// If no link exists, this will return an error.
    pub async fn remove_link(&self, sender: P, receiver: P) -> Result<(), Error> {
        // Sanity checks
        if sender == receiver {
            return Err(Error::LinkingSelf);
        }

        self.sender
            .0
            .request(|result| Message::RemoveLink {
                sender,
                receiver,
                result,
            })
            .await
            .ok_or(Error::NetworkClosed)?
    }

    /// Set the peers for a given id.
    async fn register(&self, id: u64, peers: Set<P>) {
        self.sender.0.send_lossy(Message::Update { id, peers });
    }

    /// Get the peers for a given id.
    async fn peer_set(&self, id: u64) -> Option<Set<P>> {
        self.sender
            .0
            .request(|response| Message::PeerSet { id, response })
            .await
            .flatten()
    }

    /// Subscribe to notifications when new peer sets are added.
    async fn subscribe(&self) -> mpsc::UnboundedReceiver<(u64, Set<P>, Set<P>)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.sender.0.send_lossy(Message::Subscribe { sender });
        receiver
    }
}

/// Implementation of [crate::Manager] for peers.
///
/// Useful for mocking [crate::authenticated::discovery].
pub struct Manager<P: PublicKey, E: Clock> {
    /// The oracle to send messages to.
    oracle: Oracle<P, E>,
}

impl<P: PublicKey, E: Clock> std::fmt::Debug for Manager<P, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manager").finish_non_exhaustive()
    }
}

impl<P: PublicKey, E: Clock> Clone for Manager<P, E> {
    fn clone(&self) -> Self {
        Self {
            oracle: self.oracle.clone(),
        }
    }
}

impl<P: PublicKey, E: Clock> crate::Provider for Manager<P, E> {
    type PublicKey = P;

    async fn peer_set(&mut self, id: u64) -> Option<Set<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(
        &mut self,
    ) -> mpsc::UnboundedReceiver<(u64, Set<Self::PublicKey>, Set<Self::PublicKey>)> {
        self.oracle.subscribe().await
    }
}

impl<P: PublicKey, E: Clock> crate::Manager for Manager<P, E> {
    async fn register(&mut self, id: u64, peers: Set<Self::PublicKey>) {
        self.oracle.register(id, peers).await;
    }
}

/// Implementation of [crate::AddressableManager] for peers with [Address]es.
///
/// Useful for mocking [crate::authenticated::lookup].
///
/// # Note on [Address]
///
/// Because addresses are never exposed in [crate::simulated],
/// there is nothing to assert submitted data against. We thus consider
/// all addresses to be valid.
pub struct SocketManager<P: PublicKey, E: Clock> {
    /// The oracle to send messages to.
    oracle: Oracle<P, E>,
}

impl<P: PublicKey, E: Clock> std::fmt::Debug for SocketManager<P, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketManager").finish_non_exhaustive()
    }
}

impl<P: PublicKey, E: Clock> Clone for SocketManager<P, E> {
    fn clone(&self) -> Self {
        Self {
            oracle: self.oracle.clone(),
        }
    }
}

impl<P: PublicKey, E: Clock> crate::Provider for SocketManager<P, E> {
    type PublicKey = P;

    async fn peer_set(&mut self, id: u64) -> Option<Set<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(
        &mut self,
    ) -> mpsc::UnboundedReceiver<(u64, Set<Self::PublicKey>, Set<Self::PublicKey>)> {
        self.oracle.subscribe().await
    }
}

impl<P: PublicKey, E: Clock> crate::AddressableManager for SocketManager<P, E> {
    async fn register(&mut self, id: u64, peers: Map<Self::PublicKey, Address>) {
        // Ignore all addresses (simulated network doesn't use them)
        self.oracle.register(id, peers.into_keys()).await;
    }

    async fn overwrite(&mut self, _peers: Map<Self::PublicKey, Address>) {
        // We consider all addresses to be valid, so this is a no-op
    }
}

/// Individual control interface for a peer in the simulated network.
#[derive(Debug)]
pub struct Control<P: PublicKey, E: Clock> {
    /// The public key of the peer this control interface is for.
    me: P,

    /// Sender for messages to the oracle.
    sender: UnboundedMailbox<Message<P, E>>,
}

impl<P: PublicKey, E: Clock> Clone for Control<P, E> {
    fn clone(&self) -> Self {
        Self {
            me: self.me.clone(),
            sender: self.sender.clone(),
        }
    }
}

impl<P: PublicKey, E: Clock> Control<P, E> {
    /// Register the communication interfaces for the peer over a given [Channel].
    ///
    /// # Rate Limiting
    ///
    /// The `quota` parameter specifies the rate limit for outbound messages to each peer.
    /// Recipients that exceed their rate limit will be skipped when sending.
    pub async fn register(
        &self,
        channel: Channel,
        quota: Quota,
    ) -> Result<(Sender<P, E>, Receiver<P>), Error> {
        let public_key = self.me.clone();
        self.sender
            .0
            .request(|result| Message::Register {
                channel,
                public_key,
                quota,
                result,
            })
            .await
            .ok_or(Error::NetworkClosed)?
    }
}

impl<P: PublicKey, E: Clock> crate::Blocker for Control<P, E> {
    type PublicKey = P;

    async fn block(&mut self, public_key: P) {
        self.sender.0.send_lossy(Message::Block {
            from: self.me.clone(),
            to: public_key,
        });
    }
}
