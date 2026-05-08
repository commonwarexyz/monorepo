use super::{Error, Receiver, Sender};
use crate::{
    authenticated::Mailbox, Address, AddressableTrackedPeers, Channel, PeerSetSubscription,
    TrackedPeers,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Quota};
use commonware_utils::{
    channel::{
        actor::{self, Backpressure, MessagePolicy}, Feedback,
        oneshot, ring,
    },
    ordered::Map,
    NZUsize,
};
use rand_distr::Normal;
use std::{collections::VecDeque, time::Duration};

pub enum Message<P: PublicKey, E: Clock> {
    Register {
        channel: Channel,
        public_key: P,
        quota: Quota,
        #[allow(clippy::type_complexity)]
        result: oneshot::Sender<Result<(Sender<P, E>, Receiver<P>), Error>>,
    },
    Track {
        id: u64,
        peers: TrackedPeers<P>,
    },
    PeerSet {
        id: u64,
        response: oneshot::Sender<Option<TrackedPeers<P>>>,
    },
    Subscribe {
        response: oneshot::Sender<PeerSetSubscription<P>>,
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
            Self::Track { id, .. } => f
                .debug_struct("Track")
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

impl<P: PublicKey, E: Clock> MessagePolicy for Message<P, E> {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        Backpressure::replace_or_retain(match message {
            Self::Track { id, peers } => actor::replace_last(
                queue,
                Self::Track { id, peers },
                |pending| matches!(pending, Self::Track { id: pending, .. } if *pending == id),
            ),
            Self::LimitBandwidth {
                public_key,
                egress_cap,
                ingress_cap,
                result,
            } => {
                let expected = public_key.clone();
                actor::replace_last(
                    queue,
                    Self::LimitBandwidth {
                        public_key,
                        egress_cap,
                        ingress_cap,
                        result,
                    },
                    |pending| matches!(pending, Self::LimitBandwidth { public_key: pending, .. } if pending == &expected),
                )
            }
            Self::AddLink {
                sender,
                receiver,
                sampler,
                success_rate,
                result,
            } => {
                let expected_sender = sender.clone();
                let expected_receiver = receiver.clone();
                actor::replace_last(
                    queue,
                    Self::AddLink {
                        sender,
                        receiver,
                        sampler,
                        success_rate,
                        result,
                    },
                    |pending| matches!(pending, Self::AddLink { sender, receiver, .. } if sender == &expected_sender && receiver == &expected_receiver),
                )
            }
            Self::RemoveLink {
                sender,
                receiver,
                result,
            } => {
                let expected_sender = sender.clone();
                let expected_receiver = receiver.clone();
                actor::replace_last(
                    queue,
                    Self::RemoveLink {
                        sender,
                        receiver,
                        result,
                    },
                    |pending| matches!(pending, Self::RemoveLink { sender, receiver, .. } if sender == &expected_sender && receiver == &expected_receiver),
                )
            }
            Self::Block { from, to } => {
                let expected_from = from.clone();
                let expected_to = to.clone();
                actor::replace_last(
                    queue,
                    Self::Block { from, to },
                    |pending| matches!(pending, Self::Block { from, to } if from == &expected_from && to == &expected_to),
                )
            }
            message => Err(message),
        }, queue)
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
    sender: Mailbox<Message<P, E>>,
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
    pub(crate) const fn new(sender: Mailbox<Message<P, E>>) -> Self {
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
        let (result, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::Blocked { result }) {
            Feedback::Ok | Feedback::Backoff => {
                receiver.await.map_err(|_| Error::NetworkClosed)?
            }
            Feedback::Dropped | Feedback::Closed => Err(Error::NetworkClosed),
        }
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
        let (result, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::LimitBandwidth {
            public_key,
            egress_cap,
            ingress_cap,
            result,
        }) {
            Feedback::Ok | Feedback::Backoff => {
                receiver.await.map_err(|_| Error::NetworkClosed)
            }
            Feedback::Dropped | Feedback::Closed => Err(Error::NetworkClosed),
        }
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

        let (result, result_receiver) = oneshot::channel();
        match self.sender.enqueue(Message::AddLink {
            sender,
            receiver,
            sampler,
            success_rate: config.success_rate,
            result,
        }) {
            Feedback::Ok | Feedback::Backoff => {
                result_receiver.await.map_err(|_| Error::NetworkClosed)?
            }
            Feedback::Dropped | Feedback::Closed => Err(Error::NetworkClosed),
        }
    }

    /// Remove a unidirectional link between two peers.
    ///
    /// If no link exists, this will return an error.
    pub async fn remove_link(&self, sender: P, receiver: P) -> Result<(), Error> {
        // Sanity checks
        if sender == receiver {
            return Err(Error::LinkingSelf);
        }

        let (result, result_receiver) = oneshot::channel();
        match self.sender.enqueue(Message::RemoveLink {
            sender,
            receiver,
            result,
        }) {
            Feedback::Ok | Feedback::Backoff => {
                result_receiver.await.map_err(|_| Error::NetworkClosed)?
            }
            Feedback::Dropped | Feedback::Closed => Err(Error::NetworkClosed),
        }
    }

    /// Set the peers for a given id.
    fn track(&self, id: u64, peers: TrackedPeers<P>) -> Feedback {
        self.sender.enqueue(Message::Track { id, peers })
    }

    /// Get the primary and secondary peers for a given ID.
    async fn peer_set(&self, id: u64) -> Option<TrackedPeers<P>> {
        let (response, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::PeerSet { id, response }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.ok().flatten(),
            Feedback::Dropped | Feedback::Closed => None,
        }
    }

    /// Subscribe to notifications when new peer sets are added.
    async fn subscribe(&self) -> PeerSetSubscription<P> {
        let (response, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::Subscribe { response }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.unwrap_or_else(|_| {
                let (_, rx) = ring::channel(NZUsize!(1));
                rx
            }),
            Feedback::Dropped | Feedback::Closed => {
                let (_, rx) = ring::channel(NZUsize!(1));
                rx
            }
        }
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

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        self.oracle.subscribe().await
    }
}

impl<P: PublicKey, E: Clock> crate::Manager for Manager<P, E> {
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<Self::PublicKey>>,
    {
        self.oracle.track(id, peers.into())
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

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<P> {
        self.oracle.subscribe().await
    }
}

impl<P: PublicKey, E: Clock> crate::AddressableManager for SocketManager<P, E> {
    fn track<R>(
        &mut self,
        id: u64,
        peers: R,
    ) -> Feedback
    where
        R: Into<AddressableTrackedPeers<Self::PublicKey>>,
    {
        // Ignore all addresses (simulated network doesn't use them)
        let peers = peers.into();
        self.oracle.track(
            id,
            TrackedPeers::new(peers.primary.into_keys(), peers.secondary.into_keys()),
        )
    }

    fn overwrite(
        &mut self,
        _peers: Map<Self::PublicKey, Address>,
    ) -> Feedback {
        // We consider all addresses to be valid, so this is a no-op
        Feedback::Ok
    }
}

/// Individual control interface for a peer in the simulated network.
#[derive(Debug)]
pub struct Control<P: PublicKey, E: Clock> {
    /// The public key of the peer this control interface is for.
    me: P,

    /// Sender for messages to the oracle.
    sender: Mailbox<Message<P, E>>,
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
        let (result, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::Register {
            channel,
            public_key,
            quota,
            result,
        }) {
            Feedback::Ok | Feedback::Backoff => {
                receiver.await.map_err(|_| Error::NetworkClosed)?
            }
            Feedback::Dropped | Feedback::Closed => Err(Error::NetworkClosed),
        }
    }
}

impl<P: PublicKey, E: Clock> crate::Blocker for Control<P, E> {
    type PublicKey = P;

    fn block(&mut self, public_key: P) -> Feedback {
        self.sender.enqueue(Message::Block {
            from: self.me.clone(),
            to: public_key,
        })
    }
}
