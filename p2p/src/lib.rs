//! Communicate with authenticated peers over encrypted connections.
//!
//! # Status
//!
//! `commonware-p2p` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Error as RuntimeError, Resolver};
use commonware_utils::set::Ordered;
use futures::channel::mpsc;
use std::{error::Error as StdError, fmt::Debug, future::Future, net::SocketAddr};

pub mod authenticated;
pub mod simulated;
pub mod utils;

/// A socket address that can be either a direct IP address or a DNS hostname with port.
///
/// This type supports both direct socket addresses and DNS entries that can be resolved
/// at connection time using the runtime's resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Socket {
    /// Direct socket address.
    Direct(SocketAddr),
    /// DNS hostname and port that needs to be resolved.
    Dns { hostname: String, port: u16 },
}

impl Socket {
    /// Resolve this socket to a direct socket address.
    ///
    /// For `Direct` variants, returns the address directly.
    /// For `Dns` variants, uses the provided resolver to resolve the hostname.
    pub async fn resolve<R: Resolver>(&self, resolver: &R) -> Result<SocketAddr, RuntimeError> {
        match self {
            Self::Direct(addr) => Ok(*addr),
            Self::Dns { hostname, port } => resolver.resolve(hostname, *port).await,
        }
    }
}

impl From<SocketAddr> for Socket {
    fn from(addr: SocketAddr) -> Self {
        Self::Direct(addr)
    }
}

/// Address configuration for a peer.
///
/// This type allows specifying either a single address for both ingress and egress
/// connections, or separate addresses for each direction. This is useful when a peer
/// has different public/private addresses or when NAT traversal is involved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// Single address for both ingress and egress.
    Single(SocketAddr),
    /// Separate addresses for ingress and egress.
    ///
    /// - `ingress`: Address where we can receive connections from this peer.
    ///   This can be a DNS entry that will be resolved at connection time.
    /// - `egress`: Address where we dial out to connect to this peer.
    Split {
        /// Address where we can receive connections from this peer.
        ingress: Socket,
        /// Address where we dial out to connect to this peer.
        egress: SocketAddr,
    },
}

impl Address {
    /// Get the egress address (address to dial).
    pub const fn egress(&self) -> SocketAddr {
        match self {
            Self::Single(addr) => *addr,
            Self::Split { egress, .. } => *egress,
        }
    }

    /// Get the ingress socket (may require resolution).
    pub fn ingress(&self) -> Socket {
        match self {
            Self::Single(addr) => Socket::Direct(*addr),
            Self::Split { ingress, .. } => ingress.clone(),
        }
    }

    /// Resolve the ingress address to a direct socket address.
    pub async fn resolve_ingress<R: Resolver>(
        &self,
        resolver: &R,
    ) -> Result<SocketAddr, RuntimeError> {
        self.ingress().resolve(resolver).await
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Self::Single(addr)
    }
}

/// Tuple representing a message received from a given public key.
///
/// This message is guaranteed to adhere to the configuration of the channel and
/// will already be decrypted and authenticated.
pub type Message<P> = (P, Bytes);

/// Alias for identifying communication channels.
pub type Channel = u64;

/// Enum indicating the set of recipients to send a message to.
#[derive(Clone, Debug)]
pub enum Recipients<P: PublicKey> {
    All,
    Some(Vec<P>),
    One(P),
}

/// Interface for sending messages to a set of recipients.
pub trait Sender: Clone + Debug + Send + 'static {
    /// Error that can occur when sending a message.
    type Error: Debug + StdError + Send + Sync;

    /// Public key type used to identify recipients.
    type PublicKey: PublicKey;

    /// Send a message to a set of recipients.
    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: Bytes,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send;
}

/// Interface for receiving messages from arbitrary recipients.
pub trait Receiver: Debug + Send + 'static {
    /// Error that can occur when receiving a message.
    type Error: Debug + StdError + Send + Sync;

    /// Public key type used to identify recipients.
    type PublicKey: PublicKey;

    /// Receive a message from an arbitrary recipient.
    fn recv(
        &mut self,
    ) -> impl Future<Output = Result<Message<Self::PublicKey>, Self::Error>> + Send;
}

/// Interface for registering new peer sets as well as fetching an ordered list of connected peers, given a set id.
pub trait Manager: Debug + Clone + Send + 'static {
    /// Public key type used to identify peers.
    type PublicKey: PublicKey;

    /// The type for the peer set in registration.
    type Peers;

    /// Update the peer set.
    ///
    /// The peer set ID passed to this function should be strictly managed, ideally matching the epoch
    /// of the consensus engine. It must be monotonically increasing as new peer sets are registered.
    fn update(&mut self, id: u64, peers: Self::Peers) -> impl Future<Output = ()> + Send;

    /// Fetch the ordered set of peers for a given ID.
    fn peer_set(
        &mut self,
        id: u64,
    ) -> impl Future<Output = Option<Ordered<Self::PublicKey>>> + Send;

    /// Subscribe to notifications when new peer sets are added.
    ///
    /// Returns a receiver that will receive the peer set ID whenever a new peer set
    /// is registered via `update`.
    #[allow(clippy::type_complexity)]
    fn subscribe(
        &mut self,
    ) -> impl Future<
        Output = mpsc::UnboundedReceiver<(u64, Ordered<Self::PublicKey>, Ordered<Self::PublicKey>)>,
    > + Send;
}

/// Interface for blocking other peers.
pub trait Blocker: Clone + Send + 'static {
    /// Public key type used to identify peers.
    type PublicKey: PublicKey;

    /// Block a peer, disconnecting them if currently connected and preventing future connections.
    fn block(&mut self, peer: Self::PublicKey) -> impl Future<Output = ()> + Send;
}
