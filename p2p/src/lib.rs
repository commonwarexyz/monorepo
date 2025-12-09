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
use commonware_utils::ordered::Set;
use futures::channel::mpsc;
use std::{error::Error as StdError, fmt::Debug, future::Future};

pub mod authenticated;
pub mod simulated;
pub mod utils;

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
    fn peer_set(&mut self, id: u64) -> impl Future<Output = Option<Set<Self::PublicKey>>> + Send;

    /// Subscribe to notifications when new peer sets are added.
    ///
    /// Returns a receiver that will receive the peer set ID whenever a new peer set
    /// is registered via `update`.
    #[allow(clippy::type_complexity)]
    fn subscribe(
        &mut self,
    ) -> impl Future<
        Output = mpsc::UnboundedReceiver<(u64, Set<Self::PublicKey>, Set<Self::PublicKey>)>,
    > + Send;
}

/// Interface for blocking other peers.
pub trait Blocker: Clone + Send + 'static {
    /// Public key type used to identify peers.
    type PublicKey: PublicKey;

    /// Block a peer, disconnecting them if currently connected and preventing future connections.
    fn block(&mut self, peer: Self::PublicKey) -> impl Future<Output = ()> + Send;
}
