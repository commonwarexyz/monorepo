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
use std::{error::Error as StdError, fmt::Debug, future::Future, time::SystemTime};

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
pub trait Sender: Debug + Clone + Send + Sync + 'static {
    /// Error that can occur when sending a message.
    type Error: Debug + StdError + Send + Sync;

    /// Public key type used to identify recipients.
    type PublicKey: PublicKey;

    /// Sends a message to a set of recipients.
    ///
    /// # Offline Recipients
    ///
    /// If a recipient is offline at the time a message is sent, the message
    /// will be dropped. It is up to the application to handle retries (if
    /// necessary).
    ///
    /// # Rate Limiting
    ///
    /// Recipients that exceed their rate limit will be skipped. The message is
    /// still sent to non-limited recipients. Check the returned vector to see
    /// which peers were sent the message.
    ///
    /// # Returns
    ///
    /// A vector of recipients that the message was sent to, or an error if the
    /// message could not be sent (e.g., too large).
    ///
    /// Note: a successful send does not guarantee that the recipient will
    /// receive the message.
    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: Bytes,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send;
}

/// Interface for constructing a [`CheckedSender`] from a set of [`Recipients`],
/// filtering out any that are currently rate-limited.
pub trait LimitedSender: Clone + Send + Sync + 'static {
    /// Public key type used to identify recipients.
    type PublicKey: PublicKey;

    /// The type of [`CheckedSender`] returned after checking recipients.
    type Checked<'a>: CheckedSender<PublicKey = Self::PublicKey>
    where
        Self: 'a;

    /// Checks which recipients are within their rate limit and returns a
    /// [`CheckedSender`] for sending to them.
    ///
    /// # Rate Limiting
    ///
    /// Recipients that exceed their rate limit will be filtered out. The
    /// returned [`CheckedSender`] will only send to non-limited recipients.
    ///
    /// # Returns
    ///
    /// A [`CheckedSender`] containing only the recipients that are not
    /// currently rate-limited, or an error with the earliest instant at which
    /// all recipients will be available if all are rate-limited.
    fn check<'a>(
        &'a mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> impl Future<Output = Result<Self::Checked<'a>, SystemTime>>;
}

/// Interface for sending messages to [`Recipients`] that are not currently rate-limited.
pub trait CheckedSender {
    /// Public key type used to identify [`Recipients`].
    type PublicKey: PublicKey;

    /// Error that can occur when sending a message.
    type Error: Debug + StdError + Send + Sync;

    /// Sends a message to the pre-checked recipients.
    ///
    /// # Offline Recipients
    ///
    /// If a recipient is offline at the time a message is sent, the message
    /// will be dropped. It is up to the application to handle retries (if
    /// necessary).
    ///
    /// # Returns
    ///
    /// A vector of recipients that the message was sent to, or an error if the
    /// message could not be sent (e.g., too large).
    ///
    /// Note: a successful send does not guarantee that the recipient will
    /// receive the message.
    fn send(
        self,
        message: Bytes,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>>;
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
