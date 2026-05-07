//! Communicate with authenticated peers over encrypted connections.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::{stability_mod, stability_scope};

stability_mod!(ALPHA, pub mod simulated);

stability_scope!(BETA {
    use commonware_cryptography::PublicKey;
    use commonware_runtime::{IoBuf, IoBufs};
    use commonware_utils::{
        channel::{actor::Enqueue, mpsc},
        ordered::{Map, Set},
    };
    use std::{error::Error as StdError, fmt::Debug, future::Future, time::SystemTime};

    pub mod authenticated;
    pub mod types;
    pub mod utils;

    pub use types::{Address, Ingress};

    /// Tuple representing a message received from a given public key.
    ///
    /// This message is guaranteed to adhere to the configuration of the channel and
    /// will already be decrypted and authenticated.
    pub type Message<P> = (P, IoBuf);

    /// Alias for identifying communication channels.
    pub type Channel = u64;

    /// Enum indicating the set of recipients to send a message to.
    #[derive(Clone, Debug)]
    pub enum Recipients<P: PublicKey> {
        All,
        Some(Vec<P>),
        One(P),
    }

    /// Interface for sending messages to a set of recipients without rate-limiting restrictions.
    pub trait UnlimitedSender: Clone + Send + Sync + 'static {
        /// Public key type used to identify recipients.
        type PublicKey: PublicKey;

        /// Error that can occur when sending a message.
        type Error: Debug + StdError + Send + Sync + 'static;

        /// Sends a message to a set of recipients.
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
        /// message could not be sent due to a validation failure (e.g., too large).
        ///
        /// Note: a successful send does not guarantee that the recipient will
        /// receive the message.
        ///
        /// # Graceful Shutdown
        ///
        /// Implementations must handle internal channel closures gracefully during
        /// shutdown. If the underlying network is shutting down, this method should
        /// return `Ok` (possibly with an empty or partial recipient list) rather
        /// than an error. Errors should only be returned for validation failures
        /// that the caller can act upon.
        fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            message: impl Into<IoBufs> + Send,
            priority: bool,
        ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send;
    }

    /// Interface for constructing a [`CheckedSender`] from a set of [`Recipients`],
    /// filtering out any that are currently rate-limited.
    pub trait LimitedSender: Clone + Send + Sync + 'static {
        /// Public key type used to identify recipients.
        type PublicKey: PublicKey;

        /// The type of [`CheckedSender`] returned after checking recipients.
        type Checked<'a>: CheckedSender<PublicKey = Self::PublicKey> + Send
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
        ) -> impl Future<Output = Result<Self::Checked<'a>, SystemTime>> + Send;
    }

    /// Interface for sending messages to [`Recipients`] that are not currently rate-limited.
    pub trait CheckedSender: Send {
        /// Public key type used to identify [`Recipients`].
        type PublicKey: PublicKey;

        /// Error that can occur when sending a message.
        type Error: Debug + StdError + Send + Sync + 'static;

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
        /// message could not be sent due to a validation failure (e.g., too large).
        ///
        /// Note: a successful send does not guarantee that the recipient will
        /// receive the message.
        ///
        /// # Graceful Shutdown
        ///
        /// Implementations must handle internal channel closures gracefully during
        /// shutdown. If the underlying network is shutting down, this method should
        /// return `Ok` (possibly with an empty or partial recipient list) rather
        /// than an error. Errors should only be returned for validation failures
        /// that the caller can act upon.
        fn send(
            self,
            message: impl Into<IoBufs> + Send,
            priority: bool,
        ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send;
    }

    /// Interface for sending messages to a set of recipients.
    pub trait Sender: LimitedSender {
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
        /// message could not be sent due to a validation failure (e.g., too large).
        ///
        /// Note: a successful send does not guarantee that the recipient will
        /// receive the message.
        ///
        /// # Graceful Shutdown
        ///
        /// Implementations must handle internal channel closures gracefully during
        /// shutdown. If the underlying network is shutting down, this method should
        /// return `Ok` (possibly with an empty or partial recipient list) rather
        /// than an error. Errors should only be returned for validation failures
        /// that the caller can act upon.
        fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            message: impl Into<IoBufs> + Send,
            priority: bool,
        ) -> impl Future<
            Output = Result<Vec<Self::PublicKey>, <Self::Checked<'_> as CheckedSender>::Error>,
        > + Send {
            async move {
                match self.check(recipients).await {
                    Ok(checked_sender) => checked_sender.send(message, priority).await,
                    Err(_) => Ok(Vec::new()),
                }
            }
        }
    }

    // Blanket implementation of `Sender` for all `LimitedSender`s.
    impl<S: LimitedSender> Sender for S {}

    /// Interface for enqueueing messages to a set of recipients without waiting on p2p delivery.
    pub trait MailboxSender: Clone + Send + Sync + 'static {
        /// Public key type used to identify recipients.
        type PublicKey: PublicKey;

        /// Enqueue a message to a set of recipients.
        ///
        /// This method only reports whether the p2p actor accepted the work. It
        /// does not report which peers eventually received the message.
        fn send(
            &self,
            recipients: Recipients<Self::PublicKey>,
            message: impl Into<IoBufs> + Send,
            priority: bool,
        ) -> Enqueue;
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

    /// Notification sent to subscribers when a peer set changes.
    #[derive(Clone, Debug)]
    pub struct PeerSetUpdate<P: PublicKey> {
        /// The index of the peer set that changed.
        pub index: u64,
        /// The primary and secondary peers in the new set.
        pub latest: TrackedPeers<P>,
        /// Union of primary and secondary peers across all tracked peer sets.
        pub all: TrackedPeers<P>,
    }

    /// Alias for the subscription type returned by [`Provider::subscribe`].
    pub type PeerSetSubscription<P> = mpsc::UnboundedReceiver<PeerSetUpdate<P>>;

    /// Primary and secondary peers provided together to [`Manager::track`].
    ///
    /// The same public key may appear in both `primary` and `secondary`. [`Manager::track`]
    /// deduplicates overlapping keys, storing them as primary only.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TrackedPeers<P: PublicKey> {
        /// Peers eligible for primary-only policies.
        pub primary: Set<P>,
        /// Peers eligible for secondary-only policies.
        pub secondary: Set<P>,
    }

    impl<P: PublicKey> TrackedPeers<P> {
        pub const fn new(primary: Set<P>, secondary: Set<P>) -> Self {
            Self { primary, secondary }
        }

        pub fn primary(primary: Set<P>) -> Self {
            Self::new(primary, Set::default())
        }

        /// Returns the deduplicated union of primary and secondary peers.
        pub fn union(self) -> Set<P> {
            Set::from_iter_dedup(self.primary.into_iter().chain(self.secondary))
        }
    }

    impl<P: PublicKey> From<Set<P>> for TrackedPeers<P> {
        fn from(primary: Set<P>) -> Self {
            Self::primary(primary)
        }
    }

    impl<P: PublicKey> Default for TrackedPeers<P> {
        fn default() -> Self {
            Self::new(Set::default(), Set::default())
        }
    }

    /// Primary and secondary peers provided together to [`AddressableManager::track`].
    ///
    /// The same public key may appear in both maps. [`AddressableManager::track`]
    /// deduplicates overlapping keys, storing them as primary only.
    #[derive(Clone, Debug)]
    pub struct AddressableTrackedPeers<P: PublicKey> {
        /// Addresses for peers eligible for primary-only policies.
        pub primary: Map<P, Address>,
        /// Addresses for peers eligible for secondary-only policies.
        pub secondary: Map<P, Address>,
    }

    impl<P: PublicKey> AddressableTrackedPeers<P> {
        pub const fn new(primary: Map<P, Address>, secondary: Map<P, Address>) -> Self {
            Self { primary, secondary }
        }

        pub fn primary(primary: Map<P, Address>) -> Self {
            Self::new(primary, Map::default())
        }
    }

    impl<P: PublicKey> From<Map<P, Address>> for AddressableTrackedPeers<P> {
        fn from(primary: Map<P, Address>) -> Self {
            Self::primary(primary)
        }
    }

    /// Interface for reading peer set information.
    pub trait Provider: Debug + Clone + Send + 'static {
        /// Public key type used to identify peers.
        type PublicKey: PublicKey;

        /// Fetch the primary and secondary peers tracked at the given ID.
        fn peer_set(
            &mut self,
            id: u64,
        ) -> impl Future<Output = Option<TrackedPeers<Self::PublicKey>>> + Send;

        /// Subscribe to notifications when new peer sets are added.
        ///
        /// Returns a receiver of [`PeerSetUpdate`] notifications. Each update's
        /// `latest` reflects how [`Manager::track`] stored the set: a peer listed in
        /// both roles appears only under `latest.primary`. The `all` field aggregates
        /// across tracked sets with the same rule (secondary excludes keys present as primary).
        fn subscribe(
            &mut self,
        ) -> impl Future<Output = PeerSetSubscription<Self::PublicKey>> + Send;
    }

    /// Interface for managing peer set membership (where peer addresses are not known).
    pub trait Manager: Provider {
        /// Track a primary and secondary peer set with the given ID.
        ///
        /// The peer set ID passed to this function should be strictly managed, ideally matching the epoch
        /// of the consensus engine. It must be monotonically increasing as new peer sets are
        /// tracked.
        ///
        /// For good connectivity, all peers must track the same peer sets at the same ID.
        ///
        /// Callers may pass either a list of primary peers or a [`TrackedPeers`] value containing both primary and secondary peers.
        ///
        /// Overlapping keys in [`TrackedPeers`] are allowed; they are deduplicated as primary only.
        ///
        /// ## Active Peers
        ///
        /// The most recently registered peer set (highest ID) is considered the
        /// active set. Implementations use the active set to decide which peers to
        /// maintain connections with and which to disconnect from.
        ///
        /// ## Primary vs Secondary Peers
        ///
        /// In p2p networks, there are often two tiers of peers: ones that help "drive progress" and ones that want to
        /// "follow that progress" (but not contribute to it). We call the former "primary" and the latter "secondary".
        /// When both are tracked, mechanisms favor "primary" peers but continue to replicate data to "secondary" peers (
        /// often both gossiping data to them and answering requests from them).
        fn track<R>(&mut self, id: u64, peers: R) -> impl Future<Output = ()> + Send
        where
            R: Into<TrackedPeers<Self::PublicKey>> + Send;
    }

    /// Interface for managing peer set membership (where peer addresses are known).
    pub trait AddressableManager: Provider {
        /// Track a primary peer set and secondary peers with the given ID.
        ///
        /// The peer set ID passed to this function should be strictly managed, ideally matching the epoch
        /// of the consensus engine. It must be monotonically increasing as new peer sets are
        /// tracked.
        ///
        /// For good connectivity, all peers must track the same peer sets at the same ID.
        ///
        /// Callers may pass either a list of primary peers or a [`AddressableTrackedPeers`] value containing
        /// both primary and secondary peers.
        ///
        /// The same key may appear in both maps; see [`AddressableTrackedPeers`].
        ///
        /// ## Active Peers
        ///
        /// The most recently registered peer set (highest ID) is considered the
        /// active set. Implementations use the active set to decide which peers to
        /// maintain connections with and which to disconnect from.
        ///
        /// ## Primary vs Secondary Peers
        ///
        /// In p2p networks, there are often two tiers of peers: ones that help "drive progress" and ones that want to
        /// "follow that progress" (but not contribute to it). We call the former "primary" and the latter "secondary".
        /// When both are tracked, mechanisms favor "primary" peers but continue to replicate data to "secondary" peers (
        /// often both gossiping data to them and answering requests from them).
        fn track<R>(&mut self, id: u64, peers: R) -> impl Future<Output = ()> + Send
        where
            R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send;

        /// Update addresses for multiple peers without creating a new peer set.
        ///
        /// For each primary or secondary peer with a changed address:
        /// - Any existing connection to the peer is severed (it was on the old IP)
        /// - The listener's allowed IPs are updated to reflect the new egress IP
        /// - Future connections will use the new address
        fn overwrite(
            &mut self,
            peers: Map<Self::PublicKey, Address>,
        ) -> impl Future<Output = ()> + Send;
    }

    /// Interface for blocking other peers.
    pub trait Blocker: Clone + Send + 'static {
        /// Public key type used to identify peers.
        type PublicKey: PublicKey;

        /// Block a peer, disconnecting them if currently connected and preventing future connections.
        fn block(&mut self, peer: Self::PublicKey) -> Enqueue;
    }
});

/// Logs a warning and blocks a peer in a single call.
///
/// This macro combines a [`tracing::warn!`] with a [`Blocker::block`] call
/// to ensure consistent logging at every block site. The peer is always
/// included as a `peer` field in the log output.
///
/// # Examples
///
/// ```ignore
/// block!(self.blocker, sender, "invalid message");
/// block!(self.blocker, sender, ?err, "invalid ack signature");
/// block!(self.blocker, sender, %view, "blocking peer for epoch mismatch");
/// ```
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! block {
    ($blocker:expr, $peer:expr, $($arg:tt)+) => {
        let peer = $peer;
        tracing::warn!(peer = ?peer, $($arg)+);
        #[allow(clippy::disallowed_methods)]
        let _ = $blocker.block(peer);
    };
}

/// Block a peer without logging.
#[allow(
    clippy::disallowed_methods,
    reason = "test helper that bypasses the block! macro"
)]
#[cfg(test)]
pub fn block_peer<B: Blocker>(blocker: &mut B, peer: B::PublicKey) -> Enqueue {
    blocker.block(peer)
}
