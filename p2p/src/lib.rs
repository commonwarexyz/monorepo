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
        channel::mpsc,
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

    /// Alias for the subscription type returned by [`Provider::subscribe`].
    pub type PeerSetSubscription<P> = mpsc::UnboundedReceiver<(u64, Set<P>, Set<P>)>;

    /// Interface for reading peer set information.
    pub trait Provider: Debug + Clone + Send + 'static {
        /// Public key type used to identify peers.
        type PublicKey: PublicKey;

        /// Fetch the ordered set of peers for a given ID.
        fn peer_set(
            &mut self,
            id: u64,
        ) -> impl Future<Output = Option<Set<Self::PublicKey>>> + Send;

        /// Subscribe to notifications when new peer sets are added.
        ///
        /// Returns a receiver that will receive tuples of:
        /// - The peer set ID
        /// - The peers in the new set
        /// - All currently tracked peers (union of recent peer sets)
        #[allow(clippy::type_complexity)]
        fn subscribe(
            &mut self,
        ) -> impl Future<Output = PeerSetSubscription<Self::PublicKey>> + Send;
    }

    /// Interface for managing peer set membership (where peer addresses are not known).
    pub trait Manager: Provider {
        /// Track a peer set with the given ID and peers.
        ///
        /// The peer set ID passed to this function should be strictly managed, ideally matching the epoch
        /// of the consensus engine. It must be monotonically increasing as new peer sets are tracked.
        ///
        /// For good connectivity, all peers must track the same peer sets at the same ID.
        fn track(
            &mut self,
            id: u64,
            peers: Set<Self::PublicKey>,
        ) -> impl Future<Output = ()> + Send;
    }

    /// Interface for managing peer set membership (where peer addresses are known).
    pub trait AddressableManager: Provider {
        /// Track a peer set with the given ID and peer<PublicKey, Address> pairs.
        ///
        /// The peer set ID passed to this function should be strictly managed, ideally matching the epoch
        /// of the consensus engine. It must be monotonically increasing as new peer sets are tracked.
        ///
        /// For good connectivity, all peers must track the same peer sets at the same ID.
        fn track(
            &mut self,
            id: u64,
            peers: Map<Self::PublicKey, Address>,
        ) -> impl Future<Output = ()> + Send;

        /// Update addresses for multiple peers without creating a new peer set.
        ///
        /// For each peer that is tracked and has a changed address:
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
        fn block(&mut self, peer: Self::PublicKey) -> impl Future<Output = ()> + Send;
    }
});
