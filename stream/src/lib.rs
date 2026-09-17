//! Exchange messages over arbitrary transport.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_cryptography::PublicKey;
    use commonware_runtime::{BufferPooler, Clock, IoBufs, Sink, Stream};
    use rand_core::CryptoRng;
    use std::{error::Error, future::Future};

    pub mod encrypted;
    pub mod utils;

    /// Authenticates a raw connection and upgrades it to an ordered message stream.
    ///
    /// Implementations own their authentication mechanism; it may be asynchronous and fallible
    /// and does not need to implement [`commonware_cryptography::Signer`]. They must prove each
    /// peer's declared identity according to their configured authority and bind the supplied
    /// application namespace, both peer identities, and both message directions to the established
    /// session. The returned sender and receiver must preserve message boundaries and provide
    /// confidentiality and integrity. A successful dial must authenticate the expected peer. A
    /// listen may succeed only if the bouncer returns `true` for the same authenticated peer that
    /// is returned.
    ///
    /// `max_message_size` limits plaintext messages. Implementations must reject unsupported
    /// limits, reject larger outbound messages, and enforce the limit before allocating for an
    /// inbound message. Framing and encryption overhead do not count toward this limit.
    ///
    /// Callers may cancel an in-progress handshake by dropping its future. Implementations must
    /// release the underlying connection when cancelled.
    pub trait Handshake: Clone + Send + Sync + 'static {
        /// Public key used to identify authenticated peers.
        type PublicKey: PublicKey;

        /// Local signing owner for the same identity returned by [`Handshake::public_key`].
        ///
        /// This type is not required to implement [`commonware_cryptography::Signer`].
        type Signer;

        /// Error returned when authentication or stream setup fails.
        type Error: Error + Send + Sync + 'static;

        /// Sender returned for a connection using `O` as its raw sink.
        type Sender<O: Sink>: Sender;

        /// Receiver returned for a connection using `I` as its raw stream.
        type Receiver<I: Stream>: Receiver;

        /// Returns the local identity authenticated by this handshake.
        fn public_key(&self) -> Self::PublicKey;

        /// Returns the local signing owner.
        fn signer(&self) -> &Self::Signer;

        /// Authenticates an outbound connection to `peer`.
        #[allow(clippy::type_complexity)]
        fn dial<C, I, O>(
            self,
            context: C,
            namespace: Vec<u8>,
            max_message_size: u32,
            peer: Self::PublicKey,
            stream: I,
            sink: O,
        ) -> impl Future<Output = Result<(Self::Sender<O>, Self::Receiver<I>), Self::Error>> + Send
        where
            C: BufferPooler + Clock + CryptoRng,
            I: Stream,
            O: Sink;

        /// Authenticates an inbound connection accepted by `bouncer`.
        #[allow(clippy::type_complexity)]
        fn listen<C, I, O, B, F>(
            self,
            context: C,
            namespace: Vec<u8>,
            max_message_size: u32,
            bouncer: B,
            stream: I,
            sink: O,
        ) -> impl Future<
            Output = Result<
                (Self::PublicKey, Self::Sender<O>, Self::Receiver<I>),
                Self::Error,
            >,
        > + Send
        where
            C: BufferPooler + Clock + CryptoRng,
            I: Stream,
            O: Sink,
            B: FnOnce(Self::PublicKey) -> F + Send,
            F: Future<Output = bool> + Send;
    }

    /// Sends ordered, authenticated messages on an established connection.
    ///
    /// Each send preserves its message boundary. After an I/O error or cancellation,
    /// callers must discard the connection because a message may have been partially sent.
    pub trait Sender: Send + 'static {
        /// Error returned when sending a message fails.
        type Error: Error + Send + Sync + 'static;

        /// Sends one message, rejecting messages larger than the connection's limit.
        fn send(
            &mut self,
            message: impl Into<IoBufs> + Send,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send;

        /// Sends messages in order, preserving each message's boundary.
        ///
        /// Implementations may combine writes. An empty batch succeeds without sending data.
        fn send_many<B, I>(&mut self, messages: I) -> impl Future<Output = Result<(), Self::Error>> + Send
        where
            B: Into<IoBufs> + Send,
            I: IntoIterator<Item = B> + Send,
            I::IntoIter: Send,
        {
            async move {
                for message in messages {
                    self.send(message).await?;
                }
                Ok(())
            }
        }
    }

    /// Receives ordered, authenticated messages on an established connection.
    ///
    /// Implementations must bound allocation by the connection's message-size limit.
    /// After an error or cancellation, callers must discard the connection because a
    /// message may have been partially consumed.
    pub trait Receiver: Send + 'static {
        /// Error returned when receiving a message fails.
        type Error: Error + Send + Sync + 'static;

        /// Receives one complete message within the connection's size limit.
        fn recv(&mut self) -> impl Future<Output = Result<IoBufs, Self::Error>> + Send;
    }
});
