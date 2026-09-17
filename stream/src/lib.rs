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
    use commonware_cryptography::AsyncSigner;
    use commonware_runtime::{BufferPooler, Clock, IoBufs, Sink, Stream};
    use rand_core::CryptoRng;
    use std::{error::Error, future::Future};

    pub mod encrypted;
    pub mod utils;

    /// Public identity key authenticated by a handshake's signing scheme.
    pub type PublicKeyOf<H> = <<H as Handshake>::Scheme as AsyncSigner>::PublicKey;

    /// Authenticates a raw connection and upgrades it to an ordered message stream.
    ///
    /// Implementations own their authentication mechanism, which may be asynchronous and fallible.
    /// They must prove each peer's declared identity according to their configured authority and
    /// bind the supplied
    /// application namespace, both peer identities, and both message directions to the established
    /// session. The returned sender and receiver must preserve message boundaries and provide
    /// confidentiality and integrity. A successful dial must authenticate the expected peer. A
    /// listen may succeed only if the bouncer returns `true` for the same authenticated peer that
    /// is returned.
    ///
    /// `max_message_size` limits plaintext messages. Callers must supply a limit no greater than
    /// [`Self::MAX_SIZE`]. Implementations must reject larger outbound messages and enforce the
    /// limit before allocating for an inbound message. Framing and encryption overhead do not
    /// count toward this limit.
    ///
    /// Callers may cancel an in-progress handshake by dropping its future. Implementations must
    /// release the underlying connection when cancelled.
    pub trait Handshake: Clone + Send + Sync + 'static {
        /// Largest plaintext message supported by the established streams, in bytes.
        const MAX_SIZE: u32;

        /// Signing scheme that owns the local authenticated identity.
        type Scheme: AsyncSigner;

        /// Error returned when authentication or stream setup fails.
        type Error: Error + Send + Sync + 'static;

        /// Sender returned for a connection using `O` as its raw sink.
        type Sender<O: Sink>: Sender;

        /// Receiver returned for a connection using `I` as its raw stream.
        type Receiver<I: Stream>: Receiver;

        /// Returns the signing scheme for the local authenticated identity.
        fn scheme(&self) -> &Self::Scheme;

        /// Authenticates an outbound connection to `peer`.
        ///
        /// # Panics
        ///
        /// Implementations may panic if `max_message_size` exceeds [`Self::MAX_SIZE`].
        #[allow(clippy::type_complexity)]
        fn dial<C, I, O>(
            self,
            context: C,
            namespace: &[u8],
            max_message_size: u32,
            peer: PublicKeyOf<Self>,
            stream: I,
            sink: O,
        ) -> impl Future<Output = Result<(Self::Sender<O>, Self::Receiver<I>), Self::Error>> + Send
        where
            C: BufferPooler + Clock + CryptoRng,
            I: Stream,
            O: Sink;

        /// Authenticates an inbound connection accepted by `bouncer`.
        ///
        /// The bouncer may receive an unverified identity claim before authentication completes.
        /// Accepting this claim permits authentication to continue. Only a successful handshake
        /// proves the returned peer's identity.
        ///
        /// # Panics
        ///
        /// Implementations may panic if `max_message_size` exceeds [`Self::MAX_SIZE`].
        #[allow(clippy::type_complexity)]
        fn listen<C, I, O, B, F>(
            self,
            context: C,
            namespace: &[u8],
            max_message_size: u32,
            bouncer: B,
            stream: I,
            sink: O,
        ) -> impl Future<
            Output = Result<
                (PublicKeyOf<Self>, Self::Sender<O>, Self::Receiver<I>),
                Self::Error,
            >,
        > + Send
        where
            C: BufferPooler + Clock + CryptoRng,
            I: Stream,
            O: Sink,
            B: FnOnce(PublicKeyOf<Self>) -> F + Send,
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
