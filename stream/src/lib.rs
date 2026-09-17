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
    use commonware_cryptography::Signer;
    use commonware_runtime::{BufferPooler, Clock, IoBufs, Sink, Stream};
    use rand_core::CryptoRng;
    use std::{error::Error, future::Future};

    pub mod encrypted;
    pub mod utils;

    /// Provides a handshake's local identity.
    ///
    /// Every [Signer] implements this trait.
    pub trait Identity {
        /// Public key identifying the local peer.
        type PublicKey;

        /// Returns the local identity.
        fn identity(&self) -> Self::PublicKey;
    }

    impl<S: Signer> Identity for S {
        type PublicKey = S::PublicKey;

        fn identity(&self) -> Self::PublicKey {
            self.public_key()
        }
    }

    /// Public identity key authenticated by a handshake's scheme.
    pub type PublicKeyOf<H> = <<H as Handshake>::Scheme as Identity>::PublicKey;

    /// Authenticates a raw connection and upgrades it to an ordered message stream.
    ///
    /// Implementations own their authentication mechanism, which may be asynchronous and fallible.
    /// They must prove each peer's declared identity according to their configured authority and
    /// bind the supplied application namespace, both peer identities, and both message directions
    /// to the established session. The returned sender and receiver must preserve message boundaries
    /// and protect message integrity. Confidentiality depends on the implementation. A successful
    /// dial must authenticate the expected peer. A listen may succeed only if the bouncer returns
    /// `true` for the same authenticated peer that is returned.
    ///
    /// `max_message_size` sets the plaintext message limit for the returned streams. Callers must
    /// supply a limit no greater than [`Self::MAX_SIZE`]. Implementations must reject larger outbound
    /// messages and enforce the limit before allocating for an inbound message. Protocol overhead
    /// does not count toward this limit.
    ///
    /// Callers must enforce their own deadline by dropping the handshake future when it expires.
    /// Dropping the future cancels the attempt, and implementations must release the underlying
    /// connection.
    pub trait Handshake: Clone + Send + Sync + 'static {
        /// Largest plaintext message supported by the established streams, in bytes.
        const MAX_SIZE: u32;

        /// Scheme that owns the local authenticated identity.
        type Scheme: Identity;

        /// Error returned when authentication or stream setup fails.
        type Error: Error + Send + Sync + 'static;

        /// Sender returned for a connection using raw stream `I` and sink `O`.
        type Sender<I: Stream, O: Sink>: Sender;

        /// Receiver returned for a connection using raw stream `I` and sink `O`.
        type Receiver<I: Stream, O: Sink>: Receiver;

        /// Returns the scheme for the local authenticated identity.
        ///
        /// Its identity must remain stable across attempts and clones of this handshake.
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
        ) -> impl Future<Output = Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>> + Send
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
                (PublicKeyOf<Self>, Self::Sender<I, O>, Self::Receiver<I, O>),
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
        fn send_many<I>(&mut self, messages: I) -> impl Future<Output = Result<(), Self::Error>> + Send
        where
            I: IntoIterator + Send,
            I::Item: Into<IoBufs> + Send,
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{convert::Infallible, future, marker::PhantomData, rc::Rc, sync::Arc};

        struct OpaqueIdentity(PhantomData<Rc<()>>);

        struct Session<I, O> {
            _stream: I,
            _sink: O,
        }

        struct SharedHalf<I, O> {
            _session: Arc<Session<I, O>>,
        }

        impl<I: Stream, O: Sink> Sender for SharedHalf<I, O> {
            type Error = Infallible;

            fn send(
                &mut self,
                _message: impl Into<IoBufs> + Send,
            ) -> impl Future<Output = Result<(), Self::Error>> + Send {
                future::pending()
            }
        }

        impl<I: Stream, O: Sink> Receiver for SharedHalf<I, O> {
            type Error = Infallible;

            fn recv(&mut self) -> impl Future<Output = Result<IoBufs, Self::Error>> + Send {
                future::pending()
            }
        }

        #[derive(Clone)]
        struct OpaqueHandshake;

        impl Identity for OpaqueHandshake {
            type PublicKey = OpaqueIdentity;

            fn identity(&self) -> Self::PublicKey {
                OpaqueIdentity(PhantomData)
            }
        }

        impl Handshake for OpaqueHandshake {
            const MAX_SIZE: u32 = encrypted::MAX_SIZE;

            type Scheme = Self;
            type Error = Infallible;
            type Sender<I: Stream, O: Sink> = SharedHalf<I, O>;
            type Receiver<I: Stream, O: Sink> = SharedHalf<I, O>;

            fn scheme(&self) -> &Self::Scheme {
                self
            }

            fn dial<C, I, O>(
                self,
                _context: C,
                _namespace: &[u8],
                _max_message_size: u32,
                _peer: PublicKeyOf<Self>,
                _stream: I,
                _sink: O,
            ) -> impl Future<Output = Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>> + Send
            where
                C: BufferPooler + Clock + CryptoRng,
                I: Stream,
                O: Sink,
            {
                future::pending()
            }

            fn listen<C, I, O, B, F>(
                self,
                _context: C,
                _namespace: &[u8],
                _max_message_size: u32,
                _bouncer: B,
                _stream: I,
                _sink: O,
            ) -> impl Future<
                Output = Result<(PublicKeyOf<Self>, Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>,
            > + Send
            where
                C: BufferPooler + Clock + CryptoRng,
                I: Stream,
                O: Sink,
                B: FnOnce(PublicKeyOf<Self>) -> F + Send,
                F: Future<Output = bool> + Send,
            {
                future::pending()
            }
        }

        #[test]
        fn handshake_supports_opaque_identity_and_shared_session() {
            let _: OpaqueIdentity = OpaqueHandshake.scheme().identity();
        }
    }
});
