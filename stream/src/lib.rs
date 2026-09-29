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
    use commonware_cryptography::Cipher;
    use commonware_runtime::{BufferPool, BufferPooler, Clock, IoBufs, Sink, Stream};
    use rand_core::CryptoRng;
    use std::{error::Error, future::Future};

    pub mod cups;
    pub mod sake;
    mod session;
    pub use session::Session;
    pub mod utils;

    /// Authenticates a raw connection and upgrades it to an ordered message stream.
    ///
    /// Implementations must authenticate each peer's declared identity and bind the supplied
    /// application namespace, both peer identities, and both message directions to the established
    /// session. The returned sender and receiver must preserve message boundaries and protect message
    /// integrity. Confidentiality depends on the implementation. A successful dial must authenticate
    /// the expected peer. A listen may succeed only if the bouncer returns `true` for the same
    /// authenticated peer that is returned.
    ///
    /// `max_message_size` sets the plaintext message limit for the returned streams. Callers must
    /// supply a limit no greater than [`Self::MAX_SIZE`]. Implementations must reject larger outbound
    /// messages and enforce the limit before allocating for an inbound message. Protocol overhead
    /// does not count toward this limit.
    ///
    /// Callers must enforce a deadline, for example with [utils::Timeout]. Dropping the handshake
    /// future cancels the attempt, and implementations must release the underlying connection.
    pub trait Handshake: Clone + Send + Sync + 'static {
        /// Largest plaintext message supported by the established streams, in bytes.
        const MAX_SIZE: u32;

        /// Public key identifying an authenticated peer.
        type PublicKey;

        /// Error returned when authentication or stream setup fails.
        type Error: Error + Send + Sync + 'static;

        /// Sender returned for a connection using raw stream `I` and sink `O`.
        type Sender<I: Stream, O: Sink>: Sender;

        /// Receiver returned for a connection using raw stream `I` and sink `O`.
        type Receiver<I: Stream, O: Sink>: Receiver;

        /// Returns the local authenticated identity.
        ///
        /// The identity must remain stable across attempts and clones of this handshake.
        fn public_key(&self) -> Self::PublicKey;

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
            peer: Self::PublicKey,
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
                (Self::PublicKey, Self::Sender<I, O>, Self::Receiver<I, O>),
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
        /// An empty batch succeeds without sending data.
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

    /// Record layer that protects messages with one cipher per direction.
    ///
    /// A [Handshake] establishes the two ciphers and uses [Records::split] to build the returned
    /// [Sender] and [Receiver].
    pub trait Records: Clone + Send + Sync + 'static {
        /// Cipher that seals and opens records.
        type Cipher: Cipher;

        /// Sender that writes records to sink `O`.
        type Sender<O: Sink>: Sender;

        /// Receiver that reads records from stream `I`.
        type Receiver<I: Stream>: Receiver;

        /// Largest plaintext message supported, in bytes.
        const MAX_SIZE: u32;

        /// Returns the namespace that identifies this record format.
        ///
        /// Record formats that differ must return different namespaces.
        fn namespace(&self) -> &'static [u8];

        /// Returns halves that protect records with `send` and `recv`.
        ///
        /// Callers must supply a `max_message_size` no greater than [Self::MAX_SIZE].
        fn split<I: Stream, O: Sink>(
            &self,
            send: Self::Cipher,
            recv: Self::Cipher,
            stream: I,
            sink: O,
            max_message_size: u32,
            pool: BufferPool,
        ) -> (Self::Sender<O>, Self::Receiver<I>);
    }

    /// Authenticates a raw connection and agrees on one [Cipher] per direction.
    ///
    /// Implementations must authenticate each peer's declared identity and bind the supplied
    /// application namespace and both peer identities to the agreed ciphers. A successful dial must
    /// authenticate the expected peer. A listen may succeed only if the bouncer returns `true` for
    /// the same authenticated peer that is returned. Implementations should also bind `records`,
    /// the [namespace](Records::namespace) of the record format the ciphers will key, so that peers
    /// with different record formats fail the exchange.
    ///
    /// Callers must enforce a deadline, for example with [utils::Timeout]. Dropping the exchange
    /// future cancels the attempt.
    pub trait Exchange: Clone + Send + Sync + 'static {
        /// Public key identifying an authenticated peer.
        type PublicKey: Send;

        /// Error returned when authentication fails.
        type Error: Error + Send + Sync + 'static;

        /// Returns the local authenticated identity.
        ///
        /// The identity must remain stable across attempts and clones of this exchange.
        fn public_key(&self) -> Self::PublicKey;

        /// Authenticates an outbound connection to `peer` and returns the send and receive
        /// ciphers.
        fn dial<C, E, I, O>(
            self,
            context: E,
            namespace: &[u8],
            records: &'static [u8],
            peer: Self::PublicKey,
            stream: &mut I,
            sink: &mut O,
        ) -> impl Future<Output = Result<(C, C), Self::Error>> + Send
        where
            C: Cipher,
            E: Clock + CryptoRng,
            I: Stream,
            O: Sink;

        /// Authenticates an inbound connection accepted by `bouncer` and returns the peer with the
        /// send and receive ciphers.
        ///
        /// The bouncer may receive an unverified identity claim before authentication completes.
        /// Accepting this claim permits authentication to continue. Only a successful exchange
        /// proves the returned peer's identity.
        fn listen<C, E, I, O, B, F>(
            self,
            context: E,
            namespace: &[u8],
            records: &'static [u8],
            bouncer: B,
            stream: &mut I,
            sink: &mut O,
        ) -> impl Future<Output = Result<(Self::PublicKey, C, C), Self::Error>> + Send
        where
            C: Cipher,
            E: Clock + CryptoRng,
            I: Stream,
            O: Sink,
            B: FnOnce(Self::PublicKey) -> F + Send,
            F: Future<Output = bool> + Send;
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::utils::{Timeout, TimeoutError};
        use commonware_cryptography::ChaCha20Poly1305;
        use commonware_runtime::{Runner as _, Supervisor as _, deterministic, mocks};
        use commonware_utils::sync::Mutex;
        use futures::{FutureExt as _, future::Either};
        use std::{
            convert::Infallible,
            future,
            marker::PhantomData,
            rc::Rc,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            time::Duration,
        };

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

        #[derive(Clone, Copy, Debug)]
        enum Outcome {
            Success,
            Error,
            Pending,
        }

        #[derive(Debug, thiserror::Error)]
        #[error("authentication rejected")]
        struct Rejected;

        #[derive(Clone, Debug, PartialEq, Eq)]
        struct HandshakeParameters {
            namespace: Vec<u8>,
            max_message_size: u32,
        }

        #[derive(Clone)]
        struct OpaqueHandshake {
            outcome: Outcome,
            received: Arc<Mutex<Vec<HandshakeParameters>>>,
        }

        impl OpaqueHandshake {
            fn new(outcome: Outcome) -> Self {
                Self {
                    outcome,
                    received: Arc::default(),
                }
            }

            async fn establish<I: Stream, O: Sink>(
                self,
                stream: I,
                sink: O,
            ) -> Result<(SharedHalf<I, O>, SharedHalf<I, O>), Rejected> {
                if matches!(self.outcome, Outcome::Pending) {
                    future::pending::<()>().await;
                }
                if matches!(self.outcome, Outcome::Error) {
                    return Err(Rejected);
                }
                let session = Arc::new(Session {
                    _stream: stream,
                    _sink: sink,
                });
                Ok((
                    SharedHalf {
                        _session: session.clone(),
                    },
                    SharedHalf { _session: session },
                ))
            }
        }

        impl Handshake for OpaqueHandshake {
            const MAX_SIZE: u32 = <cups::Cups<ChaCha20Poly1305> as Records>::MAX_SIZE;

            type PublicKey = OpaqueIdentity;
            type Error = Rejected;
            type Sender<I: Stream, O: Sink> = SharedHalf<I, O>;
            type Receiver<I: Stream, O: Sink> = SharedHalf<I, O>;

            fn public_key(&self) -> Self::PublicKey {
                OpaqueIdentity(PhantomData)
            }

            fn dial<C, I, O>(
                self,
                _context: C,
                namespace: &[u8],
                max_message_size: u32,
                _peer: Self::PublicKey,
                stream: I,
                sink: O,
            ) -> impl Future<Output = Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>> + Send
            where
                C: BufferPooler + Clock + CryptoRng,
                I: Stream,
                O: Sink,
            {
                self.received.lock().push(HandshakeParameters {
                    namespace: namespace.to_vec(),
                    max_message_size,
                });
                self.establish(stream, sink)
            }

            fn listen<C, I, O, B, F>(
                self,
                _context: C,
                namespace: &[u8],
                max_message_size: u32,
                bouncer: B,
                stream: I,
                sink: O,
            ) -> impl Future<
                Output = Result<
                    (Self::PublicKey, Self::Sender<I, O>, Self::Receiver<I, O>),
                    Self::Error,
                >,
            > + Send
            where
                C: BufferPooler + Clock + CryptoRng,
                I: Stream,
                O: Sink,
                B: FnOnce(Self::PublicKey) -> F + Send,
                F: Future<Output = bool> + Send,
            {
                self.received.lock().push(HandshakeParameters {
                    namespace: namespace.to_vec(),
                    max_message_size,
                });
                let accepted = bouncer(self.public_key());
                async move {
                    if !accepted.await {
                        return Err(Rejected);
                    }
                    let (sender, receiver) = self.establish(stream, sink).await?;
                    Ok((OpaqueIdentity(PhantomData), sender, receiver))
                }
            }
        }

        /// Reuses one handshake for repeated dials and listens and forwards each call's namespace
        /// and maximum message size to the inner handshake.
        #[test]
        fn handshake_supports_opaque_identity_and_shared_session() {
            fn assert_send<T: Send>(_: T) {}

            deterministic::Runner::default().start(|context| async move {
                for (namespace, max_message_size) in [
                    (vec![1, 2, 3], 1),
                    (b"configured".to_vec(), OpaqueHandshake::MAX_SIZE),
                ] {
                    let handshake = OpaqueHandshake::new(Outcome::Success);
                    let received = handshake.received.clone();
                    let handshake = Timeout::new(handshake, Duration::from_secs(1));
                    let _: OpaqueIdentity = handshake.public_key();

                    // Reuse one handshake for multiple connections in each direction.
                    for _ in 0..2 {
                        let (sink, stream) = mocks::Channel::init();
                        assert_send(handshake.clone().dial(
                            context.child("dialer"),
                            &namespace,
                            max_message_size,
                            OpaqueIdentity(PhantomData),
                            stream,
                            sink,
                        ));
                        let (sink, stream) = mocks::Channel::init();
                        let accepted = true;
                        assert_send(handshake.clone().listen(
                            context.child("listener"),
                            &namespace,
                            max_message_size,
                            |_| async { accepted },
                            stream,
                            sink,
                        ));
                    }
                    assert_eq!(
                        *received.lock(),
                        vec![HandshakeParameters {
                            namespace,
                            max_message_size,
                        }; 4]
                    );
                }
            });
        }

        /// Measures the handshake deadline from the dial or listen call, not the first poll, and
        /// releases the transport once the attempt expires.
        #[test]
        fn handshake_starts_timeout_when_called() {
            for dialer in [false, true] {
                deterministic::Runner::timed(Duration::from_secs(1)).start(|context| async move {
                    let (sink, mut peer_stream) = mocks::Channel::init();
                    let (mut peer_sink, stream) = mocks::Channel::init();
                    let handshake =
                        Timeout::new(OpaqueHandshake::new(Outcome::Pending), Duration::from_millis(50));
                    let attempt = if dialer {
                        Either::Left(handshake.dial(
                            context.child("handshake"),
                            b"timeout",
                            1,
                            OpaqueIdentity(PhantomData),
                            stream,
                            sink,
                        ))
                    } else {
                        Either::Right(
                            handshake
                                .listen(
                                    context.child("handshake"),
                                    b"timeout",
                                    1,
                                    |_| async { true },
                                    stream,
                                    sink,
                                )
                                .map(|result| result.map(|(_, sender, receiver)| (sender, receiver))),
                        )
                    };
                    let mut attempt = Box::pin(attempt);

                    // An unpolled attempt expires relative to the method call.
                    context.sleep(Duration::from_millis(100)).await;
                    assert!(matches!(
                        futures::poll!(attempt.as_mut()),
                        std::task::Poll::Ready(Err(TimeoutError::Timeout))
                    ));
                    drop(attempt);
                    assert!(peer_sink.send(&b"x"[..]).await.is_err());
                    assert!(peer_stream.recv(1).await.is_err());
                });
            }
        }

        #[test]
        fn timeout_preserves_results_and_releases_connections() {
            for dialer in [false, true] {
                for outcome in [Outcome::Success, Outcome::Error, Outcome::Pending] {
                    for duration in [Duration::ZERO, Duration::from_millis(50)] {
                        deterministic::Runner::timed(Duration::from_secs(1)).start(
                            |context| async move {
                                let (sink, mut peer_stream) = mocks::Channel::init();
                                let (mut peer_sink, stream) = mocks::Channel::init();
                                let handshake = Timeout::new(OpaqueHandshake::new(outcome), duration);
                                let start = context.current();
                                let result = if dialer {
                                    handshake
                                        .dial(
                                            context.child("handshake"),
                                            b"timeout",
                                            1,
                                            OpaqueIdentity(PhantomData),
                                            stream,
                                            sink,
                                        )
                                        .await
                                } else {
                                    handshake
                                        .listen(
                                            context.child("handshake"),
                                            b"timeout",
                                            1,
                                            |_| async { true },
                                            stream,
                                            sink,
                                        )
                                        .await
                                        .map(|(_, sender, receiver)| (sender, receiver))
                                };
                                match outcome {
                                    Outcome::Success => assert!(result.is_ok()),
                                    Outcome::Error => assert!(matches!(
                                        result,
                                        Err(TimeoutError::Handshake(Rejected))
                                    )),
                                    Outcome::Pending => {
                                        assert!(matches!(result, Err(TimeoutError::Timeout)));
                                        let elapsed = context.current().duration_since(start).unwrap();
                                        assert!(
                                            elapsed >= duration
                                                && elapsed < duration + Duration::from_millis(1)
                                        );
                                    }
                                }
                                drop(result);
                                assert!(peer_sink.send(&b"x"[..]).await.is_err());
                                assert!(peer_stream.recv(1).await.is_err());
                            },
                        );
                    }
                }
            }
        }

        #[test]
        fn timeout_cancels_pending_admission() {
            struct Admission(Arc<AtomicBool>);
            impl Drop for Admission {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }

            for cancel in [false, true] {
                deterministic::Runner::timed(Duration::from_secs(1)).start(|context| async move {
                    let (sink, mut peer_stream) = mocks::Channel::init();
                    let (mut peer_sink, stream) = mocks::Channel::init();
                    let dropped = Arc::new(AtomicBool::new(false));
                    let admission = Admission(dropped.clone());
                    let handshake =
                        Timeout::new(OpaqueHandshake::new(Outcome::Success), Duration::from_millis(50));
                    let mut attempt = Box::pin(handshake.listen(
                        context,
                        b"timeout",
                        1,
                        |_| async move {
                            future::pending::<()>().await;
                            drop(admission);
                            true
                        },
                        stream,
                        sink,
                    ));
                    assert!(futures::poll!(attempt.as_mut()).is_pending());
                    assert!(!dropped.load(Ordering::Relaxed));
                    if cancel {
                        drop(attempt);
                    } else {
                        assert!(matches!(attempt.await, Err(TimeoutError::Timeout)));
                    }
                    assert!(dropped.load(Ordering::Relaxed));
                    assert!(peer_sink.send(&b"x"[..]).await.is_err());
                    assert!(peer_stream.recv(1).await.is_err());
                });
            }
        }

        #[test]
        fn timeout_starts_when_called() {
            deterministic::Runner::timed(Duration::from_secs(1)).start(|context| async move {
                let (sink, stream) = mocks::Channel::init();
                let handshake =
                    Timeout::new(OpaqueHandshake::new(Outcome::Pending), Duration::from_millis(50));
                let mut attempt = Box::pin(handshake.dial(
                    context.child("handshake"),
                    b"timeout",
                    1,
                    OpaqueIdentity(PhantomData),
                    stream,
                    sink,
                ));
                context.sleep(Duration::from_millis(100)).await;
                assert!(matches!(
                    futures::poll!(attempt.as_mut()),
                    std::task::Poll::Ready(Err(TimeoutError::Timeout))
                ));
            });
        }
    }
});
