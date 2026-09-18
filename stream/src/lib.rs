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
    use commonware_runtime::{BufferPooler, Clock, IoBufs, Sink, Stream};
    use rand_core::CryptoRng;
    use std::{error::Error, future::Future};

    pub mod encrypted;
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::utils::{Timeout, TimeoutError};
        use commonware_runtime::{Runner as _, Supervisor as _, deterministic, mocks};
        use std::time::Duration;
        use std::{
            convert::Infallible,
            future,
            marker::PhantomData,
            rc::Rc,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
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

        #[derive(Clone)]
        struct OpaqueHandshake(Outcome);

        impl OpaqueHandshake {
            async fn establish<I: Stream, O: Sink>(
                self,
                stream: I,
                sink: O,
            ) -> Result<(SharedHalf<I, O>, SharedHalf<I, O>), Rejected> {
                if matches!(self.0, Outcome::Pending) {
                    future::pending::<()>().await;
                }
                if matches!(self.0, Outcome::Error) {
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
            const MAX_SIZE: u32 = encrypted::MAX_SIZE;

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
                _namespace: &[u8],
                _max_message_size: u32,
                _peer: Self::PublicKey,
                stream: I,
                sink: O,
            ) -> impl Future<Output = Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>> + Send
            where
                C: BufferPooler + Clock + CryptoRng,
                I: Stream,
                O: Sink,
            {
                self.establish(stream, sink)
            }

            fn listen<C, I, O, B, F>(
                self,
                _context: C,
                _namespace: &[u8],
                _max_message_size: u32,
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

        #[test]
        fn handshake_supports_opaque_identity_and_shared_session() {
            fn assert_send<T: Send>(_: T) {}

            deterministic::Runner::default().start(|context| async move {
                let handshake = Timeout::new(OpaqueHandshake(Outcome::Success), Duration::from_secs(1));
                let _: OpaqueIdentity = handshake.public_key();
                let namespace = vec![1, 2, 3];
                let (sink, stream) = mocks::Channel::init();
                assert_send(handshake.clone().dial(
                    context.child("handshake"),
                    &namespace,
                    1,
                    handshake.public_key(),
                    stream,
                    sink,
                ));
                let (sink, stream) = mocks::Channel::init();
                let accepted = true;
                assert_send(handshake.listen(
                    context,
                    &namespace,
                    1,
                    |_| async { accepted },
                    stream,
                    sink,
                ));
            });
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
                                let handshake = Timeout::new(OpaqueHandshake(outcome), duration);
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
                        Timeout::new(OpaqueHandshake(Outcome::Success), Duration::from_millis(50));
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
                    Timeout::new(OpaqueHandshake(Outcome::Pending), Duration::from_millis(50));
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
