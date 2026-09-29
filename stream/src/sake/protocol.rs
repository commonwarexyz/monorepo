use crate::utils::codec::{Error as FrameError, recv_frame, send_frame};
use commonware_codec::{DecodeExt, Encode, Error as CodecError, FixedSize};
use commonware_cryptography::{
    Cipher, Signer,
    handshake::sake::{
        Ack, Context, Error as HandshakeError, Syn, SynAck, Version, dial_end, dial_start,
        listen_end, listen_start,
    },
};
use commonware_formatting::hex;
use commonware_runtime::{Clock, Sink, Stream};
use commonware_utils::{DurationExt, SystemTimeExt};
use rand_core::CryptoRng;
use std::{future::Future, time::Duration};
use thiserror::Error;

/// Errors that can occur during a SAKE handshake.
#[derive(Error, Debug)]
pub enum Error {
    #[error("handshake error: {0}")]
    HandshakeError(HandshakeError),
    #[error("unable to decode: {0}")]
    UnableToDecode(CodecError),
    #[error("peer rejected: {}", hex(_0))]
    PeerRejected(Vec<u8>),
    #[error(transparent)]
    Frame(#[from] FrameError),
}

impl From<CodecError> for Error {
    fn from(value: CodecError) -> Self {
        Self::UnableToDecode(value)
    }
}

impl From<HandshakeError> for Error {
    fn from(value: HandshakeError) -> Self {
        Self::HandshakeError(value)
    }
}

/// Implements [crate::Handshake] with SAKE.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{ChaCha20Poly1305, Signer as _, ed25519::PrivateKey};
/// use commonware_stream::{cups::{self, Cups}, sake::{Sake, Version}};
/// use std::time::Duration;
///
/// let upgrader = Cups::<_, ChaCha20Poly1305>::new(
///     Sake {
///         signer: PrivateKey::from_seed(0),
///         synchrony_bound: Duration::from_secs(5),
///         max_handshake_age: Duration::from_secs(10),
///         version: Version::V1,
///     },
///     cups::Version::V1,
/// );
/// ```
#[derive(Clone)]
pub struct Sake<S> {
    /// Signer used to authenticate the local peer.
    pub signer: S,

    /// Maximum time drift allowed for future timestamps.
    pub synchrony_bound: Duration,

    /// Maximum age of handshake messages before rejection.
    pub max_handshake_age: Duration,

    /// SAKE version.
    pub version: Version,
}

impl<S> Sake<S> {
    /// Returns the SAKE context for a handshake with `peer` in `namespace`.
    fn context<P>(self, clock: &impl Clock, namespace: &[u8], peer: P) -> Context<S, P> {
        // Accept peer timestamps from `max_handshake_age` before now up to, but excluding,
        // `synchrony_bound` after now.
        let current_time = clock.current().epoch().as_millis_u64();
        let ok_timestamps = current_time.saturating_sub(self.max_handshake_age.as_millis_u64())
            ..current_time.saturating_add(self.synchrony_bound.as_millis_u64());
        Context::new(
            namespace,
            current_time,
            ok_timestamps,
            self.signer,
            peer,
            self.version,
        )
    }
}

/// Sends a handshake message bounded by its fixed encoded size.
async fn send_handshake_frame<M, T>(sink: &mut T, message: M) -> Result<(), FrameError>
where
    M: Encode + FixedSize,
    T: Sink,
{
    let max_size = u32::try_from(M::SIZE).expect("handshake frame should fit in u32");
    send_frame(sink, message.encode(), max_size).await
}

/// Receives and decodes a handshake message bounded by its fixed encoded size.
async fn recv_handshake_frame<M, T>(stream: &mut T) -> Result<M, Error>
where
    M: DecodeExt<()> + FixedSize,
    T: Stream,
{
    let frame = recv_frame(
        stream,
        u32::try_from(M::SIZE).expect("handshake frame should fit in u32"),
    )
    .await?;
    Ok(M::decode(frame)?)
}

impl<S: Signer> crate::Handshake for Sake<S> {
    type PublicKey = S::PublicKey;
    type Error = Error;

    fn public_key(&self) -> Self::PublicKey {
        self.signer.public_key()
    }

    async fn dial<C, E, I, O>(
        self,
        context: E,
        namespace: &[u8],
        peer: S::PublicKey,
        stream: &mut I,
        sink: &mut O,
    ) -> Result<(C, C), Self::Error>
    where
        C: Cipher,
        E: Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        // Send the local identity as a cleartext prelude. The listener passes it to its bouncer and
        // binds it into its SAKE context.
        send_handshake_frame(sink, self.signer.public_key()).await?;

        let sake = self.context(&context, namespace, peer);
        let (state, syn) = dial_start(context, sake);
        send_handshake_frame(sink, syn).await?;

        let syn_ack = recv_handshake_frame::<SynAck<S::Signature>, _>(stream).await?;

        let (ack, send, recv) = dial_end(state, syn_ack)?;
        send_handshake_frame(sink, ack).await?;
        Ok((send, recv))
    }

    async fn listen<C, E, I, O, B, F>(
        self,
        context: E,
        namespace: &[u8],
        bouncer: B,
        stream: &mut I,
        sink: &mut O,
    ) -> Result<(S::PublicKey, C, C), Self::Error>
    where
        C: Cipher,
        E: Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(S::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        // Consult the bouncer on the unauthenticated claim before any handshake work. Only a
        // successful `listen_end` authenticates it.
        let peer = recv_handshake_frame::<S::PublicKey, _>(stream).await?;
        if !bouncer(peer.clone()).await {
            return Err(Error::PeerRejected(peer.encode().to_vec()));
        }

        let msg1 = recv_handshake_frame::<Syn<S::Signature>, _>(stream).await?;

        // Read the clock only after the Syn arrives, so the acceptance window and the SynAck
        // timestamp reflect when the Syn is checked.
        let sake = self.context(&context, namespace, peer.clone());
        let (state, syn_ack) = listen_start(context, sake, msg1)?;
        send_handshake_frame(sink, syn_ack).await?;

        let ack = recv_handshake_frame::<Ack, _>(stream).await?;

        let (send, recv) = listen_end(state, ack)?;
        Ok((peer, send, recv))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        Upgrader as _,
        cups::{self, Cups},
        utils::{Timeout, TimeoutError},
    };
    use commonware_codec::varint::UInt;
    use commonware_cryptography::{ChaCha20Poly1305, Signer, ed25519::PrivateKey};
    use commonware_runtime::{
        BufMut, BufferPool, BufferPoolConfig, BufferPooler as _, Error as RuntimeError, IoBuf,
        IoBufs, Runner as _, Spawner as _, Supervisor as _, deterministic, mocks,
    };
    use commonware_utils::{NZU32, NZUsize, sync::Mutex};
    use futures::FutureExt as _;
    use std::{
        ops::Range,
        panic::AssertUnwindSafe,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    const NAMESPACE: &[u8] = b"fuzz_transport";
    /// Default `max_message_size` passed to dial and listen.
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    type TestCups = Cups<(), ChaCha20Poly1305>;
    type TestUpgrade = Cups<Sake<PrivateKey>, ChaCha20Poly1305>;

    /// Returns the record version that pairs with the SAKE `version`.
    const fn record_version(version: Version) -> cups::Version {
        match version {
            Version::V0 => cups::Version::V0,
            Version::V1 => cups::Version::V1,
        }
    }

    /// Checks that a closed peer fails the first handshake frame with a send error.
    #[test]
    fn test_frame_errors_surface_as_handshake_errors() {
        deterministic::Runner::default().start(|context| async move {
            let (sink, peer_stream) = mocks::Channel::init();
            let (_peer_sink, stream) = mocks::Channel::init();
            drop(peer_stream);
            let result = matched(PrivateKey::from_seed(0), Version::V1)
                .dial(
                    context.child("dialer"),
                    NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    PrivateKey::from_seed(1).public_key(),
                    stream,
                    sink,
                )
                .await;
            assert!(matches!(
                result,
                Err(Error::Frame(FrameError::SendFailed(_)))
            ));
        });
    }

    /// Checks that the upgrader limit equals the record limit, and that dial and listen panic
    /// only when `max_message_size` exceeds it.
    #[test]
    fn test_max_message_size_bounds() {
        const MAX_SIZE: u32 = <TestUpgrade as crate::Upgrader>::MAX_SIZE;
        assert_eq!(MAX_SIZE, TestCups::MAX_SIZE);
        deterministic::Runner::default().start(|context| async move {
            for max_message_size in [0, MAX_SIZE, MAX_SIZE + 1] {
                for dialer in [true, false] {
                    let (sink, _) = mocks::Channel::init();
                    let (_, stream) = mocks::Channel::init();
                    let handshake = matched(PrivateKey::from_seed(0), Version::V1);
                    let attempt = async {
                        if dialer {
                            handshake
                                .dial(
                                    context.child("dialer"),
                                    NAMESPACE,
                                    max_message_size,
                                    PrivateKey::from_seed(1).public_key(),
                                    stream,
                                    sink,
                                )
                                .await
                                .map(|_| ())
                        } else {
                            handshake
                                .listen(
                                    context.child("listener"),
                                    NAMESPACE,
                                    max_message_size,
                                    |_| async { true },
                                    stream,
                                    sink,
                                )
                                .await
                                .map(|_| ())
                        }
                    };
                    let result = AssertUnwindSafe(attempt).catch_unwind().await;

                    // Within the limit, the attempt reaches the dropped channel ends and fails
                    // without panicking.
                    if max_message_size <= MAX_SIZE {
                        assert!(result.unwrap().is_err());
                    } else {
                        assert_eq!(
                            result.err().unwrap().downcast_ref::<&str>(),
                            Some(&"maximum message size exceeds stream limit")
                        );
                    }
                }
            }
        });
    }

    /// Returns an upgrader that runs SAKE `version` with `signer` and CUPS `records`.
    fn upgrader(signer: PrivateKey, version: Version, records: cups::Version) -> TestUpgrade {
        Cups::new(
            Sake {
                signer,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                version,
            },
            records,
        )
    }

    /// Returns an upgrader that runs SAKE `version` with `signer` and the matching CUPS version.
    fn matched(signer: PrivateKey, version: Version) -> TestUpgrade {
        upgrader(signer, version, record_version(version))
    }

    /// Returns a frame length prefix that declares one byte more than the encoding of `message`.
    fn oversized_handshake_prefix(message: &impl Encode) -> IoBuf {
        let size = u32::try_from(message.encode().len()).expect("message length should fit in u32");
        IoBuf::from(UInt(size + 1).encode())
    }

    /// Wraps a sink to count `send` calls and record each call's chunk count.
    struct CountingSink<S> {
        inner: S,
        sends: Arc<AtomicUsize>,
        chunk_counts: Arc<Mutex<Vec<usize>>>,
    }

    impl<S> CountingSink<S> {
        fn new(inner: S, sends: Arc<AtomicUsize>, chunk_counts: Arc<Mutex<Vec<usize>>>) -> Self {
            Self {
                inner,
                sends,
                chunk_counts,
            }
        }
    }

    impl<S: commonware_runtime::Sink> commonware_runtime::Sink for CountingSink<S> {
        async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), RuntimeError> {
            let bufs = bufs.into();
            self.sends.fetch_add(1, Ordering::Relaxed);
            self.chunk_counts.lock().push(bufs.chunk_count());
            self.inner.send(bufs).await
        }
    }

    /// Wraps a stream to return each read as a fresh, uniquely-owned pooled
    /// buffer, mirroring the production network backends.
    ///
    /// Records the allocation handed out by the most recent read so tests can
    /// assert that decryption happened in place.
    struct PoolingStream<S> {
        inner: S,
        pool: BufferPool,
        last_alloc: Arc<Mutex<Range<usize>>>,
    }

    impl<S: commonware_runtime::Stream> commonware_runtime::Stream for PoolingStream<S> {
        async fn recv(&mut self, len: usize) -> Result<IoBufs, RuntimeError> {
            let mut bufs = self.inner.recv(len).await?;
            let mut buf = self.pool.alloc(len);
            buf.put(&mut bufs);
            let buf = buf.freeze();
            let start = buf.as_ref().as_ptr() as usize;
            *self.last_alloc.lock() = start..start + buf.len();
            Ok(buf.into())
        }

        fn peek(&self, max_len: usize) -> &[u8] {
            self.inner.peek(max_len)
        }
    }

    /// Checks that a dialer and listener at the same version establish streams that reject payloads
    /// above `max_message_size` and exchange messages in both directions.
    #[test]
    fn test_can_setup_and_send_messages() -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
            for max_message_size in [0, 1, 100, MAX_MESSAGE_SIZE] {
                let executor = deterministic::Runner::timed(Duration::from_secs(5));
                executor.start(move |context| async move {
                    // Handshake frames are bounded by their fixed sizes, so the handshake succeeds
                    // even when `max_message_size` is 0.
                    let dialer_signer = PrivateKey::from_seed(42);
                    let listener_signer = PrivateKey::from_seed(24);

                    let (dialer_sink, listener_stream) = mocks::Channel::init();
                    let (listener_sink, dialer_stream) = mocks::Channel::init();

                    let dialer_handshake = matched(dialer_signer.clone(), version);
                    let listener_handshake = matched(listener_signer.clone(), version);

                    // Run both sides of the handshake.
                    let listener_handle =
                        context.child("listener").spawn(move |context| async move {
                            Timeout::new(listener_handshake, Duration::from_secs(1))
                                .listen(
                                    context,
                                    NAMESPACE,
                                    max_message_size,
                                    |_| async { true },
                                    listener_stream,
                                    listener_sink,
                                )
                                .await
                        });

                    let (mut dialer_sender, mut dialer_receiver) =
                        Timeout::new(dialer_handshake, Duration::from_secs(1))
                            .dial(
                                context,
                                NAMESPACE,
                                max_message_size,
                                listener_signer.public_key(),
                                dialer_stream,
                                dialer_sink,
                            )
                            .await?;

                    let (listener_peer, mut listener_sender, mut listener_receiver) =
                        listener_handle.await.unwrap()?;
                    assert_eq!(listener_peer, dialer_signer.public_key());

                    // The established streams accept only payloads within the configured limit.
                    let oversized = IoBuf::from(vec![0u8; max_message_size as usize + 1]);
                    assert!(matches!(
                        dialer_sender.send(oversized.clone()).await,
                        Err(cups::Error::SendTooLarge(_))
                    ));
                    assert!(matches!(
                        listener_sender.send(oversized).await,
                        Err(cups::Error::SendTooLarge(_))
                    ));

                    // Exchange each message within the limit in both directions.
                    let messages: [&[u8]; 4] = [b"", b"A", b"B", b"C"];
                    for msg in messages
                        .iter()
                        .filter(|msg| msg.len() <= max_message_size as usize)
                    {
                        dialer_sender.send(&msg[..]).await?;
                        let syn_ack = listener_receiver.recv().await?;
                        assert_eq!(syn_ack.coalesce(), *msg);
                        listener_sender.send(&msg[..]).await?;
                        let ack = dialer_receiver.recv().await?;
                        assert_eq!(ack.coalesce(), *msg);
                    }
                    Ok::<_, Box<dyn std::error::Error>>(())
                })?;
            }
        }
        Ok(())
    }

    /// Connects a dialer and a listener configured with the given SAKE versions and records, then
    /// sends one message from the dialer to the listener.
    ///
    /// Returns the handshake error, or the result of receiving that message.
    fn connect_with(
        dialer: (Version, cups::Version),
        listener: (Version, cups::Version),
    ) -> Result<Result<(), cups::Error>, Error> {
        let executor = deterministic::Runner::timed(Duration::from_secs(5));
        executor.start(move |context| async move {
            let dialer_signer = PrivateKey::from_seed(42);
            let listener_signer = PrivateKey::from_seed(24);
            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let dialer_handshake = upgrader(dialer_signer.clone(), dialer.0, dialer.1);
            let listener_handshake = upgrader(listener_signer.clone(), listener.0, listener.1);

            // Run both sides of the handshake.
            let listener_handle = context.child("listener").spawn(move |context| async move {
                listener_handshake
                    .listen(
                        context,
                        NAMESPACE,
                        MAX_MESSAGE_SIZE,
                        |_| async { true },
                        listener_stream,
                        listener_sink,
                    )
                    .await
            });
            let listener_public_key = listener_signer.public_key();
            let dialer_handle = context.child("dialer").spawn(move |context| async move {
                dialer_handshake
                    .dial(
                        context,
                        NAMESPACE,
                        MAX_MESSAGE_SIZE,
                        listener_public_key,
                        dialer_stream,
                        dialer_sink,
                    )
                    .await
            });

            // The listener verifies the first signed message, so its error is the informative one.
            let (peer, _, mut receiver) = listener_handle.await.unwrap()?;
            assert_eq!(peer, dialer_signer.public_key());
            let (mut sender, _) = dialer_handle.await.unwrap()?;

            // Send one message and report whether it arrives intact.
            sender.send(&b"hello"[..]).await.unwrap();
            Ok(receiver.recv().await.map(|message| {
                assert_eq!(message.coalesce(), &b"hello"[..]);
            }))
        })
    }

    /// Checks that a handshake succeeds only when the dialer and listener run the same version.
    #[test]
    fn test_versions() {
        for dialer in [Version::V0, Version::V1] {
            for listener in [Version::V0, Version::V1] {
                let result = connect_with(
                    (dialer, record_version(dialer)),
                    (listener, record_version(listener)),
                );
                if dialer == listener {
                    result.unwrap().unwrap();
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::HandshakeError(HandshakeError::HandshakeFailed))
                    ));
                }
            }
        }
    }

    /// Checks that peers with different record versions complete the handshake and then fail to
    /// open the first record.
    #[test]
    fn test_record_versions() {
        for version in [Version::V0, Version::V1] {
            let result = connect_with((version, cups::Version::V0), (version, cups::Version::V1));
            assert!(matches!(result, Ok(Err(cups::Error::OpenFailed))));
        }
    }

    /// Checks that the listener decrypts each record in place, inside the pooled buffer its stream
    /// read returned.
    #[test]
    fn test_recv_decrypts_unique_frame_in_place() -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let dialer_signer = PrivateKey::from_seed(42);
                let listener_signer = PrivateKey::from_seed(24);

                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();

                let last_alloc = Arc::new(Mutex::new(0..0));
                let listener_stream = PoolingStream {
                    inner: listener_stream,
                    pool: context.network_buffer_pool().clone(),
                    last_alloc: last_alloc.clone(),
                };

                let dialer_handshake = matched(dialer_signer, version);
                let listener_handshake = matched(listener_signer.clone(), version);

                let listener_handle = context.child("listener").spawn(move |context| async move {
                    Timeout::new(listener_handshake, Duration::from_secs(1))
                        .listen(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            listener_stream,
                            listener_sink,
                        )
                        .await
                });

                let (mut dialer_sender, _dialer_receiver) =
                    Timeout::new(dialer_handshake, Duration::from_secs(1))
                        .dial(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            listener_signer.public_key(),
                            dialer_stream,
                            dialer_sink,
                        )
                        .await?;

                let (_, _, mut listener_receiver) = listener_handle.await.unwrap()?;

                // Buffer both records so V0 also exercises in-place decryption of a frame sliced
                // past its length prefix.
                dialer_sender.send(&b"hello"[..]).await?;
                dialer_sender.send(&b"world"[..]).await?;

                for expected in [&b"hello"[..], &b"world"[..]] {
                    let received = listener_receiver.recv().await?;
                    let plaintext = received.as_single().expect("single buffer expected");
                    let ptr = plaintext.as_ref().as_ptr() as usize;
                    assert!(
                        last_alloc.lock().contains(&ptr),
                        "plaintext should reuse the received frame buffer"
                    );
                    assert_eq!(plaintext.as_ref(), expected);
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
    }

    /// Checks that `send_many` of small messages reaches the sink as one single-chunk send.
    #[test]
    fn test_send_many_uses_single_runtime_send() -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let dialer_signer = PrivateKey::from_seed(42);
                let listener_signer = PrivateKey::from_seed(24);

                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();
                let sends = Arc::new(AtomicUsize::new(0));
                let chunk_counts = Arc::new(Mutex::new(Vec::new()));

                let dialer_handshake = matched(dialer_signer.clone(), version);
                let listener_handshake = matched(listener_signer.clone(), version);

                let listener_handle = context.child("listener").spawn(move |context| async move {
                    Timeout::new(listener_handshake, Duration::from_secs(1))
                        .listen(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            listener_stream,
                            listener_sink,
                        )
                        .await
                });

                let (mut dialer_sender, _dialer_receiver) =
                    Timeout::new(dialer_handshake, Duration::from_secs(1))
                        .dial(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            listener_signer.public_key(),
                            dialer_stream,
                            CountingSink::new(dialer_sink, sends.clone(), chunk_counts.clone()),
                        )
                        .await?;

                let (_listener_peer, _listener_sender, mut listener_receiver) =
                    listener_handle.await.unwrap()?;

                // Discard the counts from the handshake frames.
                sends.store(0, Ordering::Relaxed);
                chunk_counts.lock().clear();

                // Three small messages should fit in one pooled chunk, so `send_many`
                // still reaches the runtime as a single single-chunk send call.
                dialer_sender
                    .send_many(vec![
                        IoBufs::from(IoBuf::from(b"alpha")),
                        IoBufs::from(IoBuf::from(b"beta")),
                        IoBufs::from(IoBuf::from(b"gamma")),
                    ])
                    .await?;

                assert_eq!(sends.load(Ordering::Relaxed), 1);
                assert_eq!(*chunk_counts.lock(), vec![1]);
                assert_eq!(
                    listener_receiver.recv().await?.coalesce(),
                    IoBuf::from(b"alpha")
                );
                assert_eq!(
                    listener_receiver.recv().await?.coalesce(),
                    IoBuf::from(b"beta")
                );
                assert_eq!(
                    listener_receiver.recv().await?.coalesce(),
                    IoBuf::from(b"gamma")
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
    }

    /// Checks that `send_many` starts a new chunk before one would exceed a network pool item, with
    /// at most one sink call per batch.
    #[test]
    fn test_send_many_flushes_at_network_pool_item_max() -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
            // Cap network pool items at 256 bytes.
            let executor = deterministic::Runner::new(
                deterministic::Config::new().with_network_buffer_pool_config(
                    BufferPoolConfig::for_network()
                        .with_pool_min_size(256)
                        .with_size_class_range(NZUsize!(256), NZUsize!(256), NZU32!(4096)),
                ),
            );
            executor.start(|context| async move {
                let dialer_signer = PrivateKey::from_seed(42);
                let listener_signer = PrivateKey::from_seed(24);

                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();
                let sends = Arc::new(AtomicUsize::new(0));
                let chunk_counts = Arc::new(Mutex::new(Vec::new()));

                let dialer_handshake = matched(dialer_signer.clone(), version);
                let listener_handshake = matched(listener_signer.clone(), version);

                let listener_handle = context.child("listener").spawn(move |context| async move {
                    Timeout::new(listener_handshake, Duration::from_secs(1))
                        .listen(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            listener_stream,
                            listener_sink,
                        )
                        .await
                });

                let (mut dialer_sender, _dialer_receiver) =
                    Timeout::new(dialer_handshake, Duration::from_secs(1))
                        .dial(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            listener_signer.public_key(),
                            dialer_stream,
                            CountingSink::new(dialer_sink, sends.clone(), chunk_counts.clone()),
                        )
                        .await?;

                let (_listener_peer, _listener_sender, mut listener_receiver) =
                    listener_handle.await.unwrap()?;

                // A V0 frame is 117 bytes (1 length prefix + 100 payload + 16 tag), and two fit
                // under the 256-byte cap. A V1 frame is 136 bytes (20 sealed header + 116 sealed
                // payload), and each occupies its own chunk. Zero through nine messages cover
                // empty, inline, and deque-backed batches with at most one sink call.
                for count in 0..=9usize {
                    sends.store(0, Ordering::Relaxed);
                    chunk_counts.lock().clear();
                    dialer_sender
                        .send_many((0..count).map(|index| IoBuf::from(vec![index as u8; 100])))
                        .await?;

                    if count == 0 {
                        assert_eq!(sends.load(Ordering::Relaxed), 0);
                        assert!(chunk_counts.lock().is_empty());
                    } else {
                        assert_eq!(sends.load(Ordering::Relaxed), 1);
                        let expected_chunks = if version == Version::V1 {
                            count
                        } else {
                            count.div_ceil(2)
                        };
                        assert_eq!(*chunk_counts.lock(), vec![expected_chunks]);
                    }
                    for index in 0..count {
                        let expected = [index as u8; 100];
                        assert_eq!(
                            listener_receiver.recv().await?.coalesce(),
                            expected.as_slice()
                        );
                    }
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
    }

    /// Checks that `send_many` places a frame larger than one network pool item in its own chunk
    /// instead of rejecting or merging it.
    #[test]
    fn test_send_many_sends_oversized_single_message_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
            // Cap network pool items at 128 bytes, below the frame of the 200-byte message.
            let executor = deterministic::Runner::new(
                deterministic::Config::new().with_network_buffer_pool_config(
                    BufferPoolConfig::for_network()
                        .with_pool_min_size(128)
                        .with_size_class_range(NZUsize!(128), NZUsize!(128), NZU32!(4096)),
                ),
            );
            executor.start(|context| async move {
                let dialer_signer = PrivateKey::from_seed(42);
                let listener_signer = PrivateKey::from_seed(24);

                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();
                let sends = Arc::new(AtomicUsize::new(0));
                let chunk_counts = Arc::new(Mutex::new(Vec::new()));

                let dialer_handshake = matched(dialer_signer.clone(), version);
                let listener_handshake = matched(listener_signer.clone(), version);

                let listener_handle = context.child("listener").spawn(move |context| async move {
                    Timeout::new(listener_handshake, Duration::from_secs(1))
                        .listen(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            listener_stream,
                            listener_sink,
                        )
                        .await
                });

                let (mut dialer_sender, _dialer_receiver) =
                    Timeout::new(dialer_handshake, Duration::from_secs(1))
                        .dial(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            listener_signer.public_key(),
                            dialer_stream,
                            CountingSink::new(dialer_sink, sends.clone(), chunk_counts.clone()),
                        )
                        .await?;

                let (_listener_peer, _listener_sender, mut listener_receiver) =
                    listener_handle.await.unwrap()?;

                // Discard the counts from the handshake frames.
                sends.store(0, Ordering::Relaxed);
                chunk_counts.lock().clear();

                // A single framed message larger than the cap still goes out, but it
                // must occupy its own chunk instead of being rejected or merged.
                let large = vec![3u8; 200];
                let small = vec![9u8; 16];
                dialer_sender
                    .send_many(vec![
                        IoBufs::from(IoBuf::from(large.clone())),
                        IoBufs::from(IoBuf::from(small.clone())),
                    ])
                    .await?;

                assert_eq!(sends.load(Ordering::Relaxed), 1);
                assert_eq!(*chunk_counts.lock(), vec![2]);
                assert_eq!(listener_receiver.recv().await?.coalesce(), large.as_slice());
                assert_eq!(listener_receiver.recv().await?.coalesce(), small.as_slice());
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
    }

    /// Checks that `send_many` rejects a batch with an oversized message before sending or sealing
    /// any of it, leaving the sender usable.
    #[test]
    fn test_send_many_too_large_preserves_sender_state() -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let dialer_signer = PrivateKey::from_seed(42);
                let listener_signer = PrivateKey::from_seed(24);

                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();
                let sends = Arc::new(AtomicUsize::new(0));
                let chunk_counts = Arc::new(Mutex::new(Vec::new()));

                let dialer_handshake = matched(dialer_signer.clone(), version);
                let listener_handshake = matched(listener_signer.clone(), version);

                let listener_handle = context.child("listener").spawn(move |context| async move {
                    Timeout::new(listener_handshake, Duration::from_secs(1))
                        .listen(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            |_| async { true },
                            listener_stream,
                            listener_sink,
                        )
                        .await
                });

                let (mut dialer_sender, _dialer_receiver) =
                    Timeout::new(dialer_handshake, Duration::from_secs(1))
                        .dial(
                            context,
                            NAMESPACE,
                            MAX_MESSAGE_SIZE,
                            listener_signer.public_key(),
                            dialer_stream,
                            CountingSink::new(dialer_sink, sends.clone(), chunk_counts.clone()),
                        )
                        .await?;

                let (_listener_peer, _listener_sender, mut listener_receiver) =
                    listener_handle.await.unwrap()?;

                // Discard the counts from the handshake frames.
                sends.store(0, Ordering::Relaxed);
                chunk_counts.lock().clear();

                // Reject a batch whose second message exceeds the limit.
                let valid = vec![7u8; 32];
                let oversized = vec![9u8; MAX_MESSAGE_SIZE as usize + 1];
                assert!(matches!(
                    dialer_sender
                        .send_many(vec![
                            IoBufs::from(IoBuf::from(valid)),
                            IoBufs::from(IoBuf::from(oversized)),
                        ])
                        .await,
                    Err(cups::Error::SendTooLarge(_))
                ));

                assert_eq!(sends.load(Ordering::Relaxed), 0);
                assert!(chunk_counts.lock().is_empty());

                // The next record opens, so the rejected batch sealed nothing.
                let recovered = b"recovered";
                dialer_sender.send(&recovered[..]).await?;
                assert_eq!(sends.load(Ordering::Relaxed), 1);
                assert_eq!(listener_receiver.recv().await?.coalesce(), recovered);
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
    }

    /// Checks that the listener bounds the unauthenticated peer-key frame by the public key size
    /// instead of `max_message_size`.
    #[test]
    fn test_listen_rejects_oversized_fixed_size_peer_key_frame() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_signer = PrivateKey::from_seed(42);
            let listener_signer = PrivateKey::from_seed(24);
            let peer = dialer_signer.public_key();

            let (mut dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, _dialer_stream) = mocks::Channel::init();

            // Even with a large application limit, the listener should bound the
            // unauthenticated peer-key frame to the fixed public-key size.
            let listener_handshake = matched(listener_signer, Version::V1);
            let max_message_size = 1024 * 1024;

            // Advertise a frame that is one byte larger than the encoded public key and send no
            // payload. Comparing against `max_message_size` alone would accept it.
            dialer_sink
                .send(oversized_handshake_prefix(&peer))
                .await
                .unwrap();

            let result = Timeout::new(listener_handshake, Duration::from_secs(1))
                .listen(
                    context,
                    NAMESPACE,
                    max_message_size,
                    |_| async { true },
                    listener_stream,
                    listener_sink,
                )
                .await;

            // The listener should reject immediately on the fixed-size bound
            // instead of waiting for more bytes or allocating for the larger
            // application limit.
            assert!(matches!(
                result,
                Err(TimeoutError::Upgrade(Error::Frame(FrameError::RecvTooLarge(n))))
                    if n == peer.encode().len() + 1
            ));
        });
    }

    /// Checks that the dialer bounds the SynAck frame by its fixed size instead of
    /// `max_message_size`.
    #[test]
    fn test_dial_rejects_oversized_fixed_size_syn_ack_frame() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_signer = PrivateKey::from_seed(42);
            let listener_signer = PrivateKey::from_seed(24);

            let (dialer_sink, _listener_stream) = mocks::Channel::init();
            let (mut listener_sink, dialer_stream) = mocks::Channel::init();

            // Use a large application limit to make sure this path is guarded by
            // the fixed SynAck size rather than by post-handshake settings.
            let dialer_handshake = matched(dialer_signer, Version::V1);
            let max_message_size = 1024 * 1024;

            // Build a valid SynAck only to derive its true encoded size for the
            // oversized prefix we inject below.
            let listener_public_key = listener_signer.public_key();
            let listener_handshake = matched(listener_signer, Version::V1);
            let dialer_context = dialer_handshake.handshake.clone().context(
                &context,
                NAMESPACE,
                listener_public_key.clone(),
            );
            let listener_context = listener_handshake.handshake.clone().context(
                &context,
                NAMESPACE,
                dialer_handshake.public_key(),
            );
            let (_, syn) = dial_start(context.child("dialer"), dialer_context);
            let (_, syn_ack) = listen_start(context.child("listener"), listener_context, syn)
                .expect("mock handshake should produce a valid syn_ack");

            // Send only a length prefix that claims a frame one byte larger than
            // the fixed SynAck encoding.
            listener_sink
                .send(oversized_handshake_prefix(&syn_ack))
                .await
                .unwrap();

            let result = Timeout::new(dialer_handshake, Duration::from_secs(1))
                .dial(
                    context,
                    NAMESPACE,
                    max_message_size,
                    listener_public_key,
                    dialer_stream,
                    dialer_sink,
                )
                .await;

            // The dialer should reject on the fixed handshake bound before any
            // larger application-sized receive path is considered.
            assert!(matches!(
                result,
                Err(TimeoutError::Upgrade(Error::Frame(FrameError::RecvTooLarge(n))))
                    if n == syn_ack.encode().len() + 1
            ));
        });
    }
}
