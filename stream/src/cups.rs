//! Commonware CUPS (Counter Unidirectional Packet Stream).
//!
//! CUPS protects ordered message records using a separate key and implicit counter for each
//! direction. "Packet" refers to a framed message on an ordered byte stream, not a datagram.
//! The current construction uses ChaCha20-Poly1305; the construction name is independent of
//! this algorithm choice.
//!
//! # Handshake
//!
//! [Handshake] implements [crate::Handshake] using Commonware
//! [SAKE](commonware_cryptography::handshake::sake) (Simple Authenticated Key Exchange) and returns CUPS
//! [Sender] and [Receiver] halves. SAKE uses a fixed three-message exchange with ephemeral X25519
//! keys, identity signatures, and BLAKE3 transcript derivation to establish directional ciphers.
//!
//! The core SAKE protocol receives both peer identities as inputs. This adapter first sends the
//! dialer's public key in a framed, cleartext prelude, separate from SAKE's three messages. The
//! listener's bouncer may reject that claim before authentication. Accepting it only permits the
//! handshake to continue; a successful handshake authenticates the returned identity.
//!
//! Peers must agree on a unique, application-specific namespace and have clocks within the
//! configured timestamp acceptance windows. Callers must enforce a handshake deadline, for example
//! with [crate::utils::Timeout]. Identities are exposed during the handshake, and there is no 0-RTT
//! resumption.
//!
//! # Records
//!
//! Each message is independently encrypted and authenticated with a 16-byte tag and empty AEAD
//! associated data. A visible u32-varint length prefix frames the ciphertext and tag. Batching
//! writes preserves individual record boundaries.
//!
//! Each direction uses a fixed session key and an implicit 96-bit counter nonce, starting at zero
//! and encoded little-endian. The counter advances for each record and is never transmitted.
//! Counter exhaustion requires a new connection. Counters bind records to their expected positions:
//! replayed, reordered, or corrupted records fail authentication rather than being reordered for
//! delivery. Callers must discard the connection after an authentication failure.
//!
//! # Security
//!
//! SAKE provides mutual authentication and ephemeral session keys. CUPS protects record contents
//! and integrity, while lengths, boundaries, and timing remain observable. There is no padding,
//! in-session key ratchet, or rekeying. Callers must discard the connection after an I/O error or
//! cancellation, as required by [crate::Sender] and [crate::Receiver].

use crate::utils::codec::{append_frame, framed_len, recv_frame, send_frame};
use commonware_codec::{DecodeExt, Encode, Error as CodecError, FixedSize};
use commonware_cryptography::{
    Signer,
    handshake::sake::{
        self, Ack, Context, Error as HandshakeError, RecvCipher, SendCipher, Syn, SynAck, dial_end,
        dial_start, listen_end, listen_start,
    },
};
use commonware_formatting::hex;
use commonware_runtime::{
    BufMut, BufferPool, BufferPooler, Clock, Error as RuntimeError, IoBuf, IoBufMut, IoBufs, Sink,
    Stream,
};
use commonware_utils::{DurationExt, SystemTimeExt};
use rand_core::CryptoRng;
use std::{future::Future, ops::Range, time::Duration};
use thiserror::Error;

const TAG_SIZE: u32 = {
    assert!(sake::TAG_SIZE <= u32::MAX as usize);
    sake::TAG_SIZE as u32
};

/// Maximum supported plaintext message size.
pub const MAX_SIZE: u32 = u32::MAX - TAG_SIZE;

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    #[error("handshake error: {0}")]
    HandshakeError(HandshakeError),
    #[error("unable to decode: {0}")]
    UnableToDecode(CodecError),
    #[error("peer rejected: {}", hex(_0))]
    PeerRejected(Vec<u8>),
    #[error("recv failed")]
    RecvFailed(RuntimeError),
    #[error("recv too large: {0} bytes")]
    RecvTooLarge(usize),
    #[error("invalid varint length prefix")]
    InvalidVarint,
    #[error("send failed")]
    SendFailed(RuntimeError),
    #[error("send zero size")]
    SendZeroSize,
    #[error("send too large: {0} bytes")]
    SendTooLarge(usize),
    #[error("connection closed")]
    StreamClosed,
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

/// Establishes CUPS streams with Commonware SAKE (Simple Authenticated Key Exchange).
///
/// Implements [crate::Handshake] using [commonware_cryptography::handshake::sake].
#[derive(Clone)]
pub struct Handshake<S> {
    /// Signer used to authenticate the local peer.
    pub signer: S,

    /// Maximum time drift allowed for future timestamps.
    pub synchrony_bound: Duration,

    /// Maximum age of handshake messages before rejection.
    pub max_handshake_age: Duration,
}

impl<S> Handshake<S> {
    /// Creates a SAKE handshake accepting timestamps up to five seconds ahead or ten seconds old.
    pub const fn new(signer: S) -> Self {
        Self {
            signer,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
        }
    }

    /// Computes the current time and acceptable timestamp range.
    pub fn time_information(&self, ctx: &impl Clock) -> (u64, Range<u64>) {
        let current_time_ms = ctx.current().epoch().as_millis_u64();
        let ok_timestamps = (current_time_ms.saturating_sub(self.max_handshake_age.as_millis_u64()))
            ..(current_time_ms.saturating_add(self.synchrony_bound.as_millis_u64()));
        (current_time_ms, ok_timestamps)
    }
}

/// Sends a handshake message bounded by its fixed encoded size.
async fn send_handshake_frame<M, T>(sink: &mut T, message: M) -> Result<(), Error>
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

impl<S: Signer> crate::Handshake for Handshake<S> {
    const MAX_SIZE: u32 = MAX_SIZE;

    type PublicKey = S::PublicKey;
    type Error = Error;
    type Sender<I: Stream, O: Sink> = Sender<O>;
    type Receiver<I: Stream, O: Sink> = Receiver<I>;

    fn public_key(&self) -> Self::PublicKey {
        self.signer.public_key()
    }

    async fn dial<C, I, O>(
        self,
        context: C,
        namespace: &[u8],
        max_message_size: u32,
        peer: S::PublicKey,
        mut stream: I,
        mut sink: O,
    ) -> Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        assert!(
            max_message_size <= MAX_SIZE,
            "maximum message size exceeds stream limit"
        );
        let pool = context.network_buffer_pool().clone();
        send_handshake_frame(&mut sink, self.signer.public_key()).await?;

        let (current_time, ok_timestamps) = self.time_information(&context);
        let (state, syn) = dial_start(
            context,
            Context::new(namespace, current_time, ok_timestamps, self.signer, peer),
        );
        send_handshake_frame(&mut sink, syn).await?;

        let syn_ack = recv_handshake_frame::<SynAck<S::Signature>, _>(&mut stream).await?;

        let (ack, send, recv) = dial_end(state, syn_ack)?;
        send_handshake_frame(&mut sink, ack).await?;

        Ok((
            Sender {
                cipher: send,
                sink,
                max_message_size,
                pool: pool.clone(),
            },
            Receiver {
                cipher: recv,
                stream,
                max_message_size,
                pool,
            },
        ))
    }

    async fn listen<C, I, O, B, F>(
        self,
        context: C,
        namespace: &[u8],
        max_message_size: u32,
        bouncer: B,
        mut stream: I,
        mut sink: O,
    ) -> Result<(S::PublicKey, Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(S::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        assert!(
            max_message_size <= MAX_SIZE,
            "maximum message size exceeds stream limit"
        );
        let pool = context.network_buffer_pool().clone();
        let peer = recv_handshake_frame::<S::PublicKey, _>(&mut stream).await?;
        if !bouncer(peer.clone()).await {
            return Err(Error::PeerRejected(peer.encode().to_vec()));
        }

        let msg1 = recv_handshake_frame::<Syn<S::Signature>, _>(&mut stream).await?;

        let (current_time, ok_timestamps) = self.time_information(&context);
        let (state, syn_ack) = listen_start(
            context,
            Context::new(
                namespace,
                current_time,
                ok_timestamps,
                self.signer,
                peer.clone(),
            ),
            msg1,
        )?;
        send_handshake_frame(&mut sink, syn_ack).await?;

        let ack = recv_handshake_frame::<Ack, _>(&mut stream).await?;

        let (send, recv) = listen_end(state, ack)?;

        Ok((
            peer,
            Sender {
                cipher: send,
                sink,
                max_message_size,
                pool: pool.clone(),
            },
            Receiver {
                cipher: recv,
                stream,
                max_message_size,
                pool,
            },
        ))
    }
}

/// Sends CUPS records to a peer.
pub struct Sender<O> {
    cipher: SendCipher,
    sink: O,
    max_message_size: u32,
    pool: BufferPool,
}

/// Describes one contiguous sink chunk made up of one or more encrypted frames.
struct ChunkPlan {
    messages: Vec<IoBufs>,
    total_len: usize,
}

impl<O: Sink> Sender<O> {
    /// Returns the total encoded size of one encrypted frame.
    ///
    /// The returned size includes the length prefix, ciphertext, and AEAD tag.
    fn encrypted_frame_len(&self, plaintext_len: usize) -> Result<usize, Error> {
        framed_len(
            plaintext_len + TAG_SIZE as usize,
            self.max_message_size.saturating_add(TAG_SIZE),
        )
    }

    /// Appends one encrypted frame directly into caller-provided storage.
    ///
    /// This lets chunk builders append multiple independently framed
    /// ciphertexts into a single contiguous allocation without staging each
    /// frame in its own buffer first.
    fn append_encrypted_frame(
        &mut self,
        chunk: &mut IoBufMut,
        mut bufs: IoBufs,
    ) -> Result<(), Error> {
        append_frame(
            chunk,
            bufs.len() + TAG_SIZE as usize,
            self.max_message_size.saturating_add(TAG_SIZE),
            |chunk, plaintext_offset| {
                // Copy the plaintext directly into the frame.
                chunk.put(&mut bufs);

                // Encrypt in-place and append the tag to the frame.
                let tag = self
                    .cipher
                    .send_in_place(&mut chunk.as_mut()[plaintext_offset..])?;
                chunk.put_slice(&tag);
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Builds one contiguous chunk containing one or more encrypted frames.
    ///
    /// Callers compute `total_len` up front so this helper can allocate once,
    /// append each framed ciphertext in order, and freeze the result.
    fn build_chunk<I>(&mut self, messages: I, total_len: usize) -> Result<IoBuf, Error>
    where
        I: IntoIterator<Item = IoBufs>,
    {
        let mut chunk = self.pool.alloc(total_len);
        for msg in messages {
            self.append_encrypted_frame(&mut chunk, msg)?;
        }
        assert_eq!(chunk.len(), total_len);
        Ok(chunk.freeze())
    }

    /// Plans `send_many` chunk boundaries without consuming cipher state.
    ///
    /// This validation pass ensures any oversize error is reported before
    /// encryption advances nonces, so the sender remains usable after failure.
    fn plan_chunks<B, I>(&self, bufs: I) -> Result<Vec<ChunkPlan>, Error>
    where
        B: Into<IoBufs>,
        I: IntoIterator<Item = B>,
    {
        let bufs = bufs.into_iter();
        let (lower, _) = bufs.size_hint();
        let mut chunks = Vec::with_capacity(lower.max(1));
        let mut batch = Vec::new();
        let mut batch_total = 0usize;
        let max_batch_size = self.pool.config().max_size().get();

        for buf in bufs {
            let msg = buf.into();
            let frame_len = self.encrypted_frame_len(msg.len())?;

            // If one framed message is larger than the pooled batch cap, keep
            // current chunks intact and send that message as its own chunk.
            if frame_len > max_batch_size {
                if !batch.is_empty() {
                    chunks.push(ChunkPlan {
                        messages: std::mem::take(&mut batch),
                        total_len: batch_total,
                    });
                    batch_total = 0;
                }
                chunks.push(ChunkPlan {
                    messages: vec![msg],
                    total_len: frame_len,
                });
                continue;
            }

            // Close the current chunk before it would exceed one network
            // buffer-pool item.
            if batch_total.saturating_add(frame_len) > max_batch_size {
                chunks.push(ChunkPlan {
                    messages: std::mem::take(&mut batch),
                    total_len: batch_total,
                });
                batch_total = 0;
            }

            batch_total += frame_len;
            batch.push(msg);
        }

        if !batch.is_empty() {
            chunks.push(ChunkPlan {
                messages: batch,
                total_len: batch_total,
            });
        }

        Ok(chunks)
    }

    /// Encrypts and sends a message to the peer.
    ///
    /// Allocates a buffer from the pool, copies plaintext, encrypts in-place,
    /// and sends the ciphertext.
    pub async fn send(&mut self, bufs: impl Into<IoBufs>) -> Result<(), Error> {
        let bufs = bufs.into();
        let frame_len = self.encrypted_frame_len(bufs.len())?;
        let chunk = self.build_chunk(std::iter::once(bufs), frame_len)?;
        self.sink.send(chunk).await.map_err(Error::SendFailed)
    }

    /// Encrypts and sends multiple messages in a single sink call.
    ///
    /// Each message is framed independently so receivers still observe the
    /// original message boundaries. Aggregate writes are broken into contiguous
    /// chunks capped to one network buffer-pool item, then submitted together as
    /// a chunked `IoBufs`. An individual message larger than that cap is still
    /// sent as its own chunk.
    pub async fn send_many<B, I>(&mut self, bufs: I) -> Result<(), Error>
    where
        B: Into<IoBufs>,
        I: IntoIterator<Item = B>,
    {
        let plans = self.plan_chunks(bufs)?;
        if plans.is_empty() {
            return Ok(());
        }

        let chunks = plans
            .into_iter()
            .map(|plan| self.build_chunk(plan.messages, plan.total_len))
            .collect::<Result<IoBufs, Error>>()?;

        self.sink.send(chunks).await.map_err(Error::SendFailed)
    }
}

/// Receives CUPS records from a peer.
pub struct Receiver<I> {
    cipher: RecvCipher,
    stream: I,
    max_message_size: u32,
    pool: BufferPool,
}

impl<O: Sink> crate::Sender for Sender<O> {
    type Error = Error;

    async fn send(&mut self, message: impl Into<IoBufs> + Send) -> Result<(), Error> {
        Self::send(self, message).await
    }

    async fn send_many<I>(&mut self, messages: I) -> Result<(), Error>
    where
        I: IntoIterator + Send,
        I::Item: Into<IoBufs> + Send,
        I::IntoIter: Send,
    {
        Self::send_many(self, messages).await
    }
}

impl<I: Stream> crate::Receiver for Receiver<I> {
    type Error = Error;

    async fn recv(&mut self) -> Result<IoBufs, Error> {
        Self::recv(self).await
    }
}

impl<I: Stream> Receiver<I> {
    /// Receives and decrypts a message from the peer.
    ///
    /// Receives ciphertext and decrypts it in-place when the received frame is
    /// a single, uniquely-owned buffer. Otherwise, allocates a buffer from the
    /// pool, copies the ciphertext, and decrypts the copy in-place.
    pub async fn recv(&mut self) -> Result<IoBufs, Error> {
        let encrypted = recv_frame(
            &mut self.stream,
            self.max_message_size.saturating_add(TAG_SIZE),
        )
        .await?;

        // Recover the received frame for in-place decryption when it is a
        // single, uniquely-owned buffer. Otherwise, copy the ciphertext into
        // a buffer allocated from the pool.
        let mut decryption_buf = match encrypted
            .try_into_single()
            .and_then(|buf| buf.try_into_mut().map_err(IoBufs::from))
        {
            Ok(buf) => buf,
            Err(mut encrypted) => {
                let mut buf = self.pool.alloc(encrypted.len());
                buf.put(&mut encrypted);
                buf
            }
        };

        // Decrypt in-place, get plaintext length back.
        let plaintext_len = self.cipher.recv_in_place(decryption_buf.as_mut())?;

        // Truncate to remove tag bytes, keeping only plaintext.
        decryption_buf.truncate(plaintext_len);

        Ok(decryption_buf.freeze().into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        Handshake as _,
        utils::{Timeout, TimeoutError},
    };
    use commonware_codec::varint::UInt;
    use commonware_cryptography::{Signer, ed25519::PrivateKey};
    use commonware_runtime::{
        BufferPoolConfig, Error as RuntimeError, IoBuf, IoBufs, Runner as _, Spawner as _,
        Supervisor as _, deterministic, mocks,
    };
    use commonware_utils::{NZU32, NZUsize, sync::Mutex};
    use futures::FutureExt as _;
    use std::{
        panic::AssertUnwindSafe,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    const NAMESPACE: &[u8] = b"fuzz_transport";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024; // 64KB buffer

    #[test]
    fn test_max_message_size_bounds() {
        assert_eq!(MAX_SIZE + TAG_SIZE, u32::MAX);
        deterministic::Runner::default().start(|context| async move {
            for max_message_size in [0, MAX_SIZE, MAX_SIZE + 1] {
                for dialer in [true, false] {
                    let (sink, _) = mocks::Channel::init();
                    let (_, stream) = mocks::Channel::init();
                    let handshake = Handshake::new(PrivateKey::from_seed(0));
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

    fn transport_handshake(signer: PrivateKey) -> Handshake<PrivateKey> {
        Handshake {
            signer,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
        }
    }

    fn oversized_handshake_prefix(message: &impl commonware_codec::Encode) -> IoBuf {
        let size = u32::try_from(message.encode().len()).expect("message length should fit in u32");
        IoBuf::from(UInt(size + 1).encode())
    }

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

    #[test]
    fn test_can_setup_and_send_messages() -> Result<(), Box<dyn std::error::Error>> {
        for max_message_size in [0, 1, 100, MAX_MESSAGE_SIZE] {
            let executor = deterministic::Runner::timed(Duration::from_secs(5));
            executor.start(move |context| async move {
                // Authenticate independently of the returned streams' plaintext limit.
                let dialer_signer = PrivateKey::from_seed(42);
                let listener_signer = PrivateKey::from_seed(24);

                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();

                let dialer_handshake = transport_handshake(dialer_signer.clone());
                let listener_handshake = transport_handshake(listener_signer.clone());

                let listener_handle = context.child("listener").spawn(move |context| async move {
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
                    Err(Error::SendTooLarge(_))
                ));
                assert!(matches!(
                    listener_sender.send(oversized).await,
                    Err(Error::SendTooLarge(_))
                ));
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
        Ok(())
    }

    #[test]
    fn test_recv_decrypts_unique_frame_in_place() -> Result<(), Box<dyn std::error::Error>> {
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

            let dialer_handshake = transport_handshake(dialer_signer);
            let listener_handshake = transport_handshake(listener_signer.clone());

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

            // Send both messages before receiving so the second frame's varint
            // is decoded from the peek buffer, exercising in-place decryption
            // of a sliced frame in addition to a full one.
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
            Ok(())
        })
    }

    #[test]
    fn test_send_many_uses_single_runtime_send() -> Result<(), Box<dyn std::error::Error>> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_signer = PrivateKey::from_seed(42);
            let listener_signer = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));
            let chunk_counts = Arc::new(Mutex::new(Vec::new()));

            let dialer_handshake = transport_handshake(dialer_signer.clone());
            let listener_handshake = transport_handshake(listener_signer.clone());

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
            Ok(())
        })
    }

    #[test]
    fn test_send_many_flushes_at_network_pool_item_max() -> Result<(), Box<dyn std::error::Error>> {
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

            let dialer_handshake = transport_handshake(dialer_signer.clone());
            let listener_handshake = transport_handshake(listener_signer.clone());

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

            // Each frame is 117 bytes: 100 payload + 16 tag + 1 length prefix.
            // Two fit under the 256-byte cap. Zero through nine messages cover
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
                    assert_eq!(*chunk_counts.lock(), vec![count.div_ceil(2)]);
                }
                for index in 0..count {
                    let expected = [index as u8; 100];
                    assert_eq!(
                        listener_receiver.recv().await?.coalesce(),
                        expected.as_slice()
                    );
                }
            }
            Ok(())
        })
    }

    #[test]
    fn test_send_many_sends_oversized_single_message_alone()
    -> Result<(), Box<dyn std::error::Error>> {
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

            let dialer_handshake = transport_handshake(dialer_signer.clone());
            let listener_handshake = transport_handshake(listener_signer.clone());

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
            Ok(())
        })
    }

    #[test]
    fn test_send_many_too_large_preserves_sender_state() -> Result<(), Box<dyn std::error::Error>> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_signer = PrivateKey::from_seed(42);
            let listener_signer = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));
            let chunk_counts = Arc::new(Mutex::new(Vec::new()));

            let dialer_handshake = transport_handshake(dialer_signer.clone());
            let listener_handshake = transport_handshake(listener_signer.clone());

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
            sends.store(0, Ordering::Relaxed);
            chunk_counts.lock().clear();

            let valid = vec![7u8; 32];
            let oversized = vec![9u8; MAX_MESSAGE_SIZE as usize + 1];
            assert!(matches!(
                dialer_sender
                    .send_many(vec![
                        IoBufs::from(IoBuf::from(valid)),
                        IoBufs::from(IoBuf::from(oversized)),
                    ])
                    .await,
                Err(Error::SendTooLarge(_))
            ));

            assert_eq!(sends.load(Ordering::Relaxed), 0);
            assert!(chunk_counts.lock().is_empty());

            let recovered = b"recovered";
            dialer_sender.send(&recovered[..]).await?;
            assert_eq!(sends.load(Ordering::Relaxed), 1);
            assert_eq!(listener_receiver.recv().await?.coalesce(), recovered);
            Ok(())
        })
    }

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
            let listener_handshake = transport_handshake(listener_signer);
            let max_message_size = 1024 * 1024;

            // Advertise a frame that is one byte larger than the encoded public
            // key and send no payload. The old behavior accepted this because it
            // only compared against `max_message_size`.
            dialer_sink
                .send(oversized_handshake_prefix(&peer))
                .await
                .unwrap();

            let result = Timeout::new(listener_handshake, Duration::from_secs(1)).listen(context, NAMESPACE, max_message_size, |_| async { true }, listener_stream, listener_sink)
            .await;

            // The listener should reject immediately on the fixed-size bound
            // instead of waiting for more bytes or allocating for the larger
            // application limit.
            assert!(matches!(result, Err(TimeoutError::Handshake(Error::RecvTooLarge(n))) if n == peer.encode().len() + 1));
        });
    }

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
            let dialer_handshake = transport_handshake(dialer_signer);
            let max_message_size = 1024 * 1024;

            // Build a valid SynAck only to derive its true encoded size for the
            // oversized prefix we inject below.
            let (current_time, ok_timestamps) = dialer_handshake.time_information(&context);
            let listener_public_key = listener_signer.public_key();
            let dialer_public_key = dialer_handshake.signer.public_key();
            let (_, syn) = dial_start(
                context.child("dialer"),
                Context::new(
                    NAMESPACE,
                    current_time,
                    ok_timestamps.clone(),
                    dialer_handshake.signer.clone(),
                    listener_public_key.clone(),
                ),
            );
            let (_, syn_ack) = listen_start(
                context.child("listener"),
                Context::new(
                    NAMESPACE,
                    current_time,
                    ok_timestamps,
                    listener_signer,
                    dialer_public_key,
                ),
                syn,
            )
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
                Err(TimeoutError::Handshake(Error::RecvTooLarge(n)))
                    if n == syn_ack.encode().len() + 1
            ));
        });
    }
}
