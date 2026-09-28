use super::Config;
use crate::utils::codec::{Error as FrameError, recv_frame, send_frame, validate_frame_len};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, Write, varint::UInt,
};
use commonware_cryptography::{
    ChaCha20Poly1305, Cipher, Signer, chacha20_poly1305,
    handshake::sake::{
        self, Ack, Context, Error as HandshakeError, Syn, SynAck, dial_end, dial_start, listen_end,
        listen_start,
    },
};
use commonware_formatting::hex;
use commonware_runtime::{
    BufMut, BufferPool, BufferPooler, Clock, Error as RuntimeError, IoBuf, IoBufMut, IoBufs, Sink,
    Stream,
};
use commonware_utils::{DurationExt, SystemTimeExt, Widen};
use rand_core::CryptoRng;
use std::{future::Future, ops::Range};
use thiserror::Error;

const NAMESPACE: &[u8] = b"_COMMONWARE_STREAM_CUPS";
const V1_HEADER_PLAINTEXT_SIZE: usize = u32::SIZE;

/// Cipher that seals records in every [Version].
type RecordCipher = ChaCha20Poly1305;

/// Tag size of [RecordCipher] as a record length.
const TAG_SIZE: u32 = {
    assert!(RecordCipher::TAG_SIZE <= u32::MAX as usize);
    RecordCipher::TAG_SIZE as u32
};

/// Size of a version 1 header.
const V1_HEADER_SIZE: usize = V1_HEADER_PLAINTEXT_SIZE + RecordCipher::TAG_SIZE;

/// Largest payload whose record length fits in a u32.
const MAX_SIZE: u32 = u32::MAX - TAG_SIZE;

/// Seals `buf` with `cipher`, leaving it empty if sealing fails.
fn seal(cipher: &mut Option<RecordCipher>, buf: &mut [u8]) -> Result<(), Error> {
    let sealer = cipher.take().ok_or(Error::StreamClosed)?;
    *cipher = Some(sealer.seal(&[], buf)?);
    Ok(())
}

/// Opens `buf` with `cipher`, leaving it empty if opening fails.
fn open(cipher: &mut Option<RecordCipher>, buf: &mut [u8]) -> Result<usize, Error> {
    let opener = cipher.take().ok_or(Error::StreamClosed)?;
    let (opener, len) = opener.open(&[], buf)?;
    *cipher = Some(opener);
    Ok(len)
}

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    #[error("handshake error: {0}")]
    HandshakeError(HandshakeError),
    #[error("cipher error: {0}")]
    CipherError(chacha20_poly1305::Error),
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

impl From<chacha20_poly1305::Error> for Error {
    fn from(value: chacha20_poly1305::Error) -> Self {
        Self::CipherError(value)
    }
}

impl From<FrameError> for Error {
    fn from(value: FrameError) -> Self {
        match value {
            FrameError::RecvFailed(err) => Self::RecvFailed(err),
            FrameError::RecvTooLarge(len) => Self::RecvTooLarge(len),
            FrameError::InvalidVarint => Self::InvalidVarint,
            FrameError::SendFailed(err) => Self::SendFailed(err),
            FrameError::SendTooLarge(len) => Self::SendTooLarge(len),
        }
    }
}

/// Protocol version used by [Handshake], selecting the SAKE version, the transcript scope, the
/// record cipher, and the record format.
///
/// Both peers must use the same version. The version is not negotiated, so keep the older version
/// until every peer has upgraded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// [sake::Version::V0] handshakes and records framed by a visible length prefix.
    V0,
    /// [sake::Version::V1] handshakes scoped to CUPS, and records framed by an encrypted,
    /// authenticated length header.
    V1,
}

impl Version {
    /// Returns the SAKE version this protocol version runs.
    const fn sake(self) -> sake::Version {
        match self {
            Self::V0 => sake::Version::V0,
            Self::V1 => sake::Version::V1,
        }
    }

    /// Scopes the handshake transcript to CUPS.
    ///
    /// Each version must produce transcripts that no other version produces, so peers on different
    /// versions fail the handshake.
    fn scope<S, P>(self, context: Context<S, P>) -> Context<S, P> {
        match self {
            Self::V0 => context,
            Self::V1 => context.fork(NAMESPACE),
        }
    }

    /// Returns the size of the header that precedes a payload of `len` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the [MAX_SIZE](crate::Handshake::MAX_SIZE) of a [Handshake].
    pub fn header_len(self, len: usize) -> usize {
        let len = u32::try_from(len)
            .ok()
            .filter(|len| *len <= MAX_SIZE)
            .expect("payload exceeds stream limit");
        match self {
            Self::V0 => UInt(len + TAG_SIZE).encode_size(),
            Self::V1 => V1_HEADER_SIZE,
        }
    }

    /// Returns the encoded size of a record carrying `len` payload bytes.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the [MAX_SIZE](crate::Handshake::MAX_SIZE) of a [Handshake], or if
    /// the record size does not fit in a `usize`.
    pub fn record_len(self, len: usize) -> usize {
        self.header_len(len)
            .checked_add(len)
            .and_then(|size| size.checked_add(RecordCipher::TAG_SIZE))
            .expect("record size exceeds usize")
    }

    /// Appends the header for an encrypted payload of `len` bytes, consuming a cipher position when
    /// the header is encrypted.
    fn append_header(
        self,
        chunk: &mut IoBufMut,
        cipher: &mut Option<RecordCipher>,
        len: u32,
    ) -> Result<(), Error> {
        match self {
            Self::V0 => UInt(len + TAG_SIZE).write(chunk),
            Self::V1 => {
                let offset = chunk.len();
                len.write(chunk);
                chunk.put_bytes(0, RecordCipher::TAG_SIZE);
                seal(cipher, &mut chunk.as_mut()[offset..])?;
            }
        }
        Ok(())
    }

    /// Receives an encrypted payload and its tag, validating any header before requesting them.
    async fn recv_frame(
        self,
        stream: &mut impl Stream,
        cipher: &mut Option<RecordCipher>,
        pool: &BufferPool,
        max_message_size: u32,
    ) -> Result<IoBufs, Error> {
        match self {
            Self::V0 => recv_frame(stream, max_message_size.saturating_add(TAG_SIZE))
                .await
                .map_err(|err| match err {
                    // The prefix counts the tag, which is excluded from the reported payload.
                    FrameError::RecvTooLarge(len) => {
                        Error::RecvTooLarge(len - RecordCipher::TAG_SIZE)
                    }
                    err => err.into(),
                }),
            Self::V1 => {
                // Request the fixed-size header before trusting the payload length, reusing
                // its allocation for in-place decryption when possible.
                let header = stream
                    .recv(V1_HEADER_SIZE)
                    .await
                    .map_err(Error::RecvFailed)?;
                let mut header = mutable_frame(pool, header);

                // Authenticate the header before decoding its length or requesting the payload.
                let plaintext_len = open(cipher, header.as_mut())?;
                assert_eq!(plaintext_len, V1_HEADER_PLAINTEXT_SIZE);
                header.truncate(plaintext_len);
                let len = u32::decode(header)?;
                if len > max_message_size {
                    return Err(Error::RecvTooLarge(Widen::<usize>::widen(len)));
                }

                // Receive the payload and tag only after authenticating and checking the length.
                let body_len = Widen::<usize>::widen(len) + RecordCipher::TAG_SIZE;
                stream.recv(body_len).await.map_err(Error::RecvFailed)
            }
        }
    }
}

/// Establishes CUPS streams with Simple Authenticated Key Exchange (SAKE).
///
/// Implements [crate::Handshake] using [commonware_cryptography::handshake::sake].
#[derive(Clone)]
pub struct Handshake<S> {
    config: Config<S>,
}

impl<S> Handshake<S> {
    /// Creates a handshake with `config`.
    pub const fn new(config: Config<S>) -> Self {
        Self { config }
    }

    /// Returns the configuration of this handshake.
    pub const fn config(&self) -> &Config<S> {
        &self.config
    }

    /// Computes the current time and acceptable timestamp range.
    pub fn time_information(&self, ctx: &impl Clock) -> (u64, Range<u64>) {
        let current_time_ms = ctx.current().epoch().as_millis_u64();
        let ok_timestamps = (current_time_ms
            .saturating_sub(self.config.max_handshake_age.as_millis_u64()))
            ..(current_time_ms.saturating_add(self.config.synchrony_bound.as_millis_u64()));
        (current_time_ms, ok_timestamps)
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

impl<S: Signer> crate::Handshake for Handshake<S> {
    const MAX_SIZE: u32 = MAX_SIZE;

    type PublicKey = S::PublicKey;
    type Error = Error;
    type Sender<I: Stream, O: Sink> = Sender<O>;
    type Receiver<I: Stream, O: Sink> = Receiver<I>;

    fn public_key(&self) -> Self::PublicKey {
        self.config.signer.public_key()
    }

    async fn dial<E, I, O>(
        self,
        context: E,
        namespace: &[u8],
        max_message_size: u32,
        peer: S::PublicKey,
        mut stream: I,
        mut sink: O,
    ) -> Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>
    where
        E: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        assert!(
            max_message_size <= Self::MAX_SIZE,
            "maximum message size exceeds stream limit"
        );
        let pool = context.network_buffer_pool().clone();
        send_handshake_frame(&mut sink, self.config.signer.public_key()).await?;

        let (current_time, ok_timestamps) = self.time_information(&context);
        let (state, syn) = dial_start(
            context,
            self.config.version.scope(Context::new(
                namespace,
                self.config.version.sake(),
                current_time,
                ok_timestamps,
                self.config.signer,
                peer,
            )),
        );
        send_handshake_frame(&mut sink, syn).await?;

        let syn_ack = recv_handshake_frame::<SynAck<S::Signature>, _>(&mut stream).await?;

        let (ack, send, recv) = dial_end(state, syn_ack)?;
        send_handshake_frame(&mut sink, ack).await?;

        Ok((
            Sender {
                cipher: Some(send),
                sink,
                max_message_size,
                pool: pool.clone(),
                version: self.config.version,
            },
            Receiver {
                cipher: Some(recv),
                stream,
                max_message_size,
                pool,
                version: self.config.version,
            },
        ))
    }

    async fn listen<E, I, O, B, F>(
        self,
        context: E,
        namespace: &[u8],
        max_message_size: u32,
        bouncer: B,
        mut stream: I,
        mut sink: O,
    ) -> Result<(S::PublicKey, Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>
    where
        E: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(S::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        assert!(
            max_message_size <= Self::MAX_SIZE,
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
            self.config.version.scope(Context::new(
                namespace,
                self.config.version.sake(),
                current_time,
                ok_timestamps,
                self.config.signer,
                peer.clone(),
            )),
            msg1,
        )?;
        send_handshake_frame(&mut sink, syn_ack).await?;

        let ack = recv_handshake_frame::<Ack, _>(&mut stream).await?;

        let (send, recv) = listen_end(state, ack)?;

        Ok((
            peer,
            Sender {
                cipher: Some(send),
                sink,
                max_message_size,
                pool: pool.clone(),
                version: self.config.version,
            },
            Receiver {
                cipher: Some(recv),
                stream,
                max_message_size,
                pool,
                version: self.config.version,
            },
        ))
    }
}

/// Sends CUPS records to a peer.
pub struct Sender<O> {
    cipher: Option<RecordCipher>,
    sink: O,
    max_message_size: u32,
    pool: BufferPool,
    version: Version,
}

/// Describes one contiguous sink chunk made up of one or more encrypted frames.
struct ChunkPlan {
    messages: Vec<IoBufs>,
    total_len: usize,
}

impl<O: Sink> Sender<O> {
    /// Returns the total encoded size of one encrypted frame.
    ///
    /// The returned size includes the header, ciphertext, and AEAD tags.
    fn encrypted_frame_len(&self, len: usize) -> Result<usize, Error> {
        validate_frame_len(len, self.max_message_size)?;
        Ok(self.version.record_len(len))
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
        let len = validate_frame_len(bufs.len(), self.max_message_size)?;
        self.version.append_header(chunk, &mut self.cipher, len)?;

        let plaintext_offset = chunk.len();
        // Copy the plaintext directly into the frame and reserve room for its tag.
        chunk.put(&mut bufs);
        chunk.put_bytes(0, RecordCipher::TAG_SIZE);

        // Encrypt in-place and write the tag into the reserved room.
        seal(&mut self.cipher, &mut chunk.as_mut()[plaintext_offset..])?;
        assert_eq!(
            chunk.len() - plaintext_offset,
            Widen::<usize>::widen(len) + RecordCipher::TAG_SIZE
        );
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
    /// sealing consumes cipher positions, so the sender remains usable after failure.
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
            .collect::<Result<IoBufs, _>>()?;

        self.sink.send(chunks).await.map_err(Error::SendFailed)
    }
}

/// Receives CUPS records from a peer.
pub struct Receiver<I> {
    cipher: Option<RecordCipher>,
    stream: I,
    max_message_size: u32,
    pool: BufferPool,
    version: Version,
}

impl<O: Sink> crate::Sender for Sender<O> {
    type Error = Error;

    async fn send(&mut self, message: impl Into<IoBufs> + Send) -> Result<(), Self::Error> {
        Self::send(self, message).await
    }

    async fn send_many<I>(&mut self, messages: I) -> Result<(), Self::Error>
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

    async fn recv(&mut self) -> Result<IoBufs, Self::Error> {
        Self::recv(self).await
    }
}

/// Recovers a received frame for in-place decryption, copying only when needed.
fn mutable_frame(pool: &BufferPool, encrypted: IoBufs) -> IoBufMut {
    match encrypted
        .try_into_single()
        .and_then(|buf| buf.try_into_mut().map_err(IoBufs::from))
    {
        Ok(buf) => buf,
        Err(mut encrypted) => {
            let mut buf = pool.alloc(encrypted.len());
            buf.put(&mut encrypted);
            buf
        }
    }
}

impl<I: Stream> Receiver<I> {
    /// Receives and decrypts a message from the peer.
    ///
    /// Receives ciphertext and decrypts it in-place when the received frame is
    /// a single, uniquely-owned buffer. Otherwise, allocates a buffer from the
    /// pool, copies the ciphertext, and decrypts the copy in-place.
    pub async fn recv(&mut self) -> Result<IoBufs, Error> {
        let encrypted = self
            .version
            .recv_frame(
                &mut self.stream,
                &mut self.cipher,
                &self.pool,
                self.max_message_size,
            )
            .await?;
        let mut decryption_buf = mutable_frame(&self.pool, encrypted);

        // Decrypt in-place, get plaintext length back.
        let plaintext_len = open(&mut self.cipher, decryption_buf.as_mut())?;

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
    use commonware_cryptography::{
        ChaCha20Poly1305, Signer, chacha20_poly1305, ed25519::PrivateKey,
    };
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        BufferPoolConfig, Error as RuntimeError, IoBuf, IoBufs, Runner as _, Spawner as _,
        Supervisor as _, deterministic, mocks,
    };
    use commonware_utils::{NZU32, NZUsize, TestRng, sync::Mutex};
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

    /// Seals `msg` with `cipher` into a new buffer.
    fn sealed(cipher: &mut Option<ChaCha20Poly1305>, msg: &[u8]) -> Vec<u8> {
        let mut buf = msg.to_vec();
        buf.resize(msg.len() + ChaCha20Poly1305::TAG_SIZE, 0);
        seal(cipher, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_record_encoding() {
        for version in [Version::V0, Version::V1] {
            deterministic::Runner::default().start(|context| async move {
                let (sink, mut stream) = mocks::Channel::init();
                let mut sender = Sender {
                    cipher: Some(ChaCha20Poly1305::random(TestRng::new(0))),
                    sink,
                    max_message_size: 64,
                    pool: context.network_buffer_pool().clone(),
                    version,
                };
                let messages = [&b""[..], &b"hello"[..], &[7; 64][..]];
                sender.send_many(messages).await.unwrap();

                let mut cipher = Some(ChaCha20Poly1305::random(TestRng::new(0)));
                for message in messages {
                    let len = message.len() as u32;
                    let mut expected = match version {
                        Version::V0 => UInt(len + TAG_SIZE).encode().to_vec(),
                        Version::V1 => sealed(&mut cipher, &len.to_be_bytes()),
                    };
                    expected.extend(sealed(&mut cipher, message));
                    assert_eq!(version.record_len(message.len()), expected.len());
                    assert_eq!(
                        stream.recv(expected.len()).await.unwrap().coalesce(),
                        expected.as_slice()
                    );
                }
            });
        }
    }

    /// Pins the SAKE version that each CUPS version runs.
    #[test]
    fn test_version_selects_sake_version() {
        assert_eq!(Version::V0.sake(), sake::Version::V0);
        assert_eq!(Version::V1.sake(), sake::Version::V1);
    }

    /// Checks that sizing a payload beyond the stream limit panics.
    #[test]
    #[should_panic(expected = "payload exceeds stream limit")]
    fn test_header_len_rejects_oversized_payload() {
        Version::V1.header_len(Widen::<usize>::widen(u32::MAX));
    }

    /// Checks that a version 0 receiver reports the payload length of an oversized record, which
    /// excludes the tag that its length prefix counts.
    #[test]
    fn test_v0_recv_too_large_reports_payload_len() {
        deterministic::Runner::default().start(|context| async move {
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher: Some(ChaCha20Poly1305::random(TestRng::new(0))),
                stream,
                max_message_size: MAX_MESSAGE_SIZE,
                pool: context.network_buffer_pool().clone(),
                version: Version::V0,
            };
            let len = MAX_MESSAGE_SIZE + 1;
            let prefix = UInt(len + TAG_SIZE).encode().to_vec();
            sink.send(prefix).await.unwrap();

            // Keep the sink open without sending a payload: rejection must not wait for it.
            let result = receiver
                .recv()
                .now_or_never()
                .expect("prefix rejection must be immediate");
            assert!(matches!(
                result,
                Err(Error::RecvTooLarge(n)) if n == Widen::<usize>::widen(len)
            ));
        });
    }

    /// Checks that frame failures surface as the matching stream errors.
    #[test]
    fn test_frame_errors_surface_as_stream_errors() {
        deterministic::Runner::default().start(|context| async move {
            // A length prefix that never terminates is an invalid varint.
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher: Some(ChaCha20Poly1305::random(TestRng::new(0))),
                stream,
                max_message_size: MAX_MESSAGE_SIZE,
                pool: context.network_buffer_pool().clone(),
                version: Version::V0,
            };
            sink.send(vec![0xFF; 5]).await.unwrap();
            assert!(matches!(receiver.recv().await, Err(Error::InvalidVarint)));

            // A closed peer fails the read of the length prefix.
            let (sink, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher: Some(ChaCha20Poly1305::random(TestRng::new(0))),
                stream,
                max_message_size: MAX_MESSAGE_SIZE,
                pool: context.network_buffer_pool().clone(),
                version: Version::V0,
            };
            drop(sink);
            assert!(matches!(receiver.recv().await, Err(Error::RecvFailed(_))));

            // A closed peer fails the first handshake frame.
            let (sink, peer_stream) = mocks::Channel::init();
            let (_peer_sink, stream) = mocks::Channel::init();
            drop(peer_stream);
            let result = transport_handshake(PrivateKey::from_seed(0), Version::V1)
                .dial(
                    context.child("dialer"),
                    NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    PrivateKey::from_seed(1).public_key(),
                    stream,
                    sink,
                )
                .await;
            assert!(matches!(result, Err(Error::SendFailed(_))));
        });
    }

    /// Checks that a receiver that fails to open a record refuses every later record.
    #[test]
    fn test_recv_after_failure_closed() {
        deterministic::Runner::default().start(|context| async move {
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher: Some(ChaCha20Poly1305::random(TestRng::new(0))),
                stream,
                max_message_size: MAX_MESSAGE_SIZE,
                pool: context.network_buffer_pool().clone(),
                version: Version::V1,
            };
            let mut cipher = Some(ChaCha20Poly1305::random(TestRng::new(0)));

            // A corrupted header fails to open.
            let mut header = sealed(&mut cipher, &0u32.to_be_bytes());
            header[0] ^= 1;
            sink.send(header).await.unwrap();
            assert!(matches!(
                receiver.recv().await,
                Err(Error::CipherError(
                    chacha20_poly1305::Error::DecryptionFailed
                ))
            ));

            // A valid record at the next positions is refused.
            sink.send(sealed(&mut cipher, &0u32.to_be_bytes()))
                .await
                .unwrap();
            sink.send(sealed(&mut cipher, b"")).await.unwrap();
            assert!(matches!(receiver.recv().await, Err(Error::StreamClosed)));
        });
    }

    /// Checks that a version 1 receiver rejects an invalid header before any payload arrives.
    #[test]
    fn test_invalid_header_rejected_before_body() {
        for (length, corrupt) in [
            (0, Some(0)),
            (0, Some(V1_HEADER_PLAINTEXT_SIZE)),
            (MAX_MESSAGE_SIZE + 1, None),
            (u32::MAX, None),
        ] {
            deterministic::Runner::default().start(|context| async move {
                let (mut sink, stream) = mocks::Channel::init();
                let mut receiver = Receiver {
                    cipher: Some(ChaCha20Poly1305::random(TestRng::new(0))),
                    stream,
                    max_message_size: MAX_MESSAGE_SIZE,
                    pool: context.network_buffer_pool().clone(),
                    version: Version::V1,
                };
                let mut cipher = Some(ChaCha20Poly1305::random(TestRng::new(0)));
                let mut header = sealed(&mut cipher, &length.to_be_bytes());
                if let Some(offset) = corrupt {
                    header[offset] ^= 1;
                }
                sink.send(header).await.unwrap();

                // Keep the sink open without sending a payload: rejection must not wait for it.
                let result = receiver
                    .recv()
                    .now_or_never()
                    .expect("header rejection must be immediate");
                if corrupt.is_some() {
                    assert!(matches!(
                        result,
                        Err(Error::CipherError(
                            chacha20_poly1305::Error::DecryptionFailed
                        ))
                    ));
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::RecvTooLarge(n)) if n == Widen::<usize>::widen(length)
                    ));
                }
            });
        }
    }

    #[test]
    fn test_max_message_size_bounds() {
        const MAX_SIZE: u32 = <Handshake<PrivateKey> as crate::Handshake>::MAX_SIZE;
        assert_eq!(MAX_SIZE + TAG_SIZE, u32::MAX);
        deterministic::Runner::default().start(|context| async move {
            for max_message_size in [0, MAX_SIZE, MAX_SIZE + 1] {
                for dialer in [true, false] {
                    let (sink, _) = mocks::Channel::init();
                    let (_, stream) = mocks::Channel::init();
                    let handshake =
                        Handshake::new(Config::new(PrivateKey::from_seed(0), Version::V1));
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

    fn transport_handshake(signer: PrivateKey, version: Version) -> Handshake<PrivateKey> {
        Handshake::new(Config {
            signer,
            version,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
        })
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
        for version in [Version::V0, Version::V1] {
            for max_message_size in [0, 1, 100, MAX_MESSAGE_SIZE] {
                let executor = deterministic::Runner::timed(Duration::from_secs(5));
                executor.start(move |context| async move {
                    // Authenticate independently of the returned streams' plaintext limit.
                    let dialer_signer = PrivateKey::from_seed(42);
                    let listener_signer = PrivateKey::from_seed(24);

                    let (dialer_sink, listener_stream) = mocks::Channel::init();
                    let (listener_sink, dialer_stream) = mocks::Channel::init();

                    let dialer_handshake = transport_handshake(dialer_signer.clone(), version);
                    let listener_handshake = transport_handshake(listener_signer.clone(), version);

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
        }
        Ok(())
    }

    /// Runs a handshake between a dialer and listener configured with the given versions.
    fn handshake_with_versions(
        dialer_version: Version,
        listener_version: Version,
    ) -> Result<(), Error> {
        let executor = deterministic::Runner::timed(Duration::from_secs(5));
        executor.start(move |context| async move {
            let dialer_signer = PrivateKey::from_seed(42);
            let listener_signer = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            let dialer_handshake = transport_handshake(dialer_signer.clone(), dialer_version);
            let listener_handshake = transport_handshake(listener_signer.clone(), listener_version);

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
            let (peer, _, _) = listener_handle.await.unwrap()?;
            assert_eq!(peer, dialer_signer.public_key());
            dialer_handle.await.unwrap()?;
            Ok(())
        })
    }

    #[test]
    fn test_versions() {
        for dialer in [Version::V0, Version::V1] {
            for listener in [Version::V0, Version::V1] {
                let result = handshake_with_versions(dialer, listener);
                if dialer == listener {
                    result.unwrap();
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::HandshakeError(HandshakeError::HandshakeFailed))
                    ));
                }
            }
        }
    }

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

                let dialer_handshake = transport_handshake(dialer_signer, version);
                let listener_handshake = transport_handshake(listener_signer.clone(), version);

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

                let dialer_handshake = transport_handshake(dialer_signer.clone(), version);
                let listener_handshake = transport_handshake(listener_signer.clone(), version);

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
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_send_many_flushes_at_network_pool_item_max() -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
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

                let dialer_handshake = transport_handshake(dialer_signer.clone(), version);
                let listener_handshake = transport_handshake(listener_signer.clone(), version);

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

                // V0 frames are 117 bytes and pack two messages under the 256-byte
                // cap. V1 frames are 136 bytes and each occupies its own chunk.
                // Zero through nine messages cover empty, inline, and deque-backed
                // batches with at most one sink call.
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

    #[test]
    fn test_send_many_sends_oversized_single_message_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        for version in [Version::V0, Version::V1] {
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

                let dialer_handshake = transport_handshake(dialer_signer.clone(), version);
                let listener_handshake = transport_handshake(listener_signer.clone(), version);

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
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
    }

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

                let dialer_handshake = transport_handshake(dialer_signer.clone(), version);
                let listener_handshake = transport_handshake(listener_signer.clone(), version);

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
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        Ok(())
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
            let listener_handshake = transport_handshake(listener_signer, Version::V1);
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
            let dialer_handshake = transport_handshake(dialer_signer, Version::V1);
            let max_message_size = 1024 * 1024;

            // Build a valid SynAck only to derive its true encoded size for the
            // oversized prefix we inject below.
            let (current_time, ok_timestamps) = dialer_handshake.time_information(&context);
            let listener_public_key = listener_signer.public_key();
            let dialer_public_key = dialer_handshake.config().signer.public_key();
            let (_, syn) = dial_start(
                context.child("dialer"),
                Context::new(
                    NAMESPACE,
                    dialer_handshake.config().version.sake(),
                    current_time,
                    ok_timestamps.clone(),
                    dialer_handshake.config().signer.clone(),
                    listener_public_key.clone(),
                ),
            );
            let (_, syn_ack) = listen_start(
                context.child("listener"),
                Context::new(
                    NAMESPACE,
                    dialer_handshake.config().version.sake(),
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
