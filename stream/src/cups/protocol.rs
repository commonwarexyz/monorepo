use crate::utils::codec::{Error as FrameError, recv_frame, validate_frame_len};
use commonware_codec::{Copying, DecodeExt, EncodeSize, FixedSize, Write, varint::UInt};
use commonware_cryptography::Cipher;
use commonware_runtime::{
    BufMut, BufferPool, Error as RuntimeError, IoBuf, IoBufMut, IoBufs, Sink, Stream,
};
use commonware_utils::Widen;
use std::marker::PhantomData;
use thiserror::Error;

/// Size of the length field in a version 1 header, excluding its tag.
const V1_HEADER_PLAINTEXT_SIZE: usize = u32::SIZE;

/// Namespace that identifies version 0 records.
const NAMESPACE_V0: &[u8] = b"_COMMONWARE_STREAM_CUPS_V0";

/// Namespace that identifies version 1 records.
const NAMESPACE_V1: &[u8] = b"_COMMONWARE_STREAM_CUPS";

/// Returns the tag size of `C` as a record length.
const fn tag_size<C: Cipher>() -> u32 {
    let size = <C::Tag as FixedSize>::SIZE;
    assert!(size <= u32::MAX as usize);
    size as u32
}

/// Returns the size of a version 1 header sealed by `C`.
const fn v1_header_size<C: Cipher>() -> usize {
    V1_HEADER_PLAINTEXT_SIZE + <C::Tag as FixedSize>::SIZE
}

/// Seals `data` with `cipher` and returns its tag, leaving the cipher empty if sealing fails.
fn seal<C: Cipher>(cipher: &mut Option<C>, data: &mut [u8]) -> Result<C::Tag, Error> {
    let sealer = cipher.take().ok_or(Error::StreamClosed)?;
    let (sealer, tag) = sealer.seal(&[], data).ok_or(Error::SealFailed)?;
    *cipher = Some(sealer);
    Ok(tag)
}

/// Opens `buf`, a ciphertext followed by its tag, with `cipher` and returns its plaintext, leaving
/// the cipher empty if opening fails.
fn open<C: Cipher>(cipher: &mut Option<C>, mut buf: IoBufMut) -> Result<IoBufMut, Error> {
    let opener = cipher.take().ok_or(Error::StreamClosed)?;
    let len = buf
        .len()
        .checked_sub(<C::Tag as FixedSize>::SIZE)
        .ok_or(Error::OpenFailed)?;
    let (data, tag) = buf.as_mut().split_at_mut(len);
    let tag = C::Tag::decode(Copying(&*tag)).map_err(|_| Error::OpenFailed)?;
    *cipher = Some(opener.open(&[], data, &tag).ok_or(Error::OpenFailed)?);
    buf.truncate(len);
    Ok(buf)
}

/// Errors that can occur when sending or receiving records.
#[derive(Error, Debug)]
pub enum Error {
    #[error("seal failed")]
    SealFailed,
    #[error("open failed")]
    OpenFailed,
    #[error("recv failed")]
    RecvFailed(RuntimeError),
    #[error("recv too large: {0} bytes")]
    RecvTooLarge(usize),
    #[error("invalid varint length prefix")]
    InvalidVarint,
    #[error("send failed")]
    SendFailed(RuntimeError),
    #[error("send too large: {0} bytes")]
    SendTooLarge(usize),
    #[error("connection closed")]
    StreamClosed,
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

/// Record format used by [Cups].
///
/// Both peers must use the same version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// Records framed by a visible length prefix.
    V0,
    /// Records framed by an encrypted, authenticated length header.
    V1,
}

/// CUPS records of one [Version], sealed by `C`.
pub struct Cups<C> {
    version: Version,

    // `fn() -> C` keeps `Cups` `Send` and `Sync` for any `C`.
    _cipher: PhantomData<fn() -> C>,
}

// Manual impls avoid the `C: Clone` and `C: Copy` bounds a derive would add.
impl<C> Clone for Cups<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Cups<C> {}

impl<C: Cipher> Cups<C> {
    /// Creates `version` records sealed by `C`.
    pub const fn new(version: Version) -> Self {
        Self {
            version,
            _cipher: PhantomData,
        }
    }

    /// Returns the size of the header that precedes a record carrying `len` payload bytes.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the largest record payload, `u32::MAX` minus the tag size.
    pub fn header_len(&self, len: usize) -> usize {
        let len = u32::try_from(len)
            .ok()
            .filter(|len| *len <= <Self as crate::Transport>::MAX_SIZE)
            .expect("payload exceeds stream limit");
        match self.version {
            Version::V0 => UInt(len + tag_size::<C>()).encode_size(),
            Version::V1 => v1_header_size::<C>(),
        }
    }

    /// Returns the encoded size of a record carrying `len` payload bytes.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the largest record payload, `u32::MAX` minus the tag size, or if the
    /// record size does not fit in a `usize`.
    pub fn record_len(&self, len: usize) -> usize {
        self.header_len(len)
            .checked_add(len)
            .and_then(|size| size.checked_add(<C::Tag as FixedSize>::SIZE))
            .expect("record size exceeds usize")
    }
}

impl<C: Cipher> crate::Transport for Cups<C> {
    type Cipher = C;
    type Sender<O: Sink> = Sender<C, O>;
    type Receiver<I: Stream> = Receiver<C, I>;

    // Version 0 length prefixes count the tag, so a payload and its tag must fit in a u32.
    const MAX_SIZE: u32 = u32::MAX - tag_size::<C>();

    fn namespace(&self) -> &'static [u8] {
        match self.version {
            Version::V0 => NAMESPACE_V0,
            Version::V1 => NAMESPACE_V1,
        }
    }

    fn split<I: Stream, O: Sink>(
        &self,
        send: C,
        recv: C,
        stream: I,
        sink: O,
        max_message_size: u32,
        pool: BufferPool,
    ) -> (Self::Sender<O>, Self::Receiver<I>) {
        (
            Sender {
                cipher: Some(send),
                sink,
                max_message_size,
                pool: pool.clone(),
                version: self.version,
            },
            Receiver {
                cipher: Some(recv),
                stream,
                max_message_size,
                pool,
                version: self.version,
            },
        )
    }
}

/// Appends the header for an encrypted payload of `len` bytes, consuming a cipher position when
/// the header is encrypted.
fn append_header<C: Cipher>(
    version: Version,
    chunk: &mut IoBufMut,
    cipher: &mut Option<C>,
    len: u32,
) -> Result<(), Error> {
    match version {
        // Callers bound `len` by `MAX_SIZE`, so adding the tag cannot overflow.
        Version::V0 => UInt(len + tag_size::<C>()).write(chunk),
        Version::V1 => {
            let offset = chunk.len();
            len.write(chunk);
            let tag = seal(cipher, &mut chunk.as_mut()[offset..])?;
            chunk.put_slice(&tag);
        }
    }
    Ok(())
}

/// Receives an encrypted payload and its tag, validating any header before requesting them.
async fn recv_record<C: Cipher>(
    version: Version,
    stream: &mut impl Stream,
    cipher: &mut Option<C>,
    pool: &BufferPool,
    max_message_size: u32,
) -> Result<IoBufs, Error> {
    match version {
        Version::V0 => recv_frame(stream, max_message_size.saturating_add(tag_size::<C>()))
            .await
            .map_err(|err| match err {
                // The prefix counts the tag, which is excluded from the reported payload.
                FrameError::RecvTooLarge(len) => {
                    Error::RecvTooLarge(len - <C::Tag as FixedSize>::SIZE)
                }
                err => err.into(),
            }),
        Version::V1 => {
            // Request the fixed-size header before trusting the payload length, reusing
            // its allocation for in-place decryption when possible.
            let header = stream
                .recv(v1_header_size::<C>())
                .await
                .map_err(Error::RecvFailed)?;

            // Authenticate the header before decoding its length or requesting the payload.
            let header = open(cipher, mutable_frame(pool, header))?;
            assert_eq!(header.len(), V1_HEADER_PLAINTEXT_SIZE);
            let len = u32::decode(header).expect("header has a fixed size");
            if len > max_message_size {
                return Err(Error::RecvTooLarge(Widen::<usize>::widen(len)));
            }

            // Receive the payload and tag only after authenticating and checking the length.
            let body_len = Widen::<usize>::widen(len) + <C::Tag as FixedSize>::SIZE;
            stream.recv(body_len).await.map_err(Error::RecvFailed)
        }
    }
}

/// Sends CUPS records to a peer.
pub struct Sender<C, O> {
    cipher: Option<C>,
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

impl<C: Cipher, O: Sink> Sender<C, O> {
    /// Returns the total encoded size of one encrypted frame.
    ///
    /// The returned size includes the header, ciphertext, and AEAD tags.
    fn encrypted_frame_len(&self, len: usize) -> Result<usize, Error> {
        validate_frame_len(len, self.max_message_size)?;
        Ok(Cups::<C>::new(self.version).record_len(len))
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
        append_header(self.version, chunk, &mut self.cipher, len)?;

        // Copy the plaintext directly into the frame.
        let plaintext_offset = chunk.len();
        chunk.put(&mut bufs);

        // Encrypt in-place and append the tag to the frame.
        let tag = seal(&mut self.cipher, &mut chunk.as_mut()[plaintext_offset..])?;
        chunk.put_slice(&tag);
        assert_eq!(
            chunk.len() - plaintext_offset,
            Widen::<usize>::widen(len) + <C::Tag as FixedSize>::SIZE
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
pub struct Receiver<C, I> {
    cipher: Option<C>,
    stream: I,
    max_message_size: u32,
    pool: BufferPool,
    version: Version,
}

impl<C: Cipher, O: Sink> crate::Sender for Sender<C, O> {
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

impl<C: Cipher, I: Stream> crate::Receiver for Receiver<C, I> {
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

impl<C: Cipher, I: Stream> Receiver<C, I> {
    /// Receives and decrypts a message from the peer.
    ///
    /// Receives ciphertext and decrypts it in-place when the received frame is
    /// a single, uniquely-owned buffer. Otherwise, allocates a buffer from the
    /// pool, copies the ciphertext, and decrypts the copy in-place.
    pub async fn recv(&mut self) -> Result<IoBufs, Error> {
        let encrypted = recv_record(
            self.version,
            &mut self.stream,
            &mut self.cipher,
            &self.pool,
            self.max_message_size,
        )
        .await?;

        // Decrypt in place, keeping only the plaintext.
        let plaintext = open(&mut self.cipher, mutable_frame(&self.pool, encrypted))?;
        Ok(plaintext.freeze().into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::ChaCha20Poly1305;
    use commonware_math::algebra::Random;
    use commonware_runtime::{BufferPooler as _, Runner as _, deterministic, mocks};
    use commonware_utils::TestRng;
    use futures::FutureExt as _;

    const MAX_MESSAGE_SIZE: u32 = 64 * 1024; // 64KB buffer

    type RecordCipher = ChaCha20Poly1305;
    type Tag = <RecordCipher as Cipher>::Tag;
    type TestCups = Cups<RecordCipher>;
    const TAG_SIZE: u32 = tag_size::<RecordCipher>();
    const MAX_SIZE: u32 = <TestCups as crate::Transport>::MAX_SIZE;

    /// Returns the cipher every test peer derives, so each side replays the other's positions.
    fn cipher() -> Option<RecordCipher> {
        Some(RecordCipher::random(TestRng::new(0)))
    }

    /// Returns a sender of `version` records into `sink`.
    fn sender(
        context: &deterministic::Context,
        sink: mocks::Sink,
        max_message_size: u32,
        version: Version,
    ) -> Sender<RecordCipher, mocks::Sink> {
        Sender {
            cipher: cipher(),
            sink,
            max_message_size,
            pool: context.network_buffer_pool().clone(),
            version,
        }
    }

    /// Returns a receiver of `version` records from `stream`.
    fn receiver(
        context: &deterministic::Context,
        stream: mocks::Stream,
        max_message_size: u32,
        version: Version,
    ) -> Receiver<RecordCipher, mocks::Stream> {
        Receiver {
            cipher: cipher(),
            stream,
            max_message_size,
            pool: context.network_buffer_pool().clone(),
            version,
        }
    }

    /// Seals `msg` with `cipher` into a new buffer.
    fn sealed(cipher: &mut Option<ChaCha20Poly1305>, msg: &[u8]) -> Vec<u8> {
        let mut buf = msg.to_vec();
        let tag = seal(cipher, &mut buf).unwrap();
        buf.extend_from_slice(&tag);
        buf
    }

    /// Checks that each version writes a record as its length header followed by the sealed
    /// payload, and that `record_len` matches the bytes written.
    #[test]
    fn test_record_encoding() {
        for version in [Version::V0, Version::V1] {
            deterministic::Runner::default().start(|context| async move {
                let (sink, mut stream) = mocks::Channel::init();
                let mut sender = sender(&context, sink, 64, version);
                let messages = [&b""[..], &b"hello"[..], &[7; 64][..]];
                sender.send_many(messages).await.unwrap();

                // A cipher from the same seed reproduces the sender's key and nonce sequence.
                let mut cipher = cipher();
                for message in messages {
                    let len = message.len() as u32;

                    // V0 prefixes a plaintext length that counts the tag. V1 prefixes the sealed
                    // payload length.
                    let mut expected = match version {
                        Version::V0 => UInt(len + TAG_SIZE).encode().to_vec(),
                        Version::V1 => sealed(&mut cipher, &len.to_be_bytes()),
                    };
                    expected.extend(sealed(&mut cipher, message));
                    assert_eq!(
                        TestCups::new(version).record_len(message.len()),
                        expected.len()
                    );
                    assert_eq!(
                        stream.recv(expected.len()).await.unwrap().coalesce(),
                        expected.as_slice()
                    );
                }
            });
        }
    }

    /// Checks that the largest payload leaves room for the tag in a `u32` record length.
    #[test]
    fn test_max_size_fits_tag() {
        assert_eq!(MAX_SIZE + TAG_SIZE, u32::MAX);
    }

    /// Checks that sizing a payload beyond the stream limit panics.
    #[test]
    #[should_panic(expected = "payload exceeds stream limit")]
    fn test_header_len_rejects_oversized_payload() {
        TestCups::new(Version::V1).header_len(Widen::<usize>::widen(u32::MAX));
    }

    /// Checks that a version 0 receiver reports the payload length of an oversized record, which
    /// excludes the tag that its length prefix counts.
    #[test]
    fn test_v0_recv_too_large_reports_payload_len() {
        deterministic::Runner::default().start(|context| async move {
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = receiver(&context, stream, MAX_MESSAGE_SIZE, Version::V0);
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
            let mut invalid = receiver(&context, stream, MAX_MESSAGE_SIZE, Version::V0);
            sink.send(vec![0xFF; 5]).await.unwrap();
            assert!(matches!(invalid.recv().await, Err(Error::InvalidVarint)));

            // A closed peer fails the read of the length prefix.
            let (sink, stream) = mocks::Channel::init();
            let mut closed = receiver(&context, stream, MAX_MESSAGE_SIZE, Version::V0);
            drop(sink);
            assert!(matches!(closed.recv().await, Err(Error::RecvFailed(_))));
        });
    }

    /// Checks that a version 0 record shorter than a tag fails to open.
    #[test]
    fn test_v0_record_shorter_than_tag_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = receiver(&context, stream, MAX_MESSAGE_SIZE, Version::V0);
            let mut record = UInt(TAG_SIZE - 1).encode().to_vec();
            record.resize(record.len() + Tag::SIZE - 1, 0);
            sink.send(record).await.unwrap();
            assert!(matches!(receiver.recv().await, Err(Error::OpenFailed)));
        });
    }

    /// Checks that a receiver that fails to open a record refuses every later record.
    #[test]
    fn test_recv_after_failure_closed() {
        deterministic::Runner::default().start(|context| async move {
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = receiver(&context, stream, MAX_MESSAGE_SIZE, Version::V1);
            let mut cipher = cipher();

            // A corrupted header fails to open.
            let mut header = sealed(&mut cipher, &0u32.to_be_bytes());
            header[0] ^= 1;
            sink.send(header).await.unwrap();
            assert!(matches!(receiver.recv().await, Err(Error::OpenFailed)));

            // A valid record at the next positions is refused.
            sink.send(sealed(&mut cipher, &0u32.to_be_bytes()))
                .await
                .unwrap();
            sink.send(sealed(&mut cipher, b"")).await.unwrap();
            assert!(matches!(receiver.recv().await, Err(Error::StreamClosed)));
        });
    }

    /// Checks that a sender without a cipher refuses every record without writing to the sink.
    #[test]
    fn test_send_after_failure_closed() {
        for version in [Version::V0, Version::V1] {
            deterministic::Runner::default().start(|context| async move {
                let (sink, mut stream) = mocks::Channel::init();

                // A failed seal leaves the sender without a cipher.
                let mut sender: Sender<RecordCipher, _> = Sender {
                    cipher: None,
                    sink,
                    max_message_size: MAX_MESSAGE_SIZE,
                    pool: context.network_buffer_pool().clone(),
                    version,
                };

                // Both send paths refuse the record.
                assert!(matches!(
                    sender.send(&b"x"[..]).await,
                    Err(Error::StreamClosed)
                ));
                assert!(matches!(
                    sender.send_many([&b"x"[..]]).await,
                    Err(Error::StreamClosed)
                ));

                // Nothing reached the sink.
                assert!(stream.recv(1).now_or_never().is_none());
            });
        }
    }

    /// Checks that a sender reports the payload length of an oversized record without consuming
    /// its cipher or writing to the sink.
    #[test]
    fn test_send_too_large_reports_payload_len() {
        for version in [Version::V0, Version::V1] {
            deterministic::Runner::default().start(|context| async move {
                let (sink, mut stream) = mocks::Channel::init();
                let mut sender = sender(&context, sink, MAX_MESSAGE_SIZE, version);
                let oversized = vec![0u8; MAX_MESSAGE_SIZE as usize + 1];

                // Both send paths report the payload length, excluding the tag.
                assert!(matches!(
                    sender.send(oversized.clone()).await,
                    Err(Error::SendTooLarge(n)) if n == oversized.len()
                ));
                assert!(matches!(
                    sender.send_many([oversized.clone()]).await,
                    Err(Error::SendTooLarge(n)) if n == oversized.len()
                ));

                // Nothing reached the sink, and the cipher is still usable.
                assert!(stream.recv(1).now_or_never().is_none());
                assert!(sender.cipher.is_some());
            });
        }
    }

    /// Checks that a version 1 receiver rejects an invalid header before any payload arrives.
    #[test]
    fn test_invalid_header_rejected_before_body() {
        // Cases: a flipped length byte, a flipped tag byte, a length one above the limit, and
        // `u32::MAX`.
        for (length, corrupt) in [
            (0, Some(0)),
            (0, Some(V1_HEADER_PLAINTEXT_SIZE)),
            (MAX_MESSAGE_SIZE + 1, None),
            (u32::MAX, None),
        ] {
            deterministic::Runner::default().start(|context| async move {
                let (mut sink, stream) = mocks::Channel::init();
                let mut receiver = receiver(&context, stream, MAX_MESSAGE_SIZE, Version::V1);
                let mut cipher = cipher();
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
                    assert!(matches!(result, Err(Error::OpenFailed)));
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::RecvTooLarge(n)) if n == Widen::<usize>::widen(length)
                    ));
                }
            });
        }
    }
}
