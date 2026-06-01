//! Encrypted stream implementation using ChaCha20-Poly1305.
//!
//! # Design
//!
//! ## Handshake
//!
//! c.f. [commonware_cryptography::handshake]. One difference here is that the listener does not
//! know the dialer's public key in advance. Instead, the dialer tells the listener its public key
//! in the first message. The listener has an opportunity to reject the connection if it does not
//! wish to connect ([listen] takes in an arbitrary function to implement this).
//!
//! ## Encryption
//!
//! All traffic is encrypted using ChaCha20-Poly1305. A shared secret is established using an
//! ephemeral X25519 Diffie-Hellman key exchange. This secret, combined with the handshake
//! transcript, is used to derive keys for both the handshake's key confirmation messages and
//! the post-handshake data traffic. Binding the derived keys to the handshake transcript prevents
//! man-in-the-middle and transcript substitution attacks.
//!
//! Each directional cipher uses a 12-byte nonce derived from a counter that is incremented for each
//! message sent. This counter has sufficient cardinality for over 2.5 trillion years of continuous
//! communication at a rate of 1 billion messages per second - sufficient for all practical use cases.
//! This ensures that well-behaving peers can remain connected indefinitely as long as they both
//! remain online (maximizing p2p network stability). In the unlikely case of counter overflow, the
//! connection will be terminated and a new connection should be established. This method prevents
//! nonce reuse (which would compromise message confidentiality) while saving bandwidth (as there is
//! no need to transmit nonces explicitly).
//!
//! Callers that need authenticated but unencrypted records can use [dial_session] and
//! [listen_session]. Session records share the same handshake, ciphers, and nonce sequence as
//! encrypted records, but each record explicitly selects either [Protection::Encrypted] or
//! [Protection::Authenticated].
//!
//! # Security
//!
//! ## Requirements
//!
//! - **Pre-Shared Namespace**: Peers must agree on a unique, application-specific namespace
//!   out-of-band to prevent cross-application replay attacks.
//! - **Time Synchronization**: Peer clocks must be synchronized to within the `synchrony_bound`
//!   to correctly validate timestamps.
//!
//! ## Provided
//!
//! - **Mutual Authentication**: Both parties prove ownership of their static private keys through
//!   signatures.
//! - **Forward Secrecy**: Ephemeral encryption keys ensure that any compromise of long-term static keys
//!   doesn't expose the contents of previous sessions.
//! - **Session Uniqueness**: A listener's [commonware_cryptography::handshake::SynAck] is bound to the dialer's [commonware_cryptography::handshake::Syn] message and
//!   [commonware_cryptography::handshake::Ack]s are bound to the complete handshake transcript, preventing replay attacks and ensuring
//!   message integrity.
//! - **Handshake Timeout**: A configurable deadline is enforced for handshake completion to protect
//!   against malicious peers that create connections but abandon handshakes.
//!
//! ## Not Provided
//!
//! - **Anonymity**: Peer identities are not hidden during handshakes from network observers (both active
//!   and passive).
//! - **Padding**: Messages are encrypted as-is, allowing an attacker to perform traffic analysis.
//! - **Future Secrecy**: If a peer's static private key is compromised, future sessions will be exposed.
//! - **0-RTT**: The protocol does not support 0-RTT handshakes (resumed sessions).

use crate::utils::codec::{append_frame, framed_len, recv_frame, send_frame};
use commonware_codec::{DecodeExt, Encode as _, Error as CodecError, FixedSize};
use commonware_cryptography::{
    handshake::{
        self, dial_end, dial_start, listen_end, listen_start, Ack, Context,
        Error as HandshakeError, RecvCipher, SendCipher, Syn, SynAck,
    },
    transcript::Transcript,
    Signer,
};
use commonware_formatting::hex;
use commonware_macros::select;
use commonware_runtime::{
    Buf, BufMut, BufferPool, BufferPooler, Clock, Error as RuntimeError, IoBuf, IoBufMut, IoBufs,
    Sink, Stream,
};
use commonware_utils::SystemTimeExt;
use rand_core::CryptoRngCore;
use std::{future::Future, ops::Range, time::Duration};
use thiserror::Error;

const TAG_SIZE: u32 = {
    assert!(handshake::TAG_SIZE <= u32::MAX as usize);
    handshake::TAG_SIZE as u32
};

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
    #[error("invalid frame protection: {0}")]
    InvalidFrameProtection(u8),
    #[error("send failed")]
    SendFailed(RuntimeError),
    #[error("send zero size")]
    SendZeroSize,
    #[error("send too large: {0} bytes")]
    SendTooLarge(usize),
    #[error("connection closed")]
    StreamClosed,
    #[error("handshake timed out")]
    HandshakeTimeout,
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

/// Configuration for a connection.
///
/// # Warning
///
/// Synchronize this configuration across all peers.
/// Mismatched configurations may cause dropped connections or parsing errors.
#[derive(Clone)]
pub struct Config<S> {
    /// The private key used for signing messages.
    ///
    /// This proves our own identity to other peers.
    pub signing_key: S,

    /// Unique prefix for all signed messages. Should be application-specific.
    /// Prevents replay attacks across different applications using the same keys.
    pub namespace: Vec<u8>,

    /// Maximum message size (in bytes). Prevents memory exhaustion DoS attacks.
    ///
    /// Fixed-size handshake frames use their protocol-defined sizes instead of
    /// inheriting this limit.
    pub max_message_size: u32,

    /// Maximum time drift allowed for future timestamps. Handles clock skew.
    pub synchrony_bound: Duration,

    /// Maximum age of handshake messages before rejection.
    pub max_handshake_age: Duration,

    /// The allotted time for the handshake to complete.
    pub handshake_timeout: Duration,
}

impl<S> Config<S> {
    /// Computes current time and acceptable timestamp range.
    pub fn time_information(&self, ctx: &impl Clock) -> (u64, Range<u64>) {
        fn duration_to_u64(d: Duration) -> u64 {
            u64::try_from(d.as_millis()).expect("duration ms should fit in an u64")
        }
        let current_time_ms = duration_to_u64(ctx.current().epoch());
        let ok_timestamps = (current_time_ms
            .saturating_sub(duration_to_u64(self.max_handshake_age)))
            ..(current_time_ms.saturating_add(duration_to_u64(self.synchrony_bound)));
        (current_time_ms, ok_timestamps)
    }
}

/// Protection applied to a session frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protection {
    /// Encrypt and authenticate the frame payload.
    Encrypted,
    /// Authenticate the frame payload without encrypting it.
    Authenticated,
}

impl Protection {
    const ENCRYPTED: u8 = 0;
    const AUTHENTICATED: u8 = 1;

    const fn encode(self) -> u8 {
        match self {
            Self::Encrypted => Self::ENCRYPTED,
            Self::Authenticated => Self::AUTHENTICATED,
        }
    }

    const fn decode(value: u8) -> Result<Self, Error> {
        match value {
            Self::ENCRYPTED => Ok(Self::Encrypted),
            Self::AUTHENTICATED => Ok(Self::Authenticated),
            _ => Err(Error::InvalidFrameProtection(value)),
        }
    }
}

/// A received session frame.
#[derive(Debug)]
pub struct Frame {
    /// The frame protection mode.
    pub protection: Protection,

    /// The authenticated payload bytes.
    pub payload: IoBufs,
}

// Handshake frames are fixed-size protocol messages, so we cap receives to
// their exact encoded length instead of the application message limit.
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

/// Establishes an authenticated connection to a peer as the dialer.
/// Returns sender and receiver for encrypted communication.
pub async fn dial<R: BufferPooler + CryptoRngCore + Clock, S: Signer, I: Stream, O: Sink>(
    ctx: R,
    config: Config<S>,
    peer: S::PublicKey,
    stream: I,
    sink: O,
) -> Result<(Sender<O>, Receiver<I>), Error> {
    let (sender, receiver) = dial_session(ctx, config, peer, stream, sink).await?;
    Ok((Sender { inner: sender }, Receiver { inner: receiver }))
}

/// Establishes an authenticated session to a peer as the dialer.
pub async fn dial_session<
    R: BufferPooler + CryptoRngCore + Clock,
    S: Signer,
    I: Stream,
    O: Sink,
>(
    ctx: R,
    config: Config<S>,
    peer: S::PublicKey,
    mut stream: I,
    mut sink: O,
) -> Result<(SessionSender<O>, SessionReceiver<I>), Error> {
    let pool = ctx.network_buffer_pool().clone();
    let timeout = ctx.sleep(config.handshake_timeout);
    let inner_routine = async move {
        send_frame(
            &mut sink,
            config.signing_key.public_key().encode(),
            config.max_message_size,
        )
        .await?;

        let (current_time, ok_timestamps) = config.time_information(&ctx);
        let (state, syn) = dial_start(
            ctx,
            Context::new(
                &Transcript::new(&config.namespace),
                current_time,
                ok_timestamps,
                config.signing_key,
                peer,
            ),
        );
        send_frame(&mut sink, syn.encode(), config.max_message_size).await?;

        let syn_ack = recv_handshake_frame::<SynAck<S::Signature>, _>(&mut stream).await?;

        let (ack, send, recv) = dial_end(state, syn_ack)?;
        send_frame(&mut sink, ack.encode(), config.max_message_size).await?;

        Ok((
            SessionSender {
                cipher: send,
                sink,
                max_message_size: config.max_message_size,
                pool: pool.clone(),
            },
            SessionReceiver {
                cipher: recv,
                stream,
                max_message_size: config.max_message_size,
                pool,
            },
        ))
    };

    select! {
        x = inner_routine => x,
        _ = timeout => Err(Error::HandshakeTimeout),
    }
}

/// Accepts an authenticated connection from a peer as the listener.
/// Returns the peer's identity, sender, and receiver for encrypted communication.
pub async fn listen<
    R: BufferPooler + CryptoRngCore + Clock,
    S: Signer,
    I: Stream,
    O: Sink,
    Fut: Future<Output = bool>,
    F: FnOnce(S::PublicKey) -> Fut,
>(
    ctx: R,
    bouncer: F,
    config: Config<S>,
    stream: I,
    sink: O,
) -> Result<(S::PublicKey, Sender<O>, Receiver<I>), Error> {
    let (peer, sender, receiver) = listen_session(ctx, bouncer, config, stream, sink).await?;
    Ok((peer, Sender { inner: sender }, Receiver { inner: receiver }))
}

/// Accepts an authenticated session from a peer as the listener.
pub async fn listen_session<
    R: BufferPooler + CryptoRngCore + Clock,
    S: Signer,
    I: Stream,
    O: Sink,
    Fut: Future<Output = bool>,
    F: FnOnce(S::PublicKey) -> Fut,
>(
    ctx: R,
    bouncer: F,
    config: Config<S>,
    mut stream: I,
    mut sink: O,
) -> Result<(S::PublicKey, SessionSender<O>, SessionReceiver<I>), Error> {
    let pool = ctx.network_buffer_pool().clone();
    let timeout = ctx.sleep(config.handshake_timeout);
    let inner_routine = async move {
        let peer = recv_handshake_frame::<S::PublicKey, _>(&mut stream).await?;
        if !bouncer(peer.clone()).await {
            return Err(Error::PeerRejected(peer.encode().to_vec()));
        }

        let msg1 = recv_handshake_frame::<Syn<S::Signature>, _>(&mut stream).await?;

        let (current_time, ok_timestamps) = config.time_information(&ctx);
        let (state, syn_ack) = listen_start(
            ctx,
            Context::new(
                &Transcript::new(&config.namespace),
                current_time,
                ok_timestamps,
                config.signing_key,
                peer.clone(),
            ),
            msg1,
        )?;
        send_frame(&mut sink, syn_ack.encode(), config.max_message_size).await?;

        let ack = recv_handshake_frame::<Ack, _>(&mut stream).await?;

        let (send, recv) = listen_end(state, ack)?;

        Ok((
            peer,
            SessionSender {
                cipher: send,
                sink,
                max_message_size: config.max_message_size,
                pool: pool.clone(),
            },
            SessionReceiver {
                cipher: recv,
                stream,
                max_message_size: config.max_message_size,
                pool,
            },
        ))
    };

    select! {
        x = inner_routine => x,
        _ = timeout => Err(Error::HandshakeTimeout),
    }
}

/// Sends encrypted messages to a peer.
pub struct Sender<O> {
    inner: SessionSender<O>,
}

/// Receives encrypted messages from a peer.
pub struct Receiver<I> {
    inner: SessionReceiver<I>,
}

/// Sends protected messages to a peer.
pub struct SessionSender<O> {
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

struct ProtectedChunkPlan {
    messages: Vec<(Protection, IoBufs)>,
    total_len: usize,
}

impl<O: Sink> SessionSender<O> {
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

    /// Returns the total encoded size of one protected session frame.
    fn protected_frame_len(&self, plaintext_len: usize) -> Result<usize, Error> {
        framed_len(
            1 + plaintext_len + TAG_SIZE as usize,
            self.max_message_size
                .saturating_add(TAG_SIZE)
                .saturating_add(1),
        )
    }

    /// Appends one protected session frame.
    fn append_protected_frame(
        &mut self,
        chunk: &mut IoBufMut,
        protection: Protection,
        mut bufs: IoBufs,
    ) -> Result<(), Error> {
        let message_len = bufs.len();
        append_frame(
            chunk,
            1 + message_len + TAG_SIZE as usize,
            self.max_message_size
                .saturating_add(TAG_SIZE)
                .saturating_add(1),
            |chunk, payload_offset| {
                chunk.put_u8(protection.encode());
                let message_offset = chunk.len();
                chunk.put(&mut bufs);

                let tag = match protection {
                    Protection::Encrypted => self
                        .cipher
                        .send_in_place(&mut chunk.as_mut()[message_offset..])?,
                    Protection::Authenticated => self.cipher.authenticate(
                        &chunk.as_ref()[message_offset..payload_offset + 1 + message_len],
                    )?,
                };
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

    /// Builds one contiguous chunk containing protected session frames.
    fn build_protected_chunk<I>(&mut self, messages: I, total_len: usize) -> Result<IoBuf, Error>
    where
        I: IntoIterator<Item = (Protection, IoBufs)>,
    {
        let mut chunk = self.pool.alloc(total_len);
        for (protection, msg) in messages {
            self.append_protected_frame(&mut chunk, protection, msg)?;
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
        let max_batch_size = self.pool.config().max_size.get();

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

    /// Plans protected `send_many` chunk boundaries.
    fn plan_protected_chunks<B, I>(&self, bufs: I) -> Result<Vec<ProtectedChunkPlan>, Error>
    where
        B: Into<IoBufs>,
        I: IntoIterator<Item = (Protection, B)>,
    {
        let bufs = bufs.into_iter();
        let (lower, _) = bufs.size_hint();
        let mut chunks = Vec::with_capacity(lower.max(1));
        let mut batch = Vec::new();
        let mut batch_total = 0usize;
        let max_batch_size = self.pool.config().max_size.get();

        for (protection, buf) in bufs {
            let msg = buf.into();
            let frame_len = self.protected_frame_len(msg.len())?;

            if frame_len > max_batch_size {
                if !batch.is_empty() {
                    chunks.push(ProtectedChunkPlan {
                        messages: std::mem::take(&mut batch),
                        total_len: batch_total,
                    });
                    batch_total = 0;
                }
                chunks.push(ProtectedChunkPlan {
                    messages: vec![(protection, msg)],
                    total_len: frame_len,
                });
                continue;
            }

            if batch_total.saturating_add(frame_len) > max_batch_size {
                chunks.push(ProtectedChunkPlan {
                    messages: std::mem::take(&mut batch),
                    total_len: batch_total,
                });
                batch_total = 0;
            }

            batch_total += frame_len;
            batch.push((protection, msg));
        }

        if !batch.is_empty() {
            chunks.push(ProtectedChunkPlan {
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

        let mut chunks = Vec::with_capacity(plans.len());
        for plan in plans {
            chunks.push(self.build_chunk(plan.messages, plan.total_len)?);
        }

        self.sink
            .send(IoBufs::from(chunks))
            .await
            .map_err(Error::SendFailed)
    }

    /// Sends one protected session frame.
    pub async fn send_protected(
        &mut self,
        protection: Protection,
        bufs: impl Into<IoBufs>,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let frame_len = self.protected_frame_len(bufs.len())?;
        let chunk = self.build_protected_chunk(std::iter::once((protection, bufs)), frame_len)?;
        self.sink.send(chunk).await.map_err(Error::SendFailed)
    }

    /// Sends multiple protected session frames in a single sink call when possible.
    pub async fn send_many_protected<B, I>(&mut self, bufs: I) -> Result<(), Error>
    where
        B: Into<IoBufs>,
        I: IntoIterator<Item = (Protection, B)>,
    {
        let plans = self.plan_protected_chunks(bufs)?;
        if plans.is_empty() {
            return Ok(());
        }

        let mut chunks = Vec::with_capacity(plans.len());
        for plan in plans {
            chunks.push(self.build_protected_chunk(plan.messages, plan.total_len)?);
        }

        self.sink
            .send(IoBufs::from(chunks))
            .await
            .map_err(Error::SendFailed)
    }
}

impl<O: Sink> Sender<O> {
    /// Encrypts and sends a message to the peer.
    pub async fn send(&mut self, bufs: impl Into<IoBufs>) -> Result<(), Error> {
        self.inner.send(bufs).await
    }

    /// Encrypts and sends multiple messages in a single sink call.
    pub async fn send_many<B, I>(&mut self, bufs: I) -> Result<(), Error>
    where
        B: Into<IoBufs>,
        I: IntoIterator<Item = B>,
    {
        self.inner.send_many(bufs).await
    }
}

/// Receives protected messages from a peer.
pub struct SessionReceiver<I> {
    cipher: RecvCipher,
    stream: I,
    max_message_size: u32,
    pool: BufferPool,
}

impl<I: Stream> SessionReceiver<I> {
    /// Receives and decrypts a message from the peer.
    ///
    /// Receives ciphertext, allocates a buffer from the pool, copies ciphertext,
    /// and decrypts in-place.
    pub async fn recv(&mut self) -> Result<IoBufs, Error> {
        let mut encrypted = recv_frame(
            &mut self.stream,
            self.max_message_size.saturating_add(TAG_SIZE),
        )
        .await?;
        let ciphertext_len = encrypted.len();

        // Allocate buffer from pool for decryption.
        let mut decryption_buf = self.pool.alloc(ciphertext_len);

        // Copy ciphertext into buffer.
        decryption_buf.put(&mut encrypted);

        // Decrypt in-place, get plaintext length back.
        let plaintext_len = self.cipher.recv_in_place(decryption_buf.as_mut())?;

        // Truncate to remove tag bytes, keeping only plaintext.
        decryption_buf.truncate(plaintext_len);

        Ok(decryption_buf.freeze().into())
    }

    /// Receives one protected session frame.
    pub async fn recv_protected(&mut self) -> Result<Frame, Error> {
        let frame = recv_frame(
            &mut self.stream,
            self.max_message_size
                .saturating_add(TAG_SIZE)
                .saturating_add(1),
        )
        .await?;
        let mut frame = frame.coalesce_with_pool(&self.pool);
        if frame.len() < 1 + TAG_SIZE as usize {
            return Err(Error::HandshakeError(HandshakeError::DecryptionFailed));
        }

        let protection = Protection::decode(frame.as_ref()[0])?;
        frame.advance(1);

        match protection {
            Protection::Encrypted => {
                let ciphertext_len = frame.len();
                let mut decryption_buf = self.pool.alloc(ciphertext_len);
                decryption_buf.put_slice(frame.as_ref());
                let plaintext_len = self.cipher.recv_in_place(decryption_buf.as_mut())?;
                decryption_buf.truncate(plaintext_len);
                Ok(Frame {
                    protection,
                    payload: decryption_buf.freeze().into(),
                })
            }
            Protection::Authenticated => {
                let payload_len = frame.len() - TAG_SIZE as usize;
                let tag = frame.as_ref()[payload_len..]
                    .try_into()
                    .expect("tag size mismatch");
                self.cipher.verify(&frame.as_ref()[..payload_len], tag)?;
                Ok(Frame {
                    protection,
                    payload: frame.slice(..payload_len).into(),
                })
            }
        }
    }
}

impl<I: Stream> Receiver<I> {
    /// Receives and decrypts a message from the peer.
    pub async fn recv(&mut self) -> Result<IoBufs, Error> {
        self.inner.recv().await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use commonware_codec::varint::UInt;
    use commonware_cryptography::{ed25519::PrivateKey, Signer};
    use commonware_runtime::{
        deterministic, mocks, BufferPoolConfig, Error as RuntimeError, IoBuf, IoBufs, Runner as _,
        Spawner as _, Supervisor as _,
    };
    use commonware_utils::{sync::Mutex, NZUsize};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    const NAMESPACE: &[u8] = b"fuzz_transport";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024; // 64KB buffer

    fn transport_config(signing_key: PrivateKey) -> Config<PrivateKey> {
        Config {
            signing_key,
            namespace: NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
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

    struct RecordingSink<S> {
        inner: S,
        sends: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl<S> RecordingSink<S> {
        fn new(inner: S, sends: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
            Self { inner, sends }
        }
    }

    impl<S: commonware_runtime::Sink> commonware_runtime::Sink for RecordingSink<S> {
        async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), RuntimeError> {
            let bufs = bufs.into();
            let mut sent = Vec::with_capacity(bufs.len());
            bufs.for_each_chunk(|chunk| sent.extend_from_slice(chunk));
            self.sends.lock().push(sent);
            self.inner.send(bufs).await
        }
    }

    #[test]
    fn test_can_setup_and_send_messages() -> Result<(), Error> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            let dialer_config = transport_config(dialer_crypto.clone());
            let listener_config = transport_config(listener_crypto.clone());

            let listener_handle = context.child("listener").spawn(move |context| async move {
                listen(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let (mut dialer_sender, mut dialer_receiver) = dial(
                context,
                dialer_config,
                listener_crypto.public_key(),
                dialer_stream,
                dialer_sink,
            )
            .await?;

            let (listener_peer, mut listener_sender, mut listener_receiver) =
                listener_handle.await.unwrap()?;
            assert_eq!(listener_peer, dialer_crypto.public_key());
            let messages: Vec<&'static [u8]> = vec![b"A", b"B", b"C"];
            for msg in &messages {
                dialer_sender.send(&msg[..]).await?;
                let syn_ack = listener_receiver.recv().await?;
                assert_eq!(syn_ack.coalesce(), *msg);
                listener_sender.send(&msg[..]).await?;
                let ack = dialer_receiver.recv().await?;
                assert_eq!(ack.coalesce(), *msg);
            }
            Ok(())
        })
    }

    #[test]
    fn test_session_can_authenticate_plaintext_messages() -> Result<(), Error> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);
            let messages = Arc::new(Mutex::new(Vec::new()));

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            let dialer_config = transport_config(dialer_crypto.clone());
            let listener_config = transport_config(listener_crypto.clone());

            let listener_handle = context.child("listener").spawn(move |context| async move {
                listen_session(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let (mut dialer_sender, _dialer_receiver) = dial_session(
                context,
                dialer_config,
                listener_crypto.public_key(),
                dialer_stream,
                RecordingSink::new(dialer_sink, messages.clone()),
            )
            .await?;

            let (_listener_peer, _listener_sender, mut listener_receiver) =
                listener_handle.await.unwrap()?;
            messages.lock().clear();

            dialer_sender
                .send_protected(Protection::Authenticated, b"visible payload".as_ref())
                .await?;
            let frame = listener_receiver.recv_protected().await?;
            assert_eq!(frame.protection, Protection::Authenticated);
            assert_eq!(frame.payload.coalesce(), IoBuf::from(b"visible payload"));

            let sends = messages.lock();
            assert_eq!(sends.len(), 1);
            assert!(sends[0]
                .windows(b"visible payload".len())
                .any(|window| window == b"visible payload"));

            Ok(())
        })
    }

    #[test]
    fn test_session_can_mix_encrypted_and_authenticated_messages() -> Result<(), Error> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            let dialer_config = transport_config(dialer_crypto.clone());
            let listener_config = transport_config(listener_crypto.clone());

            let listener_handle = context.child("listener").spawn(move |context| async move {
                listen_session(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let (mut dialer_sender, _dialer_receiver) = dial_session(
                context,
                dialer_config,
                listener_crypto.public_key(),
                dialer_stream,
                dialer_sink,
            )
            .await?;

            let (_listener_peer, _listener_sender, mut listener_receiver) =
                listener_handle.await.unwrap()?;

            dialer_sender
                .send_many_protected(vec![
                    (Protection::Encrypted, IoBufs::from(IoBuf::from(b"secret"))),
                    (
                        Protection::Authenticated,
                        IoBufs::from(IoBuf::from(b"plain")),
                    ),
                ])
                .await?;

            let secret = listener_receiver.recv_protected().await?;
            assert_eq!(secret.protection, Protection::Encrypted);
            assert_eq!(secret.payload.coalesce(), IoBuf::from(b"secret"));

            let plain = listener_receiver.recv_protected().await?;
            assert_eq!(plain.protection, Protection::Authenticated);
            assert_eq!(plain.payload.coalesce(), IoBuf::from(b"plain"));

            Ok(())
        })
    }

    #[test]
    fn test_send_many_uses_single_runtime_send() -> Result<(), Error> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));
            let chunk_counts = Arc::new(Mutex::new(Vec::new()));

            let dialer_config = transport_config(dialer_crypto.clone());
            let listener_config = transport_config(listener_crypto.clone());

            let listener_handle = context.child("listener").spawn(move |context| async move {
                listen(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let (mut dialer_sender, _dialer_receiver) = dial(
                context,
                dialer_config,
                listener_crypto.public_key(),
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
    fn test_send_many_flushes_at_network_pool_item_max() -> Result<(), Error> {
        let executor = deterministic::Runner::new(
            deterministic::Config::new().with_network_buffer_pool_config(
                BufferPoolConfig::for_network()
                    .with_pool_min_size(256)
                    .with_min_size(NZUsize!(256))
                    .with_max_size(NZUsize!(256)),
            ),
        );
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));
            let chunk_counts = Arc::new(Mutex::new(Vec::new()));

            let dialer_config = transport_config(dialer_crypto.clone());
            let listener_config = transport_config(listener_crypto.clone());

            let listener_handle = context.child("listener").spawn(move |context| async move {
                listen(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let (mut dialer_sender, _dialer_receiver) = dial(
                context,
                dialer_config,
                listener_crypto.public_key(),
                dialer_stream,
                CountingSink::new(dialer_sink, sends.clone(), chunk_counts.clone()),
            )
            .await?;

            let (_listener_peer, _listener_sender, mut listener_receiver) =
                listener_handle.await.unwrap()?;
            sends.store(0, Ordering::Relaxed);
            chunk_counts.lock().clear();

            // The first two framed messages fit together under the 256-byte cap,
            // but the third must spill into a second chunk. We still hand the
            // runtime one chunked `IoBufs`, so there is only one sink call.
            let payload = vec![7u8; 100];
            dialer_sender
                .send_many(vec![
                    IoBufs::from(IoBuf::from(payload.clone())),
                    IoBufs::from(IoBuf::from(payload.clone())),
                    IoBufs::from(IoBuf::from(payload.clone())),
                ])
                .await?;

            assert_eq!(sends.load(Ordering::Relaxed), 1);
            assert_eq!(*chunk_counts.lock(), vec![2]);
            for _ in 0..3 {
                assert_eq!(
                    listener_receiver.recv().await?.coalesce(),
                    payload.as_slice()
                );
            }
            Ok(())
        })
    }

    #[test]
    fn test_send_many_sends_oversized_single_message_alone() -> Result<(), Error> {
        let executor = deterministic::Runner::new(
            deterministic::Config::new().with_network_buffer_pool_config(
                BufferPoolConfig::for_network()
                    .with_pool_min_size(128)
                    .with_min_size(NZUsize!(128))
                    .with_max_size(NZUsize!(128)),
            ),
        );
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));
            let chunk_counts = Arc::new(Mutex::new(Vec::new()));

            let dialer_config = transport_config(dialer_crypto.clone());
            let listener_config = transport_config(listener_crypto.clone());

            let listener_handle = context.child("listener").spawn(move |context| async move {
                listen(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let (mut dialer_sender, _dialer_receiver) = dial(
                context,
                dialer_config,
                listener_crypto.public_key(),
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
    fn test_send_many_too_large_preserves_sender_state() -> Result<(), Error> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();
            let sends = Arc::new(AtomicUsize::new(0));
            let chunk_counts = Arc::new(Mutex::new(Vec::new()));

            let dialer_config = transport_config(dialer_crypto.clone());
            let listener_config = transport_config(listener_crypto.clone());

            let listener_handle = context.child("listener").spawn(move |context| async move {
                listen(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            });

            let (mut dialer_sender, _dialer_receiver) = dial(
                context,
                dialer_config,
                listener_crypto.public_key(),
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
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);
            let peer = dialer_crypto.public_key();

            let (mut dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, _dialer_stream) = mocks::Channel::init();

            // Even with a large application limit, the listener should bound the
            // unauthenticated peer-key frame to the fixed public-key size.
            let mut listener_config = transport_config(listener_crypto);
            listener_config.max_message_size = 1024 * 1024;

            // Advertise a frame that is one byte larger than the encoded public
            // key and send no payload. The old behavior accepted this because it
            // only compared against `max_message_size`.
            dialer_sink
                .send(oversized_handshake_prefix(&peer))
                .await
                .unwrap();

            let result = listen(
                context,
                |_| async { true },
                listener_config,
                listener_stream,
                listener_sink,
            )
            .await;

            // The listener should reject immediately on the fixed-size bound
            // instead of waiting for more bytes or allocating for the larger
            // application limit.
            assert!(matches!(result, Err(Error::RecvTooLarge(n)) if n == peer.encode().len() + 1));
        });
    }

    #[test]
    fn test_dial_rejects_oversized_fixed_size_syn_ack_frame() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, _listener_stream) = mocks::Channel::init();
            let (mut listener_sink, dialer_stream) = mocks::Channel::init();

            // Use a large application limit to make sure this path is guarded by
            // the fixed SynAck size rather than by post-handshake settings.
            let mut dialer_config = transport_config(dialer_crypto);
            dialer_config.max_message_size = 1024 * 1024;

            // Build a valid SynAck only to derive its true encoded size for the
            // oversized prefix we inject below.
            let (current_time, ok_timestamps) = dialer_config.time_information(&context);
            let listener_public_key = listener_crypto.public_key();
            let dialer_public_key = dialer_config.signing_key.public_key();
            let (_, syn) = dial_start(
                context.child("dialer"),
                Context::new(
                    &Transcript::new(&dialer_config.namespace),
                    current_time,
                    ok_timestamps.clone(),
                    dialer_config.signing_key.clone(),
                    listener_public_key.clone(),
                ),
            );
            let (_, syn_ack) = listen_start(
                context.child("listener"),
                Context::new(
                    &Transcript::new(&dialer_config.namespace),
                    current_time,
                    ok_timestamps,
                    listener_crypto,
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

            let result = dial(
                context,
                dialer_config,
                listener_public_key,
                dialer_stream,
                dialer_sink,
            )
            .await;

            // The dialer should reject on the fixed handshake bound before any
            // larger application-sized receive path is considered.
            assert!(matches!(
                result,
                Err(Error::RecvTooLarge(n))
                    if n == syn_ack.encode().len() + 1
            ));
        });
    }
}
