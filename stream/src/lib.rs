//! Exchange messages over arbitrary transport.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub mod utils;

use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode as _, Error as CodecError};
use commonware_cryptography::{
    handshake::{
        dial_end, dial_start, listen_end, listen_start, Context, Error as HandshakeError, Msg1,
        Msg2, Msg3, RecvCipher, SendCipher,
    },
    Signer,
};
use commonware_runtime::{Clock, Error as RuntimeError, Sink, Stream};
use commonware_utils::SystemTimeExt;
use rand_core::CryptoRngCore;
use std::{future::Future, ops::Range, time::Duration};
use thiserror::Error;

use crate::utils::codec::{recv_frame, send_frame};

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    #[error("handshake error: {0}")]
    HandshakeError(HandshakeError),
    #[error("unable to decode: {0}")]
    UnableToDecode(CodecError),
    #[error("peer rejected: {0:X?}")]
    PeerRejected(Vec<u8>),
    #[error("recv failed")]
    RecvFailed(RuntimeError),
    #[error("recv too large: {0} bytes")]
    RecvTooLarge(usize),
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
    pub max_message_size: usize,

    /// Maximum time drift allowed for future timestamps. Handles clock skew.
    pub synchrony_bound: Duration,

    /// Maximum age of handshake messages before rejection.
    pub max_handshake_age: Duration,

    /// The allotted time for the handshake to complete.
    pub handshake_timeout: Duration,
}

impl<S> Config<S> {
    pub fn time_information(&self, ctx: &impl Clock) -> (i64, Range<i64>) {
        fn duration_to_i64(d: Duration) -> i64 {
            i64::try_from(d.as_millis()).expect("duration ms should fit in an i64")
        }
        let current_time_ms = duration_to_i64(ctx.current().epoch());
        let ok_timestamps = (current_time_ms - duration_to_i64(self.max_handshake_age))
            ..(current_time_ms + duration_to_i64(self.synchrony_bound));
        (current_time_ms, ok_timestamps)
    }
}

pub async fn dial<R: CryptoRngCore + Clock, S: Signer, I: Stream, O: Sink>(
    mut ctx: R,
    config: Config<S>,
    peer: S::PublicKey,
    mut stream: I,
    mut sink: O,
) -> Result<(Sender<O>, Receiver<I>), Error> {
    send_frame(
        &mut sink,
        config.signing_key.public_key().encode().as_ref(),
        config.max_message_size,
    )
    .await?;

    let (current_time, ok_timestamps) = config.time_information(&ctx);
    let (state, msg1) = dial_start(
        &mut ctx,
        Context::new(current_time, ok_timestamps, config.signing_key, peer),
    );
    send_frame(&mut sink, &msg1.encode(), config.max_message_size).await?;

    let msg2_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let msg2 = Msg2::<S::Signature>::decode(msg2_bytes)?;

    let (msg3, send, recv) = dial_end(state, msg2)?;
    send_frame(&mut sink, &msg3.encode(), config.max_message_size).await?;

    Ok((
        Sender {
            cipher: send,
            sink,
            max_message_size: config.max_message_size,
        },
        Receiver {
            cipher: recv,
            stream,
            max_message_size: config.max_message_size,
        },
    ))
}

pub async fn listen<
    R: CryptoRngCore + Clock,
    S: Signer,
    I: Stream,
    O: Sink,
    Fut: Future<Output = bool>,
    F: FnOnce(S::PublicKey) -> Fut,
>(
    mut ctx: R,
    bouncer: F,
    config: Config<S>,
    mut stream: I,
    mut sink: O,
) -> Result<(S::PublicKey, Sender<O>, Receiver<I>), Error> {
    let peer_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let peer = S::PublicKey::decode(peer_bytes)?;
    if !bouncer(peer.clone()).await {
        return Err(Error::PeerRejected(peer.encode().to_vec()));
    }

    let msg1_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let msg1 = Msg1::<S::Signature>::decode(msg1_bytes)?;

    let (current_time, ok_timestamps) = config.time_information(&ctx);
    let (state, msg2) = listen_start(
        &mut ctx,
        Context::new(
            current_time,
            ok_timestamps,
            config.signing_key,
            peer.clone(),
        ),
        msg1,
    )?;
    send_frame(&mut sink, &msg2.encode(), config.max_message_size).await?;

    let msg3_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let msg3 = Msg3::decode(msg3_bytes)?;

    let (send, recv) = listen_end(state, msg3)?;

    Ok((
        peer,
        Sender {
            cipher: send,
            sink,
            max_message_size: config.max_message_size,
        },
        Receiver {
            cipher: recv,
            stream,
            max_message_size: config.max_message_size,
        },
    ))
}

pub struct Sender<O> {
    cipher: SendCipher,
    sink: O,
    max_message_size: usize,
}

impl<O: Sink> Sender<O> {
    pub async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        let c = self.cipher.send(msg)?;
        send_frame(&mut self.sink, &c, self.max_message_size).await?;
        Ok(())
    }
}

pub struct Receiver<I> {
    cipher: RecvCipher,
    stream: I,
    max_message_size: usize,
}

impl<I: Stream> Receiver<I> {
    pub async fn recv(&mut self) -> Result<Bytes, Error> {
        let c = recv_frame(&mut self.stream, self.max_message_size).await?;
        Ok(self.cipher.recv(&c)?.into())
    }
}
