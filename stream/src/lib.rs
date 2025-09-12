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
        dial_end, dial_start, listen_end, listen_start, Context, Msg1, Msg2, Msg3, RecvCipher,
        SendCipher,
    },
    Signer,
};
use commonware_runtime::{Clock, Error as RuntimeError, Sink, Stream};
use commonware_utils::SystemTimeExt;
use rand_core::CryptoRngCore;
use std::{future::Future, time::Duration};
use thiserror::Error;

use crate::utils::codec::{recv_frame, send_frame};

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    // Handshake errors
    #[error("handshake timeout")]
    HandshakeTimeout,

    // Hello errors
    #[error("hello not for us")]
    HelloNotForUs,
    #[error("hello uses our public key")]
    HelloUsesOurKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("timestamp too old: {0}")]
    InvalidTimestampOld(u64),
    #[error("timestamp too future: {0}")]
    InvalidTimestampFuture(u64),
    #[error("info continuation tag was invalid")]
    InvalidInfoContinuationTag,

    // Confirmation errors
    #[error("shared secret was not contributory")]
    SharedSecretNotContributory,
    #[error("cipher creation failed")]
    CipherCreation,
    #[error("HKDF expansion failed")]
    HKDFExpansion,
    #[error("key confirmation failed")]
    ConfirmationFailed,
    #[error("invalid key confirmation")]
    InvalidConfirmation,

    // Connection errors
    #[error("cannot dial self")]
    DialSelf,
    #[error("wrong peer")]
    WrongPeer,
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

    // Encryption errors
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,

    // Codec errors
    #[error("unable to decode: {0}")]
    UnableToDecode(CodecError),

    #[error("peer rejected: {0:X?}")]
    PeerRejected(Vec<u8>),
}

impl From<CodecError> for Error {
    fn from(value: CodecError) -> Self {
        Self::UnableToDecode(value)
    }
}

/// Configuration for a connection.
///
/// # Warning
///
/// Synchronize this configuration across all peers.
/// Mismatched configurations may cause dropped connections or parsing errors.
#[derive(Clone)]
pub struct Config<S: Signer> {
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

    /// Maximum time allowed for completing the handshake.
    pub handshake_timeout: Duration,
}

/// Allows consumers to stop handshakes early if the peer is invalid.
///
/// This can be used to implement a block-list system, where some peers should
/// not be allowed to create connections, or an allow-list system where only
/// a predefined list of peers are able to create connections, or some other
/// arbitrary piece of logic.
pub trait Bouncer<K> {
    // alternative name: vibe_check
    /// This should return true if a connection to this peer should be accepted.
    fn allows_peer(&mut self, peer: K) -> impl Future<Output = bool> + Send;
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

    let current_time = ctx.current().epoch_millis();
    let (state, msg1) = dial_start(
        &mut ctx,
        Context::new(current_time, config.signing_key, peer),
    );
    send_frame(&mut sink, &msg1.encode(), config.max_message_size).await?;

    let msg2_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let msg2 = Msg2::<S::Signature>::decode(msg2_bytes)?;

    let (msg3, send, recv) = dial_end(state, msg2).expect("FIXME");
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

pub async fn listen<R: CryptoRngCore + Clock, S: Signer, I: Stream, O: Sink>(
    mut ctx: R,
    bouncer: &mut impl Bouncer<S::PublicKey>,
    config: Config<S>,
    mut stream: I,
    mut sink: O,
) -> Result<(S::PublicKey, Sender<O>, Receiver<I>), Error> {
    let peer_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let peer = S::PublicKey::decode(peer_bytes)?;
    if !bouncer.allows_peer(peer.clone()).await {
        return Err(Error::PeerRejected(peer.encode().to_vec()));
    }

    let msg1_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let msg1 = Msg1::<S::Signature>::decode(msg1_bytes)?;

    let current_time = ctx.current().epoch_millis();
    let (state, msg2) = listen_start(
        &mut ctx,
        Context::new(current_time, config.signing_key, peer.clone()),
        msg1,
    )
    .expect("FIXME");
    send_frame(&mut sink, &msg2.encode(), config.max_message_size).await?;

    let msg3_bytes = recv_frame(&mut stream, config.max_message_size).await?;
    let msg3 = Msg3::decode(msg3_bytes)?;

    let (send, recv) = listen_end(state, msg3).expect("FIXME");

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
        let c = self.cipher.send(msg);
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
        Ok(self.cipher.recv(&c).into())
    }
}
