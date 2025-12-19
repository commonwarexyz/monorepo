//! Exchange messages over arbitrary transport.
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
//! communication at a rate of 1 billion messages per second—sufficient for all practical use cases.
//! This ensures that well-behaving peers can remain connected indefinitely as long as they both
//! remain online (maximizing p2p network stability). In the unlikely case of counter overflow, the
//! connection will be terminated and a new connection should be established. This method prevents
//! nonce reuse (which would compromise message confidentiality) while saving bandwidth (as there is
//! no need to transmit nonces explicitly).
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

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub mod utils;

use crate::utils::codec::{recv_frame, send_frame};
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode as _, Error as CodecError};
use commonware_cryptography::{
    handshake::{
        self, dial_end, dial_start, listen_end, listen_start, Ack, Context,
        Error as HandshakeError, RecvCipher, SendCipher, Syn, SynAck,
    },
    transcript::Transcript,
    Signer,
};
use commonware_macros::select;
use commonware_runtime::{Clock, Error as RuntimeError, Sink, Stream};
use commonware_utils::{hex, SystemTimeExt};
use rand_core::CryptoRngCore;
use std::{future::Future, ops::Range, time::Duration};
use thiserror::Error;

const CIPHERTEXT_OVERHEAD: u32 = {
    assert!(handshake::CIPHERTEXT_OVERHEAD <= u32::MAX as usize);
    handshake::CIPHERTEXT_OVERHEAD as u32
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

/// Establishes an authenticated connection to a peer as the dialer.
/// Returns sender and receiver for encrypted communication.
pub async fn dial<R: CryptoRngCore + Clock, S: Signer, I: Stream, O: Sink>(
    mut ctx: R,
    config: Config<S>,
    peer: S::PublicKey,
    mut stream: I,
    mut sink: O,
) -> Result<(Sender<O>, Receiver<I>), Error> {
    let timeout = ctx.sleep(config.handshake_timeout);
    let inner_routine = async move {
        send_frame(
            &mut sink,
            config.signing_key.public_key().encode().as_ref(),
            config.max_message_size,
        )
        .await?;

        let (current_time, ok_timestamps) = config.time_information(&ctx);
        let (state, syn) = dial_start(
            &mut ctx,
            Context::new(
                &Transcript::new(&config.namespace),
                current_time,
                ok_timestamps,
                config.signing_key,
                peer,
            ),
        );
        send_frame(&mut sink, &syn.encode(), config.max_message_size).await?;

        let syn_ack_bytes = recv_frame(&mut stream, config.max_message_size).await?;
        let syn_ack = SynAck::<S::Signature>::decode(syn_ack_bytes)?;

        let (ack, send, recv) = dial_end(state, syn_ack)?;
        send_frame(&mut sink, &ack.encode(), config.max_message_size).await?;

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
    };

    select! {
        x = inner_routine => { x } ,
        _ = timeout => { Err(Error::HandshakeTimeout) }
    }
}

/// Accepts an authenticated connection from a peer as the listener.
/// Returns the peer's identity, sender, and receiver for encrypted communication.
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
    let timeout = ctx.sleep(config.handshake_timeout);
    let inner_routine = async move {
        let peer_bytes = recv_frame(&mut stream, config.max_message_size).await?;
        let peer = S::PublicKey::decode(peer_bytes)?;
        if !bouncer(peer.clone()).await {
            return Err(Error::PeerRejected(peer.encode().to_vec()));
        }

        let msg1_bytes = recv_frame(&mut stream, config.max_message_size).await?;
        let msg1 = Syn::<S::Signature>::decode(msg1_bytes)?;

        let (current_time, ok_timestamps) = config.time_information(&ctx);
        let (state, syn_ack) = listen_start(
            &mut ctx,
            Context::new(
                &Transcript::new(&config.namespace),
                current_time,
                ok_timestamps,
                config.signing_key,
                peer.clone(),
            ),
            msg1,
        )?;
        send_frame(&mut sink, &syn_ack.encode(), config.max_message_size).await?;

        let ack_bytes = recv_frame(&mut stream, config.max_message_size).await?;
        let ack = Ack::decode(ack_bytes)?;

        let (send, recv) = listen_end(state, ack)?;

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
    };

    select! {
        x = inner_routine => { x } ,
        _ = timeout => { Err(Error::HandshakeTimeout) }
    }
}

/// Sends encrypted messages to a peer.
pub struct Sender<O> {
    cipher: SendCipher,
    sink: O,
    max_message_size: u32,
}

impl<O: Sink> Sender<O> {
    /// Encrypts and sends a message to the peer.
    pub async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        let c = self.cipher.send(msg)?;
        send_frame(
            &mut self.sink,
            &c,
            self.max_message_size.saturating_add(CIPHERTEXT_OVERHEAD),
        )
        .await?;
        Ok(())
    }
}

/// Receives encrypted messages from a peer.
pub struct Receiver<I> {
    cipher: RecvCipher,
    stream: I,
    max_message_size: u32,
}

impl<I: Stream> Receiver<I> {
    /// Receives and decrypts a message from the peer.
    pub async fn recv(&mut self) -> Result<Bytes, Error> {
        let c = recv_frame(
            &mut self.stream,
            self.max_message_size.saturating_add(CIPHERTEXT_OVERHEAD),
        )
        .await?;
        Ok(self.cipher.recv(&c)?.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use commonware_cryptography::{ed25519::PrivateKey, Signer};
    use commonware_runtime::{deterministic, mocks, Runner as _, Spawner as _};

    const NAMESPACE: &[u8] = b"fuzz_transport";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024; // 64KB buffer

    #[test]
    fn test_can_setup_and_send_messages() -> Result<(), Error> {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            let dialer_config = Config {
                signing_key: dialer_crypto.clone(),
                namespace: NAMESPACE.to_vec(),
                max_message_size: MAX_MESSAGE_SIZE,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_secs(1),
            };

            let listener_config = Config {
                signing_key: listener_crypto.clone(),
                namespace: NAMESPACE.to_vec(),
                max_message_size: MAX_MESSAGE_SIZE,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_secs(1),
            };

            let listener_handle = context.clone().spawn(move |context| async move {
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
                dialer_sender.send(msg).await?;
                let syn_ack = listener_receiver.recv().await?;
                assert_eq!(msg, &syn_ack);
                listener_sender.send(msg).await?;
                let ack = dialer_receiver.recv().await?;
                assert_eq!(msg, &ack);
            }
            Ok(())
        })
    }
}
