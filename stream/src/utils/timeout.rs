use crate::Handshake;
use commonware_macros::select;
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
use rand_core::CryptoRng;
use std::{future::Future, time::Duration};
use thiserror::Error;

/// Errors returned by a handshake with a deadline.
#[derive(Debug, Error)]
pub enum TimeoutError<E> {
    #[error("handshake failed: {0}")]
    Handshake(#[source] E),
    #[error("handshake timed out")]
    Timeout,
}

/// Applies a timeout to each handshake attempt.
///
/// The deadline starts when [`Handshake::dial`] or [`Handshake::listen`] is called.
/// It covers the entire attempt, including the listener's peer admission check.
/// Expiration drops the handshake future and releases its connection.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
/// use commonware_stream::{cups::{Handshake, Version}, utils::Timeout};
/// use std::time::Duration;
///
/// let handshake = Timeout::new(Handshake::new(PrivateKey::from_seed(0), Version::V1), Duration::from_secs(5));
/// ```
#[derive(Clone)]
pub struct Timeout<H> {
    handshake: H,
    timeout: Duration,
}

impl<H> Timeout<H> {
    /// Wraps a handshake with a deadline for each connection attempt.
    pub const fn new(handshake: H, timeout: Duration) -> Self {
        Self { handshake, timeout }
    }
}

impl<H: Handshake> Handshake for Timeout<H> {
    const MAX_SIZE: u32 = H::MAX_SIZE;

    type PublicKey = H::PublicKey;
    type Error = TimeoutError<H::Error>;
    type Sender<I: Stream, O: Sink> = H::Sender<I, O>;
    type Receiver<I: Stream, O: Sink> = H::Receiver<I, O>;

    fn public_key(&self) -> Self::PublicKey {
        self.handshake.public_key()
    }

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
        O: Sink,
    {
        // Construct the handshake future before wrapping it so it can consume a non-Send peer.
        let timeout = context.sleep(self.timeout);
        let attempt = self
            .handshake
            .dial(context, namespace, max_message_size, peer, stream, sink);
        async move {
            select! {
                result = attempt => result.map_err(TimeoutError::Handshake),
                _ = timeout => Err(TimeoutError::Timeout),
            }
        }
    }

    fn listen<C, I, O, B, F>(
        self,
        context: C,
        namespace: &[u8],
        max_message_size: u32,
        bouncer: B,
        stream: I,
        sink: O,
    ) -> impl Future<
        Output = Result<(Self::PublicKey, Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>,
    > + Send
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(Self::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        let timeout = context.sleep(self.timeout);
        let attempt =
            self.handshake
                .listen(context, namespace, max_message_size, bouncer, stream, sink);
        async move {
            select! {
                result = attempt => result.map_err(TimeoutError::Handshake),
                _ = timeout => Err(TimeoutError::Timeout),
            }
        }
    }
}
