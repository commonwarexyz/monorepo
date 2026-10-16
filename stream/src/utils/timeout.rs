use crate::Upgrader;
use commonware_macros::select;
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
use rand_core::CryptoRng;
use std::{future::Future, time::Duration};
use thiserror::Error;

/// Errors returned by [Timeout].
#[derive(Debug, Error)]
pub enum TimeoutError<E> {
    #[error("handshake failed: {0}")]
    Upgrade(#[source] E),
    #[error("handshake timed out")]
    Timeout,
}

/// Applies a deadline to each [Upgrader] attempt.
///
/// The deadline starts when [`Upgrader::dial`] or [`Upgrader::listen`] is called.
/// It covers the entire attempt, including the listener's peer admission check.
/// Expiration drops the attempt and releases its connection.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{ChaCha20Poly1305, Signer as _, ed25519::PrivateKey};
/// use commonware_stream::{
///     cups::{self, Cups},
///     sake::{self, Sake},
///     utils::Timeout,
/// };
/// use std::time::Duration;
///
/// let upgrader = Timeout::new(
///     Cups::<_, ChaCha20Poly1305>::new(
///         Sake {
///             signer: PrivateKey::from_seed(0),
///             synchrony_bound: Duration::from_secs(5),
///             max_handshake_age: Duration::from_secs(10),
///             version: sake::Version::V1,
///         },
///         cups::Version::V1,
///     ),
///     Duration::from_secs(5),
/// );
/// ```
#[derive(Clone)]
pub struct Timeout<U> {
    upgrader: U,
    timeout: Duration,
}

impl<U> Timeout<U> {
    /// Wraps `upgrader` with a deadline for each connection attempt.
    pub const fn new(upgrader: U, timeout: Duration) -> Self {
        Self { upgrader, timeout }
    }
}

impl<U: Upgrader> Upgrader for Timeout<U> {
    const MAX_SIZE: u32 = U::MAX_SIZE;

    type PublicKey = U::PublicKey;
    type Error = TimeoutError<U::Error>;
    type Sender<I: Stream, O: Sink> = U::Sender<I, O>;
    type Receiver<I: Stream, O: Sink> = U::Receiver<I, O>;

    fn public_key(&self) -> Self::PublicKey {
        self.upgrader.public_key()
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
        // Construct the attempt before wrapping it so it can consume a non-Send peer.
        let timeout = context.sleep(self.timeout);
        let attempt = self
            .upgrader
            .dial(context, namespace, max_message_size, peer, stream, sink);
        async move {
            select! {
                result = attempt => result.map_err(TimeoutError::Upgrade),
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
            self.upgrader
                .listen(context, namespace, max_message_size, bouncer, stream, sink);
        async move {
            select! {
                result = attempt => result.map_err(TimeoutError::Upgrade),
                _ = timeout => Err(TimeoutError::Timeout),
            }
        }
    }
}
