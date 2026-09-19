use crate::Handshake;
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
use rand_core::CryptoRng;
use std::future::Future;

/// Reuses a handshake with a fixed namespace and plaintext message limit.
///
/// Works with any [Handshake] implementation, cloning it for each connection attempt.
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
/// use commonware_stream::{cups::{Config, Handshake}, utils::Timeout};
/// use std::time::Duration;
///
/// let config = Config::new(
///     Timeout::new(Handshake::new(PrivateKey::from_seed(0)), Duration::from_secs(5)),
///     b"_COMMONWARE_STREAM_CONFIG_EXAMPLE",
///     1024,
/// );
/// ```
pub struct Config<H: Handshake> {
    handshake: H,
    namespace: Vec<u8>,
    max_message_size: u32,
}

impl<H: Handshake> Config<H> {
    /// Configures the namespace and plaintext message limit for every connection.
    ///
    /// # Panics
    ///
    /// Panics if `max_message_size` exceeds [`Handshake::MAX_SIZE`].
    pub fn new(handshake: H, namespace: impl Into<Vec<u8>>, max_message_size: u32) -> Self {
        assert!(
            max_message_size <= H::MAX_SIZE,
            "maximum message size exceeds stream limit"
        );
        Self {
            handshake,
            namespace: namespace.into(),
            max_message_size,
        }
    }

    /// Authenticates an outbound connection to `peer`.
    #[allow(clippy::type_complexity)]
    pub fn dial<C, I, O>(
        &self,
        context: C,
        peer: H::PublicKey,
        stream: I,
        sink: O,
    ) -> impl Future<Output = Result<(H::Sender<I, O>, H::Receiver<I, O>), H::Error>> + Send
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        self.handshake.clone().dial(
            context,
            &self.namespace,
            self.max_message_size,
            peer,
            stream,
            sink,
        )
    }

    /// Authenticates an inbound connection accepted by `bouncer`.
    ///
    /// The bouncer may receive an unverified identity claim. Only a successful handshake
    /// authenticates the returned peer.
    #[allow(clippy::type_complexity)]
    pub fn listen<C, I, O, B, F>(
        &self,
        context: C,
        bouncer: B,
        stream: I,
        sink: O,
    ) -> impl Future<Output = Result<(H::PublicKey, H::Sender<I, O>, H::Receiver<I, O>), H::Error>> + Send
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(H::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        self.handshake.clone().listen(
            context,
            &self.namespace,
            self.max_message_size,
            bouncer,
            stream,
            sink,
        )
    }
}
