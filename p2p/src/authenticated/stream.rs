//! Connection upgrades shared by the dialer and listener actors.

#[cfg(test)]
use commonware_cryptography::{ChaCha20Poly1305, Signer};
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
use commonware_stream::Handshake;
#[cfg(test)]
use commonware_stream::{
    Upgrade,
    cups::{self, Cups},
    sake::{self, Version},
};
use rand_core::CryptoRng;
use std::future::Future;

/// SAKE handshake that keys CUPS records, shared by tests.
#[cfg(test)]
pub(crate) type StreamHandshake<S> = Upgrade<sake::Exchange<S>, Cups<ChaCha20Poly1305>>;

/// Returns a version 1 [StreamHandshake] that signs with `signer`.
#[cfg(test)]
pub(crate) const fn sake_handshake<S: Signer>(signer: S) -> StreamHandshake<S> {
    Upgrade::new(
        sake::Exchange::new(sake::Config::new(signer, Version::V1)),
        Cups::new(cups::Version::V1),
    )
}

/// Reuses a handshake with a fixed namespace and plaintext message limit.
///
/// Works with any [Handshake] implementation, cloning it for each connection attempt.
pub(crate) struct Config<H: Handshake> {
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
    pub(crate) fn new(handshake: H, namespace: impl Into<Vec<u8>>, max_message_size: u32) -> Self {
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
    pub(crate) fn dial<C, I, O>(
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
    pub(crate) fn listen<C, I, O, B, F>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::ed25519::PrivateKey;
    use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic, mocks};
    use commonware_stream::cups;

    type SakeHandshake = StreamHandshake<PrivateKey>;

    const NAMESPACE: &[u8] = b"test_namespace";
    const LIMIT: u32 = 1024;

    fn handshake(seed: u64) -> SakeHandshake {
        sake_handshake(PrivateKey::from_seed(seed))
    }

    #[test]
    fn test_max_message_size_within_limit() {
        for max_message_size in [0, SakeHandshake::MAX_SIZE] {
            Config::new(handshake(0), NAMESPACE, max_message_size);
        }
    }

    #[test]
    #[should_panic(expected = "maximum message size exceeds stream limit")]
    fn test_max_message_size_above_limit() {
        Config::new(handshake(0), NAMESPACE, SakeHandshake::MAX_SIZE + 1);
    }

    /// Dials through the config against a listener given the namespace and limit directly, so the
    /// connection completes and bounds messages at the limit only if the config forwards both.
    #[test]
    fn test_dial_forwards_namespace_and_limit() {
        deterministic::Runner::default()
            .start(|context| async move {
                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();
                let config = Config::new(handshake(0), NAMESPACE, LIMIT);
                let listener = handshake(1);
                let listener_key = listener.public_key();

                // Listen with the bare handshake while dialing through the config.
                let listen = context.child("listener").spawn(move |context| {
                    listener.listen(
                        context,
                        NAMESPACE,
                        LIMIT,
                        |_| async { true },
                        listener_stream,
                        listener_sink,
                    )
                });
                let (mut sender, _) = config
                    .dial(
                        context.child("dialer"),
                        listener_key,
                        dialer_stream,
                        dialer_sink,
                    )
                    .await?;
                let (_, _, mut receiver) = listen.await??;

                // A message at the forwarded limit reaches the listener.
                sender.send(vec![0; LIMIT as usize]).await?;
                assert_eq!(receiver.recv().await?.len(), LIMIT as usize);

                // A message above it is refused before sending.
                assert!(matches!(
                    sender.send(vec![0; LIMIT as usize + 1]).await,
                    Err(cups::Error::SendTooLarge(_))
                ));
                Ok::<_, Box<dyn std::error::Error>>(())
            })
            .unwrap();
    }
}
