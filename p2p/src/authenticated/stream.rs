//! Connection upgrades shared by the dialer and listener actors.

#[cfg(test)]
use commonware_cryptography::Signer;
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
#[cfg(test)]
use commonware_stream::SakeCups;
use commonware_stream::Upgrader;
use rand_core::CryptoRng;
use std::future::Future;

/// Reuses an [Upgrader] with a fixed namespace and plaintext message limit.
///
/// Clones the upgrader for each connection attempt.
pub(crate) struct Config<U: Upgrader> {
    handshake: U,
    namespace: Vec<u8>,
    max_message_size: u32,
}

impl<U: Upgrader> Config<U> {
    /// Configures the namespace and plaintext message limit for every connection.
    ///
    /// # Panics
    ///
    /// Panics if `max_message_size` exceeds [`Upgrader::MAX_SIZE`].
    pub(crate) fn new(handshake: U, namespace: impl Into<Vec<u8>>, max_message_size: u32) -> Self {
        assert!(
            max_message_size <= U::MAX_SIZE,
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
        peer: U::PublicKey,
        stream: I,
        sink: O,
    ) -> impl Future<Output = Result<(U::Sender<I, O>, U::Receiver<I, O>), U::Error>> + Send
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
    ) -> impl Future<Output = Result<(U::PublicKey, U::Sender<I, O>, U::Receiver<I, O>), U::Error>> + Send
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(U::PublicKey) -> F + Send,
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
    use commonware_cryptography::{ChaCha20Poly1305, ed25519::PrivateKey};
    use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic, mocks};
    use commonware_stream::{cups, cups::Cups, sake, sake::Sake, sake_cups};
    use std::time::Duration;

    const NAMESPACE: &[u8] = b"test_namespace";
    const LIMIT: u32 = 1024;

    fn handshake(seed: u64) -> SakeCups<PrivateKey, ChaCha20Poly1305> {
        sake_cups(
            Sake {
                signer: PrivateKey::from_seed(seed),
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(10),
                version: sake::Version::V1,
            },
            Cups::<ChaCha20Poly1305>::new(cups::Version::V1),
        )
    }

    #[test]
    fn test_max_message_size_within_limit() {
        for max_message_size in [0, SakeCups::<PrivateKey, ChaCha20Poly1305>::MAX_SIZE] {
            Config::new(handshake(0), NAMESPACE, max_message_size);
        }
    }

    #[test]
    #[should_panic(expected = "maximum message size exceeds stream limit")]
    fn test_max_message_size_above_limit() {
        Config::new(
            handshake(0),
            NAMESPACE,
            SakeCups::<PrivateKey, ChaCha20Poly1305>::MAX_SIZE + 1,
        );
    }

    /// Dials through the config to a listener configured with the namespace and limit directly.
    /// The connection completes and the limit holds only if the config forwards both.
    #[test]
    fn test_dial_forwards_namespace_and_limit() {
        deterministic::Runner::default()
            .start(|context| async move {
                let (dialer_sink, listener_stream) = mocks::Channel::init();
                let (listener_sink, dialer_stream) = mocks::Channel::init();
                let config = Config::new(handshake(0), NAMESPACE, LIMIT);
                let listener = handshake(1);
                let listener_key = listener.public_key();

                // Listen with the bare upgrader while dialing through the config.
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
