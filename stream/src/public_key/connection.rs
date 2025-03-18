use super::{handshake, nonce, x25519, Config};
use crate::{
    utils::codec::{recv_frame, send_frame},
    Error,
};
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use commonware_codec::Codec;
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_utils::SystemTimeExt as _;
use rand::{CryptoRng, Rng};
use std::time::SystemTime;

// When encrypting data, an encryption tag is appended to the ciphertext.
// This constant represents the size of the encryption tag in bytes.
const ENCRYPTION_TAG_LENGTH: usize = 16;

/// An incoming connection with a verified peer handshake.
pub struct IncomingConnection<C: Scheme, Si: Sink, St: Stream> {
    config: Config<C>,
    sink: Si,
    stream: St,
    deadline: SystemTime,
    ephemeral_public_key: x25519::PublicKey,
    peer_public_key: C::PublicKey,
}

impl<C: Scheme, Si: Sink, St: Stream> IncomingConnection<C, Si, St> {
    pub async fn verify<E: Clock + Spawner>(
        context: &E,
        config: Config<C>,
        sink: Si,
        mut stream: St,
    ) -> Result<Self, Error> {
        // Set handshake deadline
        let deadline = context.current() + config.handshake_timeout;

        // Wait for up to handshake timeout for response
        let msg = select! {
            _ = context.sleep_until(deadline) => { return Err(Error::HandshakeTimeout) },
            result = recv_frame(&mut stream, config.max_message_size) => { result? },
        };

        // Verify handshake message from peer
        let signed_handshake =
            handshake::Signed::<C>::decode(msg).map_err(Error::UnableToDecode)?;
        signed_handshake.verify(
            context,
            &config.crypto,
            &config.namespace,
            config.synchrony_bound,
            config.max_handshake_age,
        )?;
        Ok(Self {
            config,
            sink,
            stream,
            deadline,
            ephemeral_public_key: signed_handshake.ephemeral(),
            peer_public_key: signed_handshake.signer(),
        })
    }

    /// The public key of the peer attempting to connect.
    pub fn peer(&self) -> C::PublicKey {
        self.peer_public_key.clone()
    }

    /// The ephemeral public key of the peer attempting to connect.
    pub fn ephemeral(&self) -> x25519::PublicKey {
        self.ephemeral_public_key
    }
}

/// A fully initialized connection with some peer.
pub struct Connection<Si: Sink, St: Stream> {
    dialer: bool,
    sink: Si,
    stream: St,
    cipher: ChaCha20Poly1305,
    max_message_size: usize,
}

impl<Si: Sink, St: Stream> Connection<Si, St> {
    /// Create a new connection from pre-established components.
    ///
    /// This is useful in tests, or when upgrading a connection that has already been verified.
    pub fn from_preestablished(
        dialer: bool,
        sink: Si,
        stream: St,
        cipher: ChaCha20Poly1305,
        max_message_size: usize,
    ) -> Self {
        Self {
            dialer,
            sink,
            stream,
            cipher,
            max_message_size,
        }
    }

    /// Attempt to upgrade a raw connection we initiated.
    ///
    /// This will send a handshake message to the peer, wait for a response,
    /// and verify the peer's handshake message.
    pub async fn upgrade_dialer<R: Rng + CryptoRng + Spawner + Clock, C: Scheme>(
        mut context: R,
        mut config: Config<C>,
        mut sink: Si,
        mut stream: St,
        peer: C::PublicKey,
    ) -> Result<Self, Error> {
        // Set handshake deadline
        let deadline = context.current() + config.handshake_timeout;

        // Generate shared secret
        let secret = x25519::new(&mut context);

        // Send handshake
        let timestamp = context.current().epoch_millis();
        let msg = handshake::Signed::sign(
            &mut config.crypto,
            &config.namespace,
            handshake::Info::<C>::new(peer.clone(), &secret, timestamp),
        )
        .encode();

        // Wait for up to handshake timeout to send
        select! {
            _ = context.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(&mut sink, &msg, config.max_message_size) => {
                result?;
            },
        }

        // Wait for up to handshake timeout for response
        let msg = select! {
            _ = context.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = recv_frame(&mut stream, config.max_message_size) => {
                result?
            },
        };

        // Verify handshake message from peer
        let signed_handshake =
            handshake::Signed::<C>::decode(msg).map_err(Error::UnableToDecode)?;
        signed_handshake.verify(
            &context,
            &config.crypto,
            &config.namespace,
            config.synchrony_bound,
            config.max_handshake_age,
        )?;

        // Ensure we connected to the right peer
        if peer != signed_handshake.signer() {
            return Err(Error::WrongPeer);
        }

        // Create cipher
        let shared_secret = secret.diffie_hellman(signed_handshake.ephemeral().as_ref());
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| Error::CipherCreationFailed)?;

        // We keep track of dialer to determine who adds a bit to their nonce (to prevent reuse)
        Ok(Self {
            dialer: true,
            sink,
            stream,
            cipher,
            max_message_size: config.max_message_size,
        })
    }

    /// Attempt to upgrade a connection initiated by some peer.
    ///
    /// Because we already verified the peer's handshake, this function
    /// only needs to send our handshake message for the connection to be fully
    /// initialized.
    pub async fn upgrade_listener<R: Rng + CryptoRng + Spawner + Clock, C: Scheme>(
        mut context: R,
        incoming: IncomingConnection<C, Si, St>,
    ) -> Result<Self, Error> {
        // Extract fields
        let max_message_size = incoming.config.max_message_size;
        let mut crypto = incoming.config.crypto;
        let namespace = incoming.config.namespace;
        let mut sink = incoming.sink;
        let stream = incoming.stream;

        // Generate personal secret
        let secret = x25519::new(&mut context);

        // Send handshake
        let timestamp = context.current().epoch_millis();
        let msg = handshake::Signed::sign(
            &mut crypto,
            &namespace,
            handshake::Info::<C>::new(incoming.peer_public_key, &secret, timestamp),
        )
        .encode();

        // Wait for up to handshake timeout
        select! {
            _ = context.sleep_until(incoming.deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(&mut sink, &msg, max_message_size) => {
                result?;
            },
        }

        // Create cipher based on the shared secret
        let shared_secret = secret.diffie_hellman(incoming.ephemeral_public_key.as_ref());
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| Error::CipherCreationFailed)?;

        // Track whether or not we are the dialer to ensure we send correctly formatted nonces.
        Ok(Connection {
            dialer: false,
            sink,
            stream,
            cipher,
            max_message_size,
        })
    }

    /// Split the connection into a `Sender` and `Receiver`.
    ///
    /// This pattern is commonly used to efficiently send and receive messages
    /// over the same connection concurrently.
    pub fn split(self) -> (Sender<Si>, Receiver<St>) {
        (
            Sender {
                cipher: self.cipher.clone(),
                sink: self.sink,
                max_message_size: self.max_message_size,
                nonce: nonce::Info::new(self.dialer),
            },
            Receiver {
                cipher: self.cipher,
                stream: self.stream,
                max_message_size: self.max_message_size,
                nonce: nonce::Info::new(!self.dialer),
            },
        )
    }
}

/// The half of the `Connection` that implements `crate::Sender`.
pub struct Sender<Si: Sink> {
    cipher: ChaCha20Poly1305,
    sink: Si,

    max_message_size: usize,
    nonce: nonce::Info,
}

impl<Si: Sink> crate::Sender for Sender<Si> {
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        // Encrypt data
        let msg = self
            .cipher
            .encrypt(&self.nonce.encode(), msg.as_ref())
            .map_err(|_| Error::EncryptionFailed)?;
        self.nonce.inc()?;

        // Send data
        send_frame(
            &mut self.sink,
            &msg,
            self.max_message_size + ENCRYPTION_TAG_LENGTH,
        )
        .await?;
        Ok(())
    }
}

/// The half of a `Connection` that implements `crate::Receiver`.
pub struct Receiver<St: Stream> {
    cipher: ChaCha20Poly1305,
    stream: St,

    max_message_size: usize,
    nonce: nonce::Info,
}

impl<St: Stream> crate::Receiver for Receiver<St> {
    async fn receive(&mut self) -> Result<Bytes, Error> {
        // Read data
        let msg = recv_frame(
            &mut self.stream,
            self.max_message_size + ENCRYPTION_TAG_LENGTH,
        )
        .await?;

        // Decrypt data
        let msg = self
            .cipher
            .decrypt(&self.nonce.encode(), msg.as_ref())
            .map_err(|_| Error::DecryptionFailed)?;
        self.nonce.inc()?;

        Ok(Bytes::from(msg))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{Receiver as _, Sender as _};
    use commonware_cryptography::Ed25519;
    use commonware_runtime::{deterministic::Executor, mocks, Metrics, Runner};

    #[test]
    fn test_decryption_failure() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size: 1024,
                nonce: nonce::Info::new(false),
            };

            // Send invalid ciphertext
            send_frame(&mut sink, b"invalid data", receiver.max_message_size)
                .await
                .unwrap();

            let result = receiver.receive().await;
            assert!(matches!(result, Err(Error::DecryptionFailed)));
        });
    }

    #[test]
    fn test_send_too_large() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let message = b"hello world";
            let (sink, _) = mocks::Channel::init();
            let mut sender = Sender {
                cipher,
                sink,
                max_message_size: message.len() - 1,
                nonce: nonce::Info::new(true),
            };

            let result = sender.send(message).await;
            let expected_length = message.len() + ENCRYPTION_TAG_LENGTH;
            assert!(matches!(result, Err(Error::SendTooLarge(n)) if n == expected_length));
        });
    }

    #[test]
    fn test_receive_too_large() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let message = b"hello world";
            let (sink, stream) = mocks::Channel::init();

            let mut sender = Sender {
                cipher: cipher.clone(),
                sink,
                max_message_size: message.len(),
                nonce: nonce::Info::new(true),
            };
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size: message.len() - 1,
                nonce: nonce::Info::new(false),
            };

            sender.send(message).await.unwrap();
            let result = receiver.receive().await;
            let expected_length = message.len() + ENCRYPTION_TAG_LENGTH;
            assert!(matches!(result, Err(Error::RecvTooLarge(n)) if n == expected_length));
        });
    }

    #[test]
    fn test_send_receive() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let max_message_size = 1024;

            // Create channels
            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            // Create dialer connection
            let connection_dialer = Connection::from_preestablished(
                true, // dialer
                dialer_sink,
                dialer_stream,
                cipher.clone(),
                max_message_size,
            );

            // Create listener connection
            let connection_listener = Connection::from_preestablished(
                false, // listener
                listener_sink,
                listener_stream,
                cipher,
                max_message_size,
            );

            // Split into sender and receiver for both connections
            let (mut dialer_sender, mut dialer_receiver) = connection_dialer.split();
            let (mut listener_sender, mut listener_receiver) = connection_listener.split();

            // Test 1: Send from dialer to listener
            let msg1 = b"hello from dialer";
            dialer_sender.send(msg1).await.unwrap();
            let received1 = listener_receiver.receive().await.unwrap();
            assert_eq!(received1, &msg1[..]);

            // Test 2: Send from listener to dialer
            let msg2 = b"hello from listener";
            listener_sender.send(msg2).await.unwrap();
            let received2 = dialer_receiver.receive().await.unwrap();
            assert_eq!(received2, &msg2[..]);

            // Test 3: Send multiple messages both ways
            let messages_to_listener = vec![b"msg1", b"msg2", b"msg3"];
            for msg in &messages_to_listener {
                dialer_sender.send(*msg).await.unwrap();
                let received = listener_receiver.receive().await.unwrap();
                assert_eq!(received, &msg[..]);
            }
            let messages_to_dialer = vec![b"reply1", b"reply2", b"reply3"];
            for msg in &messages_to_dialer {
                listener_sender.send(*msg).await.unwrap();
                let received = dialer_receiver.receive().await.unwrap();
                assert_eq!(received, &msg[..]);
            }
        });
    }
    #[test]
    fn test_full_connection_establishment_and_exchange() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create cryptographic identities
            let dialer_crypto = Ed25519::from_seed(0);
            let listener_crypto = Ed25519::from_seed(1);

            // Set up mock channels for transport simulation
            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            // Configuration for dialer
            let dialer_config = Config {
                crypto: dialer_crypto.clone(),
                namespace: b"test_namespace".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };

            // Configuration for listener
            let listener_config = Config {
                crypto: listener_crypto.clone(),
                namespace: b"test_namespace".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };

            // Spawn listener to handle incoming connection
            let listener_handle = context.with_label("listener").spawn({
                move |context| async move {
                    let incoming = IncomingConnection::verify(
                        &context,
                        listener_config,
                        listener_sink,
                        listener_stream,
                    )
                    .await
                    .unwrap();
                    Connection::upgrade_listener(context, incoming)
                        .await
                        .unwrap()
                }
            });

            // Dialer initiates the connection
            let dialer_connection = Connection::upgrade_dialer(
                context.clone(),
                dialer_config,
                dialer_sink,
                dialer_stream,
                listener_crypto.public_key(),
            )
            .await
            .unwrap();

            // Wait for listener connection to be established
            let listener_connection = listener_handle.await.unwrap();

            // Split connections into sender and receiver halves
            let (mut dialer_sender, mut dialer_receiver) = dialer_connection.split();
            let (mut listener_sender, mut listener_receiver) = listener_connection.split();

            // Dialer sends to listener twice
            let message1 = b"Hello from dialer";
            dialer_sender.send(message1).await.unwrap();
            dialer_sender.send(message1).await.unwrap();
            let received = listener_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &message1[..]);
            let received = listener_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &message1[..]);

            // Listener sends to dialer twice
            let message2 = b"Hello from listener";
            listener_sender.send(message2).await.unwrap();
            listener_sender.send(message2).await.unwrap();
            let received = dialer_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &message2[..]);
            let received = dialer_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &message2[..]);
        });
    }

    #[test]
    fn test_upgrade_dialer_wrong_peer() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create cryptographic identities
            let dialer_crypto = Ed25519::from_seed(0);
            let expected_peer = Ed25519::from_seed(1).public_key();
            let mut actual_peer = Ed25519::from_seed(2);

            // Set up mock channels
            let (dialer_sink, mut peer_stream) = mocks::Channel::init();
            let (mut peer_sink, dialer_stream) = mocks::Channel::init();

            // Dialer configuration
            let dialer_config = Config {
                crypto: dialer_crypto,
                namespace: b"test_namespace".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };
            let peer_config = dialer_config.clone();

            // Spawn a mock peer that responds with its own handshake without checking recipient
            context.with_label("mock_peer").spawn({
                move |mut context| async move {
                    // Read the handshake from dialer
                    let msg = recv_frame(&mut peer_stream, 1024).await.unwrap();
                    let _ = handshake::Signed::<Ed25519>::decode(msg).unwrap(); // Simulate reading

                    // Create and send own handshake
                    let secret = x25519::new(&mut context);
                    let timestamp = context.current().epoch_millis();
                    let info =
                        handshake::Info::new(peer_config.crypto.public_key(), &secret, timestamp);
                    let signed_handshake =
                        handshake::Signed::sign(&mut actual_peer, &peer_config.namespace, info);
                    send_frame(&mut peer_sink, &signed_handshake.encode(), 1024)
                        .await
                        .unwrap();
                }
            });

            // Attempt connection with expected peer key
            let result = Connection::upgrade_dialer(
                context,
                dialer_config,
                dialer_sink,
                dialer_stream,
                expected_peer,
            )
            .await;

            // Verify the error
            assert!(matches!(result, Err(Error::WrongPeer)));
        });
    }
}
