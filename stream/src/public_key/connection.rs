use super::{
    cipher,
    handshake::{self, Confirmation},
    nonce, x25519, Config, AUTHENTICATION_TAG_LENGTH,
};
use crate::{
    utils::codec::{recv_frame, send_frame},
    Error,
};
use bytes::Bytes;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_utils::{union, SystemTimeExt as _};
use rand::{CryptoRng, Rng};
use std::time::SystemTime;

/// An incoming connection with a verified peer handshake.
pub struct IncomingConnection<C: Signer, Si: Sink, St: Stream> {
    config: Config<C>,
    sink: Si,
    stream: St,
    deadline: SystemTime,
    ephemeral_public_key: x25519::PublicKey,
    peer_public_key: C::PublicKey,

    /// Stores the raw bytes of the dialer hello message.
    /// Necessary for the cipher derivation.
    dialer_hello_msg: Bytes,
}

impl<C: Signer, Si: Sink, St: Stream> IncomingConnection<C, Si, St> {
    pub async fn verify<E: Clock + Spawner>(
        context: &E,
        config: Config<C>,
        sink: Si,
        mut stream: St,
    ) -> Result<Self, Error> {
        // Set handshake deadline
        let deadline = context.current() + config.handshake_timeout;

        // Wait for up to handshake timeout for response (Message 1)
        let msg = select! {
            _ = context.sleep_until(deadline) => { return Err(Error::HandshakeTimeout) },
            result = recv_frame(&mut stream, config.max_message_size) => { result? },
        };

        // Verify hello message from peer
        let hello = handshake::Hello::decode(msg.as_ref()).map_err(Error::UnableToDecode)?;
        hello.verify(
            context,
            &config.crypto.public_key(),
            &config.namespace,
            config.synchrony_bound,
            config.max_handshake_age,
        )?;
        Ok(Self {
            config,
            sink,
            stream,
            deadline,
            ephemeral_public_key: hello.ephemeral(),
            peer_public_key: hello.signer(),
            dialer_hello_msg: msg,
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
    sink: Si,
    stream: St,

    /// The maximum size of a message that can be sent or received.
    max_message_size: usize,

    /// The cipher used for sending messages.
    cipher_send: ChaCha20Poly1305,

    /// The cipher used for receiving messages.
    cipher_recv: ChaCha20Poly1305,
}

impl<Si: Sink, St: Stream> Connection<Si, St> {
    /// Create a new connection from pre-established components.
    ///
    /// This is useful in tests, or when upgrading a connection that has already been verified.
    pub fn from_preestablished(
        sink: Si,
        stream: St,
        max_message_size: usize,
        cipher_send: ChaCha20Poly1305,
        cipher_recv: ChaCha20Poly1305,
    ) -> Self {
        Self {
            sink,
            stream,
            max_message_size,
            cipher_send,
            cipher_recv,
        }
    }

    /// Attempt to upgrade a raw connection we initiated as the dialer.
    ///
    /// This implements the 3-message handshake protocol where the dialer:
    /// 1. Sends initial `hello` message to the listener
    /// 2. Receives listener response with `hello + confirmation`
    /// 3. Sends `confirmation` to the listener
    pub async fn upgrade_dialer<R: Rng + CryptoRng + Spawner + Clock, C: Signer>(
        mut context: R,
        mut config: Config<C>,
        mut sink: Si,
        mut stream: St,
        peer: C::PublicKey,
    ) -> Result<Self, Error> {
        // Ensure we are not trying to connect to ourselves
        if peer == config.crypto.public_key() {
            return Err(Error::DialSelf);
        }

        // Set handshake deadline
        let deadline = context.current() + config.handshake_timeout;

        // Generate shared secret
        let secret = x25519::new(&mut context);

        // Send hello (Message 1)
        let dialer_timestamp = context.current().epoch_millis();
        let dialer_ephemeral = x25519::PublicKey::from_secret(&secret);
        let hello_msg = handshake::Hello::sign(
            &mut config.crypto,
            &config.namespace,
            handshake::Info::new(peer.clone(), dialer_ephemeral, dialer_timestamp),
        )
        .encode();

        // Wait for up to handshake timeout to send
        select! {
            _ = context.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(&mut sink, &hello_msg, config.max_message_size) => {
                result?;
            },
        }

        // Wait for listener's hello + confirmation (Message 2)
        let listener_response_msg = select! {
            _ = context.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = recv_frame(&mut stream, config.max_message_size) => {
                result?
            },
        };

        // Verify listener's hello
        let (listener_hello, listener_confirmation) =
            <(handshake::Hello<C::PublicKey>, Confirmation)>::decode(
                listener_response_msg.as_ref(),
            )
            .map_err(Error::UnableToDecode)?;
        listener_hello.verify(
            &context,
            &config.crypto.public_key(),
            &config.namespace,
            config.synchrony_bound,
            config.max_handshake_age,
        )?;

        // Ensure we connected to the right peer
        if peer != listener_hello.signer() {
            return Err(Error::WrongPeer);
        }

        // Derive shared secret and ensure it is contributory
        let shared_secret = secret.diffie_hellman(listener_hello.ephemeral().as_ref());
        if !shared_secret.was_contributory() {
            return Err(Error::SharedSecretNotContributory);
        }

        // Create ciphers
        let hello_transcript = union(&hello_msg, &listener_hello.encode());
        let cipher::Full {
            confirmation,
            traffic,
        } = cipher::derive_directional(
            shared_secret.as_bytes(),
            &config.namespace,
            &hello_transcript,
        )?;

        // Verify listener's confirmation
        let cipher::Directional { d2l, l2d } = confirmation;
        listener_confirmation.verify(l2d, &hello_transcript)?;

        // Create our own confirmation (Message 3)
        let full_transcript = union(&hello_msg, &listener_response_msg);
        let confirmation_msg = Confirmation::create(d2l, &full_transcript)?.encode();
        select! {
            _ = context.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(
                &mut sink,
                &confirmation_msg,
                config.max_message_size,
            ) => {
                result?;
            },
        }

        // Connection successfully established
        Ok(Self {
            sink,
            stream,
            max_message_size: config.max_message_size,
            cipher_send: traffic.d2l,
            cipher_recv: traffic.l2d,
        })
    }

    /// Attempt to upgrade a connection we received as the listener.
    ///
    /// This implements the last two steps of the 3-message handshake protocol. The first step,
    /// where the listener receives the dialer's `hello`, is handled by [IncomingConnection::verify].
    ///
    /// The last two steps are:
    /// 2. Sends a response with `hello + confirmation`
    /// 3. Receives the dialer's `confirmation`
    pub async fn upgrade_listener<R: Rng + CryptoRng + Spawner + Clock, C: Signer>(
        mut context: R,
        incoming: IncomingConnection<C, Si, St>,
    ) -> Result<Self, Error> {
        // Extract fields
        let max_message_size = incoming.config.max_message_size;
        let mut crypto = incoming.config.crypto;
        let namespace = incoming.config.namespace;
        let mut sink = incoming.sink;
        let mut stream = incoming.stream;

        // Generate personal secret
        let secret = x25519::new(&mut context);

        // Create hello
        let timestamp = context.current().epoch_millis();
        let listener_ephemeral = x25519::PublicKey::from_secret(&secret);
        let hello = handshake::Hello::sign(
            &mut crypto,
            &namespace,
            handshake::Info::new(incoming.peer_public_key, listener_ephemeral, timestamp),
        );

        // Derive shared secret and ensure it is contributory
        let shared_secret = secret.diffie_hellman(incoming.ephemeral_public_key.as_ref());
        if !shared_secret.was_contributory() {
            return Err(Error::SharedSecretNotContributory);
        }

        // Create ciphers
        let hello_transcript = union(&incoming.dialer_hello_msg, &hello.encode());
        let cipher::Full {
            confirmation,
            traffic,
        } = cipher::derive_directional(shared_secret.as_bytes(), &namespace, &hello_transcript)?;

        // Create and send hello + confirmation (Message 2)
        let cipher::Directional { l2d, d2l } = confirmation;
        let confirmation = Confirmation::create(l2d, &hello_transcript)?;
        let response_msg = (hello, confirmation).encode();
        select! {
            _ = context.sleep_until(incoming.deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(&mut sink, &response_msg, max_message_size) => {
                result?;
            },
        }

        // Wait for dialer confirmation (Message 3)
        let confirmation_msg = select! {
            _ = context.sleep_until(incoming.deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = recv_frame(&mut stream, max_message_size) => {
                result?
            },
        };

        // Verify dialer's confirmation
        let full_transcript = union(&incoming.dialer_hello_msg, &response_msg);
        Confirmation::decode(confirmation_msg.as_ref())
            .map_err(Error::UnableToDecode)?
            .verify(d2l, &full_transcript)?;

        // Connection successfully established
        Ok(Connection {
            sink,
            stream,
            max_message_size,
            cipher_send: traffic.l2d,
            cipher_recv: traffic.d2l,
        })
    }

    /// Split the connection into a `Sender` and `Receiver`.
    ///
    /// This pattern is commonly used to efficiently send and receive messages
    /// over the same connection concurrently.
    pub fn split(self) -> (Sender<Si>, Receiver<St>) {
        (
            Sender {
                sink: self.sink,
                max_message_size: self.max_message_size,
                cipher: self.cipher_send,
                nonce: nonce::Info::default(),
            },
            Receiver {
                stream: self.stream,
                max_message_size: self.max_message_size,
                cipher: self.cipher_recv,
                nonce: nonce::Info::default(),
            },
        )
    }
}

/// The half of the `Connection` that implements `crate::Sender`.
pub struct Sender<Si: Sink> {
    sink: Si,
    max_message_size: usize,
    cipher: ChaCha20Poly1305,
    nonce: nonce::Info,
}

impl<Si: Sink> crate::Sender for Sender<Si> {
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        // Encrypt data
        let nonce = self.nonce.next()?;
        let msg = self
            .cipher
            .encrypt(&nonce, msg.as_ref())
            .map_err(|_| Error::EncryptionFailed)?;

        // Send data
        send_frame(
            &mut self.sink,
            &msg,
            self.max_message_size + AUTHENTICATION_TAG_LENGTH,
        )
        .await?;
        Ok(())
    }
}

/// The half of a `Connection` that implements `crate::Receiver`.
pub struct Receiver<St: Stream> {
    stream: St,
    max_message_size: usize,
    cipher: ChaCha20Poly1305,
    nonce: nonce::Info,
}

impl<St: Stream> crate::Receiver for Receiver<St> {
    async fn receive(&mut self) -> Result<Bytes, Error> {
        // Read data
        let msg = recv_frame(
            &mut self.stream,
            self.max_message_size + AUTHENTICATION_TAG_LENGTH,
        )
        .await?;

        // Decrypt data
        let nonce = self.nonce.next()?;
        self.cipher
            .decrypt(&nonce, msg.as_ref())
            .map(Bytes::from)
            .map_err(|_| Error::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver as _, Sender as _};
    use chacha20poly1305::KeyInit;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt as _,
    };
    use commonware_runtime::{deterministic, mocks, Metrics, Runner};
    use std::time::Duration;

    #[test]
    fn test_decryption_failure() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (mut sink, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size: 1024,
                nonce: nonce::Info::default(),
            };

            // Store initial nonce value
            let initial_nonce = receiver.nonce;

            // Send invalid ciphertext
            send_frame(&mut sink, b"invalid data", receiver.max_message_size)
                .await
                .unwrap();

            // Attempt to receive (should fail)
            let result = receiver.receive().await;
            assert!(matches!(result, Err(Error::DecryptionFailed)));

            // Verify nonce was incremented despite decryption failure
            let final_nonce = receiver.nonce;
            assert_ne!(initial_nonce, final_nonce);
        });
    }

    #[test]
    fn test_send_too_large() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let message = b"hello world";
            let (sink, _) = mocks::Channel::init();
            let mut sender = Sender {
                cipher,
                sink,
                max_message_size: message.len() - 1,
                nonce: nonce::Info::default(),
            };

            let result = sender.send(message).await;
            let expected_length = message.len() + AUTHENTICATION_TAG_LENGTH;
            assert!(matches!(result, Err(Error::SendTooLarge(n)) if n == expected_length));
        });
    }

    #[test]
    fn test_receive_too_large() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let message = b"hello world";
            let (sink, stream) = mocks::Channel::init();

            let mut sender = Sender {
                cipher: cipher.clone(),
                sink,
                max_message_size: message.len(),
                nonce: nonce::Info::default(),
            };
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size: message.len() - 1,
                nonce: nonce::Info::default(),
            };

            sender.send(message).await.unwrap();
            let result = receiver.receive().await;
            let expected_length = message.len() + AUTHENTICATION_TAG_LENGTH;
            assert!(matches!(result, Err(Error::RecvTooLarge(n)) if n == expected_length));
        });
    }

    #[test]
    fn test_send_receive() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let max_message_size = 1024;

            // Create channels
            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            // Create dialer connection
            let connection_dialer = Connection::from_preestablished(
                dialer_sink,
                dialer_stream,
                max_message_size,
                cipher.clone(),
                cipher.clone(),
            );

            // Create listener connection
            let connection_listener = Connection::from_preestablished(
                listener_sink,
                listener_stream,
                max_message_size,
                cipher.clone(),
                cipher,
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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create cryptographic identities
            let dialer_crypto = PrivateKey::from_seed(0);
            let listener_crypto = PrivateKey::from_seed(1);

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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create cryptographic identities
            let dialer_crypto = PrivateKey::from_seed(0);
            let expected_peer = PrivateKey::from_seed(1).public_key();
            let mut actual_peer = PrivateKey::from_seed(2);

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

            // Spawn a mock peer that responds with a listener response from wrong peer
            context.with_label("mock_peer").spawn({
                move |mut context| async move {
                    use chacha20poly1305::KeyInit;

                    // Read the hello from dialer
                    let msg = recv_frame(&mut peer_stream, 1024).await.unwrap();
                    let _ = handshake::Hello::<PublicKey>::decode(msg).unwrap();

                    // Create mock shared secret and cipher for `confirmation`
                    let mock_secret = [1u8; 32];
                    let mock_cipher = ChaCha20Poly1305::new(&mock_secret.into());

                    // Create and send own hello as listener response
                    let secret = x25519::new(&mut context);
                    let timestamp = context.current().epoch_millis();
                    let info = handshake::Info::new(
                        peer_config.crypto.public_key(),
                        x25519::PublicKey::from_secret(&secret),
                        timestamp,
                    );
                    let hello =
                        handshake::Hello::sign(&mut actual_peer, &peer_config.namespace, info);

                    // Create fake `confirmation` (using fake transcript)
                    let fake_transcript = b"fake_transcript_data";
                    let confirmation = Confirmation::create(mock_cipher, fake_transcript).unwrap();

                    send_frame(&mut peer_sink, &(hello, confirmation).encode(), 1024)
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

    #[test]
    fn test_upgrade_dialer_non_contributory_secret() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create cryptographic identities
            let dialer_crypto = PrivateKey::from_seed(0);
            let mut listener_crypto = PrivateKey::from_seed(1);
            let listener_public_key = listener_crypto.public_key();

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

            // Spawn a mock peer that responds with a listener response containing an all-zero ephemeral key
            context.with_label("mock_peer").spawn({
                let namespace = dialer_config.namespace.clone();
                let recipient_pk = dialer_config.crypto.public_key();
                move |context| async move {
                    use chacha20poly1305::KeyInit;

                    // Read the hello from dialer
                    let msg = recv_frame(&mut peer_stream, 1024).await.unwrap();
                    let _ = handshake::Hello::<PublicKey>::decode(msg).unwrap();

                    // Create mock cipher for `confirmation`
                    let mock_secret = [1u8; 32];
                    let mock_cipher = ChaCha20Poly1305::new(&mock_secret.into());

                    // Create a custom hello info bytes with zero ephemeral key
                    let timestamp = context.current().epoch_millis();
                    let info = handshake::Info::new(
                        recipient_pk,
                        x25519::PublicKey::from_bytes([0u8; 32]),
                        timestamp,
                    );

                    // Create the signed `hello`
                    let hello = handshake::Hello::sign(&mut listener_crypto, &namespace, info);

                    // Create fake listener response (using fake transcript)
                    let fake_transcript = b"fake_transcript_for_non_contributory_test";
                    let confirmation = Confirmation::create(mock_cipher, fake_transcript).unwrap();

                    // Send the listener response
                    send_frame(&mut peer_sink, &(hello, confirmation).encode(), 1024)
                        .await
                        .unwrap();
                }
            });

            // Attempt connection - should fail due to non-contributory shared secret
            let result = Connection::upgrade_dialer(
                context,
                dialer_config,
                dialer_sink,
                dialer_stream,
                listener_public_key,
            )
            .await;

            // Verify the error
            assert!(matches!(result, Err(Error::SharedSecretNotContributory)));
        });
    }

    #[test]
    fn test_upgrade_listener_non_contributory_secret() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create cryptographic identities
            let mut dialer_crypto = PrivateKey::from_seed(0);
            let listener_crypto = PrivateKey::from_seed(1);

            // Set up mock channels
            let (mut dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, _dialer_stream) = mocks::Channel::init();

            // Listener configuration
            let listener_config = Config {
                crypto: listener_crypto.clone(),
                namespace: b"test_namespace".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };

            // Encode all-zero ephemeral public key (32 bytes)
            let info = handshake::Info::new(
                listener_config.crypto.public_key(),
                x25519::PublicKey::from_bytes([0u8; 32]),
                context.current().epoch_millis(),
            );

            // Create the signed hello
            let hello =
                handshake::Hello::sign(&mut dialer_crypto, &listener_config.namespace, info);

            // Send the hello
            send_frame(&mut dialer_sink, &hello.encode(), 1024)
                .await
                .unwrap();

            // Verify the incoming connection
            let incoming = IncomingConnection::verify(
                &context,
                listener_config,
                listener_sink,
                listener_stream,
            )
            .await
            .unwrap();

            // Attempt to upgrade - should fail due to non-contributory shared secret
            let result = Connection::upgrade_listener(context, incoming).await;

            // Verify the error
            assert!(matches!(result, Err(Error::SharedSecretNotContributory)));
        });
    }

    #[test]
    fn test_listener_rejects_hello_signed_with_own_key() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let self_crypto = PrivateKey::from_seed(0);
            let self_public_key = self_crypto.public_key();

            let config = Config {
                crypto: self_crypto.clone(),
                namespace: b"test_self_connect_namespace".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(1),
            };

            // Initial hello travels: dialer_sink -> listener_stream
            let (mut dialer_sink, listener_stream) = mocks::Channel::init();
            // Reply hello would travel: listener_reply_sink -> dialer_stream
            let (listener_reply_sink, _dialer_stream) = mocks::Channel::init();

            let listener_config = config.clone();
            let listener_handle =
                context
                    .with_label("self_listener")
                    .spawn(move |task_ctx| async move {
                        IncomingConnection::verify(
                            &task_ctx,
                            listener_config,
                            listener_reply_sink,
                            listener_stream,
                        )
                        .await
                    });

            let max_msg_size = config.max_message_size;
            let namespace = config.namespace.clone();
            let handshake_sender_handle =
                context
                    .with_label("handshake_sender")
                    .spawn(move |task_ctx| {
                        let mut crypto_for_signing = self_crypto.clone();
                        let recipient_pk = self_public_key.clone();
                        let ephemeral_pk = super::x25519::PublicKey::from_bytes([0xCDu8; 32]);

                        async move {
                            let timestamp = task_ctx.current().epoch_millis();
                            let info =
                                super::handshake::Info::new(recipient_pk, ephemeral_pk, timestamp);
                            let hello = super::handshake::Hello::sign(
                                &mut crypto_for_signing,
                                &namespace,
                                info,
                            );
                            crate::utils::codec::send_frame(
                                &mut dialer_sink,
                                &hello.encode(),
                                max_msg_size,
                            )
                            .await
                        }
                    });

            // Ensure hello is sent
            handshake_sender_handle.await.unwrap().unwrap();

            let listener_result = listener_handle.await.unwrap();
            assert!(matches!(listener_result, Err(Error::HelloUsesOurKey)));
        });
    }

    #[test]
    fn test_three_message_handshake_protocol() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create cryptographic identities
            let dialer_crypto = PrivateKey::from_seed(0);
            let listener_crypto = PrivateKey::from_seed(1);

            // Set up mock channels for transport simulation
            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            // Configuration for dialer
            let dialer_config = Config {
                crypto: dialer_crypto.clone(),
                namespace: b"test_3msg_namespace".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };

            // Configuration for listener
            let listener_config = Config {
                crypto: listener_crypto.clone(),
                namespace: b"test_3msg_namespace".to_vec(),
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

            // Test message exchange after successful 3-message handshake
            let message1 = b"Hello from dialer after 3-msg handshake";
            dialer_sender.send(message1).await.unwrap();
            let received = listener_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &message1[..]);

            let message2 = b"Hello from listener after 3-msg handshake";
            listener_sender.send(message2).await.unwrap();
            let received = dialer_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &message2[..]);
        });
    }

    #[test]
    fn test_upgrade_dialer_rejects_connecting_to_self() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create cryptographic identity.
            let self_crypto = PrivateKey::from_seed(0);
            let self_public_key = self_crypto.public_key();

            // Configure dialer parameters.
            let dialer_config = Config {
                crypto: self_crypto.clone(),
                namespace: b"test_dial_self_direct".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(1),
            };

            // Set up mock channels (not fully utilized due to early error).
            let (dialer_sink, _) = mocks::Channel::init();
            let (_, dialer_stream) = mocks::Channel::init();

            // Attempt to upgrade dialer connection, targeting self.
            let result = Connection::upgrade_dialer(
                context.clone(),
                dialer_config,
                dialer_sink,
                dialer_stream,
                self_public_key.clone(),
            )
            .await;

            // Verify dialer rejects self-connection attempt.
            assert!(matches!(result, Err(Error::DialSelf)));
        });
    }
}
