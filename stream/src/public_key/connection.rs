use super::{cipher, handshake, nonce, x25519, Config, AUTHENTICATION_TAG_LENGTH};
use crate::{
    public_key::cipher::DirectionalCipher,
    utils::codec::{recv_frame, send_frame},
    Error,
};
use bytes::Bytes;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_utils::SystemTimeExt as _;
use rand::{CryptoRng, Rng};
use std::time::SystemTime;

/// Creates a handshake transcript by concatenating dialer and listener handshake messages.
///
/// The transcript format is: dialer_handshake || listener_handshake
/// This ordering is critical for consistency between dialer and listener.
fn create_handshake_transcript(dialer_handshake: &[u8], listener_handshake: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(dialer_handshake.len() + listener_handshake.len());
    transcript.extend_from_slice(dialer_handshake);
    transcript.extend_from_slice(listener_handshake);
    transcript
}

/// An incoming connection with a verified peer handshake.
pub struct IncomingConnection<C: Signer, Si: Sink, St: Stream> {
    config: Config<C>,
    sink: Si,
    stream: St,
    deadline: SystemTime,
    ephemeral_public_key: x25519::PublicKey,
    peer_public_key: C::PublicKey,

    /// Stores the raw bytes of the dialer handshake message.
    /// Necessary for the cipher derivation.
    dialer_handshake_bytes: Bytes,
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

        // Wait for up to handshake timeout for response
        let msg = select! {
            _ = context.sleep_until(deadline) => { return Err(Error::HandshakeTimeout) },
            result = recv_frame(&mut stream, config.max_message_size) => { result? },
        };

        // Verify handshake message from peer
        let signed_handshake =
            handshake::Signed::decode(msg.as_ref()).map_err(Error::UnableToDecode)?;
        signed_handshake.verify(
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
            ephemeral_public_key: signed_handshake.ephemeral(),
            peer_public_key: signed_handshake.signer(),
            dialer_handshake_bytes: msg,
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

    /// Attempt to upgrade a raw connection we initiated.
    ///
    /// This implements the 3-message handshake protocol where the dialer:
    /// 1. Sends initial handshake message to the listener
    /// 2. Receives listener response with handshake + key confirmation
    /// 3. Sends confirmation with own key confirmation to complete mutual auth
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

        // Send handshake (Message 1)
        let dialer_timestamp = context.current().epoch_millis();
        let dialer_ephemeral = x25519::PublicKey::from_secret(&secret);
        let d2l_msg = handshake::Signed::sign(
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
            result = send_frame(&mut sink, &d2l_msg, config.max_message_size) => {
                result?;
            },
        }

        // Wait for listener response (Message 2)
        let listener_response_msg = select! {
            _ = context.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = recv_frame(&mut stream, config.max_message_size) => {
                result?
            },
        };

        // Decode listener response
        let listener_response = handshake::ListenerResponse::decode(listener_response_msg.as_ref())
            .map_err(Error::UnableToDecode)?;

        // Verify listener handshake
        let (signed_handshake, listener_key_confirmation) = listener_response.into_parts();
        signed_handshake.verify(
            &context,
            &config.crypto.public_key(),
            &config.namespace,
            config.synchrony_bound,
            config.max_handshake_age,
        )?;

        // Ensure we connected to the right peer
        if peer != signed_handshake.signer() {
            return Err(Error::WrongPeer);
        }

        // Derive shared secret and ensure it is contributory
        let shared_secret = secret.diffie_hellman(signed_handshake.ephemeral().as_ref());
        if !shared_secret.was_contributory() {
            return Err(Error::SharedSecretNotContributory);
        }

        // Encode the listener's handshake and create the complete transcript
        // The transcript consists of: dialer_handshake || listener_handshake
        let l2d_msg = signed_handshake.encode();
        let transcript = create_handshake_transcript(&d2l_msg, &l2d_msg);

        // Create ciphers
        let DirectionalCipher {
            l2d_confirmation,
            d2l_confirmation,
            l2d,
            d2l,
        } = cipher::derive_directional(shared_secret.as_bytes(), &config.namespace, &transcript)?;

        // Verify listener's key confirmation proves they can derive the shared secret
        // This uses the l2d_confirmation cipher with the handshake transcript as associated data
        listener_key_confirmation.verify(l2d_confirmation, &transcript)?;

        // Create our own key confirmation to prove we can derive the shared secret (Message 3)
        // This uses the d2l_confirmation cipher with the handshake transcript as associated data
        let dialer_key_confirmation =
            handshake::KeyConfirmation::create(d2l_confirmation, &transcript)?;
        let confirmation_bytes = dialer_key_confirmation.encode();

        select! {
            _ = context.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(
                &mut sink,
                &confirmation_bytes,
                config.max_message_size,
            ) => {
                result?;
            },
        }

        // Connection successfully established with mutual authentication
        Ok(Self {
            sink,
            stream,
            max_message_size: config.max_message_size,
            cipher_send: d2l,
            cipher_recv: l2d,
        })
    }

    /// Attempt to upgrade a connection initiated by some peer.
    ///
    /// This implements the 3-message handshake protocol where the listener:
    /// 1. Sends a response containing their handshake + key confirmation
    /// 2. Waits for the dialer's confirmation with their key confirmation
    /// 3. Verifies the dialer's confirmation to complete mutual authentication
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
        let d2l_msg = incoming.dialer_handshake_bytes.clone();

        // Generate personal secret
        let secret = x25519::new(&mut context);

        // Create handshake
        let timestamp = context.current().epoch_millis();
        let listener_ephemeral = x25519::PublicKey::from_secret(&secret);
        let l2d_handshake = handshake::Signed::sign(
            &mut crypto,
            &namespace,
            handshake::Info::new(incoming.peer_public_key, listener_ephemeral, timestamp),
        );
        let l2d_msg = l2d_handshake.encode();

        // Derive shared secret and ensure it is contributory
        let shared_secret = secret.diffie_hellman(incoming.ephemeral_public_key.as_ref());
        if !shared_secret.was_contributory() {
            return Err(Error::SharedSecretNotContributory);
        }

        // Create the complete handshake transcript
        // The transcript consists of: dialer_handshake || listener_handshake
        let transcript = create_handshake_transcript(&d2l_msg, &l2d_msg);

        // Create ciphers
        let DirectionalCipher {
            l2d_confirmation,
            d2l_confirmation,
            l2d,
            d2l,
        } = cipher::derive_directional(shared_secret.as_bytes(), &namespace, &transcript)?;

        // Create key confirmation to prove we can derive the shared secret
        // This uses the l2d_confirmation cipher with the handshake transcript as associated data
        let key_confirmation = handshake::KeyConfirmation::create(l2d_confirmation, &transcript)?;

        // Create and send listener response (Message 2)
        let listener_response = handshake::ListenerResponse::new(l2d_handshake, key_confirmation);
        let response_bytes = listener_response.encode();

        select! {
            _ = context.sleep_until(incoming.deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(&mut sink, &response_bytes, max_message_size) => {
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

        // Decode and verify dialer confirmation
        let dialer_confirmation = handshake::KeyConfirmation::decode(confirmation_msg.as_ref())
            .map_err(Error::UnableToDecode)?;

        // Verify dialer's key confirmation proves they can derive the shared secret
        // This uses the d2l_confirmation cipher with the handshake transcript as associated data
        dialer_confirmation.verify(d2l_confirmation, &transcript)?;

        // Connection successfully established with mutual authentication
        Ok(Connection {
            sink,
            stream,
            max_message_size,
            cipher_send: l2d,
            cipher_recv: d2l,
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

            // Spawn a mock peer that responds with a ListenerResponse from wrong peer
            context.with_label("mock_peer").spawn({
                move |mut context| async move {
                    use chacha20poly1305::KeyInit;

                    // Read the handshake from dialer
                    let msg = recv_frame(&mut peer_stream, 1024).await.unwrap();
                    let _ = handshake::Signed::<PublicKey>::decode(msg).unwrap(); // Simulate reading

                    // Create mock shared secret and cipher for key confirmation
                    let mock_secret = [1u8; 32];
                    let mock_cipher = ChaCha20Poly1305::new(&mock_secret.into());

                    // Create and send own handshake as ListenerResponse
                    let secret = x25519::new(&mut context);
                    let timestamp = context.current().epoch_millis();
                    let info = handshake::Info::new(
                        peer_config.crypto.public_key(),
                        x25519::PublicKey::from_secret(&secret),
                        timestamp,
                    );
                    let signed_handshake =
                        handshake::Signed::sign(&mut actual_peer, &peer_config.namespace, info);

                    // Create fake key confirmation (using fake transcript)
                    let fake_transcript = b"fake_transcript_data";
                    let key_confirmation =
                        handshake::KeyConfirmation::create(mock_cipher, fake_transcript).unwrap();
                    let listener_response =
                        handshake::ListenerResponse::new(signed_handshake, key_confirmation);

                    send_frame(&mut peer_sink, &listener_response.encode(), 1024)
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

            // Spawn a mock peer that responds with a ListenerResponse containing an all-zero ephemeral key
            context.with_label("mock_peer").spawn({
                let namespace = dialer_config.namespace.clone();
                let recipient_pk = dialer_config.crypto.public_key();
                move |context| async move {
                    use chacha20poly1305::KeyInit;

                    // Read the handshake from dialer
                    let msg = recv_frame(&mut peer_stream, 1024).await.unwrap();
                    let _ = handshake::Signed::<PublicKey>::decode(msg).unwrap();

                    // Create mock cipher for key confirmation
                    let mock_secret = [1u8; 32];
                    let mock_cipher = ChaCha20Poly1305::new(&mock_secret.into());

                    // Create a custom handshake info bytes with zero ephemeral key
                    let timestamp = context.current().epoch_millis();
                    let info = handshake::Info::new(
                        recipient_pk,
                        x25519::PublicKey::from_bytes([0u8; 32]),
                        timestamp,
                    );

                    // Create the signed handshake
                    let signed_handshake =
                        handshake::Signed::sign(&mut listener_crypto, &namespace, info);

                    // Create fake key confirmation and ListenerResponse (using fake transcript)
                    let fake_transcript = b"fake_transcript_for_non_contributory_test";
                    let key_confirmation =
                        handshake::KeyConfirmation::create(mock_cipher, fake_transcript).unwrap();
                    let listener_response =
                        handshake::ListenerResponse::new(signed_handshake, key_confirmation);

                    // Send the ListenerResponse
                    send_frame(&mut peer_sink, &listener_response.encode(), 1024)
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

            // Create the signed handshake
            let signed_handshake =
                handshake::Signed::sign(&mut dialer_crypto, &listener_config.namespace, info);

            // Send the handshake
            send_frame(&mut dialer_sink, &signed_handshake.encode(), 1024)
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
    fn test_listener_rejects_handshake_signed_with_own_key() {
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

            // Initial handshake travels: dialer_sink -> listener_stream
            let (mut dialer_sink, listener_stream) = mocks::Channel::init();
            // Reply handshake would travel: listener_reply_sink -> dialer_stream
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
                            let signed_handshake = super::handshake::Signed::sign(
                                &mut crypto_for_signing,
                                &namespace,
                                info,
                            );
                            crate::utils::codec::send_frame(
                                &mut dialer_sink,
                                &signed_handshake.encode(),
                                max_msg_size,
                            )
                            .await
                        }
                    });

            // Ensure handshake is sent
            handshake_sender_handle.await.unwrap().unwrap();

            let listener_result = listener_handle.await.unwrap();
            assert!(matches!(listener_result, Err(Error::HandshakeUsesOurKey)));
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
            let (dialer_sink, _unused_stream) = mocks::Channel::init();
            let (_unused_sink, dialer_stream) = mocks::Channel::init();

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
