use super::{
    handshake::{create_handshake, Handshake, IncomingHandshake},
    nonce, x25519, Config,
};
use crate::{
    utils::codec::{recv_frame, send_frame},
    Error,
};
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_utils::SystemTimeExt as _;
use rand::{CryptoRng, Rng};

// When encrypting data, an encryption tag is appended to the ciphertext.
// This constant represents the size of the encryption tag in bytes.
const ENCRYPTION_TAG_LENGTH: usize = 16;

/// An incoming connection with a verified peer handshake.
pub struct IncomingConnection<C: Scheme, Si: Sink, St: Stream> {
    config: Config<C>,
    handshake: IncomingHandshake<Si, St, C>,
}

impl<C: Scheme, Si: Sink, St: Stream> IncomingConnection<C, Si, St> {
    /// Verify the handshake of an incoming connection.
    pub async fn verify<R: Rng + CryptoRng + Spawner + Clock>(
        runtime: &R,
        config: Config<C>,
        sink: Si,
        stream: St,
    ) -> Result<Self, Error> {
        let handshake = IncomingHandshake::verify(
            runtime,
            &config.crypto,
            &config.namespace,
            config.max_message_size,
            config.synchrony_bound,
            config.max_handshake_age,
            config.handshake_timeout,
            sink,
            stream,
        )
        .await?;
        Ok(Self { config, handshake })
    }

    /// The public key of the peer attempting to connect.
    pub fn peer(&self) -> C::PublicKey {
        self.handshake.peer_public_key.clone()
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
        mut runtime: R,
        mut config: Config<C>,
        mut sink: Si,
        mut stream: St,
        peer: C::PublicKey,
    ) -> Result<Self, Error> {
        // Set handshake deadline
        let deadline = runtime.current() + config.handshake_timeout;

        // Generate shared secret
        let secret = x25519::new(&mut runtime);
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let timestamp = runtime.current().epoch_millis();
        let msg = create_handshake(
            &mut config.crypto,
            &config.namespace,
            timestamp,
            peer.clone(),
            ephemeral,
        )?;

        // Wait for up to handshake timeout to send
        select! {
            _ = runtime.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(&mut sink, &msg, config.max_message_size) => {
                result.map_err(|_| Error::SendFailed)?;
            },
        }

        // Wait for up to handshake timeout for response
        let msg = select! {
            _ = runtime.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = recv_frame(&mut stream, config.max_message_size) => {
                result.map_err(|_| Error::RecvFailed)?
            },
        };

        // Verify handshake message from peer
        let handshake = Handshake::verify(
            &runtime,
            &config.crypto,
            &config.namespace,
            config.synchrony_bound,
            config.max_handshake_age,
            msg,
        )?;

        // Ensure we connected to the right peer
        if peer != handshake.peer_public_key {
            return Err(Error::WrongPeer);
        }

        // Create cipher
        let shared_secret = secret.diffie_hellman(&handshake.ephemeral_public_key);
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
        mut runtime: R,
        incoming: IncomingConnection<C, Si, St>,
    ) -> Result<Self, Error> {
        // Generate shared secret
        let secret = x25519::new(&mut runtime);
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let (mut handshake, mut config) = (incoming.handshake, incoming.config);
        let timestamp = runtime.current().epoch_millis();
        let msg = create_handshake(
            &mut config.crypto,
            &config.namespace,
            timestamp,
            handshake.peer_public_key,
            ephemeral,
        )?;

        // Wait for up to handshake timeout
        select! {
            _ = runtime.sleep_until(handshake.deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = send_frame(&mut handshake.sink, &msg, config.max_message_size) => {
                result.map_err(|_| Error::SendFailed)?;
            },
        }

        // Create cipher
        let shared_secret = secret.diffie_hellman(&handshake.ephemeral_public_key);
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| Error::CipherCreationFailed)?;

        // Track whether or not we are the dialer to ensure we send correctly formatted nonces.
        Ok(Connection {
            dialer: false,
            sink: handshake.sink,
            stream: handshake.stream,
            cipher,
            max_message_size: config.max_message_size,
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
    use super::*;
    use crate::{Receiver as _, Sender as _};
    use commonware_runtime::{deterministic::Executor, mocks, Runner};

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
            let message = b"hello world";
            let max_message_size = message.len();

            let (sink, stream) = mocks::Channel::init();
            let is_dialer = false;
            let mut sender = Sender {
                cipher: cipher.clone(),
                sink,
                max_message_size,
                nonce: nonce::Info::new(is_dialer),
            };
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size,
                nonce: nonce::Info::new(is_dialer),
            };

            // Send data
            sender.send(message).await.unwrap();
            let data = receiver.receive().await.unwrap();
            assert_eq!(data, &message[..]);
        });
    }
}
