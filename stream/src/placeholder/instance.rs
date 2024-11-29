use super::{
    handshake::{create_handshake, Handshake, IncomingHandshake},
    utils::{
        codec::{recv_frame, send_frame},
        nonce::encode,
    },
    x25519, Config, Error,
};
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_macros::select;
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use rand::{CryptoRng, Rng};

// When encrypting data, an encryption tag is appended to the ciphertext.
// This constant represents the size of the encryption tag in bytes.
const ENCRYPTION_TAG_LENGTH: usize = 16;

pub struct Instance<C: Scheme, Si: Sink, St: Stream> {
    config: Config<C>,
    dialer: bool,
    sink: Si,
    stream: St,
    cipher: ChaCha20Poly1305,
}

impl<C: Scheme, Si: Sink, St: Stream> Instance<C, Si, St> {
    pub async fn upgrade_dialer(
        mut runtime: impl Rng + CryptoRng + Spawner + Clock,
        mut config: Config<C>,
        mut sink: Si,
        mut stream: St,
        peer: PublicKey,
    ) -> Result<Self, Error> {
        // Set handshake deadline
        let deadline = runtime.current() + config.handshake_timeout;

        // Generate shared secret
        let secret = x25519::new(&mut runtime);
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(
            runtime.clone(),
            &mut config.crypto,
            &config.namespace,
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
            runtime,
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
            config,
            dialer: true,
            sink,
            stream,
            cipher,
        })
    }

    pub async fn upgrade_listener(
        mut runtime: impl Rng + CryptoRng + Spawner + Clock,
        mut config: Config<C>,
        mut handshake: IncomingHandshake<Si, St>,
    ) -> Result<Self, Error> {
        // Generate shared secret
        let secret = x25519::new(&mut runtime);
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(
            runtime.clone(),
            &mut config.crypto,
            &config.namespace,
            handshake.peer_public_key.clone(),
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

        Ok(Instance {
            config,
            dialer: false,
            sink: handshake.sink,
            stream: handshake.stream,
            cipher,
        })
    }

    pub fn split(self) -> (Sender<Si>, Receiver<St>) {
        (
            Sender {
                cipher: self.cipher.clone(),
                sink: self.sink,

                max_message_size: self.config.max_message_size,
                dialer: self.dialer,
                iter: 0,
                seq: 0,
            },
            Receiver {
                cipher: self.cipher,
                stream: self.stream,

                max_message_size: self.config.max_message_size,
                dialer: self.dialer,
                iter: 0,
                seq: 0,
            },
        )
    }
}

pub struct Sender<Si: Sink> {
    cipher: ChaCha20Poly1305,
    sink: Si,

    max_message_size: usize,
    dialer: bool,
    iter: u16,
    seq: u64,
}

impl<Si: Sink> Sender<Si> {
    fn my_nonce(&mut self) -> Result<Nonce, Error> {
        if self.seq == u64::MAX {
            if self.iter == u16::MAX {
                return Err(Error::OurNonceOverflow);
            }
            self.iter += 1;
            self.seq = 0;
        }
        let nonce = encode(self.dialer, self.iter, self.seq);
        self.seq += 1;
        Ok(nonce)
    }

    pub async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        // Encrypt data
        let nonce = self.my_nonce()?;
        let msg = self
            .cipher
            .encrypt(&nonce, msg.as_ref())
            .map_err(|_| Error::EncryptionFailed)?;

        // Send data
        send_frame(
            &mut self.sink,
            &msg,
            self.max_message_size + ENCRYPTION_TAG_LENGTH,
        ).await?;
        Ok(())
    }
}

pub struct Receiver<St: Stream> {
    cipher: ChaCha20Poly1305,
    stream: St,

    max_message_size: usize,
    dialer: bool,
    iter: u16,
    seq: u64,
}

impl<St: Stream> Receiver<St> {
    fn peer_nonce(&mut self) -> Result<Nonce, Error> {
        if self.seq == u64::MAX {
            if self.iter == u16::MAX {
                return Err(Error::PeerNonceOverflow);
            }
            self.iter += 1;
            self.seq = 0;
        }
        let nonce = encode(!self.dialer, self.iter, self.seq);
        self.seq += 1;
        Ok(nonce)
    }

    pub async fn receive(&mut self) -> Result<Bytes, Error> {
        // Read data
        let msg = recv_frame(
            &mut self.stream,
            self.max_message_size + ENCRYPTION_TAG_LENGTH,
        ).await?;

        // Decrypt data
        let nonce = self.peer_nonce()?;
        let msg = self
            .cipher
            .decrypt(&nonce, msg.as_ref())
            .map_err(|_| Error::DecryptionFailed)?;

        Ok(Bytes::from(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        deterministic::Executor,
        mocks,
        Runner,
    };

    #[test]
    fn test_sender_nonce_overflow() {
        let (executuor, _, _) = Executor::default();
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (sink, _) = mocks::Channel::init();
            let mut sender = Sender {
                cipher,
                sink,
                max_message_size: 0,
                dialer: true,
                iter: u16::MAX,
                seq: u64::MAX,
            };
            let nonce_result = sender.my_nonce();
            assert!(matches!(nonce_result, Err(Error::OurNonceOverflow)));
        });
    }

    #[test]
    fn test_sender_seq_overflow() {
        let (executuor, _, _) = Executor::default();
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (sink, _) = mocks::Channel::init();
            let mut sender = Sender {
                cipher,
                sink,
                max_message_size: 0,
                dialer: true,
                iter: 0,
                seq: u64::MAX,
            };
            let nonce_result = sender.my_nonce().unwrap();
            assert_eq!(nonce_result, encode(true, 1, 0));
        });
    }

    #[test]
    fn test_receiver_nonce_overflow() {
        let (executuor, _, _) = Executor::default();
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (_, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size: 0,
                dialer: false,
                iter: u16::MAX,
                seq: u64::MAX,
            };
            let nonce_result = receiver.peer_nonce();
            assert!(matches!(nonce_result, Err(Error::PeerNonceOverflow)));
        });
    }

    #[test]
    fn test_receiver_seq_overflow() {
        let (executuor, _, _) = Executor::default();
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (_, stream) = mocks::Channel::init();
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size: 0,
                dialer: false,
                iter: 0,
                seq: u64::MAX,
            };
            let nonce_result = receiver.peer_nonce().unwrap();
            assert_eq!(nonce_result, encode(true, 1, 0));
        });
    }

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
                dialer: false,
                iter: 0,
                seq: 0,
            };

            // Send invalid ciphertext
            send_frame(&mut sink, b"invalid data", receiver.max_message_size).await.unwrap();

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
                dialer: true,
                iter: 0,
                seq: 0,
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
                dialer: true,
                iter: 0,
                seq: 0,
            };
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size: message.len() - 1,
                dialer: false,
                iter: 0,
                seq: 0,
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
            let mut sender = Sender {
                cipher: cipher.clone(),
                sink,
                max_message_size,
                dialer: true,
                iter: 0,
                seq: 0,
            };
            let mut receiver = Receiver {
                cipher,
                stream,
                max_message_size,
                dialer: false,
                iter: 0,
                seq: 0,
            };

            // Send data
            sender.send(message).await.unwrap();
            let data = receiver.receive().await.unwrap();
            assert_eq!(data, &message[..]);
        });
    }
}
