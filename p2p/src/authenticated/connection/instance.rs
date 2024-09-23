use super::{
    handshake::{create_handshake, Handshake, IncomingHandshake},
    utils::nonce_bytes,
    x25519, Config, Error,
};
use crate::authenticated::wire;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{select, Clock, Sink, Spawner, Stream};
use prost::Message;
use rand::{CryptoRng, Rng};

const CHUNK_PADDING: usize = 64 /* protobuf overhead */ + 12 /* chunk info */ + 16 /* encryption tag */;

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
        let msg = create_handshake(runtime.clone(), &mut config.crypto, peer.clone(), ephemeral)?;

        // Wait for up to handshake timeout to send
        select! {
            _timeout = runtime.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = sink.send(msg) => {
                result.map_err(|_| Error::SendFailed)?;
            },
        }

        // Wait for up to handshake timeout for response
        let msg = select! {
            _timeout = runtime.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = stream.recv() => {
                result.map_err(|_| Error::ReadFailed)?
            },
        };

        // Verify handshake message from peer
        let handshake = Handshake::verify(
            runtime,
            &config.crypto,
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
            handshake.peer_public_key.clone(),
            ephemeral,
        )?;

        // Wait for up to handshake timeout
        select! {
            _timeout = runtime.sleep_until(handshake.deadline) => {
                return Err(Error::HandshakeTimeout)
            },
            result = handshake.sink.send(msg) => {
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

    pub fn split(self) -> (usize, Sender<Si>, Receiver<St>) {
        (
            self.config.max_message_size - CHUNK_PADDING,
            Sender {
                cipher: self.cipher.clone(),
                sink: self.sink,

                dialer: self.dialer,
                iter: 0,
                seq: 0,
            },
            Receiver {
                cipher: self.cipher,
                stream: self.stream,

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
        let nonce_bytes = nonce_bytes(self.dialer, self.iter, self.seq);
        self.seq += 1;
        Ok(nonce_bytes)
    }

    pub async fn send(&mut self, msg: wire::Message) -> Result<(), Error> {
        // Encrypt data
        let msg = msg.encode_to_vec();
        let nonce = self.my_nonce()?;
        let msg = self
            .cipher
            .encrypt(&nonce, msg.as_ref())
            .map_err(|_| Error::EncryptionFailed)?;

        // Send data
        self.sink
            .send(Bytes::from(msg))
            .await
            .map_err(|_| Error::SendFailed)
    }
}

pub struct Receiver<St: Stream> {
    cipher: ChaCha20Poly1305,
    stream: St,

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
        let nonce_bytes = nonce_bytes(!self.dialer, self.iter, self.seq);
        self.seq += 1;
        Ok(nonce_bytes)
    }

    pub async fn receive(&mut self) -> Result<wire::Message, Error> {
        // Read message
        let msg = self.stream.recv().await.map_err(|_| Error::StreamClosed)?;

        // Decrypt data
        let nonce = self.peer_nonce()?;
        let msg = self
            .cipher
            .decrypt(&nonce, msg.as_ref())
            .map_err(|_| Error::DecryptionFailed)?;

        // Deserialize data
        wire::Message::decode(msg.as_ref()).map_err(Error::UnableToDecode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        deterministic::Executor,
        mocks::{MockSink, MockStream},
        Runner,
    };
    use std::time::Duration;

    #[test]
    fn test_sender_nonce_overflow() {
        let (executuor, _, _) = Executor::init(0, Duration::from_millis(1));
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (sink, _) = MockSink::new();
            let mut sender = Sender {
                cipher,
                sink,
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
        let (executuor, _, _) = Executor::init(0, Duration::from_millis(1));
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (sink, _) = MockSink::new();
            let mut sender = Sender {
                cipher,
                sink,
                dialer: true,
                iter: 0,
                seq: u64::MAX,
            };
            let nonce_result = sender.my_nonce().unwrap();
            assert_eq!(nonce_result, nonce_bytes(true, 1, 0));
        });
    }

    #[test]
    fn test_receiver_nonce_overflow() {
        let (executuor, _, _) = Executor::init(0, Duration::from_millis(1));
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (stream, _) = MockStream::new();
            let mut receiver = Receiver {
                cipher,
                stream,
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
        let (executuor, _, _) = Executor::init(0, Duration::from_millis(1));
        executuor.start(async {
            let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
            let (stream, _) = MockStream::new();
            let mut receiver = Receiver {
                cipher,
                stream,
                dialer: false,
                iter: 0,
                seq: u64::MAX,
            };
            let nonce_result = receiver.peer_nonce().unwrap();
            assert_eq!(nonce_result, nonce_bytes(true, 1, 0));
        });
    }
}
