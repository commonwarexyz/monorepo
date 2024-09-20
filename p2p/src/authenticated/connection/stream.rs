use super::{
    handshake::{create_handshake, Handshake, IncomingHandshake},
    utils::nonce_bytes,
    Config, Error,
};
use crate::authenticated::wire;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{select, timeout, Clock, Spawner, Stream as RStream};
use prost::Message;
use std::time::Duration;

const CHUNK_PADDING: usize = 32 /* protobuf padding*/ + 12 /* chunk info */ + 16 /* encryption tag */;

pub struct Stream<E: Clock + Spawner, C: Scheme, S: RStream> {
    context: E,
    config: Config<C>,
    dialer: bool,
    stream: S,
    cipher: ChaCha20Poly1305,
}

impl<E: Clock + Spawner, C: Scheme, S: RStream> Stream<E, C, S> {
    pub async fn upgrade_dialer(
        context: E,
        mut config: Config<C>,
        stream: S,
        peer: PublicKey,
    ) -> Result<Self, Error> {
        // Generate shared secret
        let secret = x25519_dalek::EphemeralSecret::random();
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(context.clone(), &mut config.crypto, peer.clone(), ephemeral)?;
        timeout(context.clone(), config.handshake_timeout, stream.send(msg))
            .await
            .map_err(|_| Error::HandshakeTimeout)?
            .map_err(|_| Error::SendFailed)?;

        // Verify handshake message from peer
        let msg = timeout(context.clone(), config.handshake_timeout, stream.recv())
            .await
            .map_err(|_| Error::HandshakeTimeout)?
            .map_err(|_| Error::ReadFailed)?;
        let handshake = Handshake::verify(
            context.clone(),
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
            context,
            config,
            dialer: true,
            stream,
            cipher,
        })
    }

    pub async fn upgrade_listener(
        context: E,
        mut config: Config<C>,
        handshake: IncomingHandshake<S>,
    ) -> Result<Self, Error> {
        // Generate shared secret
        let secret = x25519_dalek::EphemeralSecret::random();
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(
            context.clone(),
            &mut config.crypto,
            handshake.peer_public_key.clone(),
            ephemeral,
        )?;
        timeout(
            context.clone(),
            config.handshake_timeout,
            handshake.stream.send(msg),
        )
        .await
        .map_err(|_| Error::HandshakeTimeout)?
        .map_err(|_| Error::SendFailed)?;

        // Create cipher
        let shared_secret = secret.diffie_hellman(&handshake.ephemeral_public_key);
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| Error::CipherCreationFailed)?;

        Ok(Stream {
            context,
            config,
            dialer: false,
            stream: handshake.stream,
            cipher,
        })
    }

    pub fn split(self) -> (usize, Sender<E, S>, Receiver<E, S>) {
        (
            self.config.max_frame_length - CHUNK_PADDING,
            Sender {
                context: self.context.clone(),
                write_timeout: self.config.write_timeout,
                cipher: self.cipher.clone(),
                stream: self.stream.clone(),

                dialer: self.dialer,
                iter: 0,
                seq: 0,
            },
            Receiver {
                context: self.context,
                read_timeout: self.config.read_timeout,
                cipher: self.cipher,
                stream: self.stream,

                dialer: self.dialer,
                iter: 0,
                seq: 0,
            },
        )
    }
}

pub struct Sender<E: Spawner + Clock, S: RStream> {
    context: E,

    write_timeout: Duration,
    cipher: ChaCha20Poly1305,
    stream: S,

    dialer: bool,
    iter: u16,
    seq: u64,
}

impl<E: Spawner + Clock, S: RStream> Sender<E, S> {
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
        let result = timeout(
            self.context.clone(),
            self.write_timeout,
            self.stream.send(Bytes::from(msg)),
        )
        .await;
        result
            .map_err(|_| Error::WriteTimeout)?
            .map_err(|_| Error::SendFailed)
    }
}

pub struct Receiver<E: Clock, S: RStream> {
    context: E,

    read_timeout: Duration,
    cipher: ChaCha20Poly1305,
    stream: S,

    dialer: bool,
    iter: u16,
    seq: u64,
}

impl<E: Clock, S: RStream> Receiver<E, S> {
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
        select! {
            _timeout = self.context.sleep(self.read_timeout) => {
                Err(Error::ReadTimeout)
            },
            msg = self.stream.recv() => {
                // Read message
                let msg = msg.map_err(|_| Error::StreamClosed)?;

                // Decrypt data
                let nonce = self.peer_nonce()?;
                let msg = self
                    .cipher
                    .decrypt(&nonce, msg.as_ref())
                    .map_err(|_| Error::DecryptionFailed)?;

                // Deserialize data
                Ok(wire::Message::decode(msg.as_ref()).map_err(Error::UnableToDecode)?)
            },
        }
    }
}
