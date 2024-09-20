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
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use prost::Message;
use rand::{CryptoRng, Rng};

const CHUNK_PADDING: usize = 32 /* protobuf padding*/ + 12 /* chunk info */ + 16 /* encryption tag */;

pub struct Instance<E: Clock + Spawner, C: Scheme, Si: Sink, St: Stream> {
    context: E,
    config: Config<C>,
    dialer: bool,
    sink: Si,
    stream: St,
    cipher: ChaCha20Poly1305,
}

impl<E: Clock + Spawner + Rng + CryptoRng, C: Scheme, Si: Sink, St: Stream> Instance<E, C, Si, St> {
    pub async fn upgrade_dialer(
        mut context: E,
        mut config: Config<C>,
        mut sink: Si,
        mut stream: St,
        peer: PublicKey,
    ) -> Result<Self, Error> {
        // Generate shared secret
        let secret = x25519::new(&mut context);
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(context.clone(), &mut config.crypto, peer.clone(), ephemeral)?;
        sink.send(msg).await.map_err(|_| Error::SendFailed)?;

        // Verify handshake message from peer
        let msg = stream.recv().await.map_err(|_| Error::ReadFailed)?;
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
            sink,
            stream,
            cipher,
        })
    }

    pub async fn upgrade_listener(
        mut context: E,
        mut config: Config<C>,
        mut handshake: IncomingHandshake<Si, St>,
    ) -> Result<Self, Error> {
        // Generate shared secret
        let secret = x25519::new(&mut context);
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(
            context.clone(),
            &mut config.crypto,
            handshake.peer_public_key.clone(),
            ephemeral,
        )?;
        handshake
            .sink
            .send(msg)
            .await
            .map_err(|_| Error::SendFailed)?;

        // Create cipher
        let shared_secret = secret.diffie_hellman(&handshake.ephemeral_public_key);
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| Error::CipherCreationFailed)?;

        Ok(Instance {
            context,
            config,
            dialer: false,
            sink: handshake.sink,
            stream: handshake.stream,
            cipher,
        })
    }

    pub fn split(self) -> (usize, Sender<E, Si>, Receiver<E, St>) {
        (
            self.config.max_frame_length - CHUNK_PADDING,
            Sender {
                context: self.context.clone(),
                cipher: self.cipher.clone(),
                sink: self.sink,

                dialer: self.dialer,
                iter: 0,
                seq: 0,
            },
            Receiver {
                context: self.context,
                cipher: self.cipher,
                stream: self.stream,

                dialer: self.dialer,
                iter: 0,
                seq: 0,
            },
        )
    }
}

pub struct Sender<E: Spawner + Clock, Si: Sink> {
    context: E,

    cipher: ChaCha20Poly1305,
    sink: Si,

    dialer: bool,
    iter: u16,
    seq: u64,
}

impl<E: Spawner + Clock, Si: Sink> Sender<E, Si> {
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

pub struct Receiver<E: Clock, St: Stream> {
    context: E,

    cipher: ChaCha20Poly1305,
    stream: St,

    dialer: bool,
    iter: u16,
    seq: u64,
}

impl<E: Clock, St: Stream> Receiver<E, St> {
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
        Ok(wire::Message::decode(msg.as_ref()).map_err(Error::UnableToDecode)?)
    }
}
