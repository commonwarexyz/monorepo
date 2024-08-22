use crate::{
    connection::{
        handshake::{create_handshake, Handshake, IncomingHandshake},
        utils::{codec, nonce_bytes},
        Config, Error,
    },
    wire,
};
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use commonware_cryptography::{PublicKey, Scheme};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use prost::Message;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::{select, time};
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

const CHUNK_PADDING: usize = 32 /* protobuf padding*/ + 12 /* chunk info */ + 16 /* encryption tag */;

pub struct Stream<C: Scheme> {
    config: Config<C>,
    dialer: bool,
    framed: Framed<TcpStream, LengthDelimitedCodec>,
    cipher: ChaCha20Poly1305,
}

impl<C: Scheme> Stream<C> {
    pub async fn upgrade_dialer(
        mut config: Config<C>,
        stream: TcpStream,
        peer: PublicKey,
    ) -> Result<Self, Error> {
        // Setup connection
        let mut framed = Framed::new(stream, codec(config.max_frame_length));

        // Generate shared secret
        let secret = x25519_dalek::EphemeralSecret::random();
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(&mut config.crypto, peer.clone(), ephemeral).await?;
        time::timeout(config.handshake_timeout, framed.send(msg))
            .await
            .map_err(|_| Error::HandshakeTimeout)?
            .map_err(|_| Error::SendFailed)?;

        // Verify handshake message from peer
        let msg = time::timeout(config.handshake_timeout, framed.next())
            .await
            .map_err(|_| Error::HandshakeTimeout)?
            .ok_or(Error::StreamClosed)?
            .map_err(|_| Error::ReadFailed)?;
        let handshake = Handshake::verify(&config.crypto, msg)?;

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
            framed,
            cipher,
        })
    }

    pub async fn upgrade_listener(
        mut config: Config<C>,
        mut handshake: IncomingHandshake,
    ) -> Result<Self, Error> {
        // Generate shared secret
        let secret = x25519_dalek::EphemeralSecret::random();
        let ephemeral = x25519_dalek::PublicKey::from(&secret);

        // Send handshake
        let msg = create_handshake(
            &mut config.crypto,
            handshake.peer_public_key.clone(),
            ephemeral,
        )
        .await?;
        time::timeout(config.handshake_timeout, handshake.framed.send(msg))
            .await
            .map_err(|_| Error::HandshakeTimeout)?
            .map_err(|_| Error::SendFailed)?;

        // Create cipher
        let shared_secret = secret.diffie_hellman(&handshake.ephemeral_public_key);
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|_| Error::CipherCreationFailed)?;

        Ok(Stream {
            config,
            dialer: false,
            framed: handshake.framed,
            cipher,
        })
    }

    pub fn split(self) -> (usize, Sender, Receiver) {
        let (sink, stream) = self.framed.split();
        (
            self.config.max_frame_length - CHUNK_PADDING,
            Sender {
                write_timeout: self.config.write_timeout,
                dialer: self.dialer,
                cipher: self.cipher.clone(),
                sink,
                my_nonce: 0,
            },
            Receiver {
                read_timeout: self.config.read_timeout,
                dialer: self.dialer,
                cipher: self.cipher,
                stream,
                peer_nonce: 0,
            },
        )
    }
}

pub struct Sender {
    write_timeout: Duration,
    dialer: bool,
    cipher: ChaCha20Poly1305,
    sink: SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>,
    my_nonce: u64,
}

impl Sender {
    fn my_nonce(&mut self) -> Result<Nonce, Error> {
        if self.my_nonce == u64::MAX {
            return Err(Error::OurNonceOverflow);
        }
        let nonce_bytes = nonce_bytes(self.my_nonce, self.dialer);
        self.my_nonce += 1;
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
        let result = time::timeout(self.write_timeout, self.sink.send(Bytes::from(msg))).await;
        result
            .map_err(|_| Error::WriteTimeout)?
            .map_err(|_| Error::SendFailed)
    }
}

pub struct Receiver {
    read_timeout: Duration,
    dialer: bool,
    cipher: ChaCha20Poly1305,
    stream: SplitStream<Framed<TcpStream, LengthDelimitedCodec>>,
    peer_nonce: u64,
}

impl Receiver {
    fn peer_nonce(&mut self) -> Result<Nonce, Error> {
        if self.peer_nonce == u64::MAX {
            return Err(Error::PeerNonceOverflow);
        }
        let nonce_bytes = nonce_bytes(self.peer_nonce, !self.dialer);
        self.peer_nonce += 1;
        Ok(nonce_bytes)
    }

    pub async fn receive(&mut self) -> Result<wire::Message, Error> {
        select! {
            Some(msg) = self.stream.next() => {
                // Invalid frame
                let msg = msg.map_err(|_| Error::ReadInvalidFrame)?;

                // Decrypt data
                let nonce = self.peer_nonce()?;
                let msg = self
                    .cipher
                    .decrypt(&nonce, msg.as_ref())
                    .map_err(|_| Error::DecryptionFailed)?;

                // Deserialize data
                Ok(wire::Message::decode(msg.as_ref()).map_err(Error::UnableToDecode)?)
            },
            _ = time::sleep(self.read_timeout) => Err(Error::ReadTimeout),
            else => Err(Error::StreamClosed),
        }
    }
}
