use crate::{
    connection::{utils::codec, x25519, Error},
    wire,
};
use bytes::{Bytes, BytesMut};
use commonware_cryptography::{PublicKey, Scheme};
use futures::StreamExt;
use prost::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

const NAMESPACE: &[u8] = b"_COMMONWARE_P2P_HANDSHAKE_";

pub async fn create_handshake<C: Scheme>(
    crypto: &mut C,
    recipient_public_key: PublicKey,
    ephemeral_public_key: x25519_dalek::PublicKey,
) -> Result<Bytes, Error> {
    // Get current time
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("failed to get current time")
        .as_secs();

    // Sign their public key
    let mut payload = Vec::new();
    payload.extend_from_slice(&recipient_public_key);
    payload.extend_from_slice(ephemeral_public_key.as_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    let signature = crypto.sign(NAMESPACE, &payload);

    // Send handshake
    Ok(wire::Message {
        payload: Some(wire::message::Payload::Handshake(wire::Handshake {
            recipient_public_key,
            ephemeral_public_key: x25519::encode_public_key(ephemeral_public_key),
            timestamp,
            signature: Some(wire::Signature {
                public_key: crypto.me(),
                signature,
            }),
        })),
    }
    .encode_to_vec()
    .into())
}

pub struct Handshake {
    pub(super) ephemeral_public_key: x25519_dalek::PublicKey,
    pub(super) peer_public_key: PublicKey,
}

impl Handshake {
    pub fn verify<C: Scheme>(
        crypto: &C,
        max_handshake_age: Duration,
        msg: BytesMut,
    ) -> Result<Self, Error> {
        // Parse handshake message
        let handshake = match wire::Message::decode(msg)
            .map_err(Error::UnableToDecode)?
            .payload
        {
            Some(wire::message::Payload::Handshake(handshake)) => handshake,
            _ => return Err(Error::UnexpectedMessage),
        };

        // Verify that ephemeral public key is valid
        let ephemeral_public_key = x25519::decode_public_key(&handshake.ephemeral_public_key)
            .map_err(|_| Error::InvalidEphemeralPublicKey)?;

        // Verify that the signature is for us
        //
        // If we didn't verify this, it would be trivial for any peer to impersonate another peer (eventhough
        // they would not be able to decrypt any messages from the shared secret). This would prevent us
        // from making a legitimate connection to the intended peer.
        let our_public_key: PublicKey = handshake.recipient_public_key;
        if !C::validate(&our_public_key) {
            return Err(Error::InvalidChannelPublicKey);
        }
        if crypto.me() != our_public_key {
            return Err(Error::HandshakeNotForUs);
        }

        // Verify that the timestamp in the handshake is recent
        //
        // This prevents an adversary from reopening an encrypted connection
        // if they compromise a peer's ephemeral key (which would be stored
        // in memory unlike the peer identity) or from blocking a peer
        // from connecting if leaked.
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("failed to get current time")
            .as_secs();
        if handshake.timestamp < current_time - max_handshake_age.as_secs() {
            return Err(Error::InvalidTimestamp);
        }

        // Get signature from peer
        let signature = handshake.signature.ok_or(Error::MissingSignature)?;
        let public_key: PublicKey = signature.public_key;
        if !C::validate(&public_key) {
            return Err(Error::InvalidPeerPublicKey);
        }

        // Construct signing payload (ephemeral public key + my public key + timestamp)
        let mut payload = Vec::new();
        payload.extend_from_slice(&our_public_key);
        payload.extend_from_slice(&handshake.ephemeral_public_key);
        payload.extend_from_slice(&handshake.timestamp.to_be_bytes());

        // Verify signature
        if !C::verify(NAMESPACE, &payload, &public_key, &signature.signature) {
            return Err(Error::InvalidSignature);
        }

        Ok(Self {
            ephemeral_public_key,
            peer_public_key: public_key,
        })
    }
}

pub struct IncomingHandshake {
    pub peer_public_key: PublicKey,
    pub(super) framed: Framed<TcpStream, LengthDelimitedCodec>,
    pub(super) ephemeral_public_key: x25519_dalek::PublicKey,
}

impl IncomingHandshake {
    pub async fn verify<C: Scheme>(
        crypto: &C,
        max_frame_len: usize,
        max_handshake_age: Duration,
        handshake_timeout: Duration,
        stream: TcpStream,
    ) -> Result<Self, Error> {
        // Setup connection
        let mut framed = Framed::new(stream, codec(max_frame_len));

        // Verify handshake message from peer
        let msg = time::timeout(handshake_timeout, framed.next())
            .await
            .map_err(|_| Error::HandshakeTimeout)?
            .ok_or(Error::StreamClosed)?
            .map_err(|_| Error::ReadFailed)?;
        let handshake = Handshake::verify(crypto, max_handshake_age, msg)?;

        Ok(Self {
            framed,
            peer_public_key: handshake.peer_public_key,
            ephemeral_public_key: handshake.ephemeral_public_key,
        })
    }
}
