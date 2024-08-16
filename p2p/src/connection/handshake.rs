use super::{utils::codec, x25519, Error};
use crate::{
    crypto::{Crypto, PublicKey},
    wire,
};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use prost::Message;
use tokio::net::TcpStream;
use tokio::time;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

const NAMESPACE: &[u8] = b"_COMMONWARE_P2P_HANDSHAKE_";

pub async fn create_handshake<C: Crypto>(
    crypto: &mut C,
    recipient_public_key: PublicKey,
    ephemeral_public_key: x25519_dalek::PublicKey,
) -> Result<Bytes, Error> {
    // Sign their public key
    let mut payload = Vec::new();
    payload.extend_from_slice(&recipient_public_key);
    payload.extend_from_slice(ephemeral_public_key.as_bytes());
    let signature = crypto.sign(NAMESPACE, &payload);

    // Send handshake
    Ok(wire::Message {
        payload: Some(wire::message::Payload::Handshake(wire::Handshake {
            recipient_public_key,
            ephemeral_public_key: x25519::encode_public_key(ephemeral_public_key),
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
    pub fn verify<C: Crypto>(crypto: &C, msg: BytesMut) -> Result<Self, Error> {
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

        // Get signature from peer
        let signature = handshake.signature.ok_or(Error::MissingSignature)?;
        let public_key: PublicKey = signature.public_key;
        if !C::validate(&public_key) {
            return Err(Error::InvalidPeerPublicKey);
        }

        // Construct signing payload (ephemeral public key + my public key)
        let mut payload = Vec::new();
        payload.extend_from_slice(&our_public_key);
        payload.extend_from_slice(&handshake.ephemeral_public_key);

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
    pub async fn verify<C: Crypto>(
        crypto: &C,
        max_frame_len: usize,
        handshake_timeout: time::Duration,
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
        let handshake = Handshake::verify(crypto, msg)?;

        Ok(Self {
            framed,
            peer_public_key: handshake.peer_public_key,
            ephemeral_public_key: handshake.ephemeral_public_key,
        })
    }
}
