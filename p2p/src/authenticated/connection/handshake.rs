use super::{x25519, Error};
use crate::authenticated::wire;
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{timeout, Clock, Spawner, Stream};
use prost::Message;
use std::time::{Duration, UNIX_EPOCH};

const NAMESPACE: &[u8] = b"_COMMONWARE_P2P_HANDSHAKE_";

pub fn create_handshake<E: Clock, C: Scheme>(
    context: E,
    crypto: &mut C,
    recipient_public_key: PublicKey,
    ephemeral_public_key: x25519_dalek::PublicKey,
) -> Result<Bytes, Error> {
    // Get current time
    let timestamp = context
        .current()
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
    pub fn verify<E: Clock, C: Scheme>(
        context: E,
        crypto: &C,
        synchrony_bound: Duration,
        max_handshake_age: Duration,
        msg: Bytes,
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
        // if a peer's ephemeral key is compromised (which would be stored in-memory
        // unlike the peer identity) and/or from blocking a peer from connecting
        // to others (if an adversary recovered a handshake message could open a
        // connection to a peer first, peers only maintain one connection per peer).
        let current_time = context
            .current()
            .duration_since(UNIX_EPOCH)
            .expect("failed to get current time")
            .as_secs();
        if handshake.timestamp < current_time - max_handshake_age.as_secs() {
            return Err(Error::InvalidTimestamp);
        }
        if handshake.timestamp > current_time + synchrony_bound.as_secs() {
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

pub struct IncomingHandshake<S: Stream> {
    pub(super) stream: S,
    pub peer_public_key: PublicKey,
    pub(super) ephemeral_public_key: x25519_dalek::PublicKey,
}

impl<S: Stream> IncomingHandshake<S> {
    pub async fn verify<E: Clock + Spawner, C: Scheme>(
        context: E,
        crypto: &C,
        synchrony_bound: Duration,
        max_handshake_age: Duration,
        handshake_timeout: Duration,
        stream: S,
    ) -> Result<Self, Error> {
        // Verify handshake message from peer
        let msg = timeout(context.clone(), handshake_timeout, stream.recv())
            .await
            .map_err(|_| Error::HandshakeTimeout)?
            .map_err(|_| Error::ReadFailed)?;
        let handshake =
            Handshake::verify(context, crypto, synchrony_bound, max_handshake_age, msg)?;

        Ok(Self {
            stream,
            peer_public_key: handshake.peer_public_key,
            ephemeral_public_key: handshake.ephemeral_public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        ed25519::{self, Ed25519},
        Scheme,
    };
    use commonware_runtime::{deterministic::Executor, Runner, Spawner};
    use futures::SinkExt;
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use x25519_dalek::PublicKey;

    #[test]
    fn test_handshake_create_verify() {
        // Initialize runtime
        let (runner, context) = Executor::init(0, Duration::from_millis(1));
        runner.start(async move {
            // Create participants
            let mut sender = ed25519::insecure_signer(0);
            let recipient = ed25519::insecure_signer(1);
            let ephemeral_public_key = PublicKey::from([3u8; 32]);

            // Create handshake message
            let handshake_bytes = create_handshake(
                context.clone(),
                &mut sender,
                recipient.me(),
                ephemeral_public_key,
            )
            .unwrap();

            // Decode the handshake message
            let message = wire::Message::decode(handshake_bytes.clone()).unwrap();
            let handshake = match message.payload {
                Some(wire::message::Payload::Handshake(handshake)) => handshake,
                _ => panic!("unexpected message"),
            };
            // Verify the timestamp
            let current_timestamp = context
                .current()
                .duration_since(UNIX_EPOCH)
                .expect("failed to get current time")
                .as_secs();
            assert!(handshake.timestamp <= current_timestamp);
            assert!(handshake.timestamp >= current_timestamp - 5); // Allow a 5-second window

            // Verify the signature
            assert_eq!(handshake.recipient_public_key, recipient.me());
            assert_eq!(
                handshake.ephemeral_public_key,
                x25519::encode_public_key(ephemeral_public_key)
            );
            let mut payload = Vec::new();
            payload.extend_from_slice(&handshake.recipient_public_key);
            payload.extend_from_slice(&handshake.ephemeral_public_key);
            payload.extend_from_slice(&handshake.timestamp.to_be_bytes());

            // Verify signature
            assert!(Ed25519::verify(
                NAMESPACE,
                &payload,
                &sender.me(),
                &handshake.signature.unwrap().signature,
            ));

            // Verify using the handshake struct
            let handshake = Handshake::verify(
                context,
                &recipient,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake_bytes,
            )
            .unwrap();
            assert_eq!(handshake.peer_public_key, sender.me());
            assert_eq!(handshake.ephemeral_public_key, ephemeral_public_key);
        });
    }

    #[test]
    fn test_handshake() {
        // Initialize runtime
        let (runner, context) = Executor::init(0, Duration::from_millis(1));
        runner.start(async move {
            // Create participants
            let mut sender = ed25519::insecure_signer(0);
            let recipient = ed25519::insecure_signer(1);
            let ephemeral_public_key = PublicKey::from([3u8; 32]);

            // Create handshake message
            let handshake_bytes = create_handshake(
                context.clone(),
                &mut sender,
                recipient.me(),
                ephemeral_public_key,
            )
            .unwrap();

            // Setup a mock TcpStream that will listen for the response
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Send message over stream
            let max_frame_len = 1024;
            context.spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let codec = codec(max_frame_len);
                let mut stream = Framed::new(socket, codec);
                stream.send(handshake_bytes).await.unwrap();
            });

            // Call the verify function
            let stream = TcpStream::connect(addr).await.unwrap();
            let result = IncomingHandshake::verify(
                context,
                &recipient,
                max_frame_len,
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                stream,
            )
            .await
            .unwrap();

            // Assert that the result is expected
            assert_eq!(result.peer_public_key, sender.me());
            assert_eq!(result.ephemeral_public_key, ephemeral_public_key);
        });
    }

    #[test]
    fn test_incoming_handshake_invalid_data() {
        // Initialize runtime
        let (runner, context) = Executor::init(0, Duration::from_millis(1));
        runner.start(async move {
            // Setup a mock TcpStream that will listen for the response
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Send message over stream
            context.spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let _ = socket.write_all(b"mock data").await;
            });

            // Parameters for the verify function
            let crypto = ed25519::insecure_signer(0);
            let max_frame_len = 1024;
            let synchrony_bound = Duration::from_secs(1);
            let max_handshake_age = Duration::from_secs(1);
            let handshake_timeout = Duration::from_secs(500);

            // Call the verify function
            let stream = TcpStream::connect(addr).await.unwrap();
            let result = IncomingHandshake::verify(
                context,
                &crypto,
                max_frame_len,
                synchrony_bound,
                max_handshake_age,
                handshake_timeout,
                stream,
            )
            .await;

            // Assert that the result is an Err of type Error::ReadFailed (no frame len)
            assert!(matches!(result, Err(Error::ReadFailed)));
        });
    }

    #[test]
    fn test_incoming_handshake_verify_timeout() {
        // Initialize runtime
        let (runner, context) = Executor::init(0, Duration::from_millis(1));
        runner.start(async move {
            // Setup a mock TcpStream
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Parameters for the verify function
            let crypto = ed25519::insecure_signer(0);
            let max_frame_len = 1024;
            let synchrony_bound = Duration::from_secs(1);
            let max_handshake_age = Duration::from_secs(1);
            let handshake_timeout = Duration::from_millis(500); // Short timeout to trigger the error

            // Call the verify function
            let stream = TcpStream::connect(addr).await.unwrap();
            let result = IncomingHandshake::verify(
                context,
                &crypto,
                max_frame_len,
                synchrony_bound,
                max_handshake_age,
                handshake_timeout,
                stream,
            )
            .await;

            // Assert that the result is an Err of type Error::HandshakeTimeout
            assert!(matches!(result, Err(Error::HandshakeTimeout)));
        });
    }
}
