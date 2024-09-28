use super::{x25519, Error};
use crate::authenticated::wire;
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::{select, Clock, Sink, Spawner, Stream};
use prost::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NAMESPACE: &[u8] = b"_COMMONWARE_P2P_HANDSHAKE_";

pub fn create_handshake<E: Clock, C: Scheme>(
    runtime: E,
    crypto: &mut C,
    recipient_public_key: PublicKey,
    ephemeral_public_key: x25519_dalek::PublicKey,
) -> Result<Bytes, Error> {
    // Get current time
    let timestamp = runtime
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
                public_key: crypto.public_key(),
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
        runtime: E,
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
        if crypto.public_key() != our_public_key {
            return Err(Error::HandshakeNotForUs);
        }

        // Verify that the timestamp in the handshake is recent
        //
        // This prevents an adversary from reopening an encrypted connection
        // if a peer's ephemeral key is compromised (which would be stored in-memory
        // unlike the peer identity) and/or from blocking a peer from connecting
        // to others (if an adversary recovered a handshake message could open a
        // connection to a peer first, peers only maintain one connection per peer).
        let current_time = runtime
            .current()
            .duration_since(UNIX_EPOCH)
            .expect("failed to get current time")
            .as_secs();
        if handshake.timestamp + max_handshake_age.as_secs() < current_time {
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

pub struct IncomingHandshake<Si: Sink, St: Stream> {
    pub(super) sink: Si,
    pub(super) stream: St,
    pub(super) deadline: SystemTime,
    pub(super) ephemeral_public_key: x25519_dalek::PublicKey,
    pub peer_public_key: PublicKey,
}

impl<Si: Sink, St: Stream> IncomingHandshake<Si, St> {
    pub async fn verify<E: Clock + Spawner, C: Scheme>(
        runtime: E,
        crypto: &C,
        synchrony_bound: Duration,
        max_handshake_age: Duration,
        handshake_timeout: Duration,
        sink: Si,
        mut stream: St,
    ) -> Result<Self, Error> {
        // Set handshake deadline
        let deadline = runtime.current() + handshake_timeout;

        // Wait for up to handshake timeout for response
        let msg = select! {
            _timeout = runtime.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout);
            },
            result = stream.recv() => {
                result.map_err(|_| Error::ReadFailed)?
            },
        };

        // Verify handshake message from peer
        let handshake =
            Handshake::verify(runtime, crypto, synchrony_bound, max_handshake_age, msg)?;
        Ok(Self {
            sink,
            stream,
            deadline,
            ephemeral_public_key: handshake.ephemeral_public_key,
            peer_public_key: handshake.peer_public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_runtime::{
        deterministic::Executor,
        mocks::{MockSink, MockStream},
        Runner,
    };
    use futures::SinkExt;
    use x25519_dalek::PublicKey;

    #[test]
    fn test_handshake_create_verify() {
        // Initialize runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create participants
            let mut sender = Ed25519::from_seed(0);
            let recipient = Ed25519::from_seed(1);
            let ephemeral_public_key = PublicKey::from([3u8; 32]);

            // Create handshake message
            let handshake_bytes = create_handshake(
                runtime.clone(),
                &mut sender,
                recipient.public_key(),
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
            let current_timestamp = runtime
                .current()
                .duration_since(UNIX_EPOCH)
                .expect("failed to get current time")
                .as_secs();
            assert!(handshake.timestamp <= current_timestamp);
            assert!(handshake.timestamp + 5 >= current_timestamp); // Allow a 5-second window

            // Verify the signature
            assert_eq!(handshake.recipient_public_key, recipient.public_key());
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
                &sender.public_key(),
                &handshake.signature.unwrap().signature,
            ));

            // Verify using the handshake struct
            let handshake = Handshake::verify(
                runtime,
                &recipient,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake_bytes,
            )
            .unwrap();
            assert_eq!(handshake.peer_public_key, sender.public_key());
            assert_eq!(handshake.ephemeral_public_key, ephemeral_public_key);
        });
    }

    #[test]
    fn test_handshake() {
        // Initialize runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create participants
            let mut sender = Ed25519::from_seed(0);
            let recipient = Ed25519::from_seed(1);
            let ephemeral_public_key = PublicKey::from([3u8; 32]);

            // Create handshake message
            let handshake_bytes = create_handshake(
                runtime.clone(),
                &mut sender,
                recipient.public_key(),
                ephemeral_public_key,
            )
            .unwrap();

            // Setup a mock sink and stream
            let (sink, _) = MockSink::new();
            let (stream, mut stream_sender) = MockStream::new();

            // Send message over stream
            runtime.spawn("stream_sender", async move {
                stream_sender.send(handshake_bytes).await.unwrap();
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                runtime,
                &recipient,
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                sink,
                stream,
            )
            .await
            .unwrap();

            // Assert that the result is expected
            assert_eq!(result.peer_public_key, sender.public_key());
            assert_eq!(result.ephemeral_public_key, ephemeral_public_key);
        });
    }

    #[test]
    fn test_handshake_not_for_us() {
        // Initialize runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create participants
            let mut sender = Ed25519::from_seed(0);
            let ephemeral_public_key = PublicKey::from([3u8; 32]);

            // Create handshake message
            let handshake_bytes = create_handshake(
                runtime.clone(),
                &mut sender,
                Ed25519::from_seed(1).public_key(),
                ephemeral_public_key,
            )
            .unwrap();

            // Setup a mock sink and stream
            let (sink, _) = MockSink::new();
            let (stream, mut stream_sender) = MockStream::new();

            // Send message over stream
            runtime.spawn("stream_sender", async move {
                stream_sender.send(handshake_bytes).await.unwrap();
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                runtime,
                &Ed25519::from_seed(2),
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                sink,
                stream,
            )
            .await;

            // Assert that the result is an error
            assert!(matches!(result, Err(Error::HandshakeNotForUs)));
        });
    }

    #[test]
    fn test_incoming_handshake_invalid_data() {
        // Initialize runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Setup a mock sink and stream
            let (sink, _) = MockSink::new();
            let (stream, mut stream_sender) = MockStream::new();

            // Send invalid data over stream
            runtime.spawn("stream_sender", async move {
                stream_sender.send(Bytes::from("mock data")).await.unwrap();
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                runtime,
                &Ed25519::from_seed(0),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                sink,
                stream,
            )
            .await;

            // Assert that the result is an error
            assert!(matches!(result, Err(Error::UnableToDecode(_))));
        });
    }

    #[test]
    fn test_incoming_handshake_verify_timeout() {
        // Initialize runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create participants
            let mut sender = Ed25519::from_seed(0);
            let recipient = Ed25519::from_seed(1);
            let ephemeral_public_key = PublicKey::from([3u8; 32]);

            // Setup a mock sink and stream
            let (sink, _) = MockSink::new();
            let (stream, mut stream_sender) = MockStream::new();

            // Accept connections but do nothing
            runtime.spawn("stream_sender", {
                let runtime = runtime.clone();
                let recipient = recipient.clone();
                async move {
                    runtime.sleep(Duration::from_secs(10)).await;
                    let handshake_bytes = create_handshake(
                        runtime,
                        &mut sender,
                        recipient.public_key(),
                        ephemeral_public_key,
                    )
                    .unwrap();
                    stream_sender.send(handshake_bytes).await.unwrap();
                }
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                runtime,
                &recipient,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                sink,
                stream,
            )
            .await;

            // Assert that the result is an Err of type Error::HandshakeTimeout
            assert!(matches!(result, Err(Error::HandshakeTimeout)));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_public_key() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient_public_key = crypto.public_key();
            let ephemeral_public_key = x25519_dalek::PublicKey::from([0u8; 32]);

            let handshake = create_handshake(
                runtime.clone(),
                &mut crypto,
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Tamper with the handshake to make the signature invalid
            let mut handshake = match wire::Message::decode(handshake).unwrap().payload {
                Some(wire::message::Payload::Handshake(handshake)) => handshake,
                _ => panic!("unexpected message"),
            };
            let (public_key, signature) = match handshake.signature {
                Some(wire::Signature {
                    public_key,
                    signature,
                }) => (public_key, signature),
                _ => panic!("signature missing"),
            };
            let mut public_key = public_key.to_vec();
            public_key.truncate(28);
            handshake.signature = Some(wire::Signature {
                public_key: public_key.into(),
                signature,
            });
            let handshake = wire::Message {
                payload: Some(wire::message::Payload::Handshake(handshake)),
            }
            .encode_to_vec()
            .into();

            // Verify the handshake
            let result = Handshake::verify(
                runtime,
                &crypto,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake,
            );
            assert!(matches!(result, Err(Error::InvalidPeerPublicKey)));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_ephemeral_public_key() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient_public_key = crypto.public_key();
            let ephemeral_public_key = x25519_dalek::PublicKey::from([0u8; 32]);

            let handshake = create_handshake(
                runtime.clone(),
                &mut crypto,
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Tamper with the handshake to make the signature invalid
            let mut handshake = match wire::Message::decode(handshake).unwrap().payload {
                Some(wire::message::Payload::Handshake(handshake)) => handshake,
                _ => panic!("unexpected message"),
            };
            let mut ephemeral_public_key = handshake.ephemeral_public_key.to_vec();
            ephemeral_public_key.truncate(28);
            handshake.ephemeral_public_key = ephemeral_public_key.into();
            let handshake = wire::Message {
                payload: Some(wire::message::Payload::Handshake(handshake)),
            }
            .encode_to_vec()
            .into();

            // Verify the handshake
            let result = Handshake::verify(
                runtime,
                &crypto,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake,
            );
            assert!(matches!(result, Err(Error::InvalidEphemeralPublicKey)));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_signature() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient_public_key = crypto.public_key();
            let ephemeral_public_key = x25519_dalek::PublicKey::from([0u8; 32]);

            let handshake = create_handshake(
                runtime.clone(),
                &mut crypto,
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Tamper with the handshake to make the signature invalid
            let mut handshake = match wire::Message::decode(handshake).unwrap().payload {
                Some(wire::message::Payload::Handshake(handshake)) => handshake,
                _ => panic!("unexpected message"),
            };
            let (public_key, signature) = match handshake.signature {
                Some(wire::Signature {
                    public_key,
                    signature,
                }) => (public_key, signature),
                _ => panic!("signature missing"),
            };
            let mut signature = signature.to_vec();
            signature[0] ^= 0xFF;
            handshake.signature = Some(wire::Signature {
                public_key,
                signature: signature.into(),
            });
            let handshake = wire::Message {
                payload: Some(wire::message::Payload::Handshake(handshake)),
            }
            .encode_to_vec()
            .into();

            // Verify the handshake
            let result = Handshake::verify(
                runtime,
                &crypto,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake,
            );
            assert!(matches!(result, Err(Error::InvalidSignature)));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_timestamp() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient_public_key = crypto.public_key();
            let ephemeral_public_key = x25519_dalek::PublicKey::from([0u8; 32]);

            // Sleep a long time (time starts at 0 in deterministic executor)
            runtime.sleep(Duration::from_secs(100000)).await;

            // Create a handshake
            let handshake = create_handshake(
                runtime.clone(),
                &mut crypto,
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Tamper with the handshake to make the timestamp invalid
            let mut handshake = match wire::Message::decode(handshake).unwrap().payload {
                Some(wire::message::Payload::Handshake(handshake)) => handshake,
                _ => panic!("unexpected message"),
            };
            handshake.timestamp = 0;
            let handshake = wire::Message {
                payload: Some(wire::message::Payload::Handshake(handshake)),
            }
            .encode_to_vec()
            .into();

            // Verify the handshake
            let result = Handshake::verify(
                runtime,
                &crypto,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake,
            );
            assert!(matches!(result, Err(Error::InvalidTimestamp)));
        });
    }
}
