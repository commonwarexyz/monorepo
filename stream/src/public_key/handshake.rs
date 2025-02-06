use super::{wire, x25519};
use crate::{utils::codec::recv_frame, Error};
use bytes::{BufMut, Bytes};
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_runtime::{Clock, Sink, Spawner, Stream};
use commonware_utils::{SizedSerialize, SystemTimeExt};
use prost::Message;
use std::time::{Duration, SystemTime};

pub fn create_handshake<C: Scheme>(
    crypto: &mut C,
    namespace: &[u8],
    timestamp: u64,
    recipient_public_key: C::PublicKey,
    ephemeral_public_key: x25519_dalek::PublicKey,
) -> Result<Bytes, Error> {
    // Sign their public key
    let ephemeral_public_key_bytes = ephemeral_public_key.as_bytes();
    let payload_len =
        C::PublicKey::SERIALIZED_LEN + ephemeral_public_key_bytes.len() + u64::SERIALIZED_LEN;
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&recipient_public_key);
    payload.extend_from_slice(ephemeral_public_key_bytes);
    payload.put_u64(timestamp);
    let signature = crypto.sign(Some(namespace), &payload);

    // Send handshake
    Ok(wire::Handshake {
        recipient_public_key: recipient_public_key.to_vec(),
        ephemeral_public_key: x25519::encode_public_key(ephemeral_public_key).to_vec(),
        timestamp,
        signature: Some(wire::Signature {
            public_key: crypto.public_key().to_vec(),
            signature: signature.to_vec(),
        }),
    }
    .encode_to_vec()
    .into())
}

pub struct Handshake<C: Scheme> {
    pub ephemeral_public_key: x25519_dalek::PublicKey,
    pub peer_public_key: C::PublicKey,
}

impl<C: Scheme> Handshake<C> {
    pub fn verify<E: Clock>(
        runtime: &E,
        crypto: &C,
        namespace: &[u8],
        synchrony_bound: Duration,
        max_handshake_age: Duration,
        msg: Bytes,
    ) -> Result<Self, Error> {
        // Parse handshake message
        let handshake = wire::Handshake::decode(msg).map_err(Error::UnableToDecode)?;

        // Verify that ephemeral public key is valid
        let ephemeral_public_key = x25519::decode_public_key(&handshake.ephemeral_public_key)
            .map_err(|_| Error::InvalidEphemeralPublicKey)?;

        // Verify that the signature is for us
        //
        // If we didn't verify this, it would be trivial for any peer to impersonate another peer (even though
        // they would not be able to decrypt any messages from the shared secret). This would prevent us
        // from making a legitimate connection to the intended peer.
        let our_public_key = C::PublicKey::try_from(handshake.recipient_public_key)
            .map_err(|_| Error::InvalidChannelPublicKey)?;
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
        let current_timestamp = runtime.current().epoch();
        let handshake_timestamp = Duration::from_millis(handshake.timestamp);
        if handshake_timestamp + max_handshake_age < current_timestamp {
            return Err(Error::InvalidTimestampOld(handshake.timestamp));
        }
        if handshake_timestamp > current_timestamp + synchrony_bound {
            return Err(Error::InvalidTimestampFuture(handshake.timestamp));
        }

        // Get signature from peer
        let signature = handshake.signature.ok_or(Error::MissingSignature)?;
        let public_key: C::PublicKey = C::PublicKey::try_from(signature.public_key)
            .map_err(|_| Error::InvalidPeerPublicKey)?;

        // Construct signing payload (ephemeral public key + my public key + timestamp)
        let payload_len = C::PublicKey::SERIALIZED_LEN
            + handshake.ephemeral_public_key.len()
            + u64::SERIALIZED_LEN;
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&our_public_key);
        payload.extend_from_slice(&handshake.ephemeral_public_key);
        payload.put_u64(handshake.timestamp);

        // Verify signature
        let signature =
            C::Signature::try_from(signature.signature).map_err(|_| Error::InvalidSignature)?;
        if !C::verify(Some(namespace), &payload, &public_key, &signature) {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            ephemeral_public_key,
            peer_public_key: public_key,
        })
    }
}

pub struct IncomingHandshake<Si: Sink, St: Stream, C: Scheme> {
    pub sink: Si,
    pub stream: St,
    pub deadline: SystemTime,
    pub ephemeral_public_key: x25519_dalek::PublicKey,
    pub peer_public_key: C::PublicKey,
}

impl<Si: Sink, St: Stream, C: Scheme> IncomingHandshake<Si, St, C> {
    #[allow(clippy::too_many_arguments)]
    pub async fn verify<E: Clock + Spawner>(
        runtime: &E,
        crypto: &C,
        namespace: &[u8],
        max_message_size: usize,
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
            _ = runtime.sleep_until(deadline) => {
                return Err(Error::HandshakeTimeout);
            },
            result = recv_frame(&mut stream, max_message_size) => {
                result.map_err(|_| Error::RecvFailed)?
            },
        };

        // Verify handshake message from peer
        let handshake = Handshake::verify(
            runtime,
            crypto,
            namespace,
            synchrony_bound,
            max_handshake_age,
            msg,
        )?;
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
    use crate::utils::codec::send_frame;
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_runtime::{deterministic::Executor, mocks, Runner};
    use x25519_dalek::PublicKey;

    const TEST_NAMESPACE: &[u8] = b"test_namespace";
    const ONE_MEGABYTE: usize = 1024 * 1024;

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
            let epoch_millis = runtime.current().epoch_millis();
            let handshake_bytes = create_handshake(
                &mut sender,
                TEST_NAMESPACE,
                epoch_millis,
                recipient.public_key(),
                ephemeral_public_key,
            )
            .unwrap();

            // Decode the handshake message
            let handshake = wire::Handshake::decode(handshake_bytes.clone())
                .expect("failed to decode handshake");

            // Verify the timestamp
            let synchrony_bound = Duration::from_secs(5);
            let max_handshake_age = Duration::from_secs(5);
            let handshake_timestamp = Duration::from_millis(handshake.timestamp);
            let current_timestamp = Duration::from_millis(epoch_millis);
            assert!(handshake_timestamp <= current_timestamp + synchrony_bound);
            assert!(handshake_timestamp + max_handshake_age >= current_timestamp);
            let handshake_recipient_public_key =
                <Ed25519 as Scheme>::PublicKey::try_from(&handshake.recipient_public_key).unwrap();
            let handshake_signature =
                <Ed25519 as Scheme>::Signature::try_from(&handshake.signature.unwrap().signature)
                    .unwrap();

            // Verify the signature
            assert_eq!(handshake_recipient_public_key, recipient.public_key());
            assert_eq!(
                handshake.ephemeral_public_key,
                x25519::encode_public_key(ephemeral_public_key)
            );
            let mut payload = Vec::new();
            payload.extend_from_slice(&handshake.recipient_public_key);
            payload.extend_from_slice(&handshake.ephemeral_public_key);
            payload.put_u64(handshake.timestamp);

            // Verify signature
            assert!(Ed25519::verify(
                Some(TEST_NAMESPACE),
                &payload,
                &sender.public_key(),
                &handshake_signature,
            ));

            // Verify using the handshake struct
            let handshake = Handshake::verify(
                &runtime,
                &recipient,
                TEST_NAMESPACE,
                synchrony_bound,
                max_handshake_age,
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
                &mut sender,
                TEST_NAMESPACE,
                0, // timestamp
                recipient.public_key(),
                ephemeral_public_key,
            )
            .unwrap();

            // Setup a mock sink and stream
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Send message over stream
            runtime.spawn("stream_sender", async move {
                send_frame(&mut stream_sender, &handshake_bytes, ONE_MEGABYTE)
                    .await
                    .unwrap();
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                &runtime,
                &recipient,
                TEST_NAMESPACE,
                ONE_MEGABYTE,
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
                &mut sender,
                TEST_NAMESPACE,
                0, // timestamp
                Ed25519::from_seed(1).public_key(),
                ephemeral_public_key,
            )
            .unwrap();

            // Setup a mock sink and stream
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Send message over stream
            runtime.spawn("stream_sender", async move {
                send_frame(&mut stream_sender, &handshake_bytes, ONE_MEGABYTE)
                    .await
                    .unwrap();
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                &runtime,
                &Ed25519::from_seed(2),
                TEST_NAMESPACE,
                ONE_MEGABYTE,
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
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Send invalid data over stream
            runtime.spawn("stream_sender", async move {
                send_frame(&mut stream_sender, b"mock data", ONE_MEGABYTE)
                    .await
                    .unwrap();
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                &runtime,
                &Ed25519::from_seed(0),
                TEST_NAMESPACE,
                ONE_MEGABYTE,
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
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Accept connections but do nothing
            runtime.spawn("stream_sender", {
                let runtime = runtime.clone();
                let recipient = recipient.clone();
                async move {
                    runtime.sleep(Duration::from_secs(10)).await;
                    let timestamp = runtime.current().epoch_millis();
                    let handshake_bytes = create_handshake(
                        &mut sender,
                        TEST_NAMESPACE,
                        timestamp,
                        recipient.public_key(),
                        ephemeral_public_key,
                    )
                    .unwrap();
                    send_frame(&mut stream_sender, &handshake_bytes, ONE_MEGABYTE)
                        .await
                        .unwrap();
                }
            });

            // Call the verify function
            let result = IncomingHandshake::verify(
                &runtime,
                &recipient,
                TEST_NAMESPACE,
                ONE_MEGABYTE,
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
                &mut crypto,
                TEST_NAMESPACE,
                0, // timestamp
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Tamper with the handshake to make the signature invalid
            let mut handshake =
                wire::Handshake::decode(handshake).expect("failed to decode handshake");
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
                public_key,
                signature,
            });

            // Verify the handshake
            let result = Handshake::verify(
                &runtime,
                &crypto,
                TEST_NAMESPACE,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake.encode_to_vec().into(),
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
                &mut crypto,
                TEST_NAMESPACE,
                0, // timestamp
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Tamper with the handshake to make the signature invalid
            let mut handshake =
                wire::Handshake::decode(handshake).expect("failed to decode handshake");
            let mut ephemeral_public_key = handshake.ephemeral_public_key.to_vec();
            ephemeral_public_key.truncate(28);
            handshake.ephemeral_public_key = ephemeral_public_key;

            // Verify the handshake
            let result = Handshake::verify(
                &runtime,
                &crypto,
                TEST_NAMESPACE,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake.encode_to_vec().into(),
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
                &mut crypto,
                TEST_NAMESPACE,
                0, // timestamp
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Tamper with the handshake to make the signature invalid
            let mut handshake =
                wire::Handshake::decode(handshake).expect("failed to decode handshake");
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
                signature,
            });

            // Verify the handshake
            let result = Handshake::verify(
                &runtime,
                &crypto,
                TEST_NAMESPACE,
                Duration::from_secs(5),
                Duration::from_secs(5),
                handshake.encode_to_vec().into(),
            );
            assert!(matches!(result, Err(Error::InvalidSignature)));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_timestamp_old() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient_public_key = crypto.public_key();
            let ephemeral_public_key = x25519_dalek::PublicKey::from([0u8; 32]);

            let timeout_duration = Duration::from_secs(5);
            let synchrony_bound = Duration::from_secs(0);

            // Create a handshake, setting the timestamp to 0.
            let handshake = create_handshake(
                &mut crypto,
                TEST_NAMESPACE,
                0, // timestamp
                recipient_public_key,
                ephemeral_public_key,
            )
            .unwrap();

            // Time starts at 0 in deterministic executor.
            // Sleep for the exact timeout duration.
            runtime.sleep(timeout_duration).await;

            // Verify the handshake, it should be fine still.
            Handshake::verify(
                &runtime,
                &crypto,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
                handshake.clone(),
            )
            .unwrap(); // no error

            // Timeout by waiting 1 more millisecond.
            runtime.sleep(Duration::from_millis(1)).await;

            // Verify that a timeout error is returned.
            let result = Handshake::verify(
                &runtime,
                &crypto,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
                handshake,
            );
            assert!(matches!(result, Err(Error::InvalidTimestampOld(t)) if t == 0));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_timestamp_future() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient_public_key = crypto.public_key();
            let ephemeral_public_key = x25519_dalek::PublicKey::from([0u8; 32]);

            let timeout_duration = Duration::from_secs(0);
            const SYNCHRONY_BOUND_MILLIS: u64 = 5_000;
            let synchrony_bound = Duration::from_millis(SYNCHRONY_BOUND_MILLIS);

            // Create a handshake at the synchrony bound.
            let handshake_ok = create_handshake(
                &mut crypto,
                TEST_NAMESPACE,
                SYNCHRONY_BOUND_MILLIS,
                recipient_public_key.clone(),
                ephemeral_public_key,
            ).unwrap();

            // Create a handshake 1ms too far into the future.
            let handshake_late = create_handshake(
                &mut crypto,
                TEST_NAMESPACE,
                SYNCHRONY_BOUND_MILLIS + 1,
                recipient_public_key,
                ephemeral_public_key,
            ).unwrap();

            // Verify the okay handshake.
            Handshake::verify(
                &runtime,
                &crypto,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
                handshake_ok,
            ).unwrap(); // no error

            // Handshake too far into the future fails.
            let result = Handshake::verify(
                &runtime,
                &crypto,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
                handshake_late,
            );
            assert!(matches!(result, Err(Error::InvalidTimestampFuture(t)) if t == SYNCHRONY_BOUND_MILLIS + 1));
        });
    }
}
