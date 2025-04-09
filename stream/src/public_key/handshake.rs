use super::x25519;
use crate::Error;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::Scheme;
use commonware_runtime::Clock;
use commonware_utils::SystemTimeExt;
use std::time::Duration;

/// Handshake information that is signed over by the sender.
pub struct Info<C: Scheme> {
    recipient: C::PublicKey,
    ephemeral_public_key: x25519::PublicKey,
    timestamp: u64,
}

impl<C: Scheme> Info<C> {
    pub fn new(
        recipient: C::PublicKey,
        secret: &x25519_dalek::EphemeralSecret,
        timestamp: u64,
    ) -> Self {
        Self {
            recipient,
            ephemeral_public_key: x25519::PublicKey::from_secret(secret),
            timestamp,
        }
    }
}

impl<C: Scheme> Write for Info<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.ephemeral_public_key.write(buf);
        self.timestamp.write(buf);
    }
}

impl<C: Scheme> Read for Info<C> {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, CodecError> {
        let recipient = C::PublicKey::read(buf)?;
        let ephemeral_public_key = x25519::PublicKey::read(buf)?;
        let timestamp = u64::read(buf)?;
        Ok(Info {
            recipient,
            ephemeral_public_key,
            timestamp,
        })
    }
}

impl<C: Scheme> FixedSize for Info<C> {
    const LEN_ENCODED: usize =
        C::PublicKey::LEN_ENCODED + x25519::PublicKey::LEN_ENCODED + u64::LEN_ENCODED;
}

// Allows recipient to verify that the sender has the private key
// of public key before sending any data.
//
// By requiring the server to have their public key signed, they prevent
// a malicious peer from forwarding a handshake message from a previous
// connection with public key (which could be used to convince the server
// to start a useless handshake). Alternatively, we could require the
// dialer to sign some random bytes provided by the server but this would
// require the server to send a message to a peer before authorizing that
// it should connect to them.
pub struct Signed<C: Scheme> {
    // The handshake info that was signed over
    info: Info<C>,

    // The public key of the sender
    signer: C::PublicKey,

    // The signature of the sender
    signature: C::Signature,
}

impl<C: Scheme> Signed<C> {
    pub fn sign(crypto: &mut C, namespace: &[u8], info: Info<C>) -> Self {
        let signature = crypto.sign(Some(namespace), &info.encode());
        Self {
            info,
            signer: crypto.public_key(),
            signature,
        }
    }

    pub fn signer(&self) -> C::PublicKey {
        self.signer.clone()
    }

    pub fn ephemeral(&self) -> x25519::PublicKey {
        self.info.ephemeral_public_key
    }

    pub fn verify<E: Clock>(
        &self,
        context: &E,
        crypto: &C,
        namespace: &[u8],
        synchrony_bound: Duration,
        max_handshake_age: Duration,
    ) -> Result<(), Error> {
        // Verify that the signature is for us
        //
        // If we didn't verify this, it would be trivial for any peer to impersonate another peer (even though
        // they would not be able to decrypt any messages from the shared secret). This would prevent us
        // from making a legitimate connection to the intended peer.
        if crypto.public_key() != self.info.recipient {
            return Err(Error::HandshakeNotForUs);
        }

        // Verify that the timestamp in the handshake is recent
        //
        // This prevents an adversary from reopening an encrypted connection
        // if a peer's ephemeral key is compromised (which would be stored in-memory
        // unlike the peer identity) and/or from blocking a peer from connecting
        // to others (if an adversary recovered a handshake message could open a
        // connection to a peer first, peers only maintain one connection per peer).
        let current_timestamp = context.current().epoch();
        let handshake_timestamp = Duration::from_millis(self.info.timestamp);
        if handshake_timestamp + max_handshake_age < current_timestamp {
            return Err(Error::InvalidTimestampOld(self.info.timestamp));
        }
        if handshake_timestamp > current_timestamp + synchrony_bound {
            return Err(Error::InvalidTimestampFuture(self.info.timestamp));
        }

        // Verify signature
        if !C::verify(
            Some(namespace),
            &self.info.encode(),
            &self.signer,
            &self.signature,
        ) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl<C: Scheme> Write for Signed<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.info.write(buf);
        self.signer.write(buf);
        self.signature.write(buf);
    }
}

impl<C: Scheme> Read for Signed<C> {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, CodecError> {
        let info = Info::<C>::read(buf)?;
        let signer = C::PublicKey::read(buf)?;
        let signature = C::Signature::read(buf)?;
        Ok(Self {
            info,
            signer,
            signature,
        })
    }
}

impl<C: Scheme> FixedSize for Signed<C> {
    const LEN_ENCODED: usize =
        Info::<C>::LEN_ENCODED + C::PublicKey::LEN_ENCODED + C::Signature::LEN_ENCODED;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        public_key::{Config, IncomingConnection},
        utils::codec::send_frame,
    };
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{Ed25519, Signer, Verifier};
    use commonware_runtime::{deterministic::Executor, mocks, Metrics, Runner, Spawner};
    use x25519::PublicKey;

    const TEST_NAMESPACE: &[u8] = b"test_namespace";
    const ONE_MEGABYTE: usize = 1024 * 1024;

    #[test]
    fn test_handshake_create_verify() {
        // Initialize context
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create participants
            let mut sender = Ed25519::from_seed(0);
            let recipient = Ed25519::from_seed(1);
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create handshake message
            let timestamp = context.current().epoch_millis();
            let handshake = Signed::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp,
                    recipient: recipient.public_key(),
                    ephemeral_public_key,
                },
            );

            // Decode the handshake message
            let handshake =
                Signed::<Ed25519>::decode(handshake.encode()).expect("failed to decode handshake");

            // Verify the timestamp
            let synchrony_bound = Duration::from_secs(5);
            let max_handshake_age = Duration::from_secs(5);
            let handshake_timestamp = Duration::from_millis(handshake.info.timestamp);
            let current_timestamp = Duration::from_millis(timestamp);
            assert!(handshake_timestamp <= current_timestamp + synchrony_bound);
            assert!(handshake_timestamp + max_handshake_age >= current_timestamp);

            // Verify the signature
            assert_eq!(handshake.info.recipient, recipient.public_key());
            assert_eq!(handshake.info.ephemeral_public_key, ephemeral_public_key,);

            // Verify signature
            assert!(Ed25519::verify(
                Some(TEST_NAMESPACE),
                &handshake.info.encode(),
                &sender.public_key(),
                &handshake.signature,
            ));

            // Verify using the handshake struct
            handshake
                .verify(
                    &context,
                    &recipient,
                    TEST_NAMESPACE,
                    synchrony_bound,
                    max_handshake_age,
                )
                .unwrap();
            assert_eq!(handshake.signer, sender.public_key());
            assert_eq!(handshake.info.ephemeral_public_key, ephemeral_public_key);
        });
    }

    #[test]
    fn test_handshake() {
        // Initialize context
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create participants
            let mut sender = Ed25519::from_seed(0);
            let recipient = Ed25519::from_seed(1);
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create handshake message
            let handshake = Signed::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient: recipient.public_key(),
                    ephemeral_public_key,
                },
            );

            // Setup a mock sink and stream
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Send message over stream
            context.with_label("stream_sender").spawn(|_| async move {
                send_frame(&mut stream_sender, &handshake.encode(), ONE_MEGABYTE)
                    .await
                    .unwrap();
            });

            // Call the verify function
            let config = Config {
                crypto: recipient.clone(),
                namespace: TEST_NAMESPACE.to_vec(),
                max_message_size: ONE_MEGABYTE,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };
            let result = IncomingConnection::verify(&context, config, sink, stream)
                .await
                .unwrap();

            // Assert that the result is expected
            assert_eq!(result.peer(), sender.public_key());
            assert_eq!(result.ephemeral(), ephemeral_public_key);
        });
    }

    #[test]
    fn test_handshake_not_for_us() {
        // Initialize context
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Create participants
            let mut sender = Ed25519::from_seed(0);
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create handshake message
            let handshake = Signed::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient: Ed25519::from_seed(1).public_key(),
                    ephemeral_public_key,
                },
            );

            // Setup a mock sink and stream
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Send message over stream
            context.with_label("stream_sender").spawn(|_| async move {
                send_frame(&mut stream_sender, &handshake.encode(), ONE_MEGABYTE)
                    .await
                    .unwrap();
            });

            // Call the verify function
            let config = Config {
                crypto: Ed25519::from_seed(2),
                namespace: TEST_NAMESPACE.to_vec(),
                max_message_size: ONE_MEGABYTE,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };
            let result = IncomingConnection::verify(&context, config, sink, stream).await;

            // Assert that the result is an error
            assert!(matches!(result, Err(Error::HandshakeNotForUs)));
        });
    }

    #[test]
    fn test_incoming_handshake_invalid_data() {
        // Initialize context
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Setup a mock sink and stream
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Send invalid data over stream
            context.with_label("stream_sender").spawn(|_| async move {
                send_frame(&mut stream_sender, b"mock data", ONE_MEGABYTE)
                    .await
                    .unwrap();
            });

            // Call the verify function
            let config = Config {
                crypto: Ed25519::from_seed(0),
                namespace: TEST_NAMESPACE.to_vec(),
                max_message_size: ONE_MEGABYTE,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_secs(1),
            };
            let result = IncomingConnection::verify(&context, config, sink, stream).await;

            // Assert that the result is an error
            assert!(matches!(result, Err(Error::UnableToDecode(_))));
        });
    }

    #[test]
    fn test_incoming_handshake_verify_timeout() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Setup a mock sink and stream
            let (sink, _) = mocks::Channel::init();
            let (_, stream) = mocks::Channel::init();

            // Call the verify function for one peer, but never send the handshake from the other
            let config = Config {
                crypto: Ed25519::from_seed(1),
                namespace: TEST_NAMESPACE.to_vec(),
                max_message_size: ONE_MEGABYTE,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_secs(1),
            };
            let result = IncomingConnection::verify(&context, config, sink, stream).await;

            // Assert that the result is an Err of type Error::HandshakeTimeout
            assert!(matches!(result, Err(Error::HandshakeTimeout)));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_signature() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient = crypto.public_key();
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            let handshake = Signed::sign(
                &mut crypto,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient,
                    ephemeral_public_key,
                },
            );

            // Tamper with the handshake to make the signature invalid
            let mut handshake =
                Signed::decode(handshake.encode()).expect("failed to decode handshake");
            handshake.info.timestamp += 1;

            // Verify the handshake
            let result = handshake.verify(
                &context,
                &crypto,
                TEST_NAMESPACE,
                Duration::from_secs(5),
                Duration::from_secs(5),
            );
            assert!(matches!(result, Err(Error::InvalidSignature)));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_timestamp_old() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient = crypto.public_key();
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            let timeout_duration = Duration::from_secs(5);
            let synchrony_bound = Duration::from_secs(0);

            // Create a handshake, setting the timestamp to 0.
            let handshake = Signed::sign(
                &mut crypto,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient,
                    ephemeral_public_key,
                },
            );

            // Time starts at 0 in deterministic executor.
            // Sleep for the exact timeout duration.
            context.sleep(timeout_duration).await;

            // Verify the handshake, it should be fine still.
            handshake
                .verify(
                    &context,
                    &crypto,
                    TEST_NAMESPACE,
                    synchrony_bound,
                    timeout_duration,
                )
                .unwrap();

            // Timeout by waiting 1 more millisecond.
            context.sleep(Duration::from_millis(1)).await;

            // Verify that a timeout error is returned.
            let result = handshake.verify(
                &context,
                &crypto,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
            );
            assert!(matches!(result, Err(Error::InvalidTimestampOld(t)) if t == 0));
        });
    }

    #[test]
    fn test_handshake_verify_invalid_timestamp_future() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let mut crypto = Ed25519::from_seed(0);
            let recipient = crypto.public_key();
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            let timeout_duration = Duration::from_secs(0);
            const SYNCHRONY_BOUND_MILLIS: u64 = 5_000;
            let synchrony_bound = Duration::from_millis(SYNCHRONY_BOUND_MILLIS);

            // Create a handshake at the synchrony bound.
            let handshake_ok = Signed::sign(
                &mut crypto,
                TEST_NAMESPACE,
                Info{
                    timestamp: SYNCHRONY_BOUND_MILLIS,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Create a handshake 1ms too far into the future.
            let handshake_late = Signed::sign(
                &mut crypto,
                TEST_NAMESPACE,
                Info{
                    timestamp:SYNCHRONY_BOUND_MILLIS + 1,
                    recipient,
                    ephemeral_public_key,
                },
            );

            // Verify the okay handshake.
            handshake_ok.verify(
                &context,
                &crypto,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
            ).unwrap(); // no error

            // Handshake too far into the future fails.
            let result = handshake_late.verify(
                &context,
                &crypto,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
            );
            assert!(matches!(result, Err(Error::InvalidTimestampFuture(t)) if t == SYNCHRONY_BOUND_MILLIS + 1));
        });
    }
}
