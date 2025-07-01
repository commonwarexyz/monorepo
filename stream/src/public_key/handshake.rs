//! Operations over handshake messages.

use super::{x25519, AUTHENTICATION_TAG_LENGTH};
use crate::Error;
use bytes::{Buf, BufMut};
use chacha20poly1305::{
    aead::{AeadMutInPlace, Tag},
    ChaCha20Poly1305, Nonce,
};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_runtime::Clock;
use commonware_utils::SystemTimeExt;
use std::time::Duration;

/// Handshake information that is signed over by some peer.
pub struct Info<P: PublicKey> {
    /// The public key of the recipient.
    recipient: P,

    /// The ephemeral public key of the sender.
    ///
    /// This is used to derive the shared secret for the encrypted connection.
    ephemeral_public_key: x25519::PublicKey,

    /// Timestamp of the handshake (in epoch milliseconds).
    timestamp: u64,
}

impl<P: PublicKey> Info<P> {
    /// Create a new hello.
    pub fn new(recipient: P, ephemeral_public_key: x25519::PublicKey, timestamp: u64) -> Self {
        Self {
            recipient,
            ephemeral_public_key,
            timestamp,
        }
    }
}

impl<P: PublicKey> Write for Info<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.ephemeral_public_key.write(buf);
        UInt(self.timestamp).write(buf);
    }
}

impl<P: PublicKey> Read for Info<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let recipient = P::read(buf)?;
        let ephemeral_public_key = x25519::PublicKey::read(buf)?;
        let timestamp = UInt::read(buf)?.into();
        Ok(Info {
            recipient,
            ephemeral_public_key,
            timestamp,
        })
    }
}

impl<P: PublicKey> EncodeSize for Info<P> {
    fn encode_size(&self) -> usize {
        self.recipient.encode_size()
            + self.ephemeral_public_key.encode_size()
            + UInt(self.timestamp).encode_size()
    }
}

/// A signed hello message.
///
/// Allows recipient to verify that the sender has the private key
/// of public key before sending any data.
///
/// By requiring the server to have their public key signed, they prevent
/// a malicious peer from forwarding a handshake message from a previous
/// connection with public key (which could be used to convince the server
/// to start a useless handshake). Alternatively, we could require the
/// dialer to sign some random bytes provided by the server but this would
/// require the server to send a message to a peer before authorizing that
/// it should connect to them.
pub struct Hello<P: PublicKey> {
    // The handshake info that was signed over
    info: Info<P>,

    // The public key of the sender
    signer: P,

    // The signature of the sender
    signature: P::Signature,
}

impl<P: PublicKey> Hello<P> {
    /// Sign a hello message.
    pub fn sign<Sk: Signer<PublicKey = P, Signature = P::Signature>>(
        crypto: &mut Sk,
        namespace: &[u8],
        info: Info<P>,
    ) -> Self {
        let signature = crypto.sign(Some(namespace), &info.encode());
        Self {
            info,
            signer: crypto.public_key(),
            signature,
        }
    }

    /// Get the public key of the signer.
    pub fn signer(&self) -> P {
        self.signer.clone()
    }

    /// Get the ephemeral public key of the signer.
    pub fn ephemeral(&self) -> x25519::PublicKey {
        self.info.ephemeral_public_key
    }

    /// Verify a signed hello message.
    pub fn verify<E: Clock>(
        &self,
        context: &E,
        crypto: &P,
        namespace: &[u8],
        synchrony_bound: Duration,
        max_handshake_age: Duration,
    ) -> Result<(), Error> {
        // Verify that the signature is for us
        //
        // If we didn't verify this, it would be trivial for any peer to impersonate another peer (even though
        // they would not be able to decrypt any messages from the shared secret). This would prevent us
        // from making a legitimate connection to the intended peer.
        if *crypto != self.info.recipient {
            return Err(Error::HelloNotForUs);
        }

        // Verify that the hello is not signed by us
        //
        // This could indicate a self-connection attempt, which is not allowed.
        // It could also indicate a replay attack or a malformed message.
        // Either way, fail early to avoid any potential issues.
        if *crypto == self.signer {
            return Err(Error::HelloUsesOurKey);
        }

        // Verify that the timestamp in the hello is recent
        //
        // This prevents an adversary from reopening an encrypted connection
        // if a peer's ephemeral key is compromised (which would be stored in-memory
        // unlike the peer identity) and/or from blocking a peer from connecting
        // to others (if an adversary recovered a handshake message could open a
        // connection to a peer first, peers only maintain one connection per peer).
        let current_timestamp = context.current().epoch();
        let hello_timestamp = Duration::from_millis(self.info.timestamp);
        if hello_timestamp + max_handshake_age < current_timestamp {
            return Err(Error::InvalidTimestampOld(self.info.timestamp));
        }
        if hello_timestamp > current_timestamp + synchrony_bound {
            return Err(Error::InvalidTimestampFuture(self.info.timestamp));
        }

        // Verify signature
        if !self
            .signer
            .verify(Some(namespace), &self.info.encode(), &self.signature)
        {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl<P: PublicKey> Write for Hello<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.info.write(buf);
        self.signer.write(buf);
        self.signature.write(buf);
    }
}

impl<P: PublicKey> Read for Hello<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let info = Info::read(buf)?;
        let signer = P::read(buf)?;
        let signature = P::Signature::read(buf)?;
        Ok(Self {
            info,
            signer,
            signature,
        })
    }
}

impl<P: PublicKey> EncodeSize for Hello<P> {
    fn encode_size(&self) -> usize {
        self.info.encode_size() + self.signer.encode_size() + self.signature.encode_size()
    }
}

/// Key confirmation message used during the handshake.
///
/// This struct contains cryptographic proof that a party can correctly derive
/// the shared secret from the Diffie-Hellman exchange. It prevents attacks where
/// an adversary might forward [Hello] messages without actually knowing the
/// corresponding private keys.
pub struct Confirmation {
    /// AEAD tag of the encrypted proof demonstrating knowledge of the shared secret.
    tag: Tag<ChaCha20Poly1305>,
}

impl Confirmation {
    /// Create a new [Confirmation] using the provided cipher and [Hello] transcript.
    ///
    /// The confirmation encrypts the hello transcript to demonstrate knowledge of the shared
    /// secret and bind the confirmation to the entire hello exchange.
    ///
    /// # Security
    ///
    /// To prevent nonce-reuse, the cipher should **not** be the same cipher used for future
    /// encrypted messages, but should be generated from the same shared secret. The function takes
    /// ownership of the cipher to help prevent this.
    pub fn create(mut cipher: ChaCha20Poly1305, transcript: &[u8]) -> Result<Self, Error> {
        // Encrypt the confirmation using the transcript as associated data
        let tag = cipher
            .encrypt_in_place_detached(&Nonce::default(), transcript, &mut [])
            .map_err(|_| Error::ConfirmationFailed)?;

        Ok(Self { tag })
    }

    /// Verify the [Confirmation] using the provided cipher and [Hello] transcript.
    ///
    /// Returns Ok(()) if the confirmation is valid, otherwise returns an error.
    pub fn verify(&self, mut cipher: ChaCha20Poly1305, transcript: &[u8]) -> Result<(), Error> {
        // Decrypt the confirmation using the transcript as associated data
        cipher
            .decrypt_in_place_detached(&Nonce::default(), transcript, &mut [], &self.tag)
            .map_err(|_| Error::InvalidConfirmation)?;
        Ok(())
    }
}

impl Write for Confirmation {
    fn write(&self, buf: &mut impl BufMut) {
        let tag_bytes: [u8; Self::SIZE] = self.tag.into();
        tag_bytes.write(buf);
    }
}

impl Read for Confirmation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = <[u8; Self::SIZE]>::read_cfg(buf, &())?;
        Ok(Self { tag: tag.into() })
    }
}

impl FixedSize for Confirmation {
    const SIZE: usize = AUTHENTICATION_TAG_LENGTH;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        public_key::{Config, IncomingConnection},
        utils::codec::send_frame,
    };
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey as edPublicKey},
        PrivateKeyExt as _, Verifier as _,
    };
    use commonware_runtime::{deterministic, mocks, Metrics, Runner, Spawner};
    use x25519::PublicKey;

    const TEST_NAMESPACE: &[u8] = b"test_namespace";
    const ONE_MEGABYTE: usize = 1024 * 1024;

    #[test]
    fn test_hello_create_verify() {
        // Initialize context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create participants
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1).public_key();
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create hello message
            let timestamp = context.current().epoch_millis();
            let hello = Hello::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Decode the hello message
            let hello =
                Hello::<edPublicKey>::decode(hello.encode()).expect("failed to decode hello");

            // Verify the timestamp
            let synchrony_bound = Duration::from_secs(5);
            let max_handshake_age = Duration::from_secs(5);
            let hello_timestamp = Duration::from_millis(hello.info.timestamp);
            let current_timestamp = Duration::from_millis(timestamp);
            assert!(hello_timestamp <= current_timestamp + synchrony_bound);
            assert!(hello_timestamp + max_handshake_age >= current_timestamp);

            // Verify the signature
            assert_eq!(hello.info.recipient, recipient);
            assert_eq!(hello.info.ephemeral_public_key, ephemeral_public_key,);

            // Verify signature
            assert!(sender.public_key().verify(
                Some(TEST_NAMESPACE),
                &hello.info.encode(),
                &hello.signature,
            ));

            // Verify using the hello struct
            hello
                .verify(
                    &context,
                    &recipient,
                    TEST_NAMESPACE,
                    synchrony_bound,
                    max_handshake_age,
                )
                .unwrap();
            assert_eq!(hello.signer, sender.public_key());
            assert_eq!(hello.info.ephemeral_public_key, ephemeral_public_key);
        });
    }

    #[test]
    fn test_hello() {
        // Initialize context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create participants
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1);
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create hello message
            let hello = Hello::sign(
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
                send_frame(&mut stream_sender, &hello.encode(), ONE_MEGABYTE)
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
    fn test_hello_not_for_us() {
        // Initialize context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create participants
            let mut sender = PrivateKey::from_seed(0);
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create hello message
            let hello = Hello::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient: PrivateKey::from_seed(1).public_key(),
                    ephemeral_public_key,
                },
            );

            // Setup a mock sink and stream
            let (sink, _) = mocks::Channel::init();
            let (mut stream_sender, stream) = mocks::Channel::init();

            // Send message over stream
            context.with_label("stream_sender").spawn(|_| async move {
                send_frame(&mut stream_sender, &hello.encode(), ONE_MEGABYTE)
                    .await
                    .unwrap();
            });

            // Call the verify function
            let config = Config {
                crypto: PrivateKey::from_seed(2),
                namespace: TEST_NAMESPACE.to_vec(),
                max_message_size: ONE_MEGABYTE,
                synchrony_bound: Duration::from_secs(5),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(5),
            };
            let result = IncomingConnection::verify(&context, config, sink, stream).await;

            // Assert that the result is an error
            assert!(matches!(result, Err(Error::HelloNotForUs)));
        });
    }

    #[test]
    fn test_incoming_hello_invalid_data() {
        // Initialize context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
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
                crypto: PrivateKey::from_seed(0),
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
    fn test_incoming_hello_verify_timeout() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Setup a mock sink and stream
            let (sink, _stream) = mocks::Channel::init();
            let (_sink, stream) = mocks::Channel::init();

            // Call the verify function for one peer, but never send the handshake from the other
            let config = Config {
                crypto: PrivateKey::from_seed(1),
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
    fn test_hello_verify_invalid_signature() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1);
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            // The peer creates a valid hello intended for us
            let hello = Hello::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient: recipient.public_key(),
                    ephemeral_public_key,
                },
            );

            // Tamper with the hello to make the signature invalid
            let mut hello =
                Hello::<edPublicKey>::decode(hello.encode()).expect("failed to decode hello");
            hello.info.timestamp += 1;

            // Verify the hello
            let result = hello.verify(
                &context,
                &recipient.public_key(),
                TEST_NAMESPACE,
                Duration::from_secs(5),
                Duration::from_secs(5),
            );
            assert!(matches!(result, Err(Error::InvalidSignature)));
        });
    }

    #[test]
    fn test_hello_verify_invalid_timestamp_old() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut signer = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1).public_key();
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            let timeout_duration = Duration::from_secs(5);
            let synchrony_bound = Duration::from_secs(0);

            // The peer creates a hello, setting the timestamp to 0.
            let hello = Hello::sign(
                &mut signer,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Time starts at 0 in deterministic executor.
            // Sleep for the exact timeout duration.
            context.sleep(timeout_duration).await;

            // Verify the hello, it should be fine still.
            hello
                .verify(
                    &context,
                    &recipient,
                    TEST_NAMESPACE,
                    synchrony_bound,
                    timeout_duration,
                )
                .unwrap();

            // Timeout by waiting 1 more millisecond.
            context.sleep(Duration::from_millis(1)).await;

            // Verify that a timeout error is returned.
            let result = hello.verify(
                &context,
                &recipient,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
            );
            assert!(matches!(result, Err(Error::InvalidTimestampOld(t)) if t == 0));
        });
    }

    #[test]
    fn test_confirmation_create_and_verify() {
        use chacha20poly1305::KeyInit;

        let key = [1u8; 32];
        let cipher = ChaCha20Poly1305::new(&key.into());
        let transcript = b"test_transcript_data";

        // Create confirmation
        let confirmation = Confirmation::create(cipher, transcript).unwrap();

        // Verify the confirmation with the same parameters
        let cipher = ChaCha20Poly1305::new(&key.into());
        confirmation.verify(cipher, transcript).unwrap();

        // Verify that confirmation fails with different transcript
        let different_transcript = b"different_transcript_data";
        let cipher = ChaCha20Poly1305::new(&key.into());
        let result = confirmation.verify(cipher, different_transcript);
        assert!(matches!(result, Err(Error::InvalidConfirmation)));

        // Verify that confirmation fails with different cipher
        let different_key = [2u8; 32];
        let different_cipher = ChaCha20Poly1305::new(&different_key.into());
        let result = confirmation.verify(different_cipher, transcript);
        assert!(matches!(result, Err(Error::InvalidConfirmation)));
    }

    #[test]
    fn test_confirmation_encoding() {
        use chacha20poly1305::KeyInit;
        use commonware_codec::{DecodeExt, Encode};

        let key = [1u8; 32];
        let cipher = ChaCha20Poly1305::new(&key.into());
        let transcript = b"test_transcript_for_encoding";

        // Create and encode confirmation
        let original_confirmation = Confirmation::create(cipher, transcript).unwrap();
        let encoded = original_confirmation.encode();

        // Decode and verify it matches
        let decoded_confirmation = Confirmation::decode(encoded).unwrap();
        let cipher = ChaCha20Poly1305::new(&key.into());
        decoded_confirmation.verify(cipher, transcript).unwrap();
    }

    #[test]
    fn test_hello_verify_invalid_timestamp_future() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut signer = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1).public_key();
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            let timeout_duration = Duration::from_secs(0);
            const SYNCHRONY_BOUND_MILLIS: u64 = 5_000;
            let synchrony_bound = Duration::from_millis(SYNCHRONY_BOUND_MILLIS);

            // The peer creates a hello at the synchrony bound.
            let hello_ok = Hello::sign(
                &mut signer,
                TEST_NAMESPACE,
                Info{
                    timestamp: SYNCHRONY_BOUND_MILLIS,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Create a hello 1ms too far into the future.
            let hello_late = Hello::sign(
                &mut signer,
                TEST_NAMESPACE,
                Info{
                    timestamp:SYNCHRONY_BOUND_MILLIS + 1,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Verify the okay hello.
            hello_ok.verify(
                &context,
                &recipient,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
            ).unwrap(); // no error

            // Hello too far into the future fails.
            let result = hello_late.verify(
                &context,
                &recipient,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
            );
            assert!(matches!(result, Err(Error::InvalidTimestampFuture(t)) if t == SYNCHRONY_BOUND_MILLIS + 1));
        });
    }
}
