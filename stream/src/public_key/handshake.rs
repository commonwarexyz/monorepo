//! Operations over handshake messages.

use super::{x25519, ENCRYPTION_TAG_LENGTH};
use crate::Error;
use bytes::{Buf, BufMut, Bytes};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt,
    Write,
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_runtime::Clock;
use commonware_utils::SystemTimeExt;
use std::time::Duration;

/// Handshake information that is signed over by some peer.
pub struct Info<C: PublicKey> {
    /// The public key of the recipient.
    recipient: C,

    /// The ephemeral public key of the sender.
    ///
    /// This is used to derive the shared secret for the encrypted connection.
    ephemeral_public_key: x25519::PublicKey,

    /// Timestamp of the handshake (in epoch milliseconds).
    timestamp: u64,
}

impl<C: PublicKey> Info<C> {
    /// Create a new handshake.
    pub fn new(recipient: C, ephemeral_public_key: x25519::PublicKey, timestamp: u64) -> Self {
        Self {
            recipient,
            ephemeral_public_key,
            timestamp,
        }
    }
}

impl<C: PublicKey> Write for Info<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.ephemeral_public_key.write(buf);
        UInt(self.timestamp).write(buf);
    }
}

impl<C: PublicKey> Read for Info<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let recipient = C::read(buf)?;
        let ephemeral_public_key = x25519::PublicKey::read(buf)?;
        let timestamp = UInt::read(buf)?.into();
        Ok(Info {
            recipient,
            ephemeral_public_key,
            timestamp,
        })
    }
}

impl<K: PublicKey> EncodeSize for Info<K> {
    fn encode_size(&self) -> usize {
        self.recipient.encode_size()
            + self.ephemeral_public_key.encode_size()
            + UInt(self.timestamp).encode_size()
    }
}

/// A signed handshake message.
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
pub struct Signed<C: PublicKey> {
    // The handshake info that was signed over
    info: Info<C>,

    // The public key of the sender
    signer: C,

    // The signature of the sender
    signature: C::Signature,
}

impl<C: PublicKey> Signed<C> {
    /// Sign a handshake message.
    pub fn sign<Sk: Signer<PublicKey = C, Signature = C::Signature>>(
        crypto: &mut Sk,
        namespace: &[u8],
        info: Info<C>,
    ) -> Self {
        let signature = crypto.sign(Some(namespace), &info.encode());
        Self {
            info,
            signer: crypto.public_key(),
            signature,
        }
    }

    /// Get the public key of the signer.
    pub fn signer(&self) -> C {
        self.signer.clone()
    }

    /// Get the ephemeral public key of the signer.
    pub fn ephemeral(&self) -> x25519::PublicKey {
        self.info.ephemeral_public_key
    }

    pub fn timestamp(&self) -> u64 {
        self.info.timestamp
    }

    /// Verify a signed handshake message.
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
        if *crypto != self.info.recipient {
            return Err(Error::HandshakeNotForUs);
        }

        // Verify that the handshake is not signed by us
        //
        // This could indicate a self-connection attempt, which is not allowed.
        // It could also indicate a replay attack or a malformed message.
        // Either way, fail early to avoid any potential issues.
        if *crypto == self.signer {
            return Err(Error::HandshakeUsesOurKey);
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
        if !self
            .signer
            .verify(Some(namespace), &self.info.encode(), &self.signature)
        {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl<C: PublicKey> Write for Signed<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.info.write(buf);
        self.signer.write(buf);
        self.signature.write(buf);
    }
}

impl<C: PublicKey> Read for Signed<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let info = Info::read(buf)?;
        let signer = C::read(buf)?;
        let signature = C::Signature::read(buf)?;
        Ok(Self {
            info,
            signer,
            signature,
        })
    }
}

impl<C: PublicKey> EncodeSize for Signed<C> {
    fn encode_size(&self) -> usize {
        self.info.encode_size() + self.signer.encode_size() + self.signature.encode_size()
    }
}

/// Proof that a party can correctly derive the shared secret.
///
/// This is used in the 3-message handshake protocol to ensure mutual authentication.
/// Each party encrypts a known plaintext using the derived shared secret to prove
/// they can compute the same key material.
pub struct AuthenticationProof {
    /// Encrypted proof demonstrating knowledge of the shared secret.
    ///
    /// Contains a known plaintext encrypted with ChaCha20Poly1305 using
    /// the derived cipher. The plaintext is "auth_proof" concatenated
    /// with the timestamp to prevent replay attacks.
    encrypted_proof: Bytes,
}

impl AuthenticationProof {
    /// Create a new authentication proof using the provided cipher and ephemeral public key.
    ///
    /// The proof encrypts the ephemeral public key of the peer to demonstrate
    /// knowledge of the shared secret in a challenge-response fashion.
    pub fn create(
        cipher: &ChaCha20Poly1305,
        nonce: &Nonce,
        ephemeral_key: &x25519::PublicKey,
    ) -> Result<Self, Error> {
        // Encrypt the proof
        let encrypted_proof = cipher
            .encrypt(nonce, ephemeral_key.encode().as_ref())
            .map_err(|_| Error::EncryptionFailed)?;

        Ok(Self {
            encrypted_proof: Bytes::from(encrypted_proof),
        })
    }

    /// Verify the authentication proof using the provided cipher and ephemeral public key.
    ///
    /// Returns Ok(()) if the proof is valid, otherwise returns an error.
    pub fn verify(
        &self,
        cipher: &ChaCha20Poly1305,
        nonce: &Nonce,
        ephemeral_key: &x25519::PublicKey,
    ) -> Result<(), Error> {
        // Decrypt the proof
        let decrypted = cipher
            .decrypt(nonce, self.encrypted_proof.as_ref())
            .map_err(|_| Error::DecryptionFailed)?;

        // Verify the proof content
        let expected_proof = ephemeral_key.encode();
        if decrypted == expected_proof {
            Ok(())
        } else {
            Err(Error::InvalidAuthenticationProof)
        }
    }
}

impl Write for AuthenticationProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.encrypted_proof.write(buf);
    }
}

impl Read for AuthenticationProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let len = x25519::PublicKey::SIZE + ENCRYPTION_TAG_LENGTH;
        let range = RangeCfg::from(len..=len);
        let encrypted_proof = Bytes::read_cfg(buf, &range)?;
        Ok(Self { encrypted_proof })
    }
}

impl EncodeSize for AuthenticationProof {
    fn encode_size(&self) -> usize {
        self.encrypted_proof.encode_size()
    }
}

/// Message 2 in the 3-message handshake protocol: Listener's response with authentication proof.
///
/// The listener sends their signed handshake along with a proof that they can
/// derive the correct shared secret.
pub struct ListenerResponse<C: PublicKey> {
    /// The signed handshake from the listener
    handshake: Signed<C>,

    /// Proof that the listener can derive the shared secret
    auth_proof: AuthenticationProof,
}

impl<C: PublicKey> ListenerResponse<C> {
    pub fn new(handshake: Signed<C>, auth_proof: AuthenticationProof) -> Self {
        Self {
            handshake,
            auth_proof,
        }
    }

    pub fn into_parts(self) -> (Signed<C>, AuthenticationProof) {
        (self.handshake, self.auth_proof)
    }
}

impl<C: PublicKey> Write for ListenerResponse<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.handshake.write(buf);
        self.auth_proof.write(buf);
    }
}

impl<C: PublicKey> Read for ListenerResponse<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let handshake = Signed::read(buf)?;
        let auth_proof = AuthenticationProof::read(buf)?;
        Ok(Self {
            handshake,
            auth_proof,
        })
    }
}

impl<C: PublicKey> EncodeSize for ListenerResponse<C> {
    fn encode_size(&self) -> usize {
        self.handshake.encode_size() + self.auth_proof.encode_size()
    }
}

/// Message 3 in the 3-message handshake protocol: Dialer's final confirmation.
///
/// The dialer sends a proof that they can derive the correct shared secret,
/// completing the mutual authentication.
pub struct DialerConfirmation {
    /// Proof that the dialer can derive the shared secret
    auth_proof: AuthenticationProof,
}

impl DialerConfirmation {
    pub fn new(auth_proof: AuthenticationProof) -> Self {
        Self { auth_proof }
    }

    pub fn auth_proof(&self) -> &AuthenticationProof {
        &self.auth_proof
    }
}

impl Write for DialerConfirmation {
    fn write(&self, buf: &mut impl BufMut) {
        self.auth_proof.write(buf);
    }
}

impl Read for DialerConfirmation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let auth_proof = AuthenticationProof::read(buf)?;
        Ok(Self { auth_proof })
    }
}

impl EncodeSize for DialerConfirmation {
    fn encode_size(&self) -> usize {
        self.auth_proof.encode_size()
    }
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
    fn test_handshake_create_verify() {
        // Initialize context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create participants
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1).public_key();
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create handshake message
            let timestamp = context.current().epoch_millis();
            let handshake = Signed::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Decode the handshake message
            let handshake = Signed::<edPublicKey>::decode(handshake.encode())
                .expect("failed to decode handshake");

            // Verify the timestamp
            let synchrony_bound = Duration::from_secs(5);
            let max_handshake_age = Duration::from_secs(5);
            let handshake_timestamp = Duration::from_millis(handshake.info.timestamp);
            let current_timestamp = Duration::from_millis(timestamp);
            assert!(handshake_timestamp <= current_timestamp + synchrony_bound);
            assert!(handshake_timestamp + max_handshake_age >= current_timestamp);

            // Verify the signature
            assert_eq!(handshake.info.recipient, recipient);
            assert_eq!(handshake.info.ephemeral_public_key, ephemeral_public_key,);

            // Verify signature
            assert!(sender.public_key().verify(
                Some(TEST_NAMESPACE),
                &handshake.info.encode(),
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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create participants
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1);
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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create participants
            let mut sender = PrivateKey::from_seed(0);
            let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

            // Create handshake message
            let handshake = Signed::sign(
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
                send_frame(&mut stream_sender, &handshake.encode(), ONE_MEGABYTE)
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
            assert!(matches!(result, Err(Error::HandshakeNotForUs)));
        });
    }

    #[test]
    fn test_incoming_handshake_invalid_data() {
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
    fn test_incoming_handshake_verify_timeout() {
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
    fn test_handshake_verify_invalid_signature() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1);
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            // The peer creates a valid handshake intended for us
            let handshake = Signed::sign(
                &mut sender,
                TEST_NAMESPACE,
                Info {
                    timestamp: 0,
                    recipient: recipient.public_key(),
                    ephemeral_public_key,
                },
            );

            // Tamper with the handshake to make the signature invalid
            let mut handshake = Signed::<edPublicKey>::decode(handshake.encode())
                .expect("failed to decode handshake");
            handshake.info.timestamp += 1;

            // Verify the handshake
            let result = handshake.verify(
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
    fn test_handshake_verify_invalid_timestamp_old() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut signer = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1).public_key();
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            let timeout_duration = Duration::from_secs(5);
            let synchrony_bound = Duration::from_secs(0);

            // The peer creates a handshake, setting the timestamp to 0.
            let handshake = Signed::sign(
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

            // Verify the handshake, it should be fine still.
            handshake
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
            let result = handshake.verify(
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
    fn test_authentication_proof_create_and_verify() {
        use chacha20poly1305::KeyInit;

        let key = [1u8; 32];
        let cipher = ChaCha20Poly1305::new(&key.into());
        let ephemeral_key = x25519::PublicKey::from_bytes([42u8; 32]);

        // Create authentication proof
        let nonce_zero = Nonce::from_slice(&[0u8; 12]);
        let proof = AuthenticationProof::create(&cipher, nonce_zero, &ephemeral_key).unwrap();

        // Verify the proof with the same parameters
        proof.verify(&cipher, nonce_zero, &ephemeral_key).unwrap();

        // Verify that proof fails with different ephemeral key
        let different_ephemeral = x25519::PublicKey::from_bytes([43u8; 32]);
        let result = proof.verify(&cipher, nonce_zero, &different_ephemeral);
        assert!(matches!(result, Err(Error::InvalidAuthenticationProof)));

        // Verify that proof fails with different cipher
        let different_key = [2u8; 32];
        let different_cipher = ChaCha20Poly1305::new(&different_key.into());
        let result = proof.verify(&different_cipher, nonce_zero, &ephemeral_key);
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn test_authentication_proof_encoding() {
        use chacha20poly1305::KeyInit;
        use commonware_codec::{DecodeExt, Encode};

        let key = [1u8; 32];
        let cipher = ChaCha20Poly1305::new(&key.into());
        let ephemeral_key = x25519::PublicKey::from_bytes([42u8; 32]);

        // Create and encode proof
        let nonce_zero = Nonce::from_slice(&[0u8; 12]);
        let original_proof =
            AuthenticationProof::create(&cipher, nonce_zero, &ephemeral_key).unwrap();
        let encoded = original_proof.encode();

        // Decode and verify it matches
        let decoded_proof = AuthenticationProof::decode(encoded).unwrap();
        decoded_proof
            .verify(&cipher, nonce_zero, &ephemeral_key)
            .unwrap();
    }

    #[test]
    fn test_listener_response_encoding() {
        use chacha20poly1305::KeyInit;
        use commonware_codec::{DecodeExt, Encode};

        // Create test components
        let mut sender = PrivateKey::from_seed(0);
        let recipient = PrivateKey::from_seed(1).public_key();
        let ephemeral_public_key = PublicKey::from_bytes([3u8; 32]);

        let handshake = Signed::sign(
            &mut sender,
            TEST_NAMESPACE,
            Info {
                timestamp: 12345,
                recipient: recipient.clone(),
                ephemeral_public_key,
            },
        );

        let key = [1u8; 32];
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce_zero = Nonce::from_slice(&[0u8; 12]);
        let auth_proof =
            AuthenticationProof::create(&cipher, nonce_zero, &ephemeral_public_key).unwrap();

        // Create and encode listener response
        let original_response = ListenerResponse::new(handshake, auth_proof);
        let encoded = original_response.encode();

        // Decode and verify components
        let decoded_response = ListenerResponse::<edPublicKey>::decode(encoded).unwrap();
        let (decoded_handshake, decoded_proof) = decoded_response.into_parts();

        assert_eq!(decoded_handshake.signer(), sender.public_key());
        let nonce_zero = Nonce::from_slice(&[0u8; 12]);
        decoded_proof
            .verify(&cipher, nonce_zero, &ephemeral_public_key)
            .unwrap();
    }

    #[test]
    fn test_dialer_confirmation_encoding() {
        use chacha20poly1305::KeyInit;
        use commonware_codec::{DecodeExt, Encode};

        let key = [1u8; 32];
        let cipher = ChaCha20Poly1305::new(&key.into());
        let ephemeral_key = x25519::PublicKey::from_bytes([42u8; 32]);

        let nonce_zero = Nonce::from_slice(&[0u8; 12]);
        let auth_proof = AuthenticationProof::create(&cipher, nonce_zero, &ephemeral_key).unwrap();

        // Create and encode dialer confirmation
        let original_confirmation = DialerConfirmation::new(auth_proof);
        let encoded = original_confirmation.encode();

        // Decode and verify
        let decoded_confirmation = DialerConfirmation::decode(encoded).unwrap();
        decoded_confirmation
            .auth_proof()
            .verify(&cipher, nonce_zero, &ephemeral_key)
            .unwrap();
    }

    #[test]
    fn test_handshake_verify_invalid_timestamp_future() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut signer = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1).public_key();
            let ephemeral_public_key = x25519::PublicKey::from_bytes([0u8; 32]);

            let timeout_duration = Duration::from_secs(0);
            const SYNCHRONY_BOUND_MILLIS: u64 = 5_000;
            let synchrony_bound = Duration::from_millis(SYNCHRONY_BOUND_MILLIS);

            // The peer creates a handshake at the synchrony bound.
            let handshake_ok = Signed::sign(
                &mut signer,
                TEST_NAMESPACE,
                Info{
                    timestamp: SYNCHRONY_BOUND_MILLIS,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Create a handshake 1ms too far into the future.
            let handshake_late = Signed::sign(
                &mut signer,
                TEST_NAMESPACE,
                Info{
                    timestamp:SYNCHRONY_BOUND_MILLIS + 1,
                    recipient: recipient.clone(),
                    ephemeral_public_key,
                },
            );

            // Verify the okay handshake.
            handshake_ok.verify(
                &context,
                &recipient,
                TEST_NAMESPACE,
                synchrony_bound,
                timeout_duration,
            ).unwrap(); // no error

            // Handshake too far into the future fails.
            let result = handshake_late.verify(
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
