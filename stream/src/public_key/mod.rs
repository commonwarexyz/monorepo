//! Communicate with an authenticated peer over an encrypted connection.
//!
//! Provides encrypted communication with peers identified by developer-specified
//! cryptographic identities (e.g., BLS, ed25519, etc.).
//! Implements its own encrypted transport layer (no TLS, no X.509 certificates,
//! no protocol negotiation) that exclusively uses these cryptographic identities
//! to authenticate incoming connections. Uses ChaCha20-Poly1305 for message encryption.
//!
//! # Design
//!
//! ## Handshake
//!
//! A 3-message handshake provides mutual authentication and establishes a shared secret
//! between peers. Custom implementation supports arbitrary cryptographic schemes without
//! protocol negotiation overhead.
//!
//! The **dialer** initiates the connection to a known peer identity, while the **listener**
//! accepts incoming connections. Much like a SYN / SYN-ACK / ACK handshake, the dialer and listener
//! exchange messages in three rounds.
//!
//! The SYN-equivalent is a handshake message that contains:
//! - The recipient's expected public key (prevents wrong-target attacks)
//! - The sender's ephemeral public key (for Diffie-Hellman key exchange)
//! - The current timestamp (prevents replay attacks)
//! - The sender's static public key and signature
//!
//! The ACK-equivalent is a key confirmation message that proves that each party can derive the
//! correct shared secret.
//!
//! Thus:
//! - Message 1 is a handshake message from the dialer to the listener
//! - Message 2 is a handshake and key confirmation message from the listener to the dialer
//! - Message 3 is a key confirmation message from the dialer to the listener
//!
//! ### Security Properties
//!
//! This protocol provides:
//!
//! - **Mutual Authentication**: Both parties prove existence of their static private keys through
//!   signatures.
//! - **Replay Protection**: Key confirmations are bound to the complete handshake exchange to
//!   prevent replay attacks by confirming that the peer that sent the handshake message (with the
//!   cryptographic signature) also had possession of the ephemeral key.
//! - **Forward Secrecy**: Ephemeral keys ensure that any compromise of long-term static keys
//!   doesn't affect other sessions.
//! - **DoS Protection**: A configurable deadline is enforced for handshake completion to protect
//!   against DoS attacks by malicious peers that create connections but abandon handshakes.
//!
//! ## Encryption
//!
//! During the handshake, a shared X25519 secret is established using
//! Diffie-Hellman key exchange. This secret is combined with the handshake
//! transcript to derive four separate ChaCha20-Poly1305 ciphers:
//!
//! - **Confirmation Ciphers**: One cipher per direction for key confirmation during the handshake
//! - **Traffic Ciphers**: One cipher per direction for encrypting post-handshake traffic
//!
//! Using the handshake transcript in key derivation ensures that derived keys
//! are bound to the specific handshake exchange, providing additional security against
//! man-in-the-middle and transcript substitution attacks.
//!
//! Each direction of communication uses a 12-byte nonce derived from a counter that is
//! incremented for each message sent. This provides a maximum of 2^96 messages per sender,
//! which would be sufficient for over 2.5 trillion years of continuous communication at a rate of
//! 1 billion messages per second—sufficient for all practical use cases. This approach ensures that
//! well-behaving peers can remain connected indefinitely as long as they both stay online
//! (maximizing p2p network stability). In the unlikely case of counter overflow, the connection
//! will be terminated and a new connection should be established.
//!
//! This prevents nonce reuse (which would compromise message confidentiality)
//! and saves bandwidth (as there is no need to transmit nonces alongside encrypted messages).

use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, AeadCore},
    ChaCha20Poly1305,
};
use std::time::Duration;

mod cipher;
mod connection;
use commonware_cryptography::Signer;
pub use connection::{Connection, IncomingConnection, Receiver, Sender};
pub mod handshake;
mod nonce;
pub mod x25519;

// When encrypting data, an authentication tag is appended to the ciphertext.
// This constant represents the size of the authentication tag in bytes.
const AUTHENTICATION_TAG_LENGTH: usize = <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// Configuration for a connection.
///
/// # Warning
///
/// Synchronize this configuration across all peers.
/// Mismatched configurations may cause dropped connections or parsing errors.
#[derive(Clone)]
pub struct Config<C: Signer> {
    /// Cryptographic primitives for signing and verification.
    pub crypto: C,

    /// Unique prefix for all signed messages. Should be application-specific.
    /// Prevents replay attacks across different applications using the same keys.
    pub namespace: Vec<u8>,

    /// Maximum message size (in bytes). Prevents memory exhaustion DoS attacks.
    pub max_message_size: usize,

    /// Maximum time drift allowed for future timestamps. Handles clock skew.
    pub synchrony_bound: Duration,

    /// Maximum age of handshake messages before rejection.
    pub max_handshake_age: Duration,

    /// Maximum time allowed for completing the handshake.
    pub handshake_timeout: Duration,
}
