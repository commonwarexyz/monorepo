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
//! A 3-message handshake is performed to mutually authenticate and establish a shared secret.
//! This handshake is used instead of TLS, Noise, WireGuard, etc. because:
//! - It supports arbitrary cryptographic schemes
//! - No protocol negotiation (only one way to connect)
//! - Simple implementation (few hundred lines of code)
//! - Can be simulated deterministically
//!
//! The **dialer** initiates connection to a known address/identity (public key)
//! and the **listener** receives this connection. The protocol works as follows:
//!
//! ### Message 1: Dialer → Listener (Initial Handshake)
//! Upon establishing a TCP connection, the dialer sends a signed handshake message to the listener.
//! This message contains the dialer's signature and static public key, plus:
//!
//! - The listener's expected public key
//! - The dialer's ephemeral public key (for establishing a shared secret)
//! - The current timestamp (for replay attack prevention)
//!
//! ### Message 2: Listener → Dialer (Response with Key Confirmation)
//! The listener verifies:
//! - Public keys are well-formatted
//! - Timestamp is valid (not too old, not too far in the future)
//! - Signature is valid
//! - It is not already connected to or dialing this peer
//!
//! If all checks pass, the listener:
//!
//! 1. Creates its own signed handshake message
//! 2. Computes the X25519 Diffie-Hellman shared secret
//! 3. Creates a key confirmation by encrypting the handshake transcript
//! 4. Sends back a `ListenerResponse` containing both the signed handshake and key confirmation
//!
//! ### Message 3: Dialer → Listener (Final Confirmation)
//! The dialer:
//!
//! 1. Verifies the listener's signed handshake message
//! 2. Verifies the returned static public key matches expectations
//! 3. Computes the shared secret and verifies the listener's key confirmation
//! 4. Creates its own key confirmation
//! 5. Sends the key confirmation to complete mutual authentication
//!
//! ### Security Properties
//! This protocol provides:
//!
//! - **Mutual Authentication**: Both parties prove knowledge of their static private keys through
//!   signatures
//! - **Key Confirmation**: Both parties prove they can derive the correct shared secret
//! - **Transcript Binding**: Key confirmations are bound to the complete handshake exchange
//! - **Replay Protection**: Timestamps prevent reuse of old handshake messages within the configured timestamp window
//! - **Forward Secrecy**: Ephemeral keys ensure compromise of long-term static keys doesn't affect past
//!   or future sessions
//!
//! A configurable deadline is enforced for handshake completion to protect against DOS attacks by
//! malicious peers that create connections but abandon handshakes.
//!
//! ## Encryption
//!
//! During the handshake, a shared X25519 secret is established using
//! Diffie-Hellman key exchange. This secret is combined with the handshake
//! transcript to derive separate ChaCha20-Poly1305 ciphers:
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
//! 1 billion messages per second—sufficient for all practical use cases. This
//! approach ensures that well-behaving peers can remain connected
//! indefinitely as long as they both stay online (maximizing p2p network stability). In the unlikely case of
//! counter overflow, a new connection should be established.
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
