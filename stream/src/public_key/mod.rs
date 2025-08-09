//! Communicate with an authenticated peer over an encrypted connection.
//!
//! This module provides a lightweight, self-contained transport layer for systems where peers
//! already know one another's cryptographic identities (any [commonware_cryptography::Signer]).
//! It offers mutual authentication and encrypted communication using a simplified handshake,
//! eliminating the need for complex protocols like TLS or X.509 certificates. The implementation
//! uses a fixed, non-negotiable cryptographic protocol to simplify implementation and reduce
//! overhead, resulting in a minimal performance impact.
//!
//! # Design
//!
//! ## Handshake
//!
//! A three-message handshake is used to authenticate peers and establish a shared secret. The
//! **dialer** initiates the connection, and the **listener** responds.
//!
//! The **dialer** initiates the connection to a known peer identity, while the **listener** accepts
//! incoming connections. Much like a SYN / SYN-ACK / ACK handshake, the dialer and listener
//! exchange messages in three rounds.
//!
//! The SYN-equivalent is a [handshake::Hello] message that contains:
//! - The listener's expected public key (prevents wrong-target attacks)
//! - The dialer's ephemeral public key (for Diffie-Hellman key exchange)
//! - The current timestamp (prevents replay attacks)
//! - The dialer's static public key and signature
//!
//! The ACK-equivalent is a [handshake::Confirmation] message that proves that each party can derive
//! the correct shared secret.
//!
//! Thus:
//! - Message 1 is a `Hello` message from the dialer to the listener
//! - Message 2 is a `Hello` and `Confirmation` message from the listener to the dialer
//! - Message 3 is a `Confirmation` message from the dialer to the listener
//!
//! ## Encryption
//!
//! All traffic is encrypted using ChaCha20-Poly1305. A shared secret is established using an
//! ephemeral X25519 Diffie-Hellman key exchange. This secret, combined with the handshake
//! transcript, is used to derive keys for both the handshake's key confirmation messages and
//! the post-handshake data traffic. Binding the derived keys to the handshake transcript prevents
//! man-in-the-middle and transcript substitution attacks.
//!
//! Each directional cipher uses a 12-byte nonce derived from a counter that is incremented for each
//! message sent. This counter has sufficient cardinality for over 2.5 trillion years of continuous
//! communication at a rate of 1 billion messages per second—sufficient for all practical use cases.
//! This ensures that well-behaving peers can remain connected indefinitely as long as they both
//! remain online (maximizing p2p network stability). In the unlikely case of counter overflow, the
//! connection will be terminated and a new connection should be established. This method prevents
//! nonce reuse (which would compromise message confidentiality) while saving bandwidth (as there is
//! no need to transmit nonces explicitly).
//!
//! # Security
//!
//! ## Requirements
//!
//! - **Pre-Shared Namespace**: Peers must agree on a unique, application-specific namespace
//!   out-of-band to prevent cross-application replay attacks.
//! - **Time Synchronization**: Peer clocks must be synchronized to within the `synchrony_bound`
//!   to correctly validate timestamps.
//!
//! ## Provided
//!
//! - **Mutual Authentication**: Both parties prove ownership of their static private keys through
//!   signatures.
//! - **Forward Secrecy**: Ephemeral encryption keys ensure that any compromise of long-term static keys
//!   doesn't expose the contents of previous sessions.
//! - **Session Uniqueness**: Confirmations are bound to the complete handshake transcript (including
//!   the randomly generated session key), preventing replay attacks and ensuring message integrity.
//! - **Handshake Timeout**: A configurable deadline is enforced for handshake completion to protect
//!   against malicious peers that create connections but abandon handshakes.
//!
//! ## Not Provided
//!
//! - **Anonymity**: Peer identities are not hidden during handshakes from network observers (both active
//!   and passive).
//! - **Padding**: Messages are encrypted as-is, allowing an attacker to perform traffic analysis.
//! - **Future Secrecy**: If a peer's static private key is compromised, future sessions will be exposed.
//! - **0-RTT**: The protocol does not support 0-RTT handshakes (resumed sessions).

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
