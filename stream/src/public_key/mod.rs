//! Communicate with an authenticated peer over an encrypted connection.
//!
//! Encrypted communication with a peer, identified by a developer-specified
//! cryptographic identity (i.e. BLS, ed25519, etc.).
//! Implements its own encrypted transport layer (No TLS, No X.509 Certificates,
//! No Protocol Negotiation) that exclusively uses said cryptographic identities
//! to authenticate incoming connections (dropping any that aren't explicitly
//! authorized). Uses ChaCha20-Poly1305 for encryption of messages.
//!
//! # Design
//!
//! ## Handshake
//!
//! When establishing a connection with a peer, a simple handshake is performed
//! to authenticate each other and to establish a shared secret for connection
//! encryption (explained below). This simple handshake is done in lieu of using
//! TLS, Noise, WireGuard, etc. because it supports the usage of arbitrary
//! cryptographic schemes, there is no protocol negotiation (only one way to
//! connect), because it only takes a few hundred lines of code to implement
//! (not having any features is a feature in safety-critical code), and because
//! it can be simulated deterministically.
//!
//! In any handshake, the dialer is the party that attempts to connect to some known address/identity (public key)
//! and the recipient of this connection is the listener. Upon forming a TCP connection, the dialer sends a signed
//! handshake message to the listener. Besides the signature and the public key of the dialer, the handshake message
//! contains:
//!
//! - The receiver's public key.
//! - The sender's ephemeral public key (used to establish a shared secret).
//! - The current timestamp (used to prevent replay attacks).
//!
//! The listener verifies the public keys are well-formatted, the timestamp is valid (not too old/not too far in the future),
//! and that the signature is valid. If all these checks pass, the listener checks to see if it is already connected or dialing
//! this peer. If it is, it drops the connection. If it isn't, it sends back its own signed handshake message (same as above)
//! and considers the connection established.
//!
//! Upon receiving the listener's handshake message, the dialer verifies the same data as the listener and additionally verifies
//! that the public key returned matches what they expected at the address. If all these checks pass, the dialer considers the
//! connection established. If not, the dialer drops the connection.
//!
//! To better protect against malicious peers that create and/or accept connections but do not participate in handshakes,
//! a configurable deadline is enforced for any handshake to be completed. This allows for the underlying runtime to maintain
//! a standard read/write timeout for connections without making it easier for malicious peers to keep useless connections open.
//!
//! ## Encryption
//!
//! During the handshake (described above), a shared x25519 secret is established using a
//! Diffie-Hellman Key Exchange. This x25519 secret is then used in-conjunction with the handshake
//! data in a key-derivation-function to create a pair of ChaCha20-Poly1305 ciphers. One cipher per
//! direction allows for encryption of all messages.
//!
//! Each direction of communication also uses a 12-byte nonce derived from a counter that is
//! incremented for each message sent. This provides for a maximum of 2^96 messages per sender,
//! which would be sufficient for over 2.5 trillion years of continuous communication at a rate of
//! 1 billion messages per second. In other words, sufficient for all practical use cases. This
//! approach ensures well-behaving peers, as long as they both stay online, remain connected
//! indefinitely (maximizing the stability of any p2p construction). In an unlikely case of
//! overflow, a new connection should be established.
//!
//! This simple coordination prevents nonce reuse (which would allow for messages to be decrypted)
//! and saves a small amount of bandwidth (no need to send the nonce alongside the encrypted
//! message). This also avoids accidental reuse of a nonce over long-lived connections (for example
//! when setting it to be a small hash as in XChaCha20-Poly1305).

use std::time::Duration;

mod cipher;
mod connection;
use commonware_cryptography::Signer;
pub use connection::{Connection, IncomingConnection, Receiver, Sender};
mod handshake;
mod nonce;
mod x25519;

/// Configuration for a connection.
///
/// # Warning
///
/// It is recommended to synchronize this configuration with any relevant peer.
/// If this is not synchronized, connections could be unnecessarily dropped,
/// or messages could be parsed incorrectly.
#[derive(Clone)]
pub struct Config<C: Signer> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Prefix for all signed messages. Should be unique to the application.
    /// Used to avoid replay attacks across different applications
    pub namespace: Vec<u8>,

    /// Maximum size allowed for messages (in bytes).
    /// Used to prevent DoS attacks.
    pub max_message_size: usize,

    /// Time into the future that a timestamp can be and still be considered valid.
    /// Used to handle clock skew between peers.
    pub synchrony_bound: Duration,

    /// Maximum age of a handshake message before it is considered stale.
    pub max_handshake_age: Duration,

    /// Timeout for completing the handshake process.
    pub handshake_timeout: Duration,
}
