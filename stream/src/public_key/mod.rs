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
//! and the recipient of this connection is the dialee. Upon forming a TCP connection, the dialer sends a signed
//! handshake message to the dialee.
//!
//! ```protobuf
//! message Handshake {
//!     bytes recipient_public_key = 1;
//!     bytes ephemeral_public_key = 2;
//!     uint64 timestamp = 3;
//!     Signature signature = 4;
//! }
//! ```
//!
//! The dialee verifies the public keys are well-formatted, the timestamp is valid (not too old/not too far in the future),
//! and that the signature is valid. If all these checks pass, the dialee checks to see if it is already connected or dialing
//! this peer. If it is, it drops the connection. If it isn't, it sends back its own signed handshake message (same as above)
//! and considers the connection established.
//!
//! Upon receiving the dialee's handshake message, the dialer verifies the same data as the dialee and additionally verifies
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
//! Diffie-Hellman Key Exchange. This x25519 secret is then used to create a ChaCha20-Poly1305
//! cipher for encrypting all messages exchanged with the peer.
//!
//! Each peer maintains a pair of ChaCha20-Poly1305 nonces (12 bytes), one for itself and one for
//! the other. Each nonce is constructed using a counter that starts at either 1 for the dialer, or
//! 0 for the dialee. For each message sent, the relevant counter is incremented by 2, ensuring that
//! the two counters have disjoint nonce spaces. The nonce is the least-significant 12 bytes of the
//! counter, encoded big-endian.
//!
//! This provides 2^95 unique nonces per sender, sufficient for over 1 trillion years at 1 billion
//! messages/second—far exceeding practical limits. Maintaining long-lived connections to reliable
//! peers enhances network stability by removing the overhead of connection churn. In an unlikely
//! case of overflow, the connection would terminate, and a new handshake would be required.
//!
//! This construction saves bandwidth, as the nonce does not need to be sent as part of the message.
//! It also prevents nonce-reuse, which would otherwise allow for messages to be decrypted.

use commonware_cryptography::Scheme;
use std::time::Duration;

mod connection;
pub use connection::{Connection, IncomingConnection, Receiver, Sender};
mod handshake;
mod nonce;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}
mod x25519;

/// Configuration for a connection.
///
/// # Warning
///
/// It is recommended to synchronize this configuration with any relevant peer.
/// If this is not synchronized, connections could be unnecessarily dropped,
/// or messages could be parsed incorrectly.
#[derive(Clone)]
pub struct Config<C: Scheme> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Prefix for all signed messages to avoid replay attacks.
    pub namespace: Vec<u8>,

    /// Maximum size allowed for messages over any connection.
    pub max_message_size: usize,

    /// Time into the future that a timestamp can be and still be considered valid.
    pub synchrony_bound: Duration,

    /// Duration after which a handshake message is considered stale.
    pub max_handshake_age: Duration,

    /// Timeout for the handshake process.
    pub handshake_timeout: Duration,
}
