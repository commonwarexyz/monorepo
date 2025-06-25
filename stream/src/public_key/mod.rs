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
//! When establishing a connection with a peer, a 3-message handshake is performed
//! to authenticate each other and to establish a shared secret for connection
//! encryption (explained below). This handshake is done in lieu of using
//! TLS, Noise, WireGuard, etc. because it supports the usage of arbitrary
//! cryptographic schemes, there is no protocol negotiation (only one way to
//! connect), because it only takes a few hundred lines of code to implement
//! (not having any features is a feature in safety-critical code), and because
//! it can be simulated deterministically.
//!
//! In any handshake, the dialer is the party that attempts to connect to some known address/identity (public key)
//! and the recipient of this connection is the listener. The 3-message handshake protocol works as follows:
//!
//! ### Message 1: Dialer → Listener (Initial Handshake)
//! Upon forming a TCP connection, the dialer sends a signed handshake message to the listener.
//! Besides the signature and the static public key of the dialer, the handshake message contains:
//!
//! - The receiver's public key.
//! - The sender's ephemeral public key (used to establish a shared secret).
//! - The current timestamp (used to prevent replay attacks).
//!
//! ### Message 2: Listener → Dialer (Response with Key Confirmation)
//! The listener verifies the public keys are well-formatted, the timestamp is valid (not too old/not too far in the future),
//! and that the signature is valid. If all these checks pass, the listener checks to see if it is already connected or dialing
//! this peer. If it is, it drops the connection. If it isn't, the listener:
//!
//! 1. Creates its own signed handshake message (same format as above)
//! 2. Computes the X25519 Diffie-Hellman shared secret using our newly generated ephemeral private
//!    key and the peer's ephemeral public key.
//! 3. Creates a key confirmation by encrypting the complete handshake transcript using the
//!    confirmation key derived from the shared secret.
//! 4. Sends back a `ListenerResponse` containing both the signed handshake and key confirmation
//!
//! This key confirmation serves as cryptographic proof that the listener can correctly derive the shared secret,
//! ensuring that only parties with the correct key material can proceed.
//!
//! ### Message 3: Dialer → Listener (Final Confirmation)
//! Upon receiving the listener's response, the dialer:
//!
//! 1. Verifies the listener's signed handshake message (same checks as the listener performed)
//! 2. Additionally verifies that the static public key returned matches what they expected at the address
//! 3. Computes the X25519 Diffie-Hellman shared secret using its ephemeral private key and the
//!    listener’s ephemeral public key. Derives the key confirmation keys and verifies the
//!    listener's key confirmation message.
//! 4. Creates its own key confirmation using the same handshake transcript
//! 5. Sends the key confirmation to the listener to complete mutual authentication
//!
//! The listener then verifies the dialer's key confirmation. If all checks pass, both parties
//! consider the connection established with mutual authentication.
//!
//! ### Security Properties
//! This 3-message protocol provides several important security properties:
//!
//! - **Mutual Authentication**: Both parties prove knowledge of their static private keys through
//!   signatures
//! - **Key Confirmation**: Both parties prove they can derive the correct shared secret
//! - **Transcript Binding**: Key confirmations are bound to the complete handshake exchange
//! - **Replay Protection**: Timestamps prevent reuse of old handshake messages
//! - **Forward Secrecy**: Ephemeral keys ensure compromise of long-term keys doesn't affect past
//!   sessions
//!
//! To better protect against malicious peers that create and/or accept connections but do not participate in handshakes,
//! a configurable deadline is enforced for any handshake to be completed. This allows for the underlying runtime to maintain
//! a standard read/write timeout for connections without making it easier for malicious peers to keep useless connections open.
//!
//! ## Encryption
//!
//! During the handshake (described above), a shared x25519 secret is established using a
//! Diffie-Hellman Key Exchange. This x25519 secret is then used in-conjunction with the handshake
//! transcript in a key-derivation-function to create multiple ChaCha20-Poly1305 ciphers:
//!
//! - **Confirmation Ciphers**: One cipher per direction for key-confirmation during the handshake
//! - **Traffic Ciphers**: One cipher per direction for encrypting normal traffic
//!
//! The use of the complete handshake transcript in the key derivation ensures that the derived keys
//! are bound to the specific handshake exchange, providing additional security against various attacks.
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
