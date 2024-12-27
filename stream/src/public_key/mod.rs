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
//! During the handshake (described above), a shared x25519 secret is established using a Diffie-Hellman Key Exchange. This
//! x25519 secret is then used to create a ChaCha20-Poly1305 cipher for encrypting all messages exchanged with the peer.
//!
//! ChaCha20-Poly1305 nonces (12 bytes) are constructed such that the first bit indicates whether the sender is a dialer (1) or
//! dialee (0). The rest of the first byte (next 7 bits) and next byte (all 8 bits) are unused (set to 0). The next 2 bytes
//! are a `u16` iterator and the final 8 bytes are a `u64` sequence number. When the sequence reaches `u64::MAX`, the iterator
//! is incremented and the sequence is reset to 0. This technique provides each sender with a channel duration of `2^80` frames
//! (and automatically terminates when this number of frames has been sent). In the blockchain context, validators often maintain
//! long-lived connections with each other and avoiding connection re-establishment (to reset iterator/sequence with a new cipher)
//! is desirable.
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | D | U |It(u16)|         Sequence(u64)         |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//!
//! D = Dialer/Dialee, U = Unused, It = Iterator
//! ```
//!
//! _We use a combination of `u64` (sequence) and `u16` (iterator) instead of implementing `u80/u88` because
//! CPUs provide native support for `u64` operations (which will always be faster than an implementation of a
//! "wrapping add" over arbitrary bytes). With this technique, almost all operations (other than iterator
//! increments every `2^64` frames) are just a basic `u64` increment._
//!
//! This simple coordination prevents nonce reuse (which would allow for messages to be decrypted) and saves a small amount of
//! bandwidth (no need to send the nonce alongside the encrypted message). This "pedantic" construction of the nonce
//! also avoids accidentally reusing a nonce over long-lived connections when setting it to be a small hash (as in XChaCha-Poly1305).
//!
//! # Benchmarks
//!
//! _The following benchmarks were collected on 12/17/24 on a MacBook Air (15-inch M3 2024)._
//!
//! ## Connection (Send/Receive)
//!
//! The number indicates the size of the message in bytes.
//!
//! ```txt
//! sender/1024             time:   [3.3344 µs 3.3436 µs 3.3576 µs]
//! sender/4096             time:   [12.333 µs 12.364 µs 12.412 µs]
//! sender/16384            time:   [48.218 µs 48.405 µs 48.647 µs]
//! sender/262144           time:   [774.05 µs 783.77 µs 799.62 µs]
//! sender/1048576          time:   [3.2141 ms 3.2447 ms 3.2812 ms]
//! sender/4194304          time:   [12.729 ms 12.770 ms 12.813 ms]
//! sender/16777216         time:   [50.453 ms 54.099 ms 60.754 ms]
//! sender/67108864         time:   [205.32 ms 206.76 ms 208.58 ms]
//! receiver/1024           time:   [4.0555 µs 4.0902 µs 4.1304 µs]
//! receiver/4096           time:   [15.131 µs 15.360 µs 15.652 µs]
//! receiver/16384          time:   [58.597 µs 62.849 µs 71.720 µs]
//! receiver/262144         time:   [971.47 µs 972.63 µs 973.71 µs]
//! receiver/1048576        time:   [3.8288 ms 3.8748 ms 3.9336 ms]
//! receiver/4194304        time:   [15.516 ms 15.750 ms 16.170 ms]
//! receiver/16777216       time:   [61.675 ms 61.708 ms 61.740 ms]
//! receiver/67108864       time:   [251.29 ms 255.99 ms 264.45 ms]
//! ```

use commonware_cryptography::Scheme;
use std::time::Duration;

mod connection;
pub use connection::{Connection, IncomingConnection, Receiver, Sender};
mod handshake;
mod utils;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}
mod x25519;

/// Configuration for a connection.
///
/// # Warning
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
