//! Exchange messages over arbitrary transport.
//!
//! # Design
//!
//! ## Handshake
//!
//! c.f. [commonware_cryptography::handshake]. One difference here is that the listener does not
//! know the dialer's public key in advance. Instead, the dialer tells the listener its public key
//! in the first message. The listener has an opportunity to reject the connection if it does not
//! wish to connect ([encrypted::listen] takes in an arbitrary function to implement this).
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
//! communication at a rate of 1 billion messages per second - sufficient for all practical use cases.
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
//! - **Session Uniqueness**: A listener's [commonware_cryptography::handshake::SynAck] is bound to the dialer's [commonware_cryptography::handshake::Syn] message and
//!   [commonware_cryptography::handshake::Ack]s are bound to the complete handshake transcript, preventing replay attacks and ensuring
//!   message integrity.
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

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_utils::ready_mod;

ready_mod!(2, pub mod encrypted);
ready_mod!(2, pub mod utils);
