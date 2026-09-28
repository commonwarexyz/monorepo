//! Counter Unidirectional Packet Stream (CUPS).
//!
//! CUPS protects ordered message records using a separate key and implicit counter for each
//! direction. "Packet" refers to a framed message on an ordered byte stream, not a datagram.
//!
//! # Handshake
//!
//! [Handshake] implements [crate::Handshake] using
//! [Simple Authenticated Key Exchange (SAKE)](commonware_cryptography::handshake::sake) and returns CUPS
//! [Sender] and [Receiver] halves. SAKE uses a fixed three-message exchange with ephemeral X25519
//! keys, identity signatures, and BLAKE3 transcript derivation to establish directional ciphers.
//!
//! The core SAKE protocol receives both peer identities as inputs. This adapter first sends the
//! dialer's public key in a framed, cleartext prelude, separate from SAKE's three messages. The
//! listener's bouncer may reject that claim before authentication. Accepting it only permits the
//! handshake to continue. A successful handshake authenticates the returned identity.
//!
//! Version 1 forks the SAKE transcript with `_COMMONWARE_STREAM_CUPS` after the application
//! namespace and before SAKE's own protocol namespace ([sake::Context::fork](commonware_cryptography::handshake::sake::Context::fork)), so its handshakes
//! differ from SAKE handshakes that another protocol runs with the same application namespace.
//! Version 0 does not fork it.
//!
//! Peers must agree on a unique, application-specific namespace, a [Version], and have clocks
//! within the configured timestamp acceptance windows. The version is not negotiated: a mismatch
//! fails the handshake. Callers must enforce a handshake deadline, for example with
//! [crate::utils::Timeout]. Identities are exposed during the handshake, and there is no 0-RTT
//! resumption.
//!
//! # Records
//!
//! Each message becomes one record, and batching writes preserves record boundaries. Records are
//! sealed with the [Cipher](commonware_cryptography::Cipher) that the [Handshake] is instantiated
//! with. Both peers must use the same cipher.
//!
//! - Version 0: a visible u32 varint holding the length of the encrypted payload and its tag,
//!   then the encrypted payload and its tag.
//! - Version 1: a header holding the payload length as an encrypted 4-byte big-endian integer
//!   and its tag (20 bytes with [ChaCha20Poly1305](commonware_cryptography::ChaCha20Poly1305)),
//!   then the encrypted payload and its tag.
//!
//! Each direction uses a fixed session key. A record consumes one position of its cipher in
//! version 0 and two in version 1, first for the header and then for the payload. Positions are
//! never transmitted, so replayed, reordered, or corrupted records fail authentication rather than
//! being reordered for delivery. A cipher that can seal no more messages requires a new
//! connection. After a record fails to seal or open, that half refuses every later record.
//!
//! # Security
//!
//! SAKE provides mutual authentication and ephemeral session keys. CUPS protects record contents
//! and integrity. Version 0 exposes record lengths and boundaries in the byte stream. Version 1
//! removes them from the byte stream, but message sizes and timing remain observable through
//! transport segments. There is no padding, in-session key ratchet, or rekeying. Callers must
//! discard the connection after an I/O error or cancellation, as required by [crate::Sender] and
//! [crate::Receiver].

mod config;
pub use config::Config;

mod protocol;
pub use protocol::{Error, Handshake, Receiver, Sender, Version};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
