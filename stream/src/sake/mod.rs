//! Run [Simple Authenticated Key Exchange (SAKE)](commonware_cryptography::handshake::sake) over
//! a connection.
//!
//! [Sake] implements [crate::Handshake], deriving one
//! [Cipher](commonware_cryptography::Cipher) per direction. Use it with
//! [Cups](crate::cups::Cups) as an [crate::Upgrader] to establish streams.
//!
//! The core SAKE protocol receives both peer identities as inputs. [Sake] first sends the
//! dialer's public key in a framed, cleartext prelude, separate from SAKE's three messages. The
//! listener's bouncer may reject that claim before authentication. Accepting it only permits the
//! handshake to continue. A successful handshake authenticates the returned identity.
//!
//! The SAKE [Version] and the transport version are configured separately. [Version::V1] forks
//! the transcript with the record [namespace](crate::cups::Cups::namespace)
//! ([Context::fork](commonware_cryptography::handshake::sake::Context::fork)). Peers with
//! different transports then fail the handshake, and the transcript differs from that of a SAKE
//! handshake another protocol runs with the same application namespace. [Version::V0] binds no
//! transport namespace, so peers with different transports complete the handshake and then fail
//! to open the first record.
//!
//! Peers must agree on a unique, application-specific namespace, a [Version], and the transport,
//! and their clocks must be within the configured timestamp acceptance windows. The version is not
//! negotiated, so a mismatch fails the handshake. Keep the older version until every peer has
//! upgraded. Callers must enforce a handshake deadline, for example with [crate::utils::Timeout].
//! Identities are exposed during the handshake, and there is no 0-RTT resumption.
//!
//! # Security
//!
//! SAKE provides mutual authentication and ephemeral session keys. The transport protects the
//! messages. The transcript does not commit the cipher of the transport, so peers with different
//! ciphers complete the handshake and then fail to open the first record.

mod protocol;
pub use commonware_cryptography::handshake::sake::Version;
pub use protocol::{Error, Sake};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
