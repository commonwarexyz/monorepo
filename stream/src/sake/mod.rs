//! Run [Simple Authenticated Key Exchange (SAKE)](commonware_cryptography::handshake::sake) over
//! a connection.
//!
//! [Exchange] implements [crate::Exchange], deriving one
//! [Cipher](commonware_cryptography::Cipher) per direction. Pair it with a [crate::Transport] (for
//! example [Cups](crate::cups::Cups)) as an [crate::Upgrader] to establish streams.
//!
//! The core SAKE protocol receives both peer identities as inputs. [Exchange] first sends the
//! dialer's public key in a framed, cleartext prelude, separate from SAKE's three messages. The
//! listener's bouncer may reject that claim before authentication. Accepting it only permits the
//! handshake to continue. A successful handshake authenticates the returned identity.
//!
//! The SAKE [Version] and the version of the transport are configured separately.
//! [Version::V1] forks the transcript with the [namespace](crate::Transport::namespace) of the
//! records ([Context::fork](commonware_cryptography::handshake::sake::Context::fork)), so peers
//! with different transports fail the handshake, and these handshakes differ from SAKE
//! handshakes that another protocol runs with the same application namespace. [Version::V0] binds
//! no transport namespace, so peers with different transports complete the handshake and then
//! fail to open the first record.
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

mod config;
pub use config::Config;

mod protocol;
pub use commonware_cryptography::handshake::sake::Version;
pub use protocol::{Error, Exchange};

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
