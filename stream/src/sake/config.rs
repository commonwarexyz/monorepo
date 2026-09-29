use commonware_cryptography::handshake::sake::Version;
use std::time::Duration;

/// Configuration for an [Exchange](super::Exchange).
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{ChaCha20Poly1305, Signer as _, ed25519::PrivateKey};
/// use commonware_stream::{Upgrade, cups::{self, Cups}, sake::{Config, Exchange, Version}};
///
/// let handshake = Upgrade::new(
///     Exchange::new(Config::new(PrivateKey::from_seed(0), Version::V1)),
///     Cups::<ChaCha20Poly1305>::new(cups::Version::V1),
/// );
/// ```
#[derive(Clone)]
pub struct Config<S> {
    /// Signer used to authenticate the local peer.
    pub signer: S,

    /// SAKE version.
    pub version: Version,

    /// Maximum time drift allowed for future timestamps.
    pub synchrony_bound: Duration,

    /// Maximum age of handshake messages before rejection.
    pub max_handshake_age: Duration,
}

impl<S> Config<S> {
    /// Creates a configuration that accepts timestamps up to five seconds ahead or ten seconds old.
    pub const fn new(signer: S, version: Version) -> Self {
        Self {
            signer,
            version,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
        }
    }
}
