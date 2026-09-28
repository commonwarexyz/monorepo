use super::Version;
use std::time::Duration;

/// Configuration for a [Handshake](super::Handshake).
///
/// # Examples
///
/// ```
/// use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
/// use commonware_stream::cups::{Config, Handshake, Version};
///
/// let handshake = Handshake::new(Config::new(PrivateKey::from_seed(0), Version::V1));
/// ```
#[derive(Clone)]
pub struct Config<S> {
    /// Signer used to authenticate the local peer.
    pub signer: S,

    /// Protocol version, selecting the SAKE version, the transcript scope, the record cipher, and
    /// the record format.
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
