use commonware_cryptography::PublicKey;
use commonware_macros::ready;

/// Metadata for a peer connection.
#[ready(2)]
#[derive(Clone, Debug)]
pub enum Metadata<P: PublicKey> {
    /// We are the Dialer.
    Dialer(P),

    /// We are the Listener.
    Listener(P),
}

impl<P: PublicKey> Metadata<P> {
    /// Get the public key of the peer associated with this metadata.
    pub const fn public_key(&self) -> &P {
        match self {
            Self::Dialer(public_key) => public_key,
            Self::Listener(public_key) => public_key,
        }
    }
}
