use commonware_cryptography::PublicKey;
use std::net::SocketAddr;

/// Metadata for a peer connection.
#[derive(Clone, Debug)]
pub enum Metadata<P: PublicKey> {
    /// We are the Dialer.
    ///
    /// Contains:
    /// - The public key of the peer.
    /// - The socket address of the peer.
    Dialer(P, SocketAddr),

    /// We are the Listener.
    ///
    /// Contains:
    /// - The public key of the peer.
    Listener(P),
}

impl<P: PublicKey> Metadata<P> {
    /// Get the public key of the peer associated with this metadata.
    pub const fn public_key(&self) -> &P {
        match self {
            Self::Dialer(public_key, _) => public_key,
            Self::Listener(public_key) => public_key,
        }
    }
}
