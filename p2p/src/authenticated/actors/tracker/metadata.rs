use commonware_utils::Array;
use std::net::SocketAddr;

/// Metadata for a peer connection.
#[derive(Clone, Debug)]
pub enum Metadata<P: Array> {
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

impl<P: Array> Metadata<P> {
    /// Get the public key of the peer associated with this metadata.
    pub fn public_key(&self) -> &P {
        match self {
            Metadata::Dialer(public_key, _) => public_key,
            Metadata::Listener(public_key) => public_key,
        }
    }
}
