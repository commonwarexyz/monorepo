use super::Metadata;
use crate::authenticated::discovery::actors::tracker::ingress::ReleaserHandle;
use commonware_cryptography::PublicKey;

/// Reservation for a peer in the network. This is used to ensure that the peer is reserved only
/// once, and that the reservation is released when the peer connection fails or is closed.
pub struct Reservation<P: PublicKey> {
    /// Metadata about the reservation.
    metadata: Metadata<P>,

    /// Used to automatically notify the completion of the reservation when it is dropped.
    releaser: ReleaserHandle<P>,
}

impl<P: PublicKey> Reservation<P> {
    /// Create a new reservation for a peer.
    pub fn new(metadata: Metadata<P>, releaser: ReleaserHandle<P>) -> Self {
        Self { metadata, releaser }
    }
}

impl<P: PublicKey> Reservation<P> {
    /// Returns the metadata associated with this reservation.
    pub fn metadata(&self) -> &Metadata<P> {
        &self.metadata
    }
}

impl<P: PublicKey> Drop for Reservation<P> {
    fn drop(&mut self) {
        self.releaser.release(self.metadata.clone());
    }
}
