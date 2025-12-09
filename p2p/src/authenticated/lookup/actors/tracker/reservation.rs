use super::Metadata;
use crate::authenticated::lookup::actors::tracker::ingress::Releaser;
use commonware_cryptography::PublicKey;

/// Reservation for a peer in the network. This is used to ensure that the peer is reserved only
/// once, and that the reservation is released when the peer connection fails or is closed.
pub struct Reservation<P: PublicKey> {
    /// Metadata about the reservation.
    metadata: Metadata<P>,

    /// Used to automatically notify the completion of the reservation when it is dropped.
    ///
    /// Stored as an `Option` to avoid unnecessary cloning by `take`ing the value.
    releaser: Option<Releaser<P>>,
}

impl<P: PublicKey> Reservation<P> {
    /// Create a new reservation for a peer.
    pub const fn new(metadata: Metadata<P>, releaser: Releaser<P>) -> Self {
        Self {
            metadata,
            releaser: Some(releaser),
        }
    }
}

impl<P: PublicKey> Reservation<P> {
    /// Returns the metadata associated with this reservation.
    pub const fn metadata(&self) -> &Metadata<P> {
        &self.metadata
    }
}

impl<P: PublicKey> Drop for Reservation<P> {
    fn drop(&mut self) {
        let mut releaser = self
            .releaser
            .take()
            .expect("Reservation::drop called twice");
        releaser.release(self.metadata.clone());
    }
}
