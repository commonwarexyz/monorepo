use super::Metadata;
use crate::authenticated::lookup::actors::tracker::releaser;
use commonware_cryptography::PublicKey;

/// Reservation for a peer in the network. This is used to ensure that the peer is reserved only
/// once, and that the reservation is released when the peer connection fails or is closed.
pub struct Reservation<P: PublicKey> {
    /// Metadata about the reservation.
    metadata: Metadata<P>,

    /// The mailbox for the releaser actor responsible for issuing reservation
    /// releases back to the tracker when the reservation is dropped.
    releaser_mailbox: releaser::Mailbox<P>,
}

impl<P: PublicKey> Reservation<P> {
    /// Create a new reservation for a peer.
    pub fn new(metadata: Metadata<P>, releaser_mailbox: releaser::Mailbox<P>) -> Self {
        Self {
            metadata,
            releaser_mailbox,
        }
    }

    /// Returns the metadata associated with this reservation.
    pub fn metadata(&self) -> &Metadata<P> {
        &self.metadata
    }
}

impl<P: PublicKey> Drop for Reservation<P> {
    fn drop(&mut self) {
        let _ = self.releaser_mailbox.release(self.metadata.clone());
    }
}
