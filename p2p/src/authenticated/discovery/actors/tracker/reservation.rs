use super::Metadata;
use crate::authenticated::discovery::actors::tracker::ingress::Releaser;
use commonware_cryptography::PublicKey;
use commonware_runtime::Spawner;

/// Reservation for a peer in the network. This is used to ensure that the peer is reserved only
/// once, and that the reservation is released when the peer connection fails or is closed.
pub struct Reservation<E: Spawner, P: PublicKey> {
    /// Context needed to spawn tasks if needed.
    ///
    /// Stored as an `Option` to avoid unnecessary cloning by `take`ing the value.
    spawner: Option<E>,

    /// Metadata about the reservation.
    metadata: Metadata<P>,

    /// Used to automatically notify the completion of the reservation when it is dropped.
    ///
    /// Stored as an `Option` to avoid unnecessary cloning by `take`ing the value.
    releaser: Option<Releaser<E, P>>,
}

impl<E: Spawner, P: PublicKey> Reservation<E, P> {
    /// Create a new reservation for a peer.
    pub fn new(spawner: E, metadata: Metadata<P>, releaser: Releaser<E, P>) -> Self {
        Self {
            spawner: Some(spawner),
            metadata,
            releaser: Some(releaser),
        }
    }
}

impl<E: Spawner, P: PublicKey> Reservation<E, P> {
    /// Returns the metadata associated with this reservation.
    pub fn metadata(&self) -> &Metadata<P> {
        &self.metadata
    }
}

impl<E: Spawner, P: PublicKey> Drop for Reservation<E, P> {
    fn drop(&mut self) {
        let mut releaser = self
            .releaser
            .take()
            .expect("Reservation::drop called twice");

        // If the mailbox is not full, release the reservation immediately without spawning a task.
        if releaser.try_release(self.metadata.clone()) {
            // Sent successfully, nothing to do.
            return;
        };

        // If the mailbox is full, we avoid blocking by spawning a task to handle the release.
        // While it may not be immediately obvious how a deadlock could occur, we take the
        // conservative approach of avoiding it.
        let metadata = self.metadata.clone();
        self.spawner
            .take()
            .expect("spawner is only consumed on drop")
            .spawn(move |_| async move {
                releaser.release(metadata).await;
            });
    }
}
