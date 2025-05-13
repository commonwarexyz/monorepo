use super::Metadata;
use commonware_runtime::{Metrics, Spawner};
use commonware_utils::Array;
use futures::{channel::mpsc, SinkExt};

/// Reservation for a peer in the network. This is used to ensure that the peer is reserved only
/// once, and that the reservation is released when the peer connection fails or is closed.
pub struct Reservation<E: Spawner + Metrics, P: Array> {
    /// Context needed to spawn tasks if needed.
    context: E,

    /// Metadata about the reservation.
    metadata: Metadata<P>,

    /// Sender used to automatically notify the completion of the reservation when it is dropped.
    ///
    /// Stored as an `Option` to avoid unnecessary cloning by `take`ing the value when
    /// dropping the reservation.
    closer: Option<mpsc::Sender<Metadata<P>>>,
}

impl<E: Spawner + Metrics, P: Array> Reservation<E, P> {
    /// Create a new reservation for a peer.
    pub fn new(context: E, metadata: Metadata<P>, closer: mpsc::Sender<Metadata<P>>) -> Self {
        Self {
            context,
            metadata,
            closer: Some(closer),
        }
    }
}

impl<E: Spawner + Metrics, P: Array> Reservation<E, P> {
    /// Returns the metadata associated with this reservation.
    pub fn metadata(&self) -> &Metadata<P> {
        &self.metadata
    }
}

impl<E: Spawner + Metrics, P: Array> Drop for Reservation<E, P> {
    fn drop(&mut self) {
        let mut closer = self.closer.take().expect("Reservation::drop called twice");

        // If the mailbox is not full, we can release the reservation immediately without spawning a task.
        let Err(e) = closer.try_send(self.metadata.clone()) else {
            // Sent successfully, nothing to do.
            return;
        };
        if e.is_full() {
            // If the mailbox is full, we need to spawn a task to handle the release. If we used `block_on` here,
            // it could cause a deadlock.
            let metadata = self.metadata.clone();
            self.context.spawn_ref()(async move {
                closer.send(metadata).await.unwrap();
            });
        } else {
            // If any other error occurs, we should panic!
            panic!(
                "unexpected error while trying to release reservation: {:?}",
                e
            );
        }
    }
}
