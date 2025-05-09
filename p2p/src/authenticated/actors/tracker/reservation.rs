use commonware_runtime::{Metrics, Spawner};
use commonware_utils::Array;
use futures::{channel::mpsc, SinkExt};

/// Reservation for a peer in the network. This is used to ensure that the peer is reserved only
/// once, and that the reservation is released when the peer connection fails or is closed.
pub struct Reservation<E: Spawner + Metrics, P: Array> {
    /// Context needed to spawn tasks if needed.
    context: E,

    /// The public key of the peer associated with this reservation.
    public_key: P,

    /// Sender used to notify the completion of the reservation.
    closer: mpsc::Sender<P>,
}

impl<E: Spawner + Metrics, P: Array> Reservation<E, P> {
    /// Create a new reservation for a peer.
    pub fn new(context: E, public_key: P, closer: mpsc::Sender<P>) -> Self {
        Self {
            context,
            public_key,
            closer,
        }
    }
}

impl<E: Spawner + Metrics, P: Array> Reservation<E, P> {
    /// Get the public key of the peer associated with this reservation.
    pub fn public_key(&self) -> &P {
        &self.public_key
    }
}

impl<E: Spawner + Metrics, P: Array> Drop for Reservation<E, P> {
    fn drop(&mut self) {
        // If the mailbox is not full, we can release the reservation immediately without spawning a task.
        let Err(e) = self.closer.try_send(self.public_key.clone()) else {
            // Sent successfully, nothing to do.
            return;
        };
        if e.is_full() {
            // If the mailbox is full, we need to spawn a task to handle the release. If we used `block_on` here,
            // it could cause a deadlock.
            let mut closer = self.closer.clone();
            let public_key = self.public_key.clone();
            self.context.spawn_ref()(async move {
                closer.send(public_key).await.unwrap();
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
