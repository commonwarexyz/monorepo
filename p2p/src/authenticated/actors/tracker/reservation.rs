use commonware_runtime::{Metrics, Spawner};
use commonware_utils::Array;
use futures::{channel::mpsc, SinkExt};
use std::net::SocketAddr;

/// Reservation metadata.
#[derive(Clone, Debug)]
pub enum Metadata<P: Array> {
    /// Dialer reservation.
    ///
    /// Contains:
    /// - The public key of the peer.
    /// - The socket address of the peer.
    Dialer(P, SocketAddr),

    /// Listener reservation.
    ///
    /// Contains the public key of the peer.
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

/// Reservation for a peer in the network. This is used to ensure that the peer is reserved only
/// once, and that the reservation is released when the peer connection fails or is closed.
pub struct Reservation<E: Spawner + Metrics, P: Array> {
    /// Context needed to spawn tasks if needed.
    context: E,

    /// Metadata about the reservation.
    metadata: Metadata<P>,

    /// Sender used to notify the completion of the reservation.
    closer: mpsc::Sender<Metadata<P>>,
}

impl<E: Spawner + Metrics, P: Array> Reservation<E, P> {
    /// Create a new reservation for a peer.
    pub fn new(context: E, metadata: Metadata<P>, closer: mpsc::Sender<Metadata<P>>) -> Self {
        Self {
            context,
            metadata,
            closer,
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
        // If the mailbox is not full, we can release the reservation immediately without spawning a task.
        let Err(e) = self.closer.try_send(self.metadata.clone()) else {
            // Sent successfully, nothing to do.
            return;
        };
        if e.is_full() {
            // If the mailbox is full, we need to spawn a task to handle the release. If we used `block_on` here,
            // it could cause a deadlock.
            let mut closer = self.closer.clone();
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
