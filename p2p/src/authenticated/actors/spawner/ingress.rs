use crate::authenticated::actors::tracker::Reservation;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics, Network, SinkOf, Spawner, StreamOf};
use commonware_stream::public_key::Connection;

/// Messages that can be processed by the spawner [Actor](super::Actor).
pub enum Message<E: Spawner + Clock + Metrics + Network, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: Connection<SinkOf<E>, StreamOf<E>>,
        /// The reservation for the peer.
        reservation: Reservation<E, P>,
    },
}
