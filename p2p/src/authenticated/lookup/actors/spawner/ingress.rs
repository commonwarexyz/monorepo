use crate::authenticated::{lookup::actors::tracker::Reservation, Mailbox};
use commonware_actor::{mailbox::Policy, Feedback};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Sink, Stream};
use commonware_stream::encrypted::{Receiver, Sender};
use std::collections::VecDeque;

/// Messages that can be processed by the spawner actor.
pub enum Message<Si: Sink, St: Stream, P: PublicKey> {
    /// Notify the spawner to create a new task for the given peer.
    Spawn {
        /// The peer's public key.
        peer: P,
        /// The connection to the peer.
        connection: (Sender<Si>, Receiver<St>),
        /// The reservation for the peer.
        reservation: Reservation<P>,
    },
}

impl<Si: Sink, St: Stream, P: PublicKey> Policy for Message<Si, St, P> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) {
        // We drop spawn requests when we are backlogged because it is more likely
        // than not that by the time we get around to handling it the peer connection
        // will have already timed out (and closed).
    }
}

impl<Si: Sink, St: Stream, P: PublicKey> Mailbox<Message<Si, St, P>> {
    /// Send a message to the actor to spawn a new task for the given peer.
    ///
    /// This may fail during shutdown if the spawner has already exited,
    /// which is harmless since no new connections need to be spawned.
    pub fn spawn(
        &mut self,
        connection: (Sender<Si>, Receiver<St>),
        reservation: Reservation<P>,
    ) -> Feedback {
        self.0.enqueue(Message::Spawn {
            peer: reservation.metadata().public_key().clone(),
            connection,
            reservation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::lookup::actors::tracker::{self, Metadata};
    use commonware_actor::mailbox;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer as _,
    };
    use commonware_runtime::{deterministic, mocks, Runner as _, Spawner as _, Supervisor as _};
    use commonware_stream::encrypted::{
        dial, listen, Config as StreamConfig, Receiver as EncryptedReceiver,
        Sender as EncryptedSender,
    };
    use commonware_utils::NZUsize;
    use futures::FutureExt as _;
    use std::time::Duration;

    const STREAM_NAMESPACE: &[u8] = b"test_lookup_spawner_ingress";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    type Connection = (
        EncryptedSender<mocks::Sink>,
        EncryptedReceiver<mocks::Stream>,
    );

    fn stream_config(key: PrivateKey) -> StreamConfig<PrivateKey> {
        StreamConfig {
            signing_key: key,
            namespace: STREAM_NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(10),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }

    async fn connections(
        context: &deterministic::Context,
        local_key: PrivateKey,
        remote_key: PrivateKey,
    ) -> (Connection, Connection) {
        let local_pk = local_key.public_key();
        let remote_pk = remote_key.public_key();
        let (local_sink, remote_stream) = mocks::Channel::init();
        let (remote_sink, local_stream) = mocks::Channel::init();

        let listener = context.child("listener").spawn({
            let expected = local_pk.clone();
            move |context| async move {
                listen(
                    context,
                    |_| async { true },
                    stream_config(remote_key),
                    remote_stream,
                    remote_sink,
                )
                .await
                .map(|(peer, sender, receiver)| {
                    assert_eq!(peer, expected);
                    (sender, receiver)
                })
            }
        });

        let dialer = dial(
            context.child("dialer"),
            stream_config(local_key),
            remote_pk,
            local_stream,
            local_sink,
        )
        .await
        .expect("dial failed");

        let listener = listener
            .await
            .expect("listener task failed")
            .expect("listen failed");

        (dialer, listener)
    }

    #[test]
    fn spawn_overflow_drops_message_and_releases_reservation() {
        deterministic::Runner::default().start(|context| async move {
            let (connection_1, connection_2) =
                connections(&context, PrivateKey::from_seed(1), PrivateKey::from_seed(2)).await;
            let peer_1 = PrivateKey::from_seed(1).public_key();
            let peer_2 = PrivateKey::from_seed(2).public_key();

            let (mut spawner, mut receiver) =
                Mailbox::<Message<mocks::Sink, mocks::Stream, PublicKey>>::new(
                    context.child("spawner_mailbox"),
                    NZUsize!(1),
                );
            let (tracker_sender, mut tracker_receiver) =
                mailbox::new::<tracker::Message<PublicKey>>(
                    context.child("tracker_mailbox"),
                    NZUsize!(10),
                );
            let releaser = tracker::ingress::Releaser::new(tracker_sender);

            let reservation_1 =
                Reservation::new(Metadata::Listener(peer_1.clone()), releaser.clone());
            let reservation_2 = Reservation::new(Metadata::Listener(peer_2.clone()), releaser);

            assert_eq!(spawner.spawn(connection_1, reservation_1), Feedback::Ok);
            assert_eq!(
                spawner.spawn(connection_2, reservation_2),
                Feedback::Backoff
            );

            let release = tracker_receiver
                .recv()
                .await
                .expect("release should be enqueued");
            let tracker::Message::Release { metadata } = release else {
                panic!("unexpected tracker message");
            };
            assert_eq!(metadata.public_key(), &peer_2);

            let Message::Spawn { peer, .. } = receiver
                .recv()
                .await
                .expect("ready spawn should be retained");
            assert_eq!(peer, peer_1);
            assert!(receiver.recv().now_or_never().is_none());
        });
    }
}
