use super::ingress::Mailbox;
use crate::authenticated::lookup::actors::tracker::{Message, Metadata};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Handle, Spawner};
use futures::{channel::mpsc, SinkExt, StreamExt};

/// The releaser actor maintains a backlog of deferred release requests when the
/// main tracker mailbox is full.
pub struct Actor<E: Spawner, C: PublicKey> {
    context: E,
    tracker: mpsc::Sender<Message<C>>,
    backlog: mpsc::UnboundedReceiver<Metadata<C>>,
}

impl<E: Spawner, C: PublicKey> Actor<E, C> {
    /// Creates a new releaser [Actor] from the given `context` and tracker `sender`.
    pub fn new(context: E, tracker: mpsc::Sender<Message<C>>) -> (Self, Mailbox<C>) {
        let (backlog_sender, backlog_receiver) = mpsc::unbounded();
        (
            Self {
                context,
                tracker: tracker.clone(),
                backlog: backlog_receiver,
            },
            Mailbox::new(tracker, backlog_sender),
        )
    }

    /// Start the actor and run it in the background.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn(|_| async move {
            while let Some(metadata) = self.backlog.next().await {
                if self
                    .tracker
                    .send(Message::Release { metadata })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::lookup::actors::tracker::releaser;
    use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt, Signer};
    use commonware_runtime::{deterministic::Runner, Runner as _};
    use futures::StreamExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn releaser_actor_drains_backlog_when_mailbox_full() {
        let executor = Runner::default();
        executor.start(|context| async move {
            // tracker mailbox has capacity for only 1 element
            //
            // NOTE: mpsc::channel always reserves one slot per sender
            let (tracker_sender, mut tracker_receiver) = mpsc::channel(0);
            let (releaser, mut releaser_mailbox) = releaser::Actor::new(context.clone(), tracker_sender);
            releaser.start();

            let metadata_a = Metadata::Dialer(
                PrivateKey::from_seed(1).public_key(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1337),
            );
            let metadata_b = Metadata::Listener(PrivateKey::from_seed(2).public_key());

            // the first release request should go through directly to the tracker mailbox
            assert!(releaser_mailbox.release(metadata_a.clone()));
            // the second release request should be queued in the releaser backlog
            assert!(!releaser_mailbox.release(metadata_b.clone()));

            // both requests should reach the tracker
            let first = tracker_receiver.next().await.unwrap();
            assert!(matches!(
                first,
                Message::Release { ref metadata } if metadata.public_key() == metadata_a.public_key()
            ));

            let second = tracker_receiver.next().await.unwrap();
            assert!(matches!(
                second,
                Message::Release { ref metadata } if metadata.public_key() == metadata_b.public_key()
            ));
        });
    }
}
