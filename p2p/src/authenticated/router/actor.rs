use super::{
    Config,
    ingress::{Mailbox, Message, Messenger},
};
use crate::{
    Recipients,
    authenticated::{channels::Channels, data::EncodedData, relay::Relay},
};
use commonware_actor::mailbox;
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{BufferPooler, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::channel::ring;
use futures::Sink;
use std::{collections::BTreeMap, pin::Pin};
use tracing::debug;

/// Router actor that manages peer connections and routing messages.
pub struct Actor<E: Spawner + BufferPooler + Metrics, P: PublicKey> {
    context: ContextCell<E>,

    control: mailbox::UnreliableReceiver<Message<P>>,
    connections: BTreeMap<P, Relay<EncodedData>>,
    open_subscriptions: Vec<ring::Sender<Vec<P>>>,
}

impl<E: Spawner + BufferPooler + Metrics, P: PublicKey> Actor<E, P> {
    /// Returns a new [Actor] along with a [Mailbox] and [Messenger]
    /// that can be used to send messages to the router.
    pub fn new(context: E, cfg: Config) -> (Self, Mailbox<P>, Messenger<P>) {
        // Create mailbox
        let (control_sender, control_receiver) =
            mailbox::new_unreliable::<Message<P>>(context.child("mailbox"), cfg.mailbox_size);
        let pool = context.network_buffer_pool().clone();

        // Create actor
        (
            Self {
                context: ContextCell::new(context),
                control: control_receiver,
                connections: BTreeMap::new(),
                open_subscriptions: Vec::new(),
            },
            Mailbox::new(control_sender.clone()),
            Messenger::new(pool, Mailbox::new(control_sender)),
        )
    }

    /// Sends pre-encoded data to the given `recipient`.
    fn send(&mut self, recipient: P, encoded: EncodedData, priority: bool) {
        if let Some(relay) = self.connections.get_mut(&recipient) {
            let _ = relay.send(encoded, priority);
        }
    }

    /// Routes content to the configured recipients.
    fn route(&mut self, recipients: Recipients<P>, encoded: EncodedData, priority: bool) {
        match recipients {
            Recipients::One(recipient) => {
                self.send(recipient, encoded, priority);
            }
            Recipients::Some(recipients) => {
                for recipient in recipients {
                    self.send(recipient, encoded.clone(), priority);
                }
            }
            Recipients::All => {
                // Send to all connected peers
                for relay in self.connections.values_mut() {
                    let _ = relay.send(encoded.clone(), priority);
                }
            }
        }
    }

    /// Starts a new task that runs the router [Actor].
    /// Returns a [Handle] that can be used to await the completion of the task,
    /// which will run until its `control` receiver is closed or shutdown is signaled.
    pub fn start(mut self, routing: Channels<P>) -> Handle<()> {
        spawn_cell!(self.context, self.run(routing))
    }

    /// Runs the [Actor] event loop, processing incoming control and content messages.
    /// Returns when the `control` channel is closed or shutdown is signaled.
    async fn run(mut self, routing: Channels<P>) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping router");
            },
            Some(msg) = self.control.recv() else {
                debug!("mailbox closed, stopping router");
                break;
            } => match msg {
                Message::Ready {
                    peer,
                    relay,
                    channels,
                } => {
                    if self.connections.contains_key(&peer) {
                        debug!(?peer, "rejecting duplicate ready peer");
                    } else {
                        debug!(?peer, "peer ready");
                        assert!(self.connections.insert(peer.clone(), relay).is_none());
                        if channels.send(routing.clone()).is_err() {
                            self.connections.remove(&peer);
                        } else {
                            self.notify_subscribers();
                        }
                    }
                }
                Message::Release { peer } => {
                    debug!(?peer, "peer released");
                    self.connections.remove(&peer);
                    self.notify_subscribers();
                }
                Message::Content {
                    recipients,
                    encoded,
                    priority,
                } => {
                    self.route(recipients, encoded, priority);
                }
                Message::SubscribePeers { sender } => {
                    self.subscribe_peers(sender);
                }
            },
        }
    }

    fn subscribe_peers(&mut self, mut sender: ring::Sender<Vec<P>>) {
        let peers = self.connections.keys().cloned().collect();
        if Pin::new(&mut sender).start_send(peers).is_ok() {
            self.open_subscriptions.push(sender);
        }
    }

    /// Notifies all open peer subscriptions with the current list of connected peers.
    fn notify_subscribers(&mut self) {
        let peers: Vec<P> = self.connections.keys().cloned().collect();
        let mut keep = Vec::with_capacity(self.open_subscriptions.len());

        for mut subscriber in self.open_subscriptions.drain(..) {
            if Pin::new(&mut subscriber).start_send(peers.clone()).is_ok() {
                keep.push(subscriber);
            }
        }
        self.open_subscriptions = keep;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use futures::FutureExt as _;

    #[test]
    fn rejects_duplicate_peers_and_rolls_back_canceled_ready() {
        deterministic::Runner::default().start(|context| async move {
            let (actor, mailbox, _) = Actor::<deterministic::Context, PublicKey>::new(
                context.child("router"),
                Config {
                    mailbox_size: NZUsize!(4),
                },
            );
            let routing = Channels::new(
                Messenger::unbound(context.network_buffer_pool().clone()),
                1024,
                NZUsize!(1),
            );
            let abandoned = PrivateKey::from_seed(0).public_key();
            let (relay, _) = Relay::new(context.child("abandoned"), NZUsize!(1));
            assert!(
                mailbox
                    .ready(abandoned.clone(), relay)
                    .now_or_never()
                    .is_none()
            );

            let handle = actor.start(routing);
            let first = abandoned;
            let second = PrivateKey::from_seed(2).public_key();

            let (relay, _) = Relay::new(context.child("first"), NZUsize!(1));
            assert!(mailbox.ready(first.clone(), relay).await.is_some());

            let (relay, _) = Relay::new(context.child("duplicate"), NZUsize!(1));
            assert!(mailbox.ready(first.clone(), relay).await.is_none());

            let (relay, _) = Relay::new(context.child("second"), NZUsize!(1));
            assert!(mailbox.ready(second, relay).await.is_some());

            let _ = mailbox.release(first);

            handle.abort();
        });
    }

    #[test]
    fn subscribe_retains_only_open_initial_sender() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _, _) = Actor::<deterministic::Context, PublicKey>::new(
                context,
                Config {
                    mailbox_size: NZUsize!(1),
                },
            );
            let (sender, receiver) = ring::channel(NZUsize!(1));
            drop(receiver);

            actor.subscribe_peers(sender);
            assert!(actor.open_subscriptions.is_empty());

            let (sender, _receiver) = ring::channel(NZUsize!(1));
            actor.subscribe_peers(sender);
            assert_eq!(actor.open_subscriptions.len(), 1);
        });
    }
}
