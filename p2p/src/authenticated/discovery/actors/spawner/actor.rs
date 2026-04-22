use super::{ingress::Message, Config};
use crate::authenticated::{
    discovery::{
        actors::{
            peer, router,
            tracker::{self, Metadata},
        },
        metrics,
        types::InfoVerifier,
    },
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{
    metrics::{Counter, Family},
    spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Registered, Sink, Spawner,
    Stream,
};
use commonware_utils::channel::mpsc;
use rand_core::CryptoRngCore;
use std::{num::NonZeroUsize, time::Duration};
use tracing::debug;

pub struct Actor<
    E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics,
    O: Sink,
    I: Stream,
    C: PublicKey,
> {
    context: ContextCell<E>,

    mailbox_size: usize,
    send_batch_size: NonZeroUsize,
    gossip_bit_vec_frequency: Duration,
    max_peer_set_size: u64,
    peer_gossip_max_count: usize,
    info_verifier: InfoVerifier<C>,

    receiver: mpsc::Receiver<Message<O, I, C>>,

    sent_messages: Registered<Family<metrics::Message, Counter>>,
    received_messages: Registered<Family<metrics::Message, Counter>>,
    dropped_messages: Registered<Family<metrics::Message, Counter>>,
    rate_limited: Registered<Family<metrics::Message, Counter>>,
}

impl<
        E: Spawner + BufferPooler + Clock + CryptoRngCore + Metrics,
        O: Sink,
        I: Stream,
        C: PublicKey,
    > Actor<E, O, I, C>
{
    #[allow(clippy::type_complexity)]
    pub fn new(context: E, cfg: Config<C>) -> (Self, Mailbox<Message<O, I, C>>) {
        let sent_messages = context.family("messages_sent", "messages sent");
        let received_messages = context.family("messages_received", "messages received");
        let dropped_messages = context.family(
            "messages_dropped",
            "messages dropped due to full application buffer",
        );
        let rate_limited = context.family("messages_rate_limited", "messages rate limited");
        let (sender, receiver) = Mailbox::new(cfg.mailbox_size);

        (
            Self {
                context: ContextCell::new(context),
                mailbox_size: cfg.mailbox_size,
                send_batch_size: cfg.send_batch_size,
                gossip_bit_vec_frequency: cfg.gossip_bit_vec_frequency,
                max_peer_set_size: cfg.max_peer_set_size,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                info_verifier: cfg.info_verifier,
                receiver,
                sent_messages,
                received_messages,
                dropped_messages,
                rate_limited,
            },
            sender,
        )
    }

    pub fn start(
        mut self,
        tracker: UnboundedMailbox<tracker::Message<C>>,
        router: Mailbox<router::Message<C>>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, router))
    }

    async fn run(
        mut self,
        tracker: UnboundedMailbox<tracker::Message<C>>,
        router: Mailbox<router::Message<C>>,
    ) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping spawner");
            },
            Some(msg) = self.receiver.recv() else {
                debug!("mailbox closed, stopping spawner");
                break;
            } => {
                match msg {
                    Message::Spawn {
                        peer,
                        connection,
                        reservation,
                    } => {
                        // Spawn peer
                        self.context.with_label("peer").spawn({
                            let sent_messages = self.sent_messages.clone();
                            let received_messages = self.received_messages.clone();
                            let dropped_messages = self.dropped_messages.clone();
                            let rate_limited = self.rate_limited.clone();
                            let mut tracker = tracker.clone();
                            let mut router = router.clone();
                            let is_dialer = matches!(reservation.metadata(), Metadata::Dialer(..));
                            let info_verifier = self.info_verifier.clone();
                            move |context| async move {
                                // Get greeting from tracker (returns None if not eligible)
                                let Some(greeting) = tracker.connect(peer.clone(), is_dialer).await
                                else {
                                    debug!(?peer, "peer not eligible");
                                    drop(reservation);
                                    return;
                                };

                                // Create peer
                                debug!(?peer, "peer started");
                                let (peer_actor, messenger) = peer::Actor::new(
                                    context,
                                    peer::Config {
                                        sent_messages: sent_messages.clone(),
                                        received_messages: received_messages.clone(),
                                        dropped_messages: dropped_messages.clone(),
                                        rate_limited: rate_limited.clone(),
                                        mailbox_size: self.mailbox_size,
                                        send_batch_size: self.send_batch_size,
                                        gossip_bit_vec_frequency: self.gossip_bit_vec_frequency,
                                        max_peer_set_size: self.max_peer_set_size,
                                        peer_gossip_max_count: self.peer_gossip_max_count,
                                        info_verifier,
                                    },
                                );

                                // Register peer with the router (may fail during shutdown)
                                let Some(channels) = router.ready(peer.clone(), messenger).await
                                else {
                                    debug!(?peer, "router shut down during peer setup");
                                    return;
                                };

                                // Run peer (greeting is sent first before main loop)
                                let result = peer_actor
                                    .run(peer.clone(), greeting, connection, tracker, channels)
                                    .await;

                                // Let the router know the peer has exited
                                match result {
                                    Ok(()) => debug!(?peer, "peer shutdown gracefully"),
                                    Err(e) => debug!(error = ?e, ?peer, "peer shutdown"),
                                }
                                router.release(peer).await;
                                // Release the reservation
                                drop(reservation);
                            }
                        });
                    }
                }
            },
        }
    }
}
