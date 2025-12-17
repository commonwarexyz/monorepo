use super::{
    ingress::{Handler, Mailbox, Message},
    Config,
};
use crate::{
    simplex::{
        actors::{resolver::state::State, voter},
        scheme::Scheme,
        types::Certificate,
    },
    types::{Epoch, View},
    Epochable, Viewable,
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::{requester, StaticManager},
    Blocker, Receiver, Sender,
};
use commonware_resolver::p2p;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Quota, Spawner};
use commonware_utils::{ordered::Quorum, sequence::U64};
use futures::{channel::mpsc, StreamExt};
use rand::{CryptoRng, Rng};
use std::time::Duration;
use tracing::debug;

/// Requests are made concurrently to multiple peers.
pub struct Actor<
    E: Clock + Rng + CryptoRng + Metrics + Spawner,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
> {
    context: ContextCell<E>,
    scheme: S,
    blocker: Option<B>,

    epoch: Epoch,
    namespace: Vec<u8>,
    mailbox_size: usize,
    fetch_timeout: Duration,
    fetch_rate_per_peer: Quota,

    state: State<S, D>,

    mailbox_receiver: mpsc::Receiver<Certificate<S, D>>,
}

impl<
        E: Clock + Rng + CryptoRng + Metrics + Spawner,
        S: Scheme<D>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
    > Actor<E, S, B, D>
{
    pub fn new(context: E, cfg: Config<S, B>) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,
                blocker: Some(cfg.blocker),

                epoch: cfg.epoch,
                namespace: cfg.namespace,
                mailbox_size: cfg.mailbox_size,
                fetch_timeout: cfg.fetch_timeout,
                fetch_rate_per_peer: cfg.fetch_rate_per_peer,

                state: State::new(cfg.fetch_concurrent),

                mailbox_receiver: receiver,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, sender, receiver).await)
    }

    async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        let participants = self.scheme.participants().clone();
        let me = self
            .scheme
            .me()
            .and_then(|index| participants.key(index))
            .cloned();

        let (handler_tx, mut handler_rx) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler_tx);

        let (resolver_engine, mut resolver) = p2p::Engine::new(
            self.context.with_label("resolver"),
            p2p::Config {
                manager: StaticManager::new(self.epoch.get(), participants),
                blocker: self.blocker.take().expect("blocker must be set"),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                requester_config: requester::Config {
                    me,
                    rate_limit: self.fetch_rate_per_peer,
                    initial: self.fetch_timeout / 2,
                    timeout: self.fetch_timeout,
                },
                fetch_retry_timeout: self.fetch_timeout,
                priority_requests: true,
                priority_responses: false,
            },
        );
        let mut resolver_task = resolver_engine.start((sender, receiver));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping resolver");
            },
            _ = &mut resolver_task => {
                break;
            },
            mailbox = self.mailbox_receiver.next() => {
                let Some(message) = mailbox else {
                    break;
                };
                self.state.handle(message, &mut resolver).await;
            },
            handler = handler_rx.next() => {
                let Some(message) = handler else {
                    break;
                };
                self.handle_resolver(message, &mut voter, &mut resolver).await;
            },
        }
    }

    /// Validates an incoming message, returning the parsed message if valid.
    fn validate(&mut self, view: View, data: Bytes) -> Option<Certificate<S, D>> {
        // Decode message
        let incoming =
            Certificate::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config()).ok()?;

        // Validate message
        match incoming {
            Certificate::Notarization(notarization) => {
                if notarization.view() < view {
                    debug!(%view, received = %notarization.view(), "notarization below view");
                    return None;
                }
                if notarization.epoch() != self.epoch {
                    debug!(
                        epoch = %notarization.epoch(),
                        expected = %self.epoch,
                        "rejecting notarization from different epoch"
                    );
                    return None;
                }
                if !notarization.verify(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(%view, "notarization failed verification");
                    return None;
                }
                debug!(%view, received = %notarization.view(), "received notarization for request");
                Some(Certificate::Notarization(notarization))
            }
            Certificate::Finalization(finalization) => {
                if finalization.view() < view {
                    debug!(%view, received = %finalization.view(), "finalization below view");
                    return None;
                }
                if finalization.epoch() != self.epoch {
                    debug!(
                        epoch = %finalization.epoch(),
                        expected = %self.epoch,
                        "rejecting finalization from different epoch"
                    );
                    return None;
                }
                if !finalization.verify(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(%view, "finalization failed verification");
                    return None;
                }
                debug!(%view, received = %finalization.view(), "received finalization for request");
                Some(Certificate::Finalization(finalization))
            }
            Certificate::Nullification(nullification) => {
                if nullification.view() != view {
                    debug!(%view, received = %nullification.view(), "nullification view mismatch");
                    return None;
                }
                if nullification.epoch() != self.epoch {
                    debug!(
                        epoch = %nullification.epoch(),
                        expected = %self.epoch,
                        "rejecting nullification from different epoch"
                    );
                    return None;
                }
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(%view, "nullification failed verification");
                    return None;
                }
                debug!(%view, received = %nullification.view(), "received nullification for request");
                Some(Certificate::Nullification(nullification))
            }
        }
    }

    /// Handles a message from the [p2p::Engine].
    async fn handle_resolver(
        &mut self,
        message: Message,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey>,
    ) {
        match message {
            Message::Deliver {
                view,
                data,
                response,
            } => {
                // Validate incoming message
                let Some(parsed) = self.validate(view, data) else {
                    // Resolver will block any peers that send invalid responses, so
                    // we don't need to do again here
                    let _ = response.send(false);
                    return;
                };
                let _ = response.send(true);

                // Notify voter as soon as possible
                voter.resolved(parsed.clone()).await;

                // Process message
                self.state.handle(parsed, resolver).await;
            }
            Message::Produce { view, response } => {
                // Produce message for view
                let Some(voter) = self.state.get(view) else {
                    // If we drop the response channel, the resolver will automatically
                    // send an error response to the caller (so they don't need to wait
                    // the full timeout)
                    return;
                };
                let _ = response.send(voter.encode().into());
            }
        }
    }
}
