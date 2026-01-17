//! Resolver actor implementation.

use super::{
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
    state::State,
    Config,
};
use crate::{
    minimmit::{actors::voter, scheme::Scheme, types::Certificate},
    types::{Epoch, View},
    Epochable, Viewable,
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::StaticProvider, Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_resolver::p2p;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc},
    ordered::Quorum,
    sequence::U64,
};
use rand_core::CryptoRngCore;
use std::time::Duration;
use tracing::debug;

/// Resolver actor for Minimmit consensus.
///
/// The resolver fetches missing certificates from peers to enable view progression.
/// Unlike simplex, minimmit has no certification phase - MNotarizations and
/// Finalizations can be used directly without additional verification.
pub struct Actor<E, S, B, D, T>
where
    E: Clock + CryptoRngCore + Spawner + Metrics,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
{
    context: ContextCell<E>,
    scheme: S,
    blocker: Option<B>,
    strategy: T,

    epoch: Epoch,
    mailbox_size: usize,
    fetch_timeout: Duration,

    state: State<S, D>,

    mailbox_receiver: mpsc::Receiver<MailboxMessage<S, D>>,
}

impl<E, S, B, D, T> Actor<E, S, B, D, T>
where
    E: Clock + CryptoRngCore + Spawner + Metrics,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
{
    /// Create a new resolver actor.
    pub fn new(context: E, cfg: Config<S, B, T>) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,
                blocker: Some(cfg.blocker),
                strategy: cfg.strategy,

                epoch: cfg.epoch,
                mailbox_size: cfg.mailbox_size,
                fetch_timeout: cfg.fetch_timeout,

                state: State::new(cfg.fetch_concurrent),

                mailbox_receiver: receiver,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the resolver actor.
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
                provider: StaticProvider::new(self.epoch.get(), participants),
                blocker: self.blocker.take().expect("blocker must be set"),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                me,
                initial: self.fetch_timeout / 2,
                timeout: self.fetch_timeout,
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
            Some(message) = self.mailbox_receiver.recv() else break => {
                match message {
                    MailboxMessage::Certificate(certificate) => {
                        self.state.handle(certificate, &mut resolver).await;
                    }
                }
            },
            Some(message) = handler_rx.recv() else break => {
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
            Certificate::MNotarization(m_notarization) => {
                let m_notarization_view = m_notarization.view();
                if m_notarization_view < view {
                    debug!(%view, received = %m_notarization_view, "m-notarization below view");
                    return None;
                }
                if m_notarization.epoch() != self.epoch {
                    debug!(
                        epoch = %m_notarization.epoch(),
                        expected = %self.epoch,
                        "rejecting m-notarization from different epoch"
                    );
                    return None;
                }
                if !m_notarization.verify(&mut self.context, &self.scheme, &self.strategy) {
                    debug!(%view, "m-notarization failed verification");
                    return None;
                }
                debug!(%view, received = %m_notarization_view, "received m-notarization for request");
                Some(Certificate::MNotarization(m_notarization))
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
                if !finalization.verify(&mut self.context, &self.scheme, &self.strategy) {
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
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.strategy) {
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
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey>,
    ) {
        match message {
            HandlerMessage::Deliver {
                view,
                data,
                response,
            } => {
                // Validate incoming message
                let Some(parsed) = self.validate(view, data) else {
                    // Resolver will block any peers that send invalid responses, so
                    // we don't need to do again here
                    response.send_lossy(false);
                    return;
                };
                response.send_lossy(true);

                // Notify voter as soon as possible
                voter.resolved_certificate(parsed.clone());

                // Process message
                self.state.handle(parsed, resolver).await;
            }
            HandlerMessage::Produce { view, response } => {
                // Produce message for view
                let Some(certificate) = self.state.get(view) else {
                    // If we drop the response channel, the resolver will automatically
                    // send an error response to the caller (so they don't need to wait
                    // the full timeout)
                    return;
                };
                response.send_lossy(certificate.encode());
            }
        }
    }
}
