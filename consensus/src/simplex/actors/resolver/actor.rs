use super::{
    ingress::{Handler, Mailbox, Message},
    Config,
};
use crate::{
    simplex::{
        actors::{resolver::state::State, voter},
        signing_scheme::Scheme,
        types::{OrderedExt, Voter},
    },
    types::{Epoch, View},
    Epochable, Viewable,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    utils::{requester, StaticManager},
    Blocker, Receiver, Sender,
};
use commonware_resolver::p2p::{
    Config as ResolverConfig, Engine as ResolverEngine, Mailbox as ResolverMailbox,
};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::sequence::U64;
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use rand::{CryptoRng, Rng};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Requests are made concurrently to multiple peers.
pub struct Actor<
    E: Clock + GClock + Rng + CryptoRng + Metrics + Spawner,
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
> {
    context: ContextCell<E>,
    scheme: S,

    #[allow(dead_code)]
    blocker: B,

    epoch: Epoch,
    namespace: Vec<u8>,
    mailbox_size: usize,
    fetch_timeout: Duration,
    fetch_rate_per_peer: Quota,

    state: State<S, D>,

    mailbox_receiver: mpsc::Receiver<Voter<S, D>>,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Metrics + Spawner,
        P: PublicKey,
        S: Scheme<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        D: Digest,
    > Actor<E, P, S, B, D>
{
    pub fn new(context: E, cfg: Config<S, B>) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,

                blocker: cfg.blocker,

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
        sender: impl Sender<PublicKey = P>,
        receiver: impl Receiver<PublicKey = P>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, sender, receiver).await)
    }

    async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = P>,
        receiver: impl Receiver<PublicKey = P>,
    ) {
        let participants = self.scheme.participants().clone();
        let me = self
            .scheme
            .me()
            .and_then(|index| participants.key(index))
            .cloned();

        let (handler_tx, mut handler_rx) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler_tx);

        let (resolver_engine, mut resolver) = ResolverEngine::new(
            self.context.with_label("resolver"),
            ResolverConfig {
                manager: StaticManager::new(self.epoch, participants),
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
                priority_requests: false,
                priority_responses: false,
            },
        );
        let mut resolver_task = resolver_engine.start((sender, receiver));

        loop {
            select! {
                resolver = &mut resolver_task => {
                    warn!(?resolver, "inner resolver engine stopped");
                    break;
                },
                mailbox = self.mailbox_receiver.next() => {
                    let Some(message) = mailbox else {
                        break;
                    };
                    self.state.handle_message(message, &mut resolver).await;
                },
                message = handler_rx.next() => {
                    let Some(message) = message else {
                        break;
                    };
                    self.handle_resolver_message(message, &mut voter, &mut resolver).await;
                },
            }
        }
    }

    async fn handle_resolver_message(
        &mut self,
        message: Message,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut ResolverMailbox<U64>,
    ) {
        match message {
            Message::Deliver {
                view,
                data,
                response,
            } => {
                // Verify message
                let Ok(raw) =
                    Voter::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config())
                else {
                    let _ = response.send(false);
                    return;
                };
                let Some(parsed) = self.validate_incoming(view, &raw) else {
                    let _ = response.send(false);
                    return;
                };
                let _ = response.send(true);
                info!(view, "validated incoming message");

                // Notify voter as soon as possible
                voter.verified(raw).await;

                // Process message
                self.state.handle_message(parsed, resolver).await;
            }
            Message::Produce { view, response } => {
                let Some(voter) = self.state.produce(view) else {
                    return;
                };
                let _ = response.send(voter.encode().into());
            }
        }
    }

    fn validate_incoming(&mut self, view: View, incoming: &Voter<S, D>) -> Option<Voter<S, D>> {
        match incoming {
            Voter::Notarization(notarization) => {
                if notarization.view() < view {
                    debug!(view, "notarization below view");
                    return None;
                }
                if notarization.epoch() != self.epoch {
                    debug!(
                        view,
                        epoch = notarization.epoch(),
                        expected = self.epoch,
                        "rejecting notarization from different epoch"
                    );
                    return None;
                }
                if !notarization.verify(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(view, "notarization failed verification");
                    return None;
                }
                debug!(view, received = ?notarization.view(), "received notarization for request");
                Some(Voter::Notarization(notarization.clone()))
            }
            Voter::Finalization(finalization) => {
                if finalization.view() < view {
                    debug!(view, "finalization below view");
                    return None;
                }
                if finalization.epoch() != self.epoch {
                    debug!(view, "finalization from different epoch");
                    return None;
                }
                if !finalization.verify(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(view, "finalization failed verification");
                    return None;
                }
                debug!(view, received = ?finalization.view(), "received finalization for request");
                Some(Voter::Finalization(finalization.clone()))
            }
            Voter::Nullification(nullification) => {
                if nullification.view() != view {
                    debug!(view, "nullification view mismatch");
                    return None;
                }
                if nullification.epoch() != self.epoch {
                    debug!(
                        view,
                        epoch = nullification.epoch(),
                        expected = self.epoch,
                        "rejecting nullification from different epoch"
                    );
                    return None;
                }
                if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
                    debug!(view, "nullification failed verification");
                    return None;
                }
                Some(Voter::Nullification(nullification.clone()))
            }
            _ => None,
        }
    }
}
