use crate::{
    dkg::{
        ReshareBlock,
        probe::{ActorArtifact, mailbox::Message, wire},
    },
    stateful::probe::sample,
};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Epochable, Reporter,
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::{
        scheme::Scheme,
        types::{Activity, Finalization},
    },
    types::{Epoch, Epocher, FixedEpocher},
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{NonZeroDuration, channel::fallible::OneshotExt as _};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::collections::BTreeSet;
use tracing::debug;

/// Discovery of the finalization that ends the active epoch, pending until
/// marshal stores or has processed it.
struct Pending<P> {
    epoch: Epoch,
    /// Peers asked in the latest request round whose boundary response has not
    /// been verified.
    awaiting: BTreeSet<P>,
}

/// Serving phase of the probe actor: answers requests from the attached marshal
/// and, while the orchestrator is catching up, discovers the active epoch's
/// boundary certificate for marshal (see the
/// [module docs](crate::dkg::probe#serving)).
pub(super) struct Service<E, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    B: Blocker<PublicKey = S::PublicKey>,
    T: Strategy,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) marshal: MarshalMailbox<S, V>,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
    pub(super) verifier: S,
    pub(super) strategy: T,
    pub(super) retry_timeout: NonZeroDuration,
}

impl<E, S, V, T, B> Service<E, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    B: Blocker<PublicKey = S::PublicKey>,
    T: Strategy,
{
    /// Runs the serving loop until the actor shuts down.
    pub(super) async fn run(
        mut self,
        mut sender: impl Sender<PublicKey = S::PublicKey>,
        mut receiver: impl Receiver<PublicKey = S::PublicKey>,
        catch_up: Option<(Epoch, S::PublicKey)>,
    ) {
        let mut mailbox_drained = false;
        let mut pending = catch_up
            .map(|(epoch, peer)| Self::request_boundary(epoch, Recipients::One(peer), &mut sender));
        let mut deadline = self.context.current() + self.retry_timeout.get();
        select_loop! {
            self.context,
            on_start => {
                let mailbox_message = if mailbox_drained {
                    Either::Left(future::pending())
                } else {
                    Either::Right(self.mailbox.recv())
                };
                let retry = if pending.is_some() {
                    Either::Left(self.context.sleep_until(deadline))
                } else {
                    Either::Right(future::pending())
                };
            },
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            Some(message) = mailbox_message else {
                mailbox_drained = true;
                continue;
            } => match message {
                Message::Subscribe { response } => {
                    if let Some(artifact) = &self.artifact {
                        response.send_lossy(artifact.clone());
                    }
                }
                Message::Attach { .. } => {}
                Message::CatchUp { epoch, peer } => {
                    if pending.as_ref().is_none_or(|current| epoch > current.epoch) {
                        pending = Some(Self::request_boundary(
                            epoch,
                            Recipients::One(peer),
                            &mut sender,
                        ));
                        deadline = self.context.current() + self.retry_timeout.get();
                    }
                }
            },
            _ = retry => {
                // Processed progress remains authoritative after old certificates are pruned.
                let epoch = pending.as_ref().expect("retry requires a pending epoch").epoch;
                let height = self.epocher.last(epoch).expect("active epoch is covered");
                if self.marshal.get_finalization(height).await.is_some()
                    || self
                        .marshal
                        .get_processed()
                        .await
                        .is_some_and(|processed| processed.height() >= height)
                {
                    pending = None;
                } else {
                    pending = Some(Self::request_boundary(epoch, Recipients::All, &mut sender));
                    deadline = self.context.current() + self.retry_timeout.get();
                }
            },
            Ok((peer, message)) = receiver.recv() else {
                debug!("boundary receiver closed, shutting down");
                return;
            } => {
                // Responses from peers that are not awaited fall through to
                // request decoding, which ignores them.
                if let Some(current) = pending
                    .as_mut()
                    .filter(|current| current.awaiting.contains(&peer))
                {
                    match wire::read_response::<S, V, _>(
                        message.clone(),
                        &self.verifier.certificate_codec_config(),
                    ) {
                        Ok(Some(wire::Response::Boundary(finalization))) => {
                            if finalization.epoch() != current.epoch {
                                continue;
                            }
                            current.awaiting.remove(&peer);
                            if !finalization.verify(
                                self.context.as_present_mut(),
                                &self.verifier,
                                &self.strategy,
                            ) {
                                commonware_p2p::block!(
                                    self.blocker,
                                    peer,
                                    "invalid boundary finalization"
                                );
                                continue;
                            }

                            // The certificate binds the round and commitment; marshal establishes
                            // its height when the committed block arrives.
                            self.marshal.report(Activity::Finalization(finalization));
                            continue;
                        }
                        Ok(Some(_)) => continue,
                        Ok(None) => {}
                        Err(err) => {
                            commonware_p2p::block!(
                                self.blocker,
                                peer,
                                ?err,
                                "invalid boundary response"
                            );
                            continue;
                        }
                    }
                }
                let request = match wire::read_request(message) {
                    Ok(Some(request)) => request,
                    Ok(None) => continue,
                    Err(err) => {
                        commonware_p2p::block!(
                            self.blocker,
                            peer,
                            ?err,
                            "invalid bootstrap boundary request"
                        );
                        continue;
                    }
                };
                match request {
                    wire::Request::Latest => {
                        let Some(finalization) = sample::latest_finalization(&self.marshal).await
                        else {
                            continue;
                        };
                        sender.send(
                            Recipients::One(peer),
                            wire::Message::<S, V>::LatestResponse(finalization).encode(),
                            false,
                        );
                    }
                    wire::Request::Boundary(epoch) => {
                        let Some(finalization) = self.produce_finalization(epoch).await else {
                            continue;
                        };
                        sender.send(
                            Recipients::One(peer),
                            wire::Message::<S, V>::BoundaryResponse(finalization).encode(),
                            false,
                        );
                    }
                    wire::Request::Block(epoch) => {
                        let Some(block) = self.produce_block(epoch).await else {
                            continue;
                        };
                        sender.send(
                            Recipients::One(peer),
                            wire::Message::<S, V>::BlockResponse { epoch, block }.encode(),
                            false,
                        );
                    }
                }
            },
        }
    }

    /// Requests the finalization that ends `epoch` from `recipients`, starting
    /// a new request round.
    fn request_boundary(
        epoch: Epoch,
        recipients: Recipients<S::PublicKey>,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> Pending<S::PublicKey> {
        let awaiting = sender
            .send(
                recipients,
                wire::Message::<S, V>::BoundaryRequest(epoch.next()).encode(),
                false,
            )
            .into_iter()
            .collect();
        Pending { epoch, awaiting }
    }

    async fn produce_finalization(
        &mut self,
        epoch: Epoch,
    ) -> Option<Finalization<S, V::Commitment>> {
        let height = self.epocher.last(epoch.previous()?)?;
        self.marshal.get_finalization(height).await
    }

    async fn produce_block(&mut self, epoch: Epoch) -> Option<V::Block> {
        let height = self.epocher.last(epoch.previous()?)?;
        self.marshal.get_block(height).await
    }
}
