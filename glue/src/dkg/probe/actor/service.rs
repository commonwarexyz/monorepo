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
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, Epocher, FixedEpocher},
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::channel::fallible::OneshotExt as _;
use futures::future::{self, Either};
use rand_core::CryptoRng;
use tracing::debug;

/// The service phase of the DKG probe actor.
///
/// Answers peers' latest-finalization, boundary finalization, and boundary
/// block requests from the attached marshal. By construction it does not issue
/// outbound discovery requests.
pub(super) struct Service<E, S, V, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    B: Blocker<PublicKey = S::PublicKey>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) marshal: MarshalMailbox<S, V>,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
}

impl<E, S, V, B> Service<E, S, V, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runs the serving loop until the actor shuts down.
    pub(super) async fn run(
        mut self,
        mut sender: impl Sender<PublicKey = S::PublicKey>,
        mut receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        let mut mailbox_drained = false;
        select_loop! {
            self.context,
            on_start => {
                let mailbox_message = if mailbox_drained {
                    Either::Left(future::pending())
                } else {
                    Either::Right(self.mailbox.recv())
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
            },
            Ok((peer, message)) = receiver.recv() else {
                debug!("boundary receiver closed, shutting down");
                return;
            } => {
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
