use crate::dkg::{
    anchor::{mailbox::Message, wire, ActorArtifact},
    ReshareBlock,
};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::Encode as _;
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::scheme::Scheme,
    types::{Epoch, Epocher, FixedEpocher},
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::channel::fallible::OneshotExt as _;
use futures::{
    future::{self, Either},
    join,
};
use rand_core::CryptoRngCore;
use tracing::debug;

/// The boundary-serving phase of the anchor actor.
///
/// Answers peers' boundary requests from the attached marshal. By construction
/// it does not listen to the Simplex certificate channel or issue outbound
/// discovery requests.
pub(super) struct Serving<E, S, V, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
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

impl<E, S, V, B> Serving<E, S, V, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
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
                let epoch = match wire::read_request(message) {
                    Ok(Some(epoch)) => epoch,
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
                let Some(response) = self.produce(epoch).await else {
                    continue;
                };
                sender.send(
                    Recipients::One(peer),
                    wire::Message::<S, V>::Response(response).encode(),
                    false,
                );
            },
        }
    }

    async fn produce(&mut self, epoch: Epoch) -> Option<wire::Response<S, V>> {
        let height = self.epocher.last(epoch.previous()?)?;
        let (finalization, block) = join!(
            self.marshal.get_finalization(height),
            self.marshal.get_block(height)
        );
        Some(wire::Response {
            finalization: finalization?,
            block: block?,
        })
    }
}
