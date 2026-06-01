use crate::stateful::floor_discovery::{mailbox::Message, wire};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Encode, ReadExt as _};
use commonware_consensus::{
    marshal::{
        core::{Mailbox as MarshalMailbox, Variant},
        Identifier,
    },
    simplex::{scheme::Scheme, types::Finalization},
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::channel::fallible::OneshotExt;
use futures::future::{self, Either};
use rand_core::CryptoRngCore;
use tracing::debug;

/// The serving phase of [`FloorDiscovery`](super::FloorDiscovery).
///
/// Answers peers' `Request` with the latest finalization from the attached marshal. By
/// construction it never issues outbound requests. It is reached only after discovery has
/// consumed its floor and a marshal has been attached.
pub(super) struct Serving<E, S, V, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) marshal: MarshalMailbox<S, V>,
    pub(super) blocker: B,
    pub(super) floor: Option<Finalization<S, V::Commitment>>,
}

impl<E, S, V, P, B> Serving<E, S, V, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Runs the serving loop until the actor shuts down.
    pub(super) async fn run(
        mut self,
        sender: &mut impl Sender<PublicKey = P>,
        receiver: &mut impl Receiver<PublicKey = P>,
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
            },
            Some(message) = mailbox_message else {
                mailbox_drained = true;
                continue;
            } => match message {
                // If a floor was discovered, serve it to any late subscriber. A source node that
                // started serving directly has none, so its subscribers never resolve.
                Message::Subscribe { response } => {
                    if let Some(ref floor) = self.floor {
                        response.send_lossy(floor.clone());
                    }
                }
                // Already serving; an additional marshal attachment is ignored.
                Message::Attach { .. } => {}
            },
            Ok((peer, mut message)) = receiver.recv() else {
                debug!("network receiver closed, shutting down");
                return;
            } => {
                let tag = match wire::Tag::read(&mut message) {
                    Ok(tag) => tag,
                    Err(err) => {
                        commonware_p2p::block!(
                            self.blocker,
                            peer,
                            ?err,
                            "tag decode failed"
                        );
                        continue;
                    }
                };
                if tag != wire::Tag::Request {
                    continue;
                }
                let Some(finalization) = self.produce_latest().await else {
                    continue;
                };
                sender.send(
                    Recipients::One(peer),
                    wire::Message::<S, V>::Response(finalization).encode(),
                    false,
                );
            },
        }
    }

    /// Fetches the latest [`Finalization`] from marshal, if available.
    async fn produce_latest(&mut self) -> Option<Finalization<S, V::Commitment>> {
        let (latest_height, _) = self.marshal.get_info(Identifier::Latest).await?;
        self.marshal.get_finalization(latest_height).await
    }
}
