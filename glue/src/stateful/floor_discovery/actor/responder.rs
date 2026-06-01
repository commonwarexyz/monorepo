use crate::stateful::floor_discovery::{mailbox::Message, wire};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Encode, Error as CodecError};
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

/// The responder mode of [`FloorDiscovery`](super::FloorDiscovery).
///
/// Answers peers' `RequestLatest` with the latest finalization from the attached marshal. By
/// construction it never issues outbound requests. It is reached only after a marshal has been
/// attached.
pub(super) struct Responder<E, S, V, P, B>
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

impl<E, S, V, P, B> Responder<E, S, V, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Runs the response loop until the actor shuts down.
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
                    Either::Right(future::pending())
                } else {
                    Either::Left(self.mailbox.recv())
                };
            },
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            Some(message) = mailbox_message else {
                debug!("mailbox closed");
                mailbox_drained = true;
                continue;
            } => match message {
                // If a floor was discovered, return it to any late subscriber. A source node that
                // started responding directly has none, so its subscribers never resolve.
                Message::Subscribe { response } => {
                    if let Some(ref floor) = self.floor {
                        response.send_lossy(floor.clone());
                    }
                }
                // Already responding; an additional marshal attachment is ignored.
                Message::Attach { .. } => {}
            },
            Ok((peer, message)) = receiver.recv() else {
                debug!("network receiver closed, shutting down");
                return;
            } => {
                let mut message = message;
                let tag = match wire::Tag::read(&mut message) {
                    Ok(tag) => tag,
                    Err(err) => {
                        commonware_p2p::block!(
                            self.blocker,
                            peer,
                            ?err,
                            "message decode failed"
                        );
                        continue;
                    }
                };

                match tag {
                    wire::Tag::RequestLatest => {
                        if let Err(err) = Self::require_finished(message) {
                            commonware_p2p::block!(
                                self.blocker,
                                peer,
                                ?err,
                                "message decode failed"
                            );
                            continue;
                        }
                    }
                    wire::Tag::Finalization => {
                        // Finalizations may be delayed responses to requests we sent while in
                        // requester mode. Once responding, they are safe to ignore.
                        continue;
                    }
                }

                let Some(finalization) = self.produce_latest().await else {
                    continue;
                };
                sender.send(
                    Recipients::One(peer),
                    wire::Message::<S, V>::Finalization(finalization).encode(),
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

    fn require_finished(reader: impl Buf) -> Result<(), CodecError> {
        let remaining = reader.remaining();
        if remaining > 0 {
            return Err(CodecError::ExtraData(remaining));
        }
        Ok(())
    }
}
