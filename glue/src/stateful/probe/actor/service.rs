use crate::stateful::probe::{mailbox::Message, sample, wire};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Encode, ReadExt as _};
use commonware_consensus::simplex::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    scheme::Scheme,
    types::Finalization,
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::channel::fallible::OneshotExt;
use futures::future::{self, Either};
use rand_core::CryptoRng;
use tracing::debug;

/// The service phase of [`Probe`](super::Probe).
///
/// Answers each peer `Request` with the attached marshal's latest finalization, if any, and never
/// issues requests. See the [module documentation](crate::stateful::probe#lifecycle) for when it
/// starts.
pub(super) struct Service<E, S, V, P, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
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

impl<E, S, V, P, B> Service<E, S, V, P, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Runs the service loop until the actor stops or the network receiver closes.
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
                // Serve the selected floor, if any. Without one, dropping `response` closes the
                // subscription.
                Message::Subscribe { response } => {
                    if let Some(ref floor) = self.floor {
                        response.send_lossy(floor.clone());
                    }
                }
                Message::Attach { .. } => {}
            },
            Ok((peer, mut message)) = receiver.recv() else {
                debug!("network receiver closed, shutting down");
                return;
            } => {
                let tag = match wire::Tag::read(&mut message) {
                    Ok(tag) => tag,
                    Err(err) => {
                        commonware_p2p::block!(self.blocker, peer, ?err, "tag decode failed");
                        continue;
                    }
                };
                if tag != wire::Tag::Request {
                    continue;
                }
                let Some(finalization) = sample::latest_finalization(&self.marshal).await else {
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
}
