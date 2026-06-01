use super::responder::Responder;
use crate::stateful::floor_discovery::{mailbox::Message, wire};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Encode, Error as CodecError, Read, ReadExt as _};
use commonware_consensus::{
    marshal::core::Variant,
    simplex::{
        scheme::Scheme,
        types::{Finalization, Proposal},
    },
    types::Epoch,
    Epochable,
};
use commonware_cryptography::{certificate::Provider, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    Faults, N3f1, NonZeroDuration,
};
use futures::future::{self, Either};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, sync::Arc};
use tracing::debug;

/// The requester mode of [`FloorDiscovery`](super::FloorDiscovery).
///
/// Solicits peers' latest finalizations and selects the highest floor from a peer sample. By
/// construction it has no marshal and never answers peers' requests. Once a marshal is attached
/// (after the floor has been consumed), it hands off to [`Responder`].
pub(super) struct Requester<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) provider: D,
    pub(super) strategy: T,
    pub(super) blocker: B,
    pub(super) retry_timeout: NonZeroDuration,
    pub(super) floor: Option<Finalization<S, V::Commitment>>,
    pub(super) floor_subscribers: Vec<oneshot::Sender<Finalization<S, V::Commitment>>>,
}

impl<E, S, D, V, T, P, B> Requester<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Runs the request loop until the actor shuts down or, once a marshal is attached after the
    /// floor is consumed, hands off to [`Responder`] (running it to completion in place).
    pub(super) async fn run(
        mut self,
        sender: &mut impl Sender<PublicKey = P>,
        receiver: &mut impl Receiver<PublicKey = P>,
    ) {
        let mut deadline = self.context.current() + self.retry_timeout.get();
        let mut finalizations = BTreeMap::new();
        let mut marshal = None;

        select_loop! {
            self.context,
            on_start => {
                self.floor_subscribers.retain(|s| !s.is_closed());

                // Hand off to responder mode once a marshal is attached and no floor seeker is left
                // waiting. Dropping all subscribers cancels discovery; if marshal is attached
                // after that, the node becomes a source and responds without a cached floor. A
                // joiner must keep its subscription alive until the floor is consumed.
                if marshal.is_some() && self.floor_subscribers.is_empty() {
                    break;
                }

                // Arm the retry timer only while actively searching for a floor.
                let retry = if self.floor.is_none() && !self.floor_subscribers.is_empty() {
                    Either::Left(self.context.sleep_until(deadline))
                } else {
                    Either::Right(future::pending())
                };
            },
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return;
            } => match message {
                Message::Subscribe { response } => match self.floor {
                    Some(ref floor) => {
                        response.send_lossy(floor.clone());
                    }
                    None => {
                        let should_request = self.floor_subscribers.is_empty();
                        self.floor_subscribers.push(response);
                        if should_request {
                            Self::request_latest(sender, &mut finalizations);
                            deadline = self.context.current() + self.retry_timeout.get();
                        }
                    }
                },
                Message::Attach { marshal: attached } => {
                    marshal = Some(attached);
                }
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
                        }
                        continue;
                    }
                    wire::Tag::Finalization if self.floor.is_some() => {
                        continue;
                    }
                    wire::Tag::Finalization => {}
                }

                let read = match self.read_finalization(message) {
                    Ok(result) => result,
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
                let Some((finalization, scheme)) = read else {
                    continue;
                };
                let Some((peer, finalization)) =
                    self.verify_finalization(peer, finalization, scheme.as_ref())
                else {
                    continue;
                };
                if self.floor_subscribers.is_empty() {
                    finalizations.clear();
                    continue;
                }
                finalizations.entry(peer).or_insert(finalization);
                self.try_select_floor(&mut finalizations);
            },
            _ = retry => {
                debug!(reason = "deadline elapsed", "re-requesting finalizations");
                Self::request_latest(sender, &mut finalizations);
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }

        // Transition: a marshal was attached after the floor was discovered and consumed. Run
        // responder mode to completion in place.
        Responder {
            context: self.context,
            mailbox: self.mailbox,
            marshal: marshal.expect("transition requires an attached marshal"),
            blocker: self.blocker,
            floor: self.floor,
        }
        .run(sender, receiver)
        .await;
    }

    /// Reads a finalization using the certificate codec config for its epoch.
    ///
    /// If no scheme is available for the finalization's epoch, the payload is ignored without
    /// blocking because it cannot be judged.
    fn read_finalization(
        &self,
        mut reader: impl Buf,
    ) -> Result<Option<(Finalization<S, V::Commitment>, Arc<S>)>, CodecError> {
        let proposal = Proposal::read(&mut reader)?;
        let Some(scheme) = self.scheme(proposal.epoch()) else {
            return Ok(None);
        };

        let cfg = scheme.certificate_codec_config();
        let certificate = S::Certificate::read_cfg(&mut reader, &cfg)?;
        Self::require_finished(reader)?;

        Ok(Some((
            Finalization {
                proposal,
                certificate,
            },
            scheme,
        )))
    }

    fn require_finished(reader: impl Buf) -> Result<(), CodecError> {
        let remaining = reader.remaining();
        if remaining > 0 {
            return Err(CodecError::ExtraData(remaining));
        }
        Ok(())
    }

    /// Verifies a [`Finalization`] from `peer`.
    ///
    /// Peers that send invalid finalizations are blocked.
    fn verify_finalization(
        &mut self,
        peer: P,
        finalization: Finalization<S, V::Commitment>,
        scheme: &S,
    ) -> Option<(P, Finalization<S, V::Commitment>)> {
        if !finalization.verify(self.context.as_present_mut(), scheme, &self.strategy) {
            commonware_p2p::block!(self.blocker, peer, "invalid finalization");
            return None;
        }
        Some((peer, finalization))
    }

    /// Attempts to select the highest finalization from a sample of distinct peers.
    fn try_select_floor(
        &mut self,
        finalizations: &mut BTreeMap<P, Finalization<S, V::Commitment>>,
    ) {
        if self.floor.is_some() {
            return;
        }

        let (floor, replies) =
            finalizations
                .values()
                .fold((None, 0), |(floor, replies), finalization| {
                    if self.sample_size(finalization.epoch()).is_none() {
                        return (floor, replies);
                    }
                    let floor = floor
                        .is_none_or(|candidate: &Finalization<_, _>| {
                            finalization.round() > candidate.round()
                        })
                        .then_some(finalization)
                        .or(floor);
                    (floor, replies + 1)
                });
        let Some(floor) = floor else {
            return;
        };
        let Some(sample_size) = self.sample_size(floor.epoch()) else {
            return;
        };
        if replies < sample_size {
            return;
        }

        self.floor_subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(floor.clone());
        });
        self.floor = Some(floor.clone());
    }

    /// Clears any pending responses and re-requests peers' latest [`Finalization`].
    fn request_latest(
        sender: &mut impl Sender<PublicKey = P>,
        finalizations: &mut BTreeMap<P, Finalization<S, V::Commitment>>,
    ) {
        finalizations.clear();
        sender.send(
            Recipients::All,
            wire::Message::<S, V>::RequestLatest.encode(),
            false,
        );
    }

    /// Returns the certificate scheme to verify finalizations at `epoch`, preferring a global
    /// verifier and falling back to the epoch-scoped scheme.
    fn scheme(&self, epoch: Epoch) -> Option<Arc<S>> {
        self.provider.all().or_else(|| self.provider.scoped(epoch))
    }

    /// Returns the number of distinct peer replies (`f + 1`) required for `epoch`.
    fn sample_size(&self, epoch: Epoch) -> Option<usize> {
        self.scheme(epoch)
            .map(|scheme| N3f1::max_faults(scheme.participants().len()) as usize + 1)
    }
}
