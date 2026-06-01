use super::serving::Serving;
use crate::stateful::floor_discovery::{mailbox::Message, wire};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Decode, Encode, Error as CodecError, ReadExt};
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

/// The discovery phase of [`FloorDiscovery`](super::FloorDiscovery).
///
/// Solicits peers' latest finalizations and selects the highest floor from a peer sample. By
/// construction it has no marshal and never serves finalizations. Once a marshal is attached
/// (after the floor has been consumed), it hands off to [`Serving`].
pub(super) struct Discovery<E, S, D, V, T, P, B>
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

impl<E, S, D, V, T, P, B> Discovery<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Runs the discovery loop until the actor shuts down or, once a marshal is attached after
    /// the floor is consumed, hands off to [`Serving`] (running it to completion in place).
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

                // Hand off to serving once a marshal is attached and no floor seeker is left
                // waiting. Dropping all subscribers cancels discovery; if marshal is attached
                // after that, the node becomes a source and serves without a cached floor. A
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
                let finalization = match self.decode_finalization(message) {
                    Ok(Some(finalization)) => finalization,
                    Ok(None) => continue,
                    Err(err) => {
                        commonware_p2p::block!(
                            self.blocker,
                            peer,
                            ?err,
                            "invalid finalization message"
                        );
                        continue;
                    }
                };

                // Once a floor has been selected, ignore further finalizations.
                if self.floor.is_some() {
                    continue;
                }
                let Some((peer, finalization)) = self.verify_finalization(peer, finalization)
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
        // the serving phase to completion in place.
        Serving {
            context: self.context,
            mailbox: self.mailbox,
            marshal: marshal.expect("transition requires an attached marshal"),
            blocker: self.blocker,
            floor: self.floor,
        }
        .run(sender, receiver)
        .await;
    }

    /// Decodes a [`Finalization`] from a message, using the claimed [`Epoch`] within
    /// the [`Proposal`] to look up the appropriate certificate scheme for decoding.
    fn decode_finalization(
        &self,
        mut message: impl Buf,
    ) -> Result<Option<Finalization<S, V::Commitment>>, CodecError> {
        let tag = wire::Tag::read(&mut message)?;
        if tag != wire::Tag::Response {
            return Ok(None);
        }
        let proposal = Proposal::<V::Commitment>::read(&mut message)?;
        let Some(scheme) = self.scheme(proposal.epoch()) else {
            return Ok(None);
        };
        S::Certificate::decode_cfg(&mut message, &scheme.certificate_codec_config()).map(
            |certificate| {
                Some(Finalization {
                    proposal,
                    certificate,
                })
            },
        )
    }

    /// Verifies a [`Finalization`] from `peer`.
    ///
    /// Peers that send invalid finalizations are blocked. If no scheme is available for the
    /// finalization's epoch, the payload is ignored without blocking because it cannot be judged.
    fn verify_finalization(
        &mut self,
        peer: P,
        finalization: Finalization<S, V::Commitment>,
    ) -> Option<(P, Finalization<S, V::Commitment>)> {
        // Verify against the certificate scheme for the finalization's epoch. If no scheme is
        // available for that epoch, we cannot judge the payload, so ignore it without blocking.
        let scheme = self.scheme(finalization.epoch())?;
        if !finalization.verify(
            self.context.as_present_mut(),
            scheme.as_ref(),
            &self.strategy,
        ) {
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
            wire::Message::<S, V>::Request.encode(),
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
