use super::service::Service;
use crate::stateful::probe::{mailbox::Message, sample::Sample, wire};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Decode, Encode, Error as CodecError, ReadExt};
use commonware_consensus::{
    Epochable,
    marshal::core::Variant,
    simplex::{
        scheme::Scheme,
        types::{Finalization, Proposal},
    },
    types::Epoch,
};
use commonware_cryptography::{
    PublicKey,
    certificate::{Provider, Verifier},
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    NonZeroDuration,
    channel::{fallible::OneshotExt, oneshot},
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use tracing::debug;

/// The discovery phase of [`Probe`](super::Probe).
///
/// Solicits peers' latest finalizations and selects the highest floor from a peer sample. By
/// construction it has no marshal and never serves finalizations. Once a marshal is attached
/// (after the floor has been consumed), it hands off to [`Service`].
pub(super) struct Discovery<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment, PublicKey = P>,
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
    pub(super) sample: Sample<S, V::Commitment>,
    pub(super) floor_subscribers: Vec<oneshot::Sender<Finalization<S, V::Commitment>>>,
}

impl<E, S, D, V, T, P, B> Discovery<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment, PublicKey = P>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Runs the discovery loop until the actor shuts down or, once a marshal is attached after
    /// the floor is consumed, hands off to [`Service`] (running it to completion in place).
    pub(super) async fn run(
        mut self,
        sender: &mut impl Sender<PublicKey = P>,
        receiver: &mut impl Receiver<PublicKey = P>,
    ) {
        let mut deadline = self.context.current() + self.retry_timeout.get();
        let mut marshal = None;

        select_loop! {
            self.context,
            on_start => {
                self.floor_subscribers.retain(|s| !s.is_closed());

                // Hand off to service once a marshal is attached and no floor seeker is left
                // waiting. Dropping all subscribers cancels discovery; if marshal is attached
                // after that, the node becomes a source and serves without a cached floor. A
                // joiner must keep its subscription alive until the floor is consumed.
                if marshal.is_some() && self.floor_subscribers.is_empty() {
                    break;
                }

                // Arm the retry timer only while actively searching for a floor.
                let retry = if self.sample.floor().is_none() && !self.floor_subscribers.is_empty() {
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
                Message::Subscribe { response } => match self.sample.floor() {
                    Some(floor) => {
                        response.send_lossy(floor.clone());
                    }
                    None => {
                        let should_request = self.floor_subscribers.is_empty();
                        self.floor_subscribers.push(response);
                        if should_request {
                            self.request_latest(sender);
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
                // Once a floor has been selected or a peer has contributed this request
                // round, skip its replies before decoding or verifying to avoid useless
                // certificate work.
                if !self.sample.pending(&peer) {
                    continue;
                }

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

                let Some((peer, finalization)) = self.verify_finalization(peer, finalization)
                else {
                    continue;
                };
                if self.floor_subscribers.is_empty() {
                    self.sample.reset();
                    continue;
                }
                self.sample.record(peer, finalization);
                self.try_select_floor();
            },
            _ = retry => {
                debug!(reason = "deadline elapsed", "re-requesting finalizations");
                self.request_latest(sender);
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }

        // Transition: a marshal was attached after the floor was discovered and consumed. Run
        // the service phase to completion in place.
        Service {
            context: self.context,
            mailbox: self.mailbox,
            marshal: marshal.expect("transition requires an attached marshal"),
            blocker: self.blocker,
            floor: self.sample.floor().cloned(),
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
        if proposal.epoch() < self.sample.minimum_epoch() {
            return Ok(None);
        }
        let Some(certificate_codec_config) = self.certificate_codec_config(proposal.epoch()) else {
            return Ok(None);
        };
        let certificate = S::Certificate::decode_cfg(&mut message, &certificate_codec_config)?;
        Ok(Some(Finalization {
            proposal,
            certificate,
        }))
    }

    /// Verifies a [`Finalization`] from `peer`.
    ///
    /// Peers outside the solicited participant set or sending invalid finalizations are blocked.
    /// If no scheme is available for the finalization's epoch, the payload is ignored without
    /// blocking because it cannot be judged.
    fn verify_finalization(
        &mut self,
        peer: P,
        finalization: Finalization<S, V::Commitment>,
    ) -> Option<(P, Finalization<S, V::Commitment>)> {
        let response_epoch = finalization.epoch();
        let sample_scheme = self.provider.scheme(self.sample.minimum_epoch())?;
        if sample_scheme.participants().position(&peer).is_none() {
            commonware_p2p::block!(self.blocker, peer, "finalization sent by non-participant");
            return None;
        }

        // Verify against the certificate scheme for the finalization's epoch. If no verifier is
        // available for that epoch, we cannot judge the payload, so ignore it without blocking.
        let scoped = self.provider.scoped(response_epoch)?;
        if !finalization.verify(self.context.as_present_mut(), &scoped, &self.strategy) {
            commonware_p2p::block!(self.blocker, peer, "invalid finalization");
            return None;
        }
        Some((peer, finalization))
    }

    /// Attempts to select the highest finalization from a sample of distinct peers.
    fn try_select_floor(&mut self) {
        let Some(scheme) = self.provider.scheme(self.sample.minimum_epoch()) else {
            return;
        };
        let provider = &self.provider;
        let Some(floor) = self
            .sample
            .select(scheme.participants().len(), |finalization| {
                provider.scoped(finalization.epoch()).is_some()
            })
        else {
            return;
        };

        self.floor_subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(floor.clone());
        });
    }

    /// Clears any pending responses and requests the current committee's latest [`Finalization`].
    fn request_latest(&mut self, sender: &mut impl Sender<PublicKey = P>) {
        self.sample.reset();
        let Some(scheme) = self.provider.scheme(self.sample.minimum_epoch()) else {
            return;
        };
        sender.send(
            Recipients::Some(scheme.participants().iter().cloned().collect()),
            wire::Message::<S, V>::Request.encode(),
            false,
        );
    }

    /// Returns the certificate codec config for `epoch`.
    fn certificate_codec_config(
        &self,
        epoch: Epoch,
    ) -> Option<<S::Certificate as commonware_codec::Read>::Cfg> {
        self.provider
            .scoped(epoch)
            .map(|scoped| scoped.certificate_codec_config())
    }
}
