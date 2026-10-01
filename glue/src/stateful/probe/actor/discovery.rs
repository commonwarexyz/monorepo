use super::service::Service;
use crate::{
    probe::sample::Sample,
    stateful::probe::{mailbox::Message, wire},
};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Buf, Decode, Encode, Error as CodecError, ReadExt};
use commonware_consensus::{
    Epochable,
    simplex::{
        marshal::core::Variant,
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
    N3f1, NonZeroDuration,
    channel::{fallible::OneshotExt, oneshot},
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use tracing::debug;

/// The discovery phase of [`Probe`](super::Probe).
///
/// Solicits peers' latest finalizations and selects the floor from a peer sample. It never answers
/// requests. See the [module documentation](crate::stateful::probe#lifecycle) for when it hands
/// off to [`Service`].
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
    pub(super) minimum_epoch: Epoch,
    pub(super) sample: Sample<P, Finalization<S, V::Commitment>>,
    pub(super) subscribers: Vec<oneshot::Sender<Finalization<S, V::Commitment>>>,
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
    /// Runs discovery until a marshal is attached and no subscriber awaits a floor, then runs
    /// [`Service`] in place.
    ///
    /// Returns early if the actor stops or the mailbox or network receiver closes.
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
                self.subscribers.retain(|s| !s.is_closed());

                if marshal.is_some() && self.subscribers.is_empty() {
                    break;
                }

                let retry = if self.sample.floor().is_none() && !self.subscribers.is_empty() {
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
                        let solicit = self.subscribers.is_empty();
                        self.subscribers.push(response);
                        if solicit {
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
                // Skip unawaited replies before decoding, so duplicates cost no certificate work
                // and are never blocked.
                if !self.sample.awaits(&peer) {
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

                if !self.verify_finalization(&peer, &finalization) {
                    continue;
                }
                if self.subscribers.is_empty() {
                    self.sample.reset();
                    continue;
                }
                self.sample.record(peer, finalization);
                self.select();
            },
            _ = retry => {
                debug!(reason = "deadline elapsed", "re-requesting finalizations");
                self.request_latest(sender);
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }

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

    /// Decodes a reply, reading its certificate with the codec config of the [`Epoch`] claimed by
    /// its [`Proposal`].
    ///
    /// Returns `Ok(None)` for a request, for a finalization below the minimum epoch, and for an
    /// epoch with no known scheme. Returns an error if the message is malformed.
    fn decode_finalization(
        &self,
        mut message: impl Buf,
    ) -> Result<Option<Finalization<S, V::Commitment>>, CodecError> {
        let tag = wire::Tag::read(&mut message)?;
        if tag != wire::Tag::Response {
            return Ok(None);
        }
        let proposal = Proposal::<V::Commitment>::read(&mut message)?;
        if proposal.epoch() < self.minimum_epoch {
            return Ok(None);
        }
        let Some(scoped) = self.provider.scoped(proposal.epoch()) else {
            return Ok(None);
        };
        let certificate =
            S::Certificate::decode_cfg(&mut message, &scoped.certificate_codec_config())?;
        Ok(Some(Finalization {
            proposal,
            certificate,
        }))
    }

    /// Returns whether `finalization` from `peer` may join the sample.
    ///
    /// Blocks `peer` if it is not a participant of the minimum epoch's committee or if
    /// `finalization` does not verify under its own epoch's scheme. Returns `false` without
    /// blocking if either scheme is unavailable, because the reply cannot be judged.
    fn verify_finalization(
        &mut self,
        peer: &P,
        finalization: &Finalization<S, V::Commitment>,
    ) -> bool {
        let Some(scheme) = self.provider.scheme(self.minimum_epoch) else {
            return false;
        };
        if scheme.participants().position(peer).is_none() {
            commonware_p2p::block!(
                self.blocker,
                peer.clone(),
                "finalization sent by non-participant"
            );
            return false;
        }

        let Some(scoped) = self.provider.scoped(finalization.epoch()) else {
            return false;
        };
        if !finalization.verify(self.context.as_present_mut(), &scoped, &self.strategy) {
            commonware_p2p::block!(self.blocker, peer.clone(), "invalid finalization");
            return false;
        }
        true
    }

    /// Selects the floor once the sample resolves and delivers it to every waiting subscriber.
    fn select(&mut self) {
        let Some(scheme) = self.provider.scheme(self.minimum_epoch) else {
            return;
        };
        let provider = &self.provider;
        let Some(floor) = self.sample.select::<N3f1, _>(
            scheme.participants().len(),
            |finalization| provider.scoped(finalization.epoch()).is_some(),
            |finalization| finalization.round(),
        ) else {
            return;
        };

        self.subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(floor.clone());
        });
    }

    /// Starts a new request round: clears the sample and solicits the minimum epoch's committee
    /// (nothing is sent if that epoch has no known scheme).
    fn request_latest(&mut self, sender: &mut impl Sender<PublicKey = P>) {
        self.sample.reset();
        let Some(scheme) = self.provider.scheme(self.minimum_epoch) else {
            return;
        };
        sender.send(
            Recipients::Some(scheme.participants().iter().cloned().collect()),
            wire::Message::<S, V>::Request.encode(),
            false,
        );
    }
}
