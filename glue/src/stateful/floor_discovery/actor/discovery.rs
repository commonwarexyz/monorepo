use super::serving::Serving;
use crate::stateful::floor_discovery::{mailbox::Message, wire};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Decode, Encode};
use commonware_consensus::{
    marshal::core::Variant,
    simplex::{scheme::Scheme, types::Finalization},
    types::Epoch,
    Epochable,
};
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    PublicKey,
};
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
use std::{collections::HashMap, ops::ControlFlow, sync::Arc};
use tracing::debug;

/// The discovery phase of [`FloorDiscovery`](super::FloorDiscovery).
///
/// Solicits peers' latest finalizations and selects a floor agreed upon by a threshold of
/// distinct peers. By construction it has no marshal and never serves finalizations. Once a
/// marshal is attached (after the floor has been consumed), it hands off to [`Serving`].
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
        let mut finalizations = HashMap::new();
        let mut marshal = None;

        select_loop! {
            self.context,
            on_start => {
                self.floor_subscribers.retain(|s| !s.is_closed());

                // Hand off to serving once a marshal is attached and no floor seeker is left
                // waiting. A node that never needed a floor (a source) attaches with none and
                // transitions immediately; a joiner attaches only after its floor was consumed.
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
                // Block peers whose payloads do not decode. Discovery cannot serve, so peer
                // requests are ignored.
                let cfg = <S as CertificateScheme>::certificate_codec_config_unbounded();
                let message = match wire::Message::<S, V>::decode_cfg(message, &cfg) {
                    Ok(message) => message,
                    Err(err) => {
                        commonware_p2p::block!(self.blocker, peer, ?err, "finalization decode failed");
                        continue;
                    }
                };
                let wire::Message::Finalization(finalization) = message else {
                    continue;
                };

                // Once a floor has been selected, ignore further finalizations.
                if self.floor.is_some() {
                    continue;
                }
                let Some((peer, finalization)) = self.verify_finalization(peer, finalization) else {
                    continue;
                };
                if self.floor_subscribers.is_empty() {
                    finalizations.clear();
                    continue;
                }
                finalizations.entry(peer).or_insert(finalization);

                // If the threshold is no longer reachable with the responses gathered so far,
                // retry immediately rather than waiting.
                if self.try_select_floor(&mut finalizations) {
                    debug!(reason = "threshold unreachable", "re-requesting finalizations");
                    Self::request_latest(sender, &mut finalizations);
                    deadline = self.context.current() + self.retry_timeout.get();
                }
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

    /// Attempts to select a floor agreed upon by a threshold of distinct peers. Each candidate
    /// finalization is judged against the threshold for its own epoch. If one is found, sets the
    /// floor, notifies all subscribers, and clears the pending responses.
    ///
    /// Returns `true` if no candidate can still reach its epoch's threshold given the responses
    /// gathered so far (the caller should retry); `false` if a floor was selected or remains
    /// reachable.
    fn try_select_floor(
        &mut self,
        finalizations: &mut HashMap<P, Finalization<S, V::Commitment>>,
    ) -> bool {
        if self.floor.is_some() {
            return false;
        }

        let responded = finalizations.len();

        // Select the first finalized proposal backed by a threshold of peers for its epoch,
        // breaking as soon as one is found. Otherwise, fold across candidates to learn whether
        // any could still reach its epoch's threshold if every outstanding peer agreed. Different
        // peers may carry different valid certificates for the same finalized proposal.
        let selected = {
            let counts = finalizations.values().fold(
                HashMap::<_, (usize, _)>::new(),
                |mut counts, finalization| {
                    counts
                        .entry(finalization.proposal.clone())
                        .and_modify(|(count, _)| *count += 1)
                        .or_insert((1, finalization));
                    counts
                },
            );
            counts.iter().try_fold(
                counts.is_empty(),
                |reachable, (_, &(count, finalization))| {
                    let Some(threshold) = self.threshold(finalization.epoch()) else {
                        // Unknown epoch: cannot judge, so do not give up on it.
                        return ControlFlow::Continue(true);
                    };
                    if count >= threshold {
                        return ControlFlow::Break(finalization.clone());
                    }
                    let outstanding = self
                        .participants(finalization.epoch())
                        .unwrap_or(0)
                        .saturating_sub(responded);
                    ControlFlow::Continue(reachable || count + outstanding >= threshold)
                },
            )
        };

        match selected {
            ControlFlow::Break(floor) => {
                self.floor_subscribers.drain(..).for_each(|subscriber| {
                    subscriber.send_lossy(floor.clone());
                });
                self.floor = Some(floor);
                finalizations.clear();
                finalizations.shrink_to_fit();
                false
            }
            ControlFlow::Continue(reachable) => !reachable,
        }
    }

    /// Clears any pending responses and re-requests peers' latest [`Finalization`].
    fn request_latest(
        sender: &mut impl Sender<PublicKey = P>,
        finalizations: &mut HashMap<P, Finalization<S, V::Commitment>>,
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

    /// Returns the number of participants for `epoch`, if a scheme is available.
    fn participants(&self, epoch: Epoch) -> Option<usize> {
        self.scheme(epoch).map(|scheme| scheme.participants().len())
    }

    /// Returns the number of distinct peers (`f + 1`) that must agree for `epoch`.
    fn threshold(&self, epoch: Epoch) -> Option<usize> {
        self.participants(epoch)
            .map(|n| N3f1::max_faults(n) as usize + 1)
    }
}
