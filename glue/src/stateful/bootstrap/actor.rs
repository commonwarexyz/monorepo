use super::mailbox::{Mailbox, Message as MailboxMessage};
use crate::stateful::bootstrap::wire;
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Encode, Error as CodecError, Read, ReadExt as _};
use commonware_consensus::{
    marshal::{
        core::{Mailbox as MarshalMailbox, Variant},
        Identifier,
    },
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
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    Faults, N3f1, NonZeroDuration,
};
use futures::future::{self, Either};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};
use tracing::debug;

/// Configuration for the [`Bootstrap`] actor.
pub struct Config<E, D, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    D: Provider<Scope = Epoch>,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// The runtime context.
    pub context: E,
    /// Provider of epoch-specific certificate schemes for finalization verification.
    pub provider: D,
    /// The strategy to use for signature verification.
    pub strategy: T,
    /// The mailbox capacity.
    pub capacity: NonZeroUsize,
    /// Blocker used to block peers that send invalid finalizations.
    pub blocker: B,
    /// How long to wait for enough finalization replies before clearing the pending
    /// responses and re-requesting.
    pub retry_timeout: NonZeroDuration,
}

/// Bootstraps a node by adopting the highest finalization from a peer sample.
///
/// The actor asks peers for their latest finalizations when a subscriber needs a state sync floor.
/// Once a marshal is attached, it also answers peers' requests from that marshal. Delayed responses
/// to earlier requests are safe to ignore after the floor has been selected or abandoned.
pub struct Bootstrap<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    context: ContextCell<E>,
    mailbox: ActorReceiver<MailboxMessage<S, V>>,
    provider: D,
    strategy: T,
    blocker: B,
    retry_timeout: NonZeroDuration,
}

impl<E, S, D, V, T, P, B> Bootstrap<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Create a bootstrap actor and mailbox.
    pub fn new(config: Config<E, D, T, P, B>) -> (Self, Mailbox<S, V>) {
        let (sender, receiver) =
            commonware_actor::mailbox::new(config.context.child("mailbox"), config.capacity);
        let mailbox = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox: receiver,
                provider: config.provider,
                strategy: config.strategy,
                blocker: config.blocker,
                retry_timeout: config.retry_timeout,
            },
            mailbox,
        )
    }

    /// Start the bootstrap actor.
    pub fn start(
        mut self,
        net: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(net))
    }

    async fn run(
        mut self,
        (mut sender, mut receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let mut deadline = self.context.current() + self.retry_timeout.get();
        let mut finalizations = BTreeMap::new();
        let mut floor: Option<Finalization<S, V::Commitment>> = None;
        let mut floor_subscribers: Vec<oneshot::Sender<Finalization<S, V::Commitment>>> =
            Vec::new();
        let mut mailbox_drained = false;
        let mut marshal = None;

        select_loop! {
            self.context,
            on_start => {
                floor_subscribers.retain(|s| !s.is_closed());
                if mailbox_drained && marshal.is_none() && floor_subscribers.is_empty() {
                    debug!("mailbox drained without pending work, shutting down");
                    return;
                }

                let mailbox_message = if mailbox_drained {
                    Either::Right(future::pending())
                } else {
                    Either::Left(self.mailbox.recv())
                };

                let retry = if floor.is_none() && !floor_subscribers.is_empty() {
                    Either::Left(self.context.sleep_until(deadline))
                } else {
                    Either::Right(future::pending())
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
                MailboxMessage::Subscribe { response } => {
                    if let Some(ref floor) = floor {
                        response.send_lossy(floor.clone());
                        continue;
                    }

                    if marshal.is_some() && floor_subscribers.is_empty() {
                        continue;
                    }

                    let should_request = floor_subscribers.is_empty();
                    floor_subscribers.push(response);
                    if should_request {
                        Self::request_latest(&mut sender, &mut finalizations);
                        deadline = self.context.current() + self.retry_timeout.get();
                    }
                },
                MailboxMessage::Attach { marshal: attached } => {
                    if marshal.is_none() {
                        marshal = Some(attached);
                    }
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
                    wire::Tag::Request => {
                        if let Err(err) = Self::require_finished(message) {
                            commonware_p2p::block!(
                                self.blocker,
                                peer,
                                ?err,
                                "message decode failed"
                            );
                            continue;
                        }
                        let Some(marshal) = marshal.as_mut() else {
                            continue;
                        };
                        let Some(finalization) = Self::produce_latest(marshal).await else {
                            continue;
                        };
                        sender.send(
                            Recipients::One(peer),
                            wire::Message::<S, V>::Response(finalization).encode(),
                            false,
                        );
                    }
                    // OK to ignore: this may be a delayed response to a request we sent before
                    // selecting a floor or before all subscribers were dropped.
                    wire::Tag::Response if floor.is_some() || floor_subscribers.is_empty() => {
                        continue;
                    }
                    wire::Tag::Response => {
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

                        finalizations.entry(peer).or_insert(finalization);
                        self.try_select_floor(
                            &mut finalizations,
                            &mut floor,
                            &mut floor_subscribers,
                        );
                    }
                }
            },
            _ = retry => {
                debug!(reason = "deadline elapsed", "re-requesting finalizations");
                Self::request_latest(&mut sender, &mut finalizations);
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }
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
        &self,
        finalizations: &mut BTreeMap<P, Finalization<S, V::Commitment>>,
        floor: &mut Option<Finalization<S, V::Commitment>>,
        floor_subscribers: &mut Vec<oneshot::Sender<Finalization<S, V::Commitment>>>,
    ) {
        if floor.is_some() {
            return;
        }

        let (selected, replies) =
            finalizations
                .values()
                .fold((None, 0), |(selected, replies), finalization| {
                    if self.sample_size(finalization.epoch()).is_none() {
                        return (selected, replies);
                    }
                    let selected = selected
                        .is_none_or(|candidate: &Finalization<_, _>| {
                            finalization.round() > candidate.round()
                        })
                        .then_some(finalization)
                        .or(selected);
                    (selected, replies + 1)
                });
        let Some(selected) = selected else {
            return;
        };
        let Some(sample_size) = self.sample_size(selected.epoch()) else {
            return;
        };
        if replies < sample_size {
            return;
        }

        floor_subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(selected.clone());
        });
        *floor = Some(selected.clone());
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

    /// Fetches the latest [`Finalization`] from marshal, if available.
    async fn produce_latest(
        marshal: &mut MarshalMailbox<S, V>,
    ) -> Option<Finalization<S, V::Commitment>> {
        let (latest_height, _) = marshal.get_info(Identifier::Latest).await?;
        marshal.get_finalization(latest_height).await
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
