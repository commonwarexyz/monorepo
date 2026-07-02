use super::serving::Serving;
use crate::dkg::{
    anchor::{mailbox::Message, wire, ActorArtifact, Artifact},
    types::{EpochInfo, Payload},
    ReshareBlock,
};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Decode as _, Encode as _, Read};
use commonware_consensus::{
    marshal::core::Variant,
    simplex::{scheme::Scheme, types::Certificate},
    types::{Epoch, Epocher, FixedEpocher, Height},
    Epochable, Heightable,
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Channel, Message as P2pMessage, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    NonZeroDuration,
};
use futures::future::{self, Either};
use rand_core::CryptoRngCore;
use tracing::{debug, warn};

pub(super) struct Pending {
    height: Height,
    epoch: Epoch,
}

/// The discovery phase of the anchor actor.
///
/// Waits for subscribers, listens to the Simplex certificate channel, and uses
/// the first verifiable target finalization to fetch the previous epoch boundary
/// block. Once the boundary block yields the target epoch's public
/// [`Artifact`], discovery resolves all subscribers and can hand off to
/// [`Serving`] after marshal is attached.
pub(super) struct Discovery<E, S, V, T, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) verifier: S,
    pub(super) genesis: EpochInfo<<V::ApplicationBlock as ReshareBlock>::Variant, S::PublicKey>,
    pub(super) strategy: T,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    pub(super) retry_timeout: NonZeroDuration,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
    pub(super) subscribers: Vec<oneshot::Sender<ActorArtifact<S, V>>>,
    pub(super) pending: Option<Pending>,
}

impl<E, S, V, T, B> Discovery<E, S, V, T, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runs discovery until shutdown or until it can hand off to [`Serving`].
    pub(super) async fn run<BSE, BRE>(
        mut self,
        mut certificate_receiver: mpsc::Receiver<(Channel, P2pMessage<S::PublicKey>)>,
        mut boundary_sender: BSE,
        mut boundary_receiver: BRE,
    ) where
        BSE: Sender<PublicKey = S::PublicKey>,
        BRE: Receiver<PublicKey = S::PublicKey>,
    {
        let mut marshal = None;
        let mut deadline = self.context.current() + self.retry_timeout.get();

        select_loop! {
            self.context,
            on_start => {
                self.subscribers
                    .retain(|subscriber| !subscriber.is_closed());
                if marshal.is_some() && self.subscribers.is_empty() {
                    break;
                }

                // Arm the retry timer only while a boundary request is outstanding.
                let retry = if self.pending.is_some() && self.artifact.is_none() {
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
                Message::Subscribe { response } => self.subscribe(response),
                Message::Attach { marshal: attached } => {
                    marshal = Some(attached);
                }
            },
            Some((_channel, (peer, message))) = certificate_receiver.recv() else {
                debug!("certificate receiver closed, shutting down");
                return;
            } => {
                if self.handle_certificate(peer, message, &mut boundary_sender) {
                    deadline = self.context.current() + self.retry_timeout.get();
                }
            },
            Ok((peer, message)) = boundary_receiver.recv() else {
                debug!("boundary receiver closed, shutting down");
                return;
            } => {
                self.handle_boundary_response(peer, message);
            },
            _ = retry => {
                if let Some(pending) = self.pending.as_ref() {
                    debug!(epoch = %pending.epoch, "re-requesting boundary block");
                    Self::request_boundary(pending.epoch, &mut boundary_sender);
                    deadline = self.context.current() + self.retry_timeout.get();
                }
            },
        }

        Serving {
            context: self.context,
            mailbox: self.mailbox,
            marshal: marshal.expect("serving requires attached marshal"),
            blocker: self.blocker,
            epocher: self.epocher,
            artifact: self.artifact,
        }
        .run(boundary_sender, boundary_receiver)
        .await;
    }

    fn subscribe(&mut self, response: oneshot::Sender<ActorArtifact<S, V>>) {
        if let Some(artifact) = &self.artifact {
            response.send_lossy(artifact.clone());
            return;
        }
        self.subscribers.push(response);
    }

    /// Handle an incoming certificate, returning whether a boundary request was
    /// broadcast (so the caller can arm the retry timer).
    fn handle_certificate(
        &mut self,
        peer: S::PublicKey,
        message: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        if self.artifact.is_some() || self.subscribers.is_empty() {
            return false;
        }

        let certificate = match Certificate::<S, V::Commitment>::decode_cfg(
            message,
            &self.verifier.certificate_codec_config(),
        ) {
            Ok(certificate) => certificate,
            Err(err) => {
                commonware_p2p::block!(self.blocker, peer, ?err, "invalid bootstrap certificate");
                return false;
            }
        };
        let Certificate::Finalization(finalization) = certificate else {
            return false;
        };
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| finalization.epoch() <= pending.epoch)
        {
            return false;
        }
        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap finalization");
            return false;
        }
        if finalization.epoch().is_zero() {
            self.resolve(Artifact {
                epoch: Epoch::zero(),
                finalization: None,
                info: self.genesis.clone(),
            });
            return false;
        }

        let Some(height) = finalization
            .epoch()
            .previous()
            .and_then(|e| self.epocher.last(e))
        else {
            warn!(
                epoch = %finalization.epoch(),
                "bootstrap finalization epoch has no boundary height"
            );
            return false;
        };
        Self::request_boundary(finalization.epoch(), boundary_sender);
        self.pending = Some(Pending {
            height,
            epoch: finalization.epoch(),
        });
        true
    }

    /// Broadcast a request for the boundary block of `epoch` to all peers.
    fn request_boundary(epoch: Epoch, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        boundary_sender.send(
            Recipients::All,
            wire::Message::<S, V>::Request(epoch).encode(),
            false,
        );
    }

    fn handle_boundary_response(&mut self, peer: S::PublicKey, message: impl Buf) {
        let Some(pending) = self.pending.take() else {
            return;
        };

        let response = match wire::read_response::<S, V>(
            message,
            &self.verifier.certificate_codec_config(),
            &self.block_codec_config,
        ) {
            Ok(Some(response)) => response,
            Ok(None) => {
                self.pending = Some(pending);
                return;
            }
            Err(err) => {
                commonware_p2p::block!(
                    self.blocker,
                    peer,
                    ?err,
                    "invalid bootstrap boundary response"
                );
                self.pending = Some(pending);
                return;
            }
        };

        let response_epoch = response.finalization.epoch().next();
        if response_epoch < pending.epoch {
            debug!(
                response_epoch = %response_epoch,
                pending_epoch = %pending.epoch,
                "ignoring stale bootstrap boundary response"
            );
            self.pending = Some(pending);
            return;
        }

        match self.artifact_from_response(&pending, response) {
            Some(artifact) => self.resolve(artifact),
            None => {
                commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
                self.pending = Some(pending);
            }
        }
    }

    fn artifact_from_response(
        &mut self,
        pending: &Pending,
        response: wire::Response<S, V>,
    ) -> Option<ActorArtifact<S, V>> {
        if response.block.height() != pending.height {
            return None;
        }
        if response.finalization.epoch() != pending.epoch.previous()? {
            return None;
        }
        if response.finalization.proposal.payload != V::commitment(&response.block) {
            return None;
        }
        if !response.finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            return None;
        }

        let block = V::into_inner(response.block);
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            return None;
        };
        if info.epoch != pending.epoch {
            return None;
        }

        Some(Artifact {
            epoch: info.epoch,
            finalization: Some(response.finalization),
            info,
        })
    }

    fn resolve(&mut self, artifact: ActorArtifact<S, V>) {
        self.subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(artifact.clone());
        });
        self.artifact = Some(artifact);
    }
}
