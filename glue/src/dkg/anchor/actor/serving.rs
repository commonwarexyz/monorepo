use crate::dkg::{
    ReshareBlock,
    anchor::{ActorArtifact, mailbox::Message, wire},
};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::{
    Reporter as _,
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::{
        scheme::Scheme,
        types::{Activity, Certificate, Finalization},
    },
    types::{Epoch, Epocher, FixedEpocher, Round},
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Channel, Message as P2pMessage, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::channel::{fallible::OneshotExt as _, mpsc};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use tracing::debug;

/// The boundary-serving phase of the anchor actor.
///
/// Answers peers' boundary finalization and block requests from the attached
/// marshal. It also keeps consuming the Simplex certificate backup channel:
/// finalizations that verify under the all-epoch verifier are forwarded to
/// marshal, so block delivery keeps advancing while no epoch-scoped consensus
/// engine is registered for the certificates' epoch (e.g., while a state-synced
/// node follows an epoch whose public info it has not learned yet). It does not
/// issue outbound discovery requests.
pub(super) struct Serving<E, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) marshal: MarshalMailbox<S, V>,
    pub(super) verifier: S,
    pub(super) strategy: T,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
    pub(super) latest: Option<Round>,
}

impl<E, S, V, T, B> Serving<E, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runs the serving loop until the actor shuts down.
    pub(super) async fn run(
        mut self,
        mut certificates: mpsc::Receiver<(Channel, P2pMessage<S::PublicKey>)>,
        mut sender: impl Sender<PublicKey = S::PublicKey>,
        mut receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        let mut mailbox_drained = false;
        let mut certificates_drained = false;
        select_loop! {
            self.context,
            on_start => {
                let mailbox_message = if mailbox_drained {
                    Either::Left(future::pending())
                } else {
                    Either::Right(self.mailbox.recv())
                };
                let certificate_message = if certificates_drained {
                    Either::Left(future::pending())
                } else {
                    Either::Right(certificates.recv())
                };
            },
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            Some(message) = mailbox_message else {
                mailbox_drained = true;
                continue;
            } => match message {
                Message::Subscribe { response } => {
                    if let Some(artifact) = &self.artifact {
                        response.send_lossy(artifact.clone());
                    }
                }
                Message::Attach { .. } => {}
            },
            Some((_channel, (peer, message))) = certificate_message else {
                certificates_drained = true;
                continue;
            } => {
                self.handle_certificate(peer, message);
            },
            Ok((peer, message)) = receiver.recv() else {
                debug!("boundary receiver closed, shutting down");
                return;
            } => {
                let request = match wire::read_request(message) {
                    Ok(Some(request)) => request,
                    Ok(None) => continue,
                    Err(err) => {
                        commonware_p2p::block!(
                            self.blocker,
                            peer,
                            ?err,
                            "invalid bootstrap boundary request"
                        );
                        continue;
                    }
                };
                match request {
                    wire::Request::Finalization(epoch) => {
                        let Some(finalization) = self.produce_finalization(epoch).await else {
                            continue;
                        };
                        sender.send(
                            Recipients::One(peer),
                            wire::Message::<S, V>::FinalizationResponse(finalization).encode(),
                            false,
                        );
                    }
                    wire::Request::Block(epoch) => {
                        let Some(block) = self.produce_block(epoch).await else {
                            continue;
                        };
                        sender.send(
                            Recipients::One(peer),
                            wire::Message::<S, V>::BlockResponse { epoch, block }.encode(),
                            false,
                        );
                    }
                }
            },
        }
    }

    /// Forward a strictly-newer verified finalization from the certificate
    /// backup channel to marshal.
    ///
    /// The backup channel only carries certificates for epochs without a
    /// registered consensus subchannel, so this is the sole path that advances
    /// marshal through an epoch the node holds no epoch-scoped scheme for.
    fn handle_certificate(&mut self, peer: S::PublicKey, message: impl Buf) {
        let certificate = match Certificate::<S, V::Commitment>::decode_cfg(
            message,
            &self.verifier.certificate_codec_config(),
        ) {
            Ok(certificate) => certificate,
            Err(err) => {
                commonware_p2p::block!(self.blocker, peer, ?err, "invalid bootstrap certificate");
                return;
            }
        };
        let Certificate::Finalization(finalization) = certificate else {
            return;
        };
        // Older rounds carry nothing marshal cannot derive from the newest:
        // marshal backfills finalizations and blocks below any reported round.
        // The gate only suppresses redundant verification and reports.
        if self
            .latest
            .is_some_and(|latest| finalization.round() <= latest)
        {
            return;
        }
        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap finalization");
            return;
        }
        // Advance the gate only once marshal has ingested the finalization.
        // Backoff still ingests through the overflow policy. Closed means the
        // node is shutting down and the gate no longer matters.
        let round = finalization.round();
        if self
            .marshal
            .report(Activity::Finalization(finalization))
            .accepted()
        {
            self.latest = Some(round);
        }
    }

    async fn produce_finalization(
        &mut self,
        epoch: Epoch,
    ) -> Option<Finalization<S, V::Commitment>> {
        let height = self.epocher.last(epoch.previous()?)?;
        self.marshal.get_finalization(height).await
    }

    async fn produce_block(&mut self, epoch: Epoch) -> Option<V::Block> {
        let height = self.epocher.last(epoch.previous()?)?;
        self.marshal.get_block(height).await
    }
}
