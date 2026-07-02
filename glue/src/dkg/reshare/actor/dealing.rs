use crate::dkg::{
    reshare::{
        metrics::Phase,
        store::{Dealer, Player, Store},
        Actor, Message as MailboxMessage,
    },
    types::Message,
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
};
use commonware_codec::{Decode, Encode};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    types::{Epoch, EpochPhase, Epocher},
};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt::Verdict, primitives::variant::Variant as BlsVariant},
    certificate::Scheme,
    BatchVerifier, Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Manager, Message as NetworkMessage, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    telemetry::traces::TracedExt as _, BufferPooler, Clock, Metrics, Spawner, Storage,
};
use commonware_utils::{channel::fallible::OneshotExt, Acknowledgement};
use rand_core::CryptoRngCore;
use std::ops::ControlFlow;
use tracing::{debug, info, info_span, warn, Instrument as _};

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRngCore + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    /// Run the early dealing phase for `epoch`.
    ///
    /// The phase processes inbound dealer messages and acknowledgements while
    /// finalized blocks remain in [`EpochPhase::Early`]. It returns after the
    /// final early block is acknowledged.
    pub(super) async fn dealing<SE, RE>(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey>,
        mut dealer: Option<&mut Dealer<V, C>>,
        mut player: Option<&mut Player<V, C>>,
        (mut sender, mut receiver): (SE, RE),
    ) -> ControlFlow<()>
    where
        SE: Sender<PublicKey = C::PublicKey>,
        RE: Receiver<PublicKey = C::PublicKey>,
    {
        self.metrics.set_phase(Phase::Dealing);

        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
                return ControlFlow::Break(());
            },
            Ok(message) = receiver.recv() else {
                debug!("dealing channel closed, shutting down");
                return ControlFlow::Break(());
            } => {
                self.handle_message(
                    epoch,
                    store,
                    dealer.as_deref_mut(),
                    player.as_deref_mut(),
                    &mut sender,
                    message,
                )
                .await
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return ControlFlow::Break(());
            } => match message {
                MailboxMessage::NextLog { span, response, .. } => {
                    let process = info_span!(parent: &span, "dkg.reshare.actor.dealing.next_log");
                    process.in_scope(|| {
                        let _ = response.send_lossy(None);
                    });
                }
                MailboxMessage::EpochInfo { span, response, .. } => {
                    let process = info_span!(parent: &span, "dkg.reshare.actor.dealing.epoch_info");
                    process.in_scope(|| {
                        let _ = response.send_lossy(None);
                    });
                }
                MailboxMessage::Finalized {
                    span,
                    block,
                    response,
                } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.dealing.finalized",
                        height = block.height().traced()
                    );
                    let done = async {
                        let bounds = self
                            .epocher
                            .containing(block.height())
                            .expect("epocher must know of block height");
                        assert_eq!(bounds.epoch(), epoch, "dealing received future epoch block");
                        assert_eq!(
                            bounds.phase(),
                            EpochPhase::Early,
                            "dealing received block after early phase"
                        );

                        if let Some(dealer) = dealer.as_deref_mut() {
                            Self::send_dealings(
                                &self.signer.public_key(),
                                store,
                                epoch,
                                dealer,
                                player.as_deref_mut(),
                                &mut sender,
                            )
                            .await;
                        }

                        let done = self
                            .epocher
                            .midpoint(epoch)
                            .and_then(|midpoint| midpoint.previous())
                            == Some(block.height());
                        response.acknowledge();
                        done
                    }
                    .instrument(process)
                    .await;
                    if done {
                        return ControlFlow::Continue(());
                    }
                }
            },
        };

        ControlFlow::Break(())
    }

    async fn handle_message<SE>(
        &mut self,
        epoch: Epoch,
        store: &mut Store<E, SS, V, C::PublicKey>,
        dealer: Option<&mut Dealer<V, C>>,
        player: Option<&mut Player<V, C>>,
        sender: &mut SE,
        (from, bytes): NetworkMessage<C::PublicKey>,
    ) where
        SE: Sender<PublicKey = C::PublicKey>,
    {
        let message =
            match Message::<V, C::PublicKey>::decode_cfg(bytes.as_ref(), &self.max_participants) {
                Ok(message) => message,
                Err(error) => {
                    commonware_p2p::block!(
                        self.blocker,
                        from,
                        ?epoch,
                        ?error,
                        "failed to decode dealing message"
                    );
                    return;
                }
            };

        match message {
            Message::Dealer(public, private) => {
                let Some(player) = player else {
                    commonware_p2p::block!(
                        self.blocker,
                        from,
                        ?epoch,
                        "dealing sent to non-player"
                    );
                    return;
                };
                let ack = match player
                    .handle(store, epoch, from.clone(), public, private)
                    .await
                {
                    Verdict::Valid(ack) => ack,
                    Verdict::Skip => return,
                    Verdict::Fault => {
                        commonware_p2p::block!(self.blocker, from, ?epoch, "invalid dealing");
                        return;
                    }
                };

                self.metrics.record_share(&from, epoch.get());
                info!(?epoch, dealer = ?from, "received dealing");
                let sent = sender.send(
                    Recipients::One(from.clone()),
                    Message::<V, C::PublicKey>::Ack(ack).encode(),
                    true,
                );
                if sent.is_empty() {
                    warn!(?epoch, dealer = ?from, "failed to send ack");
                }
            }
            Message::Ack(ack) => {
                let Some(dealer) = dealer else {
                    commonware_p2p::block!(self.blocker, from, ?epoch, "ack sent to non-dealer");
                    return;
                };
                match dealer.handle(store, epoch, from.clone(), ack).await {
                    Verdict::Valid(()) => {
                        self.metrics.record_ack(&from, epoch.get());
                        info!(?epoch, player = ?from, "received ack");
                    }
                    Verdict::Skip => {}
                    Verdict::Fault => {
                        commonware_p2p::block!(self.blocker, from, ?epoch, "invalid ack signature");
                    }
                }
            }
        }
    }

    async fn send_dealings<SE>(
        public_key: &C::PublicKey,
        store: &mut Store<E, SS, V, C::PublicKey>,
        epoch: Epoch,
        dealer: &mut Dealer<V, C>,
        mut player: Option<&mut Player<V, C>>,
        sender: &mut SE,
    ) where
        SE: Sender<PublicKey = C::PublicKey>,
    {
        for (recipient, public, private) in dealer.shares_to_distribute().collect::<Vec<_>>() {
            if recipient == *public_key {
                let Some(player) = player.as_deref_mut() else {
                    continue;
                };
                let Verdict::Valid(ack) = player
                    .handle(store, epoch, public_key.clone(), public, private)
                    .await
                else {
                    continue;
                };
                let _ = dealer.handle(store, epoch, public_key.clone(), ack).await;
                continue;
            }

            let sent = sender.send(
                Recipients::One(recipient.clone()),
                Message::<V, C::PublicKey>::Dealer(public, private).encode(),
                true,
            );
            if sent.is_empty() {
                debug!(?epoch, ?recipient, "failed to send share");
            } else {
                debug!(?epoch, ?recipient, "sent share");
            }
        }
    }
}
