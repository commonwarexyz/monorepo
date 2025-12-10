use super::{
    state::{Dealer, Epoch as EpochState, Player, Storage},
    Mailbox, Message as MailboxMessage, PostUpdate, Update, UpdateCallBack,
};
use crate::{
    namespace,
    orchestrator::{self, EpochTransition},
    setup::PeerConfig,
    BLOCKS_PER_EPOCH,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::{
    types::Epoch,
    utils::{epoch as compute_epoch, is_last_block_in_epoch, relative_height_in_epoch},
    Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg::{observe, DealerPrivMsg, DealerPubMsg, Info, Output, PlayerAck},
        primitives::{group::Share, variant::Variant},
    },
    transcript::Summary,
    Digest as _, Hasher, PublicKey, Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Recipients, Sender};
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage as RuntimeStorage,
};
use commonware_utils::{ordered::Set, Acknowledgement as _, NZU32};
use futures::{channel::mpsc, StreamExt};
use rand_core::CryptoRngCore;
use std::num::NonZeroU32;
use tracing::{debug, info, warn};

/// Wire message type for DKG protocol communication.
pub enum Message<V: Variant, P: PublicKey> {
    /// A dealer message containing public and private components for a player.
    Dealer(DealerPubMsg<V>, DealerPrivMsg),
    /// A player acknowledgment sent back to a dealer.
    Ack(PlayerAck<P>),
}

impl<V: Variant, P: PublicKey> Write for Message<V, P> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Dealer(pub_msg, priv_msg) => {
                0u8.write(writer);
                pub_msg.write(writer);
                priv_msg.write(writer);
            }
            Self::Ack(ack) => {
                1u8.write(writer);
                ack.write(writer);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Message<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealer(pub_msg, priv_msg) => pub_msg.encode_size() + priv_msg.encode_size(),
            Self::Ack(ack) => ack.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Read for Message<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(reader)?;
        match tag {
            0 => {
                let pub_msg = DealerPubMsg::read_cfg(reader, cfg)?;
                let priv_msg = DealerPrivMsg::read(reader)?;
                Ok(Self::Dealer(pub_msg, priv_msg))
            }
            1 => {
                let ack = PlayerAck::read(reader)?;
                Ok(Self::Ack(ack))
            }
            _ => Err(CodecError::Invalid("dkg::Message", "Invalid type")),
        }
    }
}

pub struct Config<C: Signer, P> {
    pub manager: P,
    pub signer: C,
    pub mailbox_size: usize,
    pub partition_prefix: String,
    pub peer_config: PeerConfig<C::PublicKey>,
}

pub struct Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + RuntimeStorage,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    manager: P,
    mailbox: mpsc::Receiver<MailboxMessage<H, C, V>>,
    signer: C,
    peer_config: PeerConfig<C::PublicKey>,
    partition_prefix: String,
}

impl<E, P, H, C, V> Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + RuntimeStorage,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub async fn init(context: E, config: Config<C, P>) -> (Self, Mailbox<H, C, V>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                manager: config.manager,
                mailbox,
                signer: config.signer,
                peer_config: config.peer_config,
                partition_prefix: config.partition_prefix,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        output: Option<Output<V, C::PublicKey>>,
        share: Option<Share>,
        orchestrator: impl Reporter<Activity = orchestrator::Message<V, C::PublicKey>>,
        dkg: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) -> Handle<()> {
        // NOTE: In a production setting with a large validator set, the implementor may want
        // to choose a dedicated thread for the DKG actor. This actor can perform CPU-intensive
        // cryptographic operations.
        spawn_cell!(
            self.context,
            self.run(output, share, orchestrator, dkg, callback).await
        )
    }

    async fn run(
        mut self,
        output: Option<Output<V, C::PublicKey>>,
        share: Option<Share>,
        mut orchestrator: impl Reporter<Activity = orchestrator::Message<V, C::PublicKey>>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        mut callback: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) {
        let max_read_size = NZU32!(self.peer_config.max_participants_per_round());
        let is_dkg = output.is_none();

        // Initialize persistent state
        let mut storage = Storage::init(
            self.context.with_label("storage"),
            &self.partition_prefix,
            max_read_size,
        )
        .await;
        if storage.epoch().is_none() {
            let initial_state = EpochState {
                round: 0,
                rng_seed: Summary::random(&mut self.context),
                output,
                share,
            };
            storage.append_epoch(initial_state).await;
        }

        // Start a muxer for the physical channel used by DKG/reshare
        let (mux, mut dkg_mux) =
            Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
        mux.start();

        'actor: loop {
            // Get latest epoch and state
            let (epoch, epoch_state) = storage.epoch().expect("epoch should be initialized");

            // Prune everything older than the previous epoch
            if let Some(prev) = epoch.previous() {
                storage.prune(prev).await;
            }

            // Initialize dealer and player sets
            let (dealers, players, next_players) = if is_dkg {
                (
                    self.peer_config.participants.clone(),
                    self.peer_config.dealers(0),
                    Set::<C::PublicKey>::default(),
                )
            } else {
                // In reshare mode, the initial dealer set must exactly match the players that
                // hold shares from the prior output.
                let dealers = self.peer_config.dealers(epoch_state.round);
                let previous_players = epoch_state.output.as_ref().unwrap().players();
                if epoch_state.round == 0 {
                    assert_eq!(
                        &dealers, previous_players,
                        "dealers for round 0 must equal previous output players"
                    );
                } else {
                    assert!(
                        dealers
                            .iter()
                            .all(|d| previous_players.position(d).is_some()),
                        "dealers for round {} must be drawn from previous output players",
                        epoch_state.round
                    );
                }

                (
                    dealers,
                    self.peer_config.dealers(epoch_state.round + 1),
                    self.peer_config.dealers(epoch_state.round + 2),
                )
            };

            // Any given peer set includes:
            // - Dealers and players for the active epoch
            // - Players for the next epoch
            self.manager
                .update(
                    epoch.get(),
                    Set::from_iter_dedup(
                        dealers
                            .iter()
                            .cloned()
                            .chain(players.iter().cloned())
                            .chain(next_players.into_iter()),
                    ),
                )
                .await;

            let self_pk = self.signer.public_key();
            let am_dealer = dealers.position(&self_pk).is_some();
            let am_player = players.position(&self_pk).is_some();

            // Inform the orchestrator of the epoch transition
            let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
                epoch,
                poly: epoch_state.output.as_ref().map(|o| o.public().clone()),
                share: epoch_state.share.clone(),
                dealers: dealers.clone(),
            };
            orchestrator
                .report(orchestrator::Message::Enter(transition))
                .await;

            // Register a channel for this round
            let (mut round_sender, mut round_receiver) = dkg_mux
                .register(epoch.get())
                .await
                .expect("should be able to create channel");

            // Prepare round info
            let round = Info::new(
                namespace::APPLICATION,
                epoch.get(),
                epoch_state.output.clone(),
                dealers,
                players.clone(),
            )
            .expect("round info configuration should be correct");

            // Initialize dealer state if we are a dealer (factory handles log submission check)
            let mut dealer_state: Option<Dealer<V, C>> = am_dealer
                .then(|| {
                    storage.create_dealer(
                        epoch,
                        self.signer.clone(),
                        round.clone(),
                        epoch_state.share.clone(),
                        epoch_state.rng_seed,
                    )
                })
                .flatten();

            // Initialize player state if we are a player
            let mut player_state: Option<Player<V, C>> = am_player
                .then(|| storage.create_player(epoch, self.signer.clone(), round.clone()))
                .flatten();

            select_loop! {
                self.context,
                on_stopped => {
                    break 'actor;
                },
                // Process incoming network messages
                network_msg = round_receiver.recv() => {
                    match network_msg {
                        Ok((sender_pk, msg_bytes)) => {
                            let msg = match Message::<V, C::PublicKey>::read_cfg(
                                &mut msg_bytes.clone(),
                                &max_read_size,
                            ) {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!(?epoch, ?sender_pk, ?e, "failed to parse message");
                                    continue;
                                }
                            };
                            match msg {
                                Message::Dealer(pub_msg, priv_msg) => {
                                    if let Some(ref mut ps) = player_state {
                                        let response = ps
                                            .handle(
                                                &mut storage,
                                                epoch,
                                                sender_pk.clone(),
                                                pub_msg,
                                                priv_msg,
                                            )
                                            .await;
                                        if let Some(ack) = response {
                                            let payload = Message::<V, C::PublicKey>::Ack(ack).encode().freeze();
                                            if let Err(e) = round_sender
                                                .send(Recipients::One(sender_pk.clone()), payload, true)
                                                .await
                                            {
                                                warn!(?epoch, dealer = ?sender_pk, ?e, "failed to send ack");
                                            }
                                        }
                                    }
                                }
                                Message::Ack(ack) => {
                                    if let Some(ref mut ds) = dealer_state {
                                        ds.handle(&mut storage, epoch, sender_pk, ack).await;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            // Network closed
                            warn!(?err, "network closed");
                            break 'actor;
                        }
                    }
                },
                mailbox_msg = self.mailbox.next() => {
                    let Some(mailbox_msg) = mailbox_msg else {
                        warn!("dkg actor mailbox closed");
                        break 'actor;
                    };
                    match mailbox_msg {
                        MailboxMessage::Act { response } => {
                            let outcome = dealer_state.as_ref().and_then(|ds| ds.finalized());
                            if outcome.is_some() {
                                info!("including reshare outcome in proposed block");
                            }
                            if response.send(outcome).is_err() {
                                warn!("dkg actor could not send response to Act");
                            }
                        }
                        MailboxMessage::Finalized { block, response } => {
                            let block_epoch = compute_epoch(BLOCKS_PER_EPOCH, block.height);
                            let relative_height =
                                relative_height_in_epoch(BLOCKS_PER_EPOCH, block.height);
                            let mid_point = BLOCKS_PER_EPOCH / 2;
                            info!(epoch = %block_epoch, relative_height, "processing finalized block");

                            // Skip blocks from previous epochs (can happen on restart if we
                            // persisted state but crashed before acknowledging)
                            if block_epoch < epoch {
                                response.acknowledge();
                                continue;
                            }

                            // Inform the orchestrator of the epoch exit after first finalization
                            if relative_height == 0 {
                                if let Some(prev) = block_epoch.previous() {
                                    orchestrator.report(orchestrator::Message::Exit(prev)).await;
                                }
                            }

                            // Process dealer log from block if present
                            if let Some(log) = block.log {
                                if let Some((dealer, dealer_log)) = log.check(&round) {
                                    // If we see our dealing outcome in a finalized block,
                                    // make sure to take it, so that we don't post
                                    // it in subsequent blocks
                                    if dealer == self_pk {
                                        if let Some(ref mut ds) = dealer_state {
                                            ds.take_finalized();
                                        }
                                    }
                                    storage.append_log(epoch, dealer, dealer_log).await;
                                }
                            }

                            // In the first half of the epoch, continuously distribute shares
                            if relative_height < mid_point {
                                if let Some(ref mut ds) = dealer_state {
                                    Self::distribute_shares(
                                        &self_pk,
                                        &mut storage,
                                        epoch,
                                        ds,
                                        player_state.as_mut(),
                                        &mut round_sender,
                                    )
                                    .await;
                                }
                            }

                            // At or past the midpoint, finalize dealer if not already done.
                            // The >= check handles restart after midpoint acknowledgment.
                            if relative_height >= mid_point {
                                if let Some(ref mut ds) = dealer_state {
                                    ds.finalize();
                                }
                            }

                            // Continue if not the last block in the epoch
                            if is_last_block_in_epoch(BLOCKS_PER_EPOCH, block.height).is_none() {
                                // Acknowledge block processing
                                response.acknowledge();
                                continue;
                            }

                            // Finalize the round before acknowledging
                            let logs = storage.logs(epoch);
                            let (success, next_round, next_output, next_share) =
                                if let Some(ps) = player_state.take() {
                                    match ps.finalize(logs, 1) {
                                        Ok((new_output, new_share)) => (
                                            true,
                                            epoch_state.round + 1,
                                            Some(new_output),
                                            Some(new_share),
                                        ),
                                        Err(_) => (
                                            false,
                                            epoch_state.round,
                                            epoch_state.output.clone(),
                                            epoch_state.share.clone(),
                                        ),
                                    }
                                } else {
                                    match observe(round.clone(), logs, 1) {
                                        Ok(output) => (true, epoch_state.round + 1, Some(output), None),
                                        Err(_) => (
                                            false,
                                            epoch_state.round,
                                            epoch_state.output.clone(),
                                            epoch_state.share.clone(),
                                        ),
                                    }
                                };
                            if success {
                                info!(?epoch, "epoch succeeded");
                            } else {
                                warn!(?epoch, "epoch failed");
                            }
                            storage
                                .append_epoch(EpochState {
                                    round: next_round,
                                    rng_seed: Summary::random(&mut self.context),
                                    output: next_output.clone(),
                                    share: next_share.clone(),
                                })
                                .await;

                            // Acknowledge block processing before callback
                            response.acknowledge();

                            // Send the callback.
                            let update = if success {
                                Update::Success {
                                    epoch,
                                    output: next_output.expect("ceremony output exists"),
                                    share: next_share.clone(),
                                }
                            } else {
                                Update::Failure { epoch }
                            };

                            // If the update is stop, wait forever.
                            if let PostUpdate::Stop = callback.on_update(update).await {
                                // Close the mailbox to prevent accepting any new messages
                                drop(self.mailbox);
                                // Exit last consensus instance to avoid useless work while we wait for shutdown
                                orchestrator
                                    .report(orchestrator::Message::Exit(epoch))
                                    .await;
                                // Keep running until killed to keep the orchestrator mailbox alive
                                info!("DKG complete; waiting for shutdown...");
                                futures::future::pending::<()>().await;
                                break 'actor;
                            }

                            break;
                        }
                    }
                },
            }
        }
        info!("exiting DKG actor");
    }

    async fn distribute_shares<S: Sender<PublicKey = C::PublicKey>>(
        self_pk: &C::PublicKey,
        storage: &mut Storage<ContextCell<E>, V, C::PublicKey>,
        epoch: Epoch,
        dealer_state: &mut Dealer<V, C>,
        mut player_state: Option<&mut Player<V, C>>,
        sender: &mut S,
    ) {
        for (player, pub_msg, priv_msg) in dealer_state.shares_to_distribute().collect::<Vec<_>>() {
            // Handle self-dealing if we are both dealer and player
            if player == *self_pk {
                if let Some(ref mut ps) = player_state {
                    // Handle as player
                    let ack = match ps
                        .handle(storage, epoch, self_pk.clone(), pub_msg, priv_msg)
                        .await
                    {
                        Some(ack) => ack,
                        _ => continue,
                    };

                    // Handle our own ack as dealer
                    dealer_state
                        .handle(storage, epoch, self_pk.clone(), ack)
                        .await;
                }
                continue;
            }

            // Send to remote player
            let payload = Message::<V, C::PublicKey>::Dealer(pub_msg, priv_msg)
                .encode()
                .freeze();
            match sender
                .send(Recipients::One(player.clone()), payload, true)
                .await
            {
                Ok(success) => {
                    if success.is_empty() {
                        debug!(?epoch, ?player, "failed to send share");
                    } else {
                        debug!(?epoch, ?player, "sent share");
                    }
                }
                Err(e) => {
                    warn!(?epoch, ?player, ?e, "error sending share");
                }
            }
        }
    }
}
