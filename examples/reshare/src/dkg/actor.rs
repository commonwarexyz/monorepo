use super::{
    state::{DkgState, State},
    Mailbox, Message, PostUpdate, Update, UpdateCallBack,
};
use crate::{
    namespace,
    orchestrator::{self, EpochTransition},
    setup::PeerConfig,
    BLOCKS_PER_EPOCH,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Encode, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::{
    types::Epoch,
    utils::{epoch as compute_epoch, is_last_block_in_epoch, relative_height_in_epoch},
    Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg::{
            observe, Dealer, DealerPrivMsg, DealerPubMsg, Info, Output, Player, PlayerAck,
            SignedDealerLog,
        },
        primitives::{group::Share, variant::Variant},
    },
    transcript::{Summary, Transcript},
    Digest as _, Hasher, PublicKey, Signer,
};
use commonware_macros::select;
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{ordered::Set, Acknowledgement as _, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, num::NonZeroU32};
use tracing::{debug, info, warn};

/// Wire message type for DKG protocol communication.
pub enum DkgMessage<V: Variant, P: PublicKey> {
    /// A dealer message containing public and private components for a player.
    Dealer(DealerPubMsg<V>, DealerPrivMsg),
    /// A player acknowledgment sent back to a dealer.
    Ack(PlayerAck<P>),
}

impl<V: Variant, P: PublicKey> Write for DkgMessage<V, P> {
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

impl<V: Variant, P: PublicKey> EncodeSize for DkgMessage<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealer(pub_msg, priv_msg) => pub_msg.encode_size() + priv_msg.encode_size(),
            Self::Ack(ack) => ack.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Read for DkgMessage<V, P> {
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
            _ => Err(CodecError::Invalid("dkg::DkgMessage", "Invalid type")),
        }
    }
}

pub struct Config<C: Signer, P> {
    pub manager: P,
    pub signer: C,
    pub mailbox_size: usize,
    pub partition_prefix: String,
    pub peer_config: PeerConfig<C::PublicKey>,
    pub rate_limit: Quota,
}

pub struct Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    manager: P,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    peer_config: PeerConfig<C::PublicKey>,
    rate_limit: Quota,
    failed_rounds: Counter,
    partition_prefix: String,
}

impl<E, P, H, C, V> Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Set<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub async fn init(context: E, config: Config<C, P>) -> (Self, Mailbox<H, C, V>) {
        let failed_rounds = Counter::default();
        context.register(
            "failed_rounds",
            "Number of failed DKG/reshare rounds",
            failed_rounds.clone(),
        );

        let context = ContextCell::new(context);

        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                manager: config.manager,
                mailbox,
                signer: config.signer,
                peer_config: config.peer_config,
                rate_limit: config.rate_limit,
                failed_rounds,
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
        dkg_chan: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(output, share, orchestrator, dkg_chan, callback)
                .await
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
        mut update_cb: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) {
        let max_read_size = NZU32!(self.peer_config.max_participants_per_round());
        let is_dkg = output.is_none();

        // Initialize persistent state
        let state = State::init(
            self.context.with_label("storage"),
            &self.partition_prefix,
            max_read_size,
        )
        .await;
        if state.dkg_state().await.is_none() {
            let initial_state = DkgState {
                round: 0,
                rng_seed: Summary::random(&mut self.context),
                output,
                share,
            };
            state.append_dkg_state(initial_state).await;
        };

        // Start a muxer for the physical channel used by DKG/reshare
        let (mux, mut dkg_mux) =
            Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
        mux.start();

        'actor: loop {
            let (epoch, dkg_state) = state
                .dkg_state()
                .await
                .expect("dkg_state should be initialized");

            // Prune everything older than the previous epoch
            if let Some(prev) = epoch.previous() {
                state.prune(prev).await;
            }

            let (dealers, players, next_players) = if is_dkg {
                (
                    self.peer_config.participants.clone(),
                    self.peer_config.dealers(0),
                    Set::from_iter_dedup([]),
                )
            } else {
                (
                    self.peer_config.dealers(dkg_state.round),
                    self.peer_config.dealers(dkg_state.round + 1),
                    self.peer_config.dealers(dkg_state.round + 2),
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
            let am_dealer = dealers.position(&self_pk).is_some()
                && !state.has_submitted_log(epoch, &self_pk).await;
            let am_player = players.position(&self_pk).is_some();

            // Inform the orchestrator of the epoch transition
            if let Some(output) = dkg_state.output.as_ref() {
                let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
                    epoch,
                    poly: Some(output.public().clone()),
                    share: dkg_state.share.clone(),
                    dealers: dealers.clone(),
                };
                orchestrator
                    .report(orchestrator::Message::Enter(transition))
                    .await;
            }

            let round_info = Info::new(
                namespace::APPLICATION,
                epoch.get(),
                dkg_state.output.clone(),
                dealers,
                players.clone(),
            )
            .expect("round info configuration should be correct");

            // Register a channel for this round
            let (mut round_sender, mut round_receiver) = dkg_mux
                .register(epoch.get())
                .await
                .expect("should be able to create channel");

            // Initialize rate limiter for this round
            #[allow(clippy::type_complexity)]
            let rate_limiter: RateLimiter<
                C::PublicKey,
                HashMapStateStore<C::PublicKey>,
                ContextCell<E>,
                NoOpMiddleware<<ContextCell<E> as GClock>::Instant>,
            > = RateLimiter::hashmap_with_clock(self.rate_limit, self.context.clone());

            // Initialize dealer state if we are a dealer
            let mut dealer_state: Option<DealerState<V, C>> = if am_dealer {
                let (mut dealer, pub_msg, priv_msgs) = Dealer::start(
                    Transcript::resume(dkg_state.rng_seed).noise(b"dealer-rng"),
                    round_info.clone(),
                    self.signer.clone(),
                    dkg_state.share.clone(),
                )
                .expect("should be able to create dealer");

                // Replay stored acks
                let mut unsent_priv_msgs: BTreeMap<C::PublicKey, DealerPrivMsg> =
                    priv_msgs.into_iter().collect();
                let replay_acks = state.player_acks(epoch).await;
                for (player, ack) in replay_acks {
                    if unsent_priv_msgs.contains_key(&player)
                        && dealer
                            .receive_player_ack(player.clone(), ack.clone())
                            .is_ok()
                    {
                        unsent_priv_msgs.remove(&player);
                        debug!(?epoch, ?player, "replayed player ack");
                    }
                }

                Some(DealerState {
                    dealer: Some(dealer),
                    pub_msg,
                    unsent_priv_msgs,
                    finalized_log: None,
                })
            } else {
                None
            };

            // Initialize player state if we are a player
            let mut player_state: Option<PlayerState<V, C>> = if am_player {
                let player = Player::new(round_info.clone(), self.signer.clone())
                    .expect("should be able to create player");
                let mut ps = PlayerState::new(player);

                // Replay persisted dealer messages - these represent our commitments.
                // We will regenerate the same acks from them.
                let replay_msgs = state.dealer_msgs(epoch).await;
                for (dealer, pub_msg, priv_msg) in replay_msgs {
                    ps.handle(dealer.clone(), pub_msg, priv_msg);
                    debug!(?epoch, ?dealer, "replayed committed dealer message");
                }

                Some(ps)
            } else {
                None
            };

            let mut epoch_done = false;

            while !epoch_done {
                let mailbox_msg = select! {
                    _ = self.context.stopped() => {
                        break 'actor;
                    },
                    // Process incoming network messages
                    network_msg = round_receiver.recv().fuse() => {
                        match network_msg {
                            Ok((sender_pk, msg_bytes)) => {
                                Self::handle_network_message(
                                    &state,
                                    epoch,
                                    max_read_size,
                                    sender_pk,
                                    msg_bytes,
                                    &round_info,
                                    dealer_state.as_mut(),
                                    player_state.as_mut(),
                                    &mut round_sender,
                                ).await;
                                continue;
                            }
                            Err(_) => {
                                // Network closed
                                break 'actor;
                            }
                        }
                    },
                    mb = self.mailbox.next() => {
                        let Some(m) = mb else {
                            warn!("dkg actor mailbox closed");
                            break 'actor;
                        };
                        m
                    }
                };

                match mailbox_msg {
                    Message::Act { response } => {
                        let outcome = dealer_state
                            .as_mut()
                            .and_then(|ds| ds.finalized_log.clone());
                        if outcome.is_some() {
                            info!("including reshare outcome in proposed block");
                        }
                        if response.send(outcome).is_err() {
                            warn!("dkg actor could not send response to Act");
                        }
                    }
                    Message::Finalized { block, response } => {
                        let block_epoch = compute_epoch(BLOCKS_PER_EPOCH, block.height);
                        let relative_height =
                            relative_height_in_epoch(BLOCKS_PER_EPOCH, block.height);
                        let mid_point = BLOCKS_PER_EPOCH / 2;

                        // Inform the orchestrator of the epoch exit after first finalization
                        if relative_height == 0 {
                            if let Some(prev) = block_epoch.previous() {
                                orchestrator.report(orchestrator::Message::Exit(prev)).await;
                            }
                        }

                        // Process dealer log from block if present
                        if let Some(log) = block.log {
                            if let Some((dealer, dealer_log)) = log.check(&round_info) {
                                // If we see our dealing outcome in a finalized block,
                                // make sure to take it, so that we don't post
                                // it in subsequent blocks
                                if dealer == self_pk {
                                    if let Some(ref mut ds) = dealer_state {
                                        ds.finalized_log.take();
                                    }
                                }
                                state.append_log(epoch, dealer, dealer_log).await;
                            }
                        }

                        // In the first half of the epoch, continuously distribute shares
                        if relative_height < mid_point {
                            if let Some(ref mut ds) = dealer_state {
                                Self::distribute_shares(
                                    &self_pk,
                                    &state,
                                    epoch,
                                    &rate_limiter,
                                    ds,
                                    player_state.as_mut(),
                                    &mut round_sender,
                                )
                                .await;
                            }
                        }

                        // At the midpoint of the epoch, finalize dealer and create log for inclusion
                        if relative_height == mid_point {
                            if let Some(ref mut ds) = dealer_state {
                                if let Some(log) = ds.finalize() {
                                    info!(?epoch, "finalized dealer log for inclusion");
                                    drop(log); // Log is stored in ds.finalized_log
                                }
                            }
                        }

                        epoch_done =
                            is_last_block_in_epoch(BLOCKS_PER_EPOCH, block.height).is_some();

                        // Acknowledge block processing
                        response.acknowledge();
                    }
                }
            }

            // Finalize the round
            let logs = state.logs(epoch).await;
            let (success, next_round, next_output, next_share) = if let Some(ps) = player_state {
                match ps.player.finalize(logs, 1) {
                    Ok((new_output, new_share)) => {
                        (true, dkg_state.round + 1, Some(new_output), Some(new_share))
                    }
                    Err(_) => (
                        false,
                        dkg_state.round,
                        dkg_state.output.clone(),
                        dkg_state.share.clone(),
                    ),
                }
            } else {
                match observe(round_info, logs, 1) {
                    Ok(output) => (true, dkg_state.round + 1, Some(output), None),
                    Err(_) => (
                        false,
                        dkg_state.round,
                        dkg_state.output.clone(),
                        dkg_state.share.clone(),
                    ),
                }
            };

            if !success {
                self.failed_rounds.inc();
            }

            info!(
                success,
                ?epoch,
                "finalized epoch's reshare; instructing reconfiguration after reshare.",
            );

            state
                .append_dkg_state(DkgState {
                    round: next_round,
                    rng_seed: Summary::random(&mut self.context),
                    output: next_output.clone(),
                    share: next_share.clone(),
                })
                .await;

            let update = if success {
                Update::Success {
                    epoch,
                    output: next_output.expect("success => output exists"),
                    share: next_share.clone(),
                }
            } else {
                Update::Failure { epoch }
            };
            if let PostUpdate::Stop = update_cb.on_update(update).await {
                // Close the mailbox to prevent accepting any new messages
                drop(self.mailbox);
                // Exit last consensus instance to avoid useless work while we wait for shutdown
                orchestrator
                    .report(orchestrator::Message::Exit(epoch))
                    .await;
                // Keep running until killed to keep the orchestrator mailbox alive
                info!("DKG complete; waiting for shutdown.");
                futures::future::pending::<()>().await;
                break 'actor;
            }
        }
        info!("exiting DKG actor");
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_network_message<S: Sender<PublicKey = C::PublicKey>>(
        state: &State<ContextCell<E>, V, C::PublicKey>,
        epoch: Epoch,
        max_read_size: NonZeroU32,
        sender_pk: C::PublicKey,
        msg_bytes: bytes::Bytes,
        round_info: &Info<V, C::PublicKey>,
        dealer_state: Option<&mut DealerState<V, C>>,
        player_state: Option<&mut PlayerState<V, C>>,
        network_sender: &mut S,
    ) {
        let msg = match DkgMessage::<V, C::PublicKey>::read_cfg(&mut msg_bytes.clone(), &max_read_size) {
            Ok(m) => m,
            Err(e) => {
                warn!(?epoch, ?sender_pk, ?e, "failed to parse DKG message");
                return;
            }
        };

        match msg {
            DkgMessage::Dealer(pub_msg, priv_msg) => {
                let Some(ps) = player_state else {
                    return;
                };

                // Verify round matches
                if round_info.round() != epoch.get() {
                    return;
                }

                // If new, persist the dealer message first (this is our commitment)
                if !ps.has_committed(&sender_pk) {
                    state
                        .append_dealer_msg(
                            epoch,
                            sender_pk.clone(),
                            pub_msg.clone(),
                            priv_msg.clone(),
                        )
                        .await;
                    debug!(?epoch, dealer = ?sender_pk, "persisted dealer message");
                }

                // Handle the message and send response if any
                if let Some(response) = ps.handle(sender_pk.clone(), pub_msg, priv_msg) {
                    let payload = response.encode().freeze();
                    if let Err(e) = network_sender
                        .send(Recipients::One(sender_pk.clone()), payload, true)
                        .await
                    {
                        warn!(?epoch, dealer = ?sender_pk, ?e, "failed to send ack");
                    } else {
                        debug!(?epoch, dealer = ?sender_pk, "sent ack");
                    }
                }
            }
            DkgMessage::Ack(ack) => {
                let Some(ds) = dealer_state else {
                    return;
                };

                if let Some(ack) = ds.handle(sender_pk.clone(), ack) {
                    state.append_player_ack(epoch, sender_pk.clone(), ack).await;
                    debug!(?epoch, player = ?sender_pk, "received and stored player ack");
                }
            }
        }
    }

    #[allow(clippy::type_complexity)]
    async fn distribute_shares<S: Sender<PublicKey = C::PublicKey>>(
        self_pk: &C::PublicKey,
        state: &State<ContextCell<E>, V, C::PublicKey>,
        epoch: Epoch,
        rate_limiter: &RateLimiter<
            C::PublicKey,
            HashMapStateStore<C::PublicKey>,
            ContextCell<E>,
            NoOpMiddleware<<ContextCell<E> as GClock>::Instant>,
        >,
        dealer_state: &mut DealerState<V, C>,
        mut player_state: Option<&mut PlayerState<V, C>>,
        sender: &mut S,
    ) {
        for (player, priv_msg) in dealer_state.unsent_priv_msgs.clone() {
            // Rate limit sends
            if rate_limiter.check_key(&player).is_err() {
                debug!(?epoch, ?player, "rate limited; skipping share send");
                continue;
            }

            // Handle self-dealing if we are both dealer and player
            if player == *self_pk {
                if let Some(ref mut ps) = player_state {
                    // If new, persist the dealer message first
                    if !ps.has_committed(self_pk) {
                        state
                            .append_dealer_msg(
                                epoch,
                                self_pk.clone(),
                                dealer_state.pub_msg.clone(),
                                priv_msg.clone(),
                            )
                            .await;
                    }

                    // Handle as player and get response
                    if let Some(DkgMessage::Ack(ack)) = ps.handle(
                        self_pk.clone(),
                        dealer_state.pub_msg.clone(),
                        priv_msg.clone(),
                    ) {
                        // Handle our own ack as dealer
                        if let Some(ack) = dealer_state.handle(self_pk.clone(), ack) {
                            state.append_player_ack(epoch, self_pk.clone(), ack).await;
                            debug!(?epoch, "self-dealt and acked");
                        }
                    }
                }
                continue;
            }

            // Send to remote player using DkgMessage
            let payload = DkgMessage::<V, C::PublicKey>::Dealer(dealer_state.pub_msg.clone(), priv_msg).encode().freeze();
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

/// Internal state for a dealer in the current round.
struct DealerState<V: Variant, C: Signer> {
    dealer: Option<Dealer<V, C>>,
    pub_msg: DealerPubMsg<V>,
    unsent_priv_msgs: BTreeMap<C::PublicKey, DealerPrivMsg>,
    finalized_log: Option<SignedDealerLog<V, C>>,
}

impl<V: Variant, C: Signer> DealerState<V, C> {
    /// Handle an incoming ack from a player.
    /// Returns the ack if it was successfully processed (for persistence).
    fn handle(&mut self, player: C::PublicKey, ack: PlayerAck<C::PublicKey>) -> Option<PlayerAck<C::PublicKey>> {
        if !self.unsent_priv_msgs.contains_key(&player) {
            return None;
        }
        if let Some(ref mut dealer) = self.dealer {
            if dealer.receive_player_ack(player.clone(), ack.clone()).is_ok() {
                self.unsent_priv_msgs.remove(&player);
                return Some(ack);
            }
        }
        None
    }

    /// Finalize the dealer and produce a signed log for inclusion in a block.
    fn finalize(&mut self) -> Option<SignedDealerLog<V, C>> {
        if self.finalized_log.is_some() {
            return None;
        }
        if let Some(dealer) = self.dealer.take() {
            let log = dealer.finalize();
            self.finalized_log = Some(log.clone());
            return Some(log);
        }
        None
    }
}

/// Internal state for a player in the current round.
struct PlayerState<V: Variant, C: Signer> {
    player: Player<V, C>,
    /// Acks we've generated, keyed by dealer. Once we generate an ack for a dealer,
    /// we will not generate a different one (to avoid conflicting votes).
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
    /// Dealers we've already persisted (and thus committed to acking).
    committed_dealers: BTreeMap<C::PublicKey, bool>,
}

impl<V: Variant, C: Signer> PlayerState<V, C> {
    const fn new(player: Player<V, C>) -> Self {
        Self {
            player,
            acks: BTreeMap::new(),
            committed_dealers: BTreeMap::new(),
        }
    }

    /// Handle an incoming dealer message (already persisted).
    /// Returns an ack response message if one should be sent.
    fn handle(
        &mut self,
        dealer: C::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> Option<DkgMessage<V, C::PublicKey>> {
        self.committed_dealers.insert(dealer.clone(), true);
        // If we've already generated an ack, return it
        if let Some(ack) = self.acks.get(&dealer) {
            return Some(DkgMessage::Ack(ack.clone()));
        }
        // Otherwise generate the ack (deterministic based on the persisted message)
        if let Some(ack) = self
            .player
            .dealer_message(dealer.clone(), pub_msg, priv_msg)
        {
            self.acks.insert(dealer.clone(), ack.clone());
            return Some(DkgMessage::Ack(ack));
        }
        None
    }

    /// Check if we've already committed to acking this dealer.
    fn has_committed(&self, dealer: &C::PublicKey) -> bool {
        self.committed_dealers.contains_key(dealer)
    }
}
