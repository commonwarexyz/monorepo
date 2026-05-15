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
use commonware_actor::mailbox::{self, Receiver as ActorReceiver};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, EpochPhase, Epocher, FixedEpocher};
use commonware_cryptography::{
    bls12381::{
        dkg::{observe, DealerPrivMsg, DealerPubMsg, Info, Logs, Output, PlayerAck},
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion},
            variant::Variant,
        },
    },
    ed25519::Batch,
    transcript::Summary,
    BatchVerifier, Hasher, PublicKey, Signer,
};
use commonware_macros::select_loop;
use commonware_math::algebra::Random;
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Recipients, Sender, TrackedPeers};
use commonware_parallel::Sequential;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{Counter, EncodeStruct, GaugeExt, GaugeFamily, MetricsExt as _},
    Buf, BufMut, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
    Storage as RuntimeStorage,
};
use commonware_utils::{ordered::Set, Acknowledgement as _, N3f1, NZU32};
use rand_core::CryptoRngCore;
use std::num::{NonZeroU32, NonZeroUsize};
use tracing::{debug, info, warn};

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
struct Peer<P: PublicKey> {
    peer: P,
}

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
    pub mailbox_size: NonZeroUsize,
    pub partition_prefix: String,
    pub peer_config: PeerConfig<C::PublicKey>,
    pub max_supported_mode: ModeVersion,
}

pub struct Actor<E, P, H, C, V>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + RuntimeStorage,
    P: Manager<PublicKey = C::PublicKey>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    manager: P,
    mailbox: ActorReceiver<MailboxMessage<H, C, V>>,
    signer: C,
    peer_config: PeerConfig<C::PublicKey>,
    partition_prefix: String,
    max_supported_mode: ModeVersion,

    successful_epochs: Counter,
    failed_epochs: Counter,
    our_reveals: Counter,
    all_reveals: Counter,
    latest_share: GaugeFamily<Peer<C::PublicKey>>,
    latest_ack: GaugeFamily<Peer<C::PublicKey>>,
}

impl<E, P, H, C, V> Actor<E, P, H, C, V>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + RuntimeStorage,
    P: Manager<PublicKey = C::PublicKey>,
    H: Hasher,
    C: Signer,
    Batch: BatchVerifier<PublicKey = C::PublicKey>,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub fn new(context: E, config: Config<C, P>) -> (Self, Mailbox<H, C, V>) {
        // Create mailbox
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);

        // Create metrics
        let successful_epochs = context.counter("successful_epochs", "successful epochs");
        let failed_epochs = context.counter("failed_epochs", "failed epochs");
        let our_reveals = context.counter("our_reveals", "our share was revealed");
        let all_reveals = context.counter("all_reveals", "all share reveals");
        let latest_share = context.family(
            "latest_share",
            "epoch of latest valid share received per dealer",
        );
        let latest_ack = context.family(
            "latest_ack",
            "epoch of latest valid ack received per player",
        );

        (
            Self {
                context: ContextCell::new(context),
                manager: config.manager,
                mailbox,
                signer: config.signer,
                peer_config: config.peer_config,
                partition_prefix: config.partition_prefix,
                max_supported_mode: config.max_supported_mode,

                successful_epochs,
                failed_epochs,
                our_reveals,
                all_reveals,
                latest_share,
                latest_ack,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        output: Option<Output<V, C::PublicKey>>,
        share: Option<Share>,
        orchestrator: orchestrator::Mailbox<V, C::PublicKey>,
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
            self.run(output, share, orchestrator, dkg, callback)
        )
    }

    async fn run(
        mut self,
        output: Option<Output<V, C::PublicKey>>,
        share: Option<Share>,
        mut orchestrator: orchestrator::Mailbox<V, C::PublicKey>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        mut callback: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) {
        let max_read_size = NZU32!(self.peer_config.max_participants_per_round());
        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);

        // Initialize persistent state
        let mut storage = Storage::init(
            self.context.child("storage"),
            &self.partition_prefix,
            max_read_size,
            self.max_supported_mode,
        )
        .await;
        if storage.epoch().is_none() {
            let initial_state = EpochState {
                round: 0,
                rng_seed: Summary::random(self.context.as_present_mut()),
                output,
                share,
            };
            storage.set_epoch(Epoch::zero(), initial_state).await;
        }

        // Start a muxer for the physical channel used by DKG/reshare
        let (mux, mut dkg_mux) = Muxer::new(self.context.child("dkg_mux"), sender, receiver, 100);
        mux.start();

        'actor: loop {
            // Get latest epoch and state
            let (epoch, epoch_state) = storage.epoch().expect("epoch should be initialized");
            let is_dkg = epoch_state.output.is_none();

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

            // Primary = dealers (drive the DKG round/running consensus)
            // Secondary = current players + next-epoch players (give time to sync)
            //
            // Overlapping keys are deduplicated as primary (so we don't need to do any filtering here)
            self.manager.track(
                epoch.get(),
                TrackedPeers::new(
                    dealers.clone(),
                    Set::from_iter_dedup(players.iter().chain(next_players.iter()).cloned()),
                ),
            );

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
            orchestrator.enter(transition).await;

            // Register a channel for this round
            let (mut round_sender, mut round_receiver) = dkg_mux
                .register(epoch.get())
                .await
                .expect("should be able to create channel");

            // Prepare round info
            let round = Info::new::<N3f1>(
                namespace::APPLICATION,
                epoch.get(),
                epoch_state.output.clone(),
                Mode::NonZeroCounter,
                dealers,
                players.clone(),
            )
            .expect("round info configuration should be correct");

            // Initialize dealer state if we are a dealer (factory handles log submission check)
            let mut dealer_state: Option<Dealer<V, C>> = am_dealer
                .then(|| {
                    storage.create_dealer::<C, N3f1>(
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
                .then(|| {
                    storage.create_player::<C, N3f1>(epoch, self.signer.clone(), round.clone())
                })
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
                                            .handle::<_, N3f1>(
                                                &mut storage,
                                                epoch,
                                                sender_pk.clone(),
                                                pub_msg,
                                                priv_msg,
                                            )
                                            .await;
                                        if let Some(ack) = response {
                                            let _ = self
                                                .latest_share
                                                .get_or_create_by(&sender_pk)
                                                .try_set_max(epoch.get());

                                            let payload =
                                                Message::<V, C::PublicKey>::Ack(ack).encode();
                                            if let Err(e) = round_sender
                                                .send(
                                                    Recipients::One(sender_pk.clone()),
                                                    payload,
                                                    true,
                                                )
                                            {
                                                warn!(?epoch, dealer = ?sender_pk, ?e, "failed to send ack");
                                            }
                                        }
                                    }
                                }
                                Message::Ack(ack) => {
                                    if let Some(ref mut ds) = dealer_state {
                                        let added = ds
                                            .handle(&mut storage, epoch, sender_pk.clone(), ack)
                                            .await;
                                        if added {
                                            let _ = self
                                                .latest_ack
                                                .get_or_create_by(&sender_pk)
                                                .try_set_max(epoch.get());
                                        }
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
                Some(mailbox_msg) = self.mailbox.recv() else {
                    warn!("dkg actor mailbox closed");
                    break 'actor;
                } => match mailbox_msg {
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
                        let bounds = epocher
                            .containing(block.height)
                            .expect("block height covered by epoch strategy");
                        let block_epoch = bounds.epoch();
                        let phase = bounds.phase();
                        let relative_height = bounds.relative();
                        info!(epoch = %block_epoch, relative_height = %relative_height, "processing finalized block");

                        // Skip blocks from previous epochs (can happen on restart if we
                        // persisted state but crashed before acknowledging)
                        if block_epoch < epoch {
                            response.acknowledge();
                            continue;
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
                        if phase == EpochPhase::Early {
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
                        if matches!(phase, EpochPhase::Midpoint | EpochPhase::Late) {
                            if let Some(ref mut ds) = dealer_state {
                                ds.finalize::<N3f1>();
                            }
                        }

                        // Continue if not the last block in the epoch
                        if block.height != bounds.last() {
                            // Acknowledge block processing
                            response.acknowledge();
                            continue;
                        }

                        // Finalize the round before acknowledging
                        //
                        // TODO(#3453): Minimize end-of-epoch processing via pre-verify
                        let mut logs = Logs::<_, _, N3f1>::new(round.clone());
                        for (dealer, log) in storage.logs(epoch) {
                            logs.record(dealer, log);
                        }
                        let (success, next_round, next_output, next_share) =
                            if let Some(ps) = player_state.take() {
                                match ps.finalize::<N3f1, Batch>(
                                    self.context.as_present_mut(),
                                    logs,
                                    &Sequential,
                                ) {
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
                                match observe::<_, _, N3f1, Batch>(
                                    self.context.as_present_mut(),
                                    logs,
                                    &Sequential,
                                ) {
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
                            self.successful_epochs.inc();

                            // Record reveals
                            let output = next_output.as_ref().expect("output exists on success");
                            let revealed = output.revealed();
                            self.all_reveals.inc_by(revealed.len() as u64);
                            if revealed.position(&self_pk).is_some() {
                                self.our_reveals.inc();
                            }
                        } else {
                            warn!(?epoch, "epoch failed");
                            self.failed_epochs.inc();
                        }
                        storage
                            .set_epoch(
                                epoch.next(),
                                EpochState {
                                    round: next_round,
                                    rng_seed: Summary::random(self.context.as_present_mut()),
                                    output: next_output.clone(),
                                    share: next_share.clone(),
                                },
                            )
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

                        // Exit the engine for this epoch now that the boundary is finalized
                        orchestrator.exit(epoch).await;

                        // If the update is stop, wait forever.
                        if let PostUpdate::Stop = callback.on_update(update).await {
                            // Close the mailbox to prevent accepting any new messages
                            drop(self.mailbox);
                            // Keep running until killed to keep the orchestrator mailbox alive
                            info!("DKG complete; waiting for shutdown...");
                            futures::future::pending::<()>().await;
                            break 'actor;
                        }

                        break;
                    }
                },
            }
        }
        info!("exiting DKG actor");
    }

    async fn distribute_shares<S: Sender<PublicKey = C::PublicKey>>(
        self_pk: &C::PublicKey,
        storage: &mut Storage<E, V, C::PublicKey>,
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
                        .handle::<_, N3f1>(storage, epoch, self_pk.clone(), pub_msg, priv_msg)
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
            let payload = Message::<V, C::PublicKey>::Dealer(pub_msg, priv_msg).encode();
            match sender.send(Recipients::One(player.clone()), payload, true) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dkg::ContinueOnUpdate, orchestrator::Message, setup::PeerConfig};
    use commonware_actor::Feedback;
    use commonware_cryptography::{
        bls12381::{dkg::deal, primitives::variant::MinSig},
        ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
        transcript::Summary,
        Sha256, Signer,
    };
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_p2p::{utils::mocks::inert_channel, PeerSetSubscription, Provider};
    use commonware_runtime::{deterministic, Runner, Supervisor as _};
    use commonware_utils::{channel::mpsc, N3f1, NZUsize, TryCollect, NZU32};
    use core::marker::PhantomData;
    use std::collections::BTreeMap;

    #[derive(Clone, Debug)]
    struct NoopManager<P: PublicKey>(PhantomData<P>);

    impl<P: PublicKey> Default for NoopManager<P> {
        fn default() -> Self {
            Self(PhantomData)
        }
    }

    impl<P: PublicKey> Provider for NoopManager<P> {
        type PublicKey = P;

        async fn peer_set(&mut self, _: u64) -> Option<TrackedPeers<Self::PublicKey>> {
            None
        }

        async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
            let (_, rx) = mpsc::unbounded_channel();
            rx
        }
    }

    impl<P: PublicKey> Manager for NoopManager<P> {
        fn track<R>(&mut self, _: u64, _: R) -> Feedback
        where
            R: Into<TrackedPeers<Self::PublicKey>> + Send,
        {
            Feedback::Ok
        }
    }

    fn peer_config(
        total: u64,
        per_round: Vec<u32>,
    ) -> (
        PeerConfig<Ed25519PublicKey>,
        BTreeMap<Ed25519PublicKey, PrivateKey>,
    ) {
        let participants = (0..total)
            .map(|seed| {
                let signer = PrivateKey::from_seed(seed);
                (signer.public_key(), signer)
            })
            .collect::<BTreeMap<_, _>>();
        let peer_config = PeerConfig {
            num_participants_per_round: per_round,
            participants: participants.keys().cloned().try_collect().unwrap(),
        };
        (peer_config, participants)
    }

    #[test_traced]
    fn recovered_storage_controls_dkg_mode_on_restart() {
        let executor = deterministic::Runner::seeded(8);
        executor.start(|mut context| async move {
            // Seed a mid-life state well past the bootstrap epoch so the recovered round is
            // unambiguously not the initial DKG. Per production semantics, the stored output
            // carries the current round's dealers as its players (produced by the prior
            // reshare), so deal with `dealers(RECOVERED_ROUND)`.
            const RECOVERED_EPOCH: u64 = 5;
            const RECOVERED_ROUND: u64 = 5;
            let (peer_config, participants) = peer_config(6, vec![4]);
            let first_player = peer_config
                .dealers(RECOVERED_ROUND)
                .iter()
                .next()
                .cloned()
                .expect("recovered dealer exists");
            let signer = participants
                .get(&first_player)
                .cloned()
                .expect("signer should exist");
            let (output, shares) = deal::<MinSig, _, N3f1>(
                &mut context,
                Default::default(),
                peer_config.dealers(RECOVERED_ROUND),
            )
            .expect("deal should succeed");
            let share = shares.get_value(&first_player).cloned();
            let partition_prefix = format!("recovered_restart_{first_player}");

            // Seed durable state that looks like a completed reshare several rounds in, even
            // though the restarted actor will be given stale bootstrap inputs below.
            let mut storage = Storage::<_, MinSig, Ed25519PublicKey>::init(
                context.child("seed_storage"),
                &partition_prefix,
                NZU32!(peer_config.max_participants_per_round()),
                crate::dkg::MAX_SUPPORTED_MODE,
            )
            .await;
            storage
                .set_epoch(
                    Epoch::new(RECOVERED_EPOCH),
                    EpochState {
                        round: RECOVERED_ROUND,
                        rng_seed: Summary::random(&mut context),
                        output: Some(output),
                        share,
                    },
                )
                .await;
            drop(storage);

            // Restart the actor with stale bootstrap inputs (output=None, share=None). The
            // recovered epoch must override these.
            let (actor, _mailbox) = Actor::<_, _, Sha256, _, MinSig>::new(
                context.child("actor"),
                Config {
                    manager: NoopManager::<Ed25519PublicKey>::default(),
                    signer,
                    mailbox_size: NZUsize!(8),
                    partition_prefix,
                    peer_config: peer_config.clone(),
                    max_supported_mode: crate::dkg::MAX_SUPPORTED_MODE,
                },
            );
            let (sender, receiver) = inert_channel(&peer_config.participants);
            let (orchestrator_sender, mut orchestrator_receiver) = mpsc::channel(4);
            actor.start(
                None,
                None,
                orchestrator::Mailbox::new(orchestrator_sender),
                (sender, receiver),
                ContinueOnUpdate::boxed(),
            );

            // The first epoch transition the actor emits should describe the recovered reshare
            // round. Under the bug, `is_dkg` was computed from the `None` startup output and the
            // actor re-entered the bootstrap DKG path, producing a transition with all
            // participants as dealers and an empty poly.
            let Some(Message::Enter(transition)) = orchestrator_receiver.recv().await else {
                panic!("actor should emit an epoch transition");
            };
            assert_eq!(transition.epoch, Epoch::new(RECOVERED_EPOCH));
            assert!(
                transition.poly.is_some(),
                "transition should carry the recovered public polynomial",
            );
            assert_eq!(transition.dealers, peer_config.dealers(RECOVERED_ROUND));
        });
    }
}
