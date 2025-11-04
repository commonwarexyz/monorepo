use super::{Mailbox, Message};
use crate::{
    dkg::{actor::observer::Observer, PostUpdate, Update, UpdateCallBack},
    orchestrator::{self, EpochTransition},
    self_channel::self_channel,
    setup::PeerConfig,
    BLOCKS_PER_EPOCH,
};
use commonware_codec::{varint::UInt, EncodeSize, Read, ReadExt, Write};
use commonware_consensus::{
    types::Epoch,
    utils::{epoch, is_last_block_in_epoch, relative_height_in_epoch},
    Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg2::{observe, Output, RoundInfo, SignedDealerLog},
        primitives::{group::Share, variant::Variant},
    },
    Hasher, PrivateKey, PublicKey,
};
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{sequence::FixedBytes, set::Ordered, Acknowledgement, NZUsize};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::counter::Counter;
use rand_core::CryptoRngCore;
use std::num::NonZeroUsize;
use tracing::info;

mod dealer;
mod observer;
mod player;

#[derive(Clone)]
struct EpochState<V: Variant, P: PublicKey> {
    epoch: Epoch,
    // Increments only when the DKG is successful.
    round: u64,
    output: Option<Output<V, P>>,
    share: Option<Share>,
}

impl<V: Variant, P: PublicKey> Default for EpochState<V, P> {
    fn default() -> Self {
        Self {
            epoch: Default::default(),
            round: Default::default(),
            output: None,
            share: None,
        }
    }
}

impl<V: Variant, P: PublicKey> Write for EpochState<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.epoch.write(buf);
        UInt(self.round).write(buf);
        self.output.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for EpochState<V, P> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + UInt(self.round).encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Read for EpochState<V, P> {
    type Cfg = NonZeroUsize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            epoch: ReadExt::read(buf)?,
            round: UInt::read(buf)?.into(),
            output: Read::read_cfg(buf, &cfg)?,
            share: ReadExt::read(buf)?,
        })
    }
}

pub struct Config<C: PrivateKey, P> {
    pub manager: P,
    pub signer: C,
    pub mailbox_size: usize,
    pub partition_prefix: String,
    pub peer_config: PeerConfig<C::PublicKey>,
}

pub struct Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Ordered<C::PublicKey>>,
    H: Hasher,
    C: PrivateKey,
    V: Variant,
{
    context: ContextCell<E>,
    manager: P,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    peer_config: PeerConfig<C::PublicKey>,
    epoch_metadata: Metadata<E, FixedBytes<0>, EpochState<V, C::PublicKey>>,
    failed_rounds: Counter,
    partition_prefix: String,
}

impl<E, P, H, C, V> Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Ordered<C::PublicKey>>,
    H: Hasher,
    C: PrivateKey,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub async fn init(context: E, config: Config<C, P>) -> (Self, Mailbox<H, C, V>) {
        // Initialize a metadata store for epoch information.
        //
        // **This stores persist private key material to disk. In a production
        // environment, this key material should both be stored securely and deleted permanently
        // after use.**
        let epoch_metadata = Metadata::init(
            context.with_label("epoch_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_current_epoch", &config.partition_prefix),
                codec_config: NZUsize!(config.peer_config.num_participants_per_epoch as usize),
            },
        )
        .await
        .expect("failed to initialize epoch metadata");

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
                epoch_metadata,
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
        update_cb: Box<dyn UpdateCallBack<V, C::PublicKey>>,
    ) -> Handle<()> {
        // NOTE: In a production setting with a large validator set, the implementor may want
        // to choose a dedicated thread for the DKG actor. This actor can perform CPU-intensive
        // cryptographic operations.
        spawn_cell!(
            self.context,
            self.run(output, share, orchestrator, dkg_chan, update_cb)
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
        let is_dkg = output.is_none();

        if self.epoch_metadata.get(&FixedBytes::new([])).is_none() {
            self.epoch_metadata
                .put_sync(
                    FixedBytes::new([]),
                    EpochState {
                        epoch: Default::default(),
                        round: 0,
                        output,
                        share,
                    },
                )
                .await
                .expect("should be able to update state");
        }

        // Start a muxer for the physical channel used by DKG/reshare.
        // Make sure to use a channel allowing sending messages to ourselves.
        let (sender, receiver) = self_channel(self.signer.public_key(), 0, sender, receiver);
        let (mux, mut dkg_mux) =
            Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
        mux.start();
        'actor: loop {
            let state = self
                .epoch_metadata
                .get(&FixedBytes::new([]))
                .expect("state has been initialized above")
                .clone();
            let (dealers, players, next_players) = if is_dkg {
                (
                    self.peer_config.participants.clone(),
                    self.peer_config.dealers(0),
                    Ordered::from([]),
                )
            } else {
                (
                    self.peer_config.dealers(state.round),
                    self.peer_config.dealers(state.round + 1),
                    self.peer_config.dealers(state.round + 2),
                )
            };

            // Any given peer set includes:
            // - Dealers and players for the active epoch
            // - Players for the next epoch
            self.manager
                .update(
                    state.epoch.get(),
                    dealers
                        .iter()
                        .cloned()
                        .chain(players.iter().cloned())
                        .chain(next_players.into_iter())
                        .collect(),
                )
                .await;

            let self_pk = self.signer.public_key();
            let am_dealer = dealers.position(&self_pk).is_some();
            let am_player = players.position(&self_pk).is_some();

            // Inform the orchestrator of the epoch transition
            if let Some(output) = state.output.as_ref() {
                let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
                    epoch: state.epoch,
                    poly: Some(output.public().clone()),
                    share: state.share.clone(),
                    dealers: dealers.clone(),
                };
                orchestrator
                    .report(orchestrator::Message::Enter(transition))
                    .await;
            }

            let round_info =
                RoundInfo::new(state.epoch.get(), state.output.clone(), dealers, players)
                    .expect("round info configuration should be correct");
            let (to_players, from_dealers) = dkg_mux
                .register(0)
                .await
                .expect("should be able to create channel");
            let (to_dealers, from_players) = dkg_mux
                .register(1)
                .await
                .expect("should be able to create channel");
            let mut mb_dealer = if am_dealer {
                let (dealer, mb) = dealer::Actor::init(
                    self.context.with_label("dealer"),
                    format!("{}_dealer", &self.partition_prefix),
                    to_players,
                    from_players,
                    round_info.clone(),
                    self.signer.clone(),
                    state.share.clone(),
                )
                .await;
                dealer.start();
                Some(mb)
            } else {
                None
            };
            let mut mb_player = if am_player {
                let (player, mb) = player::Actor::init(
                    self.context.with_label("player"),
                    format!("{}_player", &self.partition_prefix),
                    to_dealers,
                    from_dealers,
                    round_info.clone(),
                    self.signer.clone(),
                )
                .await;
                player.start();
                Some(mb)
            } else {
                None
            };
            let mut observer = Observer::load(
                self.context.with_label("observer"),
                &self.partition_prefix,
                state.epoch.get(),
                round_info.max_read_size(),
            )
            .await;

            let mut dealer_result: Option<SignedDealerLog<V, C>> = None;

            let mut epoch_done = false;

            while !epoch_done {
                let Some(m) = self.mailbox.next().await else {
                    break 'actor;
                };

                match m {
                    Message::Act { response } => {
                        let outcome = dealer_result.take();
                        if outcome.is_some() {
                            tracing::info!("including reshare outcome in proposed block");
                        }
                        if response.send(outcome).is_err() {
                            break 'actor;
                        }
                    }
                    Message::Finalized { block, response } => {
                        let epoch = epoch(BLOCKS_PER_EPOCH, block.height);
                        let relative_height =
                            relative_height_in_epoch(BLOCKS_PER_EPOCH, block.height);
                        let mid_point = BLOCKS_PER_EPOCH / 2;

                        // Inform the orchestrator of the epoch exit after first finalization
                        if relative_height == 0 {
                            if let Some(prev) = epoch.previous() {
                                orchestrator.report(orchestrator::Message::Exit(prev)).await;
                            }
                        }

                        if let Some(log) = block.log {
                            observer.put_log(&round_info, log).await;
                        }

                        // Ping the player and dealer to send their messages.
                        if relative_height < mid_point {
                            if let Some(mb_player) = mb_player.as_mut() {
                                if mb_player.transmit().await.is_err() {
                                    break 'actor;
                                }
                            }

                            if let Some(mb_dealer) = mb_dealer.as_mut() {
                                if mb_dealer.transmit().await.is_err() {
                                    break 'actor;
                                }
                            }
                        }

                        // At the midpoint of the epoch, construct the deal outcome for inclusion.
                        if relative_height == BLOCKS_PER_EPOCH / 2 {
                            if let Some(mb_dealer) = mb_dealer.take() {
                                let Ok(res) = mb_dealer.finalize().await else {
                                    break 'actor;
                                };
                                dealer_result = Some(res);
                            }
                        }

                        epoch_done =
                            is_last_block_in_epoch(BLOCKS_PER_EPOCH, block.height).is_some();

                        // Wait to acknowledge until the block has been processed by the application.
                        //
                        // If we did not block on processing the block, marshal could continue processing finalized blocks and start
                        // at a future block after restart (leaving the application in an unrecoverable state where we are beyond the last epoch height
                        // and not willing to enter the next epoch).
                        response.acknowledge();
                        tracing::debug!(?epoch, relative_height, "finalized block");
                    }
                }
            }

            let logs = observer.logs().clone();
            let (success, next_round, next_output, next_share) = if let Some(mb_player) = mb_player
            {
                let Ok(res) = mb_player.finalize(logs).await else {
                    break 'actor;
                };
                match res {
                    Ok((new_output, new_share)) => {
                        (true, state.round + 1, Some(new_output), Some(new_share))
                    }
                    Err(_) => (
                        false,
                        state.round,
                        state.output.clone(),
                        state.share.clone(),
                    ),
                }
            } else {
                match observe(round_info, logs) {
                    Ok(output) => (true, state.round + 1, Some(output), None),
                    Err(_) => (
                        false,
                        state.round,
                        state.output.clone(),
                        state.share.clone(),
                    ),
                }
            };
            if !success {
                self.failed_rounds.inc();
            }

            tracing::info!(
                success,
                ?state.epoch,
                "finalized epoch's reshare; instructing reconfiguration after reshare.",
            );
            let next_epoch = state.epoch.next();

            // Persist the next epoch information
            let epoch_state = EpochState {
                epoch: next_epoch,
                round: next_round,
                output: next_output.clone(),
                share: next_share.clone(),
            };
            self.epoch_metadata
                .put_sync(FixedBytes::new([]), epoch_state)
                .await
                .expect("epoch metadata must update");

            let update = if success {
                Update::Success {
                    epoch: state.epoch,
                    output: next_output.expect("success => output exists"),
                    share: next_share.clone(),
                }
            } else {
                Update::Failure { epoch: state.epoch }
            };
            if let PostUpdate::Stop = update_cb.on_update(update).await {
                // Close the mailbox to prevent accepting any new messages.
                drop(self.mailbox);
                // Exit last consensus instance to avoid useless work while we wait for shutdown (we
                // won't need to finalize further blocks after the DKG completes).
                orchestrator
                    .report(orchestrator::Message::Exit(state.epoch))
                    .await;
                // Keep running until killed to keep the orchestrator mailbox alive, allowing
                // peers that may have gone offline to catch up.
                //
                // The initial DKG process will never be exited automatically, assuming coordination
                // between participants is manual.
                info!("DKG told to stop post update, now waiting...");
                futures::future::pending::<()>().await;
                break 'actor;
            }
        }
        info!("exiting DKG actor");
    }
}
