use super::{Mailbox, Message};
use crate::{
    orchestrator::{self, EpochTransition},
    setup::ParticipantConfig,
    BLOCKS_PER_EPOCH,
};
use commonware_codec::{Encode, EncodeSize, Read, ReadExt as _, Write};
use commonware_consensus::{
    types::Epoch,
    utils::{epoch, is_last_block_in_epoch, relative_height_in_epoch},
    Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg2::{Output, RoundInfo, SignedDealerLog},
        primitives::{group::Share, variant::Variant},
    },
    Hasher, PrivateKey, PublicKey,
};
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{hex, quorum, sequence::FixedBytes, set::Ordered, Acknowledgement, NZU32};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::counter::Counter;
use rand::{
    rngs::StdRng,
    seq::{IteratorRandom, SliceRandom},
    SeedableRng,
};
use rand_core::CryptoRngCore;
use std::{cmp::Ordering, path::PathBuf};
use tracing::info;

mod dealer;
mod player;

fn select_participants<T: Clone + Ord>(
    is_dkg: bool,
    current_epoch: Epoch,
    num_participants: usize,
    active_participants: Vec<T>,
    inactive_participants: Vec<T>,
) -> (Ordered<T>, Ordered<T>) {
    let (dealers, players) = {
        let epoch0_players = players_for_initial_epoch(
            inactive_participants.clone(),
            &active_participants,
            num_participants,
        );
        if let Some(prev) = current_epoch.previous() {
            let all_participants = active_participants
                .iter()
                .chain(inactive_participants.iter())
                .cloned()
                .collect::<Ordered<_>>();
            let dealers = if prev.is_zero() {
                epoch0_players.clone()
            } else {
                choose_from_all(&all_participants, num_participants, prev)
            };
            let players = choose_from_all(&all_participants, num_participants, current_epoch);

            (dealers, players)
        } else {
            (active_participants, epoch0_players)
        }
    };

    let dealers: Ordered<T> = dealers.into_iter().collect();
    let players: Ordered<T> = players.into_iter().collect();

    if is_dkg {
        (dealers.clone(), dealers)
    } else {
        (dealers, players)
    }
}

fn players_for_initial_epoch<T: Clone + Ord>(
    mut candidates: Vec<T>,
    fallback: &[T],
    target: usize,
) -> Vec<T> {
    match candidates.len().cmp(&target) {
        Ordering::Less => {
            let mut rng = StdRng::seed_from_u64(0);
            let additions = fallback
                .choose_multiple(&mut rng, target - candidates.len())
                .cloned()
                .collect::<Vec<_>>();
            candidates.extend(additions);
            candidates
        }
        Ordering::Greater => {
            candidates.truncate(target);
            candidates
        }
        Ordering::Equal => candidates,
    }
}

fn choose_from_all<T: Clone + Ord>(
    participants: &Ordered<T>,
    num_participants: usize,
    epoch: Epoch,
) -> Vec<T> {
    let mut rng = StdRng::seed_from_u64(epoch.get());
    participants
        .iter()
        .cloned()
        .choose_multiple(&mut rng, num_participants)
}

#[derive(Clone)]
struct EpochState<V: Variant, P: PublicKey> {
    epoch: Epoch,
    output_and_share: Option<(Output<V, P>, Share)>,
}

impl<V: Variant, P: PublicKey> Default for EpochState<V, P> {
    fn default() -> Self {
        Self {
            epoch: Default::default(),
            output_and_share: None,
        }
    }
}

impl<V: Variant, P: PublicKey> Write for EpochState<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.epoch.write(buf);
        self.output_and_share.write(buf);
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for EpochState<V, P> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.output_and_share.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Read for EpochState<V, P> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            epoch: Epoch::read(buf)?.into(),
            output_and_share: Read::read_cfg(buf, &(cfg, ()))?,
        })
    }
}

pub struct Config<C, P> {
    pub manager: P,
    pub participant_config: Option<(PathBuf, ParticipantConfig)>,
    pub signer: C,
    pub num_participants_per_epoch: u32,
    pub mailbox_size: usize,
    pub partition_prefix: String,
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
    participant_config: Option<(PathBuf, ParticipantConfig)>,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    rate_limit: Quota,
    round_metadata: Metadata<ContextCell<E>, U64, RoundInfo<V, C>>,
    epoch_metadata: Metadata<ContextCell<E>, FixedBytes<1>, EpochState<V>>,
    num_participants: u32,
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
                codec_config: quorum(config.num_participants_per_epoch),
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
                participant_config: config.participant_config,
                mailbox,
                signer: config.signer,
                num_participants: config.num_participants_per_epoch,
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
        initial: Option<(Output<V, C::PublicKey>, Share)>,
        active_participants: Vec<C::PublicKey>,
        inactive_participants: Vec<C::PublicKey>,
        orchestrator: impl Reporter<Activity = orchestrator::Message<V, C::PublicKey>>,
        dkg_chan: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        // NOTE: In a production setting with a large validator set, the implementor may want
        // to choose a dedicated thread for the DKG actor. This actor can perform CPU-intensive
        // cryptographic operations.
        spawn_cell!(
            self.context,
            self.run(
                initial,
                active_participants,
                inactive_participants,
                orchestrator,
                dkg_chan
            )
            .await
        )
    }

    async fn run(
        mut self,
        initial: Option<(Output<V, C::PublicKey>, Share)>,
        active_participants: Vec<C::PublicKey>,
        inactive_participants: Vec<C::PublicKey>,
        mut orchestrator: impl Reporter<Activity = orchestrator::Message<V, C::PublicKey>>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        let is_dkg = initial.is_none();

        // Start a muxer for the physical channel used by DKG/reshare
        let (mux, mut dkg_mux) =
            Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
        mux.start();
        'actor: loop {
            let state = self
                .epoch_metadata
                .get(&FixedBytes::new([]))
                .cloned()
                .unwrap_or_default();
            let (dealers, players) = select_participants(
                is_dkg,
                state.epoch,
                self.num_participants,
                active_participants.clone(),
                inactive_participants.clone(),
            );
            let (_, next_players) = select_participants(
                is_dkg,
                state.epoch.next(),
                self.num_participants,
                active_participants.clone(),
                inactive_participants.clone(),
            );

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

            let (output, share) = match state.output_and_share.or_else(|| initial.clone()) {
                None => (None, None),
                Some((output, share)) => (Some(output), Some(share)),
            };

            // Inform the orchestrator of the epoch transition
            let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
                epoch: state.epoch,
                poly: output.as_ref().map(|x| x.public().clone()),
                share: share.clone(),
                dealers: dealers.clone(),
            };
            orchestrator
                .report(orchestrator::Message::Enter(transition))
                .await;

            let round_info = RoundInfo::new(state.epoch.get(), output.clone(), dealers, players)
                .expect("round info configuration should be correct");
            let (to_players, from_dealers) = dkg_mux
                .register(0)
                .await
                .expect("should be able to create channel");
            let (to_dealers, from_players) = dkg_mux
                .register(1)
                .await
                .expect("should be able to create channel");
            let mut mb_dealer = {
                let (dealer, mb) = dealer::Actor::init(
                    self.context.with_label("dealer"),
                    format!("{}_dealer", &self.partition_prefix),
                    to_players,
                    from_players,
                    round_info.clone(),
                    self.signer.clone(),
                    share.clone(),
                )
                .await;
                dealer.start();
                Some(mb)
            };
            let mut mb_player = {
                let (player, mb) = player::Actor::init(
                    self.context.with_label("player"),
                    format!("{}_player", &self.partition_prefix),
                    to_dealers,
                    from_dealers,
                    round_info,
                    self.signer.clone(),
                )
                .await;
                player.start();
                mb
            };

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
                            info!("including reshare outcome in proposed block");
                        }
                        if response.send(outcome).is_err() {
                            break 'actor;
                        }
                    }
                    Message::Finalized { block, response } => {
                        let epoch = epoch(BLOCKS_PER_EPOCH, block.height);
                        let relative_height =
                            relative_height_in_epoch(BLOCKS_PER_EPOCH, block.height);

                        // Inform the orchestrator of the epoch exit after first finalization
                        if relative_height == 0 {
                            if let Some(prev) = epoch.previous() {
                                orchestrator.report(orchestrator::Message::Exit(prev)).await;
                            }
                        }

                        // If the block contains a dealer's log, process that first.
                        if let Some(log) = block.log {
                            if mb_player.log(log).await.is_err() {
                                break 'actor;
                            }
                        }

                        // Ping the player to have it send any pending messages again.
                        if mb_player.transmit().await.is_err() {
                            break 'actor;
                        }
                        // If the dealer has not finished yet, ping it to also send out any pending messages.
                        if let Some(mb_dealer) = mb_dealer.as_mut() {
                            if mb_dealer.transmit().await.is_err() {
                                break 'actor;
                            }
                        }

                        // At the midpoint of the epoch, construct the deal outcome for inclusion.
                        if relative_height == BLOCKS_PER_EPOCH / 2 {
                            let mb_dealer = mb_dealer.take().expect("dealer finalized already!");
                            let Ok(res) = mb_dealer.finalize().await else {
                                break 'actor;
                            };
                            dealer_result = Some(res);
                        }

                        epoch_done =
                            is_last_block_in_epoch(BLOCKS_PER_EPOCH, block.height).is_some();

                        // Wait to acknowledge until the block has been processed by the application.
                        //
                        // If we did not block on processing the block, marshal could continue processing finalized blocks and start
                        // at a future block after restart (leaving the application in an unrecoverable state where we are beyond the last epoch height
                        // and not willing to enter the next epoch).
                        response.acknowledge();
                        info!(?epoch, relative_height, "finalized block");
                    }
                }
            }

            let Ok(res) = mb_player.finalize().await else {
                break 'actor;
            };
            let (success, next_output_and_share) = match res {
                Ok((new_output, new_share)) => (true, Some((new_output, new_share))),
                Err(_) => (false, output.zip(share)),
            };
            if !success {
                self.failed_rounds.inc();
            }

            info!(
                success,
                ?state.epoch,
                "finalized epoch's reshare; instructing reconfiguration after reshare.",
            );
            let next_epoch = state.epoch.next();

            // Persist the next epoch information
            let epoch_state = EpochState {
                epoch: next_epoch,
                output_and_share: next_output_and_share.clone(),
            };
            self.epoch_metadata
                .put_sync(FixedBytes::new([]), epoch_state)
                .await
                .expect("epoch metadata must update");

            // If this is a DKG, we don't want to proceed to the next round.
            match next_output_and_share {
                Some((output, share)) if is_dkg => {
                    // Close the mailbox to prevent accepting any new messages.
                    drop(self.mailbox);

                    // Exit last consensus instance to avoid useless work while we wait for shutdown (we
                    // won't need to finalize further blocks after the DKG completes).
                    orchestrator
                        .report(orchestrator::Message::Exit(state.epoch))
                        .await;

                    // Dump the share and group polynomial to disk so that it can be
                    // used by the validator process.
                    //
                    // In a production setting, care should be taken to ensure the
                    // share is stored securely.
                    if let Some((path, config)) = self.participant_config.take() {
                        config.update_and_write(path.as_path(), |config| {
                            config.polynomial = Some(hex(output.encode().as_ref()));
                            config.share = Some(share);
                        });
                    }

                    info!("dkg completed successfully, persisted outcome.");

                    // Keep running until killed to keep the orchestrator mailbox alive, allowing
                    // peers that may have gone offline to catch up.
                    //
                    // The initial DKG process will never be exited automatically, assuming coordination
                    // between participants is manual.
                    info!("DKG complete...waiting for shutdown");
                    futures::future::pending::<()>().await;
                    break 'actor;
                }
                _ => {}
            }
        }
        info!("exiting DKG actor");
    }
}
