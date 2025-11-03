use super::{Mailbox, Message};
use crate::{
    dkg::{manager::RoundResult, DealOutcome, DkgManager},
    orchestrator::{self, EpochTransition},
    setup::ParticipantConfig,
    BLOCKS_PER_EPOCH,
};
use commonware_codec::{varint::UInt, Encode, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::{
    utils::{epoch, is_last_block_in_epoch, relative_height_in_epoch},
    Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg::{player::Output, types::Ack},
        primitives::{group::Share, poly::Public, variant::Variant},
    },
    Hasher, Signer,
};
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{
    fixed_bytes, hex, quorum,
    sequence::{FixedBytes, U64},
    set::Ordered,
};
use futures::{channel::mpsc, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::counter::Counter;
use rand::{
    rngs::StdRng,
    seq::{IteratorRandom, SliceRandom},
    SeedableRng,
};
use rand_core::CryptoRngCore;
use std::{cmp::Ordering, collections::BTreeMap, path::PathBuf};
use tracing::info;

const EPOCH_METADATA_KEY: FixedBytes<1> = fixed_bytes!("0xFF");

pub struct Config<C, P> {
    pub manager: P,
    pub participant_config: Option<(PathBuf, ParticipantConfig)>,
    pub namespace: Vec<u8>,
    pub signer: C,
    pub num_participants_per_epoch: usize,
    pub mailbox_size: usize,
    pub rate_limit: Quota,

    pub partition_prefix: String,
}

pub struct Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Ordered<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    manager: P,
    participant_config: Option<(PathBuf, ParticipantConfig)>,
    namespace: Vec<u8>,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    num_participants_per_epoch: usize,
    rate_limit: Quota,
    round_metadata: Metadata<ContextCell<E>, U64, RoundInfo<V, C>>,
    epoch_metadata: Metadata<ContextCell<E>, FixedBytes<1>, EpochState<V>>,
    failed_rounds: Counter,
}

impl<E, P, H, C, V> Actor<E, P, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    P: Manager<PublicKey = C::PublicKey, Peers = Ordered<C::PublicKey>>,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub async fn init(context: E, config: Config<C, P>) -> (Self, Mailbox<H, C, V>) {
        let context = ContextCell::new(context);

        // Initialize a metadata store for epoch and round information.
        //
        // **Both of these metadata stores persist private key material to disk. In a production
        // environment, this key material should both be stored securely and deleted permanently
        // after use.**
        let epoch_metadata = Metadata::init(
            context.with_label("epoch_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_current_epoch", config.partition_prefix),
                codec_config: quorum(config.num_participants_per_epoch as u32) as usize,
            },
        )
        .await
        .expect("failed to initialize epoch metadata");
        let round_metadata = Metadata::init(
            context.with_label("round_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_dkg_rounds", config.partition_prefix),
                codec_config: quorum(config.num_participants_per_epoch as u32) as usize,
            },
        )
        .await
        .expect("failed to initialize dkg round metadata");

        let failed_rounds = Counter::default();
        context.register(
            "failed_rounds",
            "Number of failed DKG/reshare rounds",
            failed_rounds.clone(),
        );

        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                manager: config.manager,
                participant_config: config.participant_config,
                namespace: config.namespace,
                mailbox,
                signer: config.signer,
                num_participants_per_epoch: config.num_participants_per_epoch,
                rate_limit: config.rate_limit,
                round_metadata,
                epoch_metadata,
                failed_rounds,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        initial_public: Option<Public<V>>,
        initial_share: Option<Share>,
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
                initial_public,
                initial_share,
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
        initial_public: Option<Public<V>>,
        initial_share: Option<Share>,
        active_participants: Vec<C::PublicKey>,
        inactive_participants: Vec<C::PublicKey>,
        mut orchestrator: impl Reporter<Activity = orchestrator::Message<V, C::PublicKey>>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        let is_dkg = initial_public.is_none();

        // Start a muxer for the physical channel used by DKG/reshare
        let (mux, mut dkg_mux) =
            Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
        mux.start();

        // Collect all contributors (active + inactive.)
        //
        // In a practical application, all possible participants would not be known ahead of time,
        // and pulled from a registry (e.g. an on-chain stake registry for a PoS chain.)
        //
        // For the sake of the example, we assume a fixed set of contributors that can be selected
        // from.
        let (current_epoch, current_public, current_share) =
            if let Some(state) = self.epoch_metadata.get(&EPOCH_METADATA_KEY).cloned() {
                (state.epoch, state.public, state.share)
            } else {
                (0, initial_public, initial_share)
            };
        let all_participants = Self::collect_all(&active_participants, &inactive_participants);
        let (dealers, mut players) = Self::select_participants(
            current_epoch,
            self.num_participants_per_epoch,
            active_participants,
            inactive_participants,
        );

        // If we're performing DKG, dealers == players.
        if is_dkg {
            players = dealers.clone();
        }

        // Inform the orchestrator of the epoch transition
        let dealers = dealers.into_iter().collect::<Ordered<_>>();
        let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
            epoch: current_epoch,
            poly: current_public.clone(),
            share: current_share.clone(),
            dealers: dealers.clone(),
        };
        orchestrator
            .report(orchestrator::Message::Enter(transition))
            .await;

        // Register the initial set of peers.
        //
        // Any given peer set includes:
        // - Dealers and players for the active epoch
        // - Players for the next epoch
        let peers = dealers
            .clone()
            .into_iter()
            .chain(players.clone())
            .chain(Self::choose_from_all(
                &all_participants,
                self.num_participants_per_epoch,
                current_epoch + 1,
            ))
            .collect();
        self.manager.update(current_epoch, peers).await;

        // Initialize the DKG manager for the first round.
        let mut manager = DkgManager::init(
            &mut self.context,
            self.namespace.clone(),
            current_epoch,
            current_public,
            current_share,
            &mut self.signer,
            dealers,
            players.into(),
            &mut dkg_mux,
            self.rate_limit,
            &mut self.round_metadata,
        )
        .await;

        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Act { response } => {
                    let outcome = manager.take_deal_outcome();

                    if let Some(ref outcome) = outcome {
                        info!(
                            n_acks = outcome.acks.len(),
                            n_reveals = outcome.reveals.len(),
                            "including reshare outcome in proposed block"
                        );
                    }

                    let _ = response.send(outcome);
                }
                Message::Finalized { block, response } => {
                    let epoch = epoch(BLOCKS_PER_EPOCH, block.height);
                    let relative_height = relative_height_in_epoch(BLOCKS_PER_EPOCH, block.height);

                    // Inform the orchestrator of the epoch exit after first finalization
                    if relative_height == 0 && epoch > 0 {
                        orchestrator
                            .report(orchestrator::Message::Exit(epoch - 1))
                            .await;
                    }

                    // While not done in the example, an implementor could choose to mark a deal outcome as
                    // "sent" as to not re-include it in future blocks in the event of a dealer node's
                    // shutdown.
                    //
                    // if let Some(deal_outcome) = &block.deal_outcome {
                    //     info!(
                    //         epoch,
                    //         n_acks = deal_outcome.acks.len(),
                    //         n_reveals = deal_outcome.reveals.len(),
                    //         "recording included deal outcome from block"
                    //     );
                    //     ...
                    // }

                    // Split the epoch into a "send" and "post" phase.
                    //
                    // In the first half of the epoch, dealers continuously distribute shares and process
                    // acknowledgements from players.
                    //
                    // In the second half of the epoch, dealers include their commitment, acknowledgements,
                    // and any share reveals in blocks. Players process these deal outcomes to gather
                    // all of the information needed to reconstruct their new shares and the new group
                    // polynomial.
                    let epoch_transition = is_last_block_in_epoch(BLOCKS_PER_EPOCH, block.height);
                    match relative_height.cmp(&(BLOCKS_PER_EPOCH / 2)) {
                        Ordering::Less => {
                            // Continuously distribute shares to any players who haven't acknowledged
                            // receipt yet.
                            manager.distribute(epoch).await;

                            // Process any incoming messages from other dealers/players.
                            manager.process_messages(epoch).await;
                        }
                        Ordering::Equal => {
                            // Process any final messages from other dealers/players.
                            manager.process_messages(epoch).await;

                            // At the midpoint of the epoch, construct the deal outcome for inclusion.
                            manager.construct_deal_outcome(epoch).await;
                        }
                        Ordering::Greater => {
                            // Process any incoming deal outcomes from dealing contributors.
                            manager.process_block(epoch, block).await;
                        }
                    }

                    // Attempt to transition epochs.
                    if let Some(epoch) = epoch_transition {
                        let (next_dealers, next_public, next_share, success) =
                            match manager.finalize(epoch).await {
                                (
                                    next_dealers,
                                    RoundResult::Output(Output { public, share }),
                                    success,
                                ) => (next_dealers, Some(public), Some(share), success),
                                (next_dealers, RoundResult::Polynomial(public), success) => {
                                    (next_dealers, Some(public), None, success)
                                }
                                (next_dealers, RoundResult::None, success) => {
                                    (next_dealers, None, None, success)
                                }
                            };

                        if !success {
                            self.failed_rounds.inc();
                        }

                        info!(
                            success,
                            epoch,
                            ?next_public,
                            "finalized epoch's reshare; instructing reconfiguration after reshare.",
                        );
                        let next_epoch = epoch + 1;

                        // Persist the next epoch information
                        let epoch_state = EpochState {
                            epoch: next_epoch,
                            public: next_public.clone(),
                            share: next_share.clone(),
                        };
                        self.epoch_metadata
                            .put_sync(EPOCH_METADATA_KEY, epoch_state)
                            .await
                            .expect("epoch metadata must update");

                        // Prune the round metadata for two epochs ago (if this block is replayed,
                        // we may still need the old metadata)
                        if let Some(epoch) = next_epoch.checked_sub(2) {
                            self.round_metadata.remove(&epoch.into());
                            self.round_metadata
                                .sync()
                                .await
                                .expect("metadata must sync");
                        }

                        // If the DKG succeeded, exit.
                        if is_dkg && next_public.is_some() {
                            // Dump the share and group polynomial to disk so that it can be
                            // used by the validator process.
                            //
                            // In a production setting, care should be taken to ensure the
                            // share is stored securely.
                            if let Some((path, config)) = self.participant_config.take() {
                                config.update_and_write(path.as_path(), |config| {
                                    config.polynomial =
                                        next_public.map(|p| hex(p.encode().as_ref()));
                                    config.share = next_share;
                                });
                            }

                            let self_idx = all_participants
                                .position(&self.signer.public_key())
                                .expect("self must be a participant");
                            info!(
                                participant = self_idx,
                                "dkg completed successfully, persisted outcome."
                            );

                            break;
                        }

                        let next_players = if is_dkg {
                            // Use the same set of participants for DKG - if we enter a new epoch,
                            // the DKG failed, and we do not want to change the set of participants.
                            next_dealers.clone()
                        } else {
                            // Pseudorandomly select some random players to receive shares for the next epoch.
                            Self::choose_from_all(
                                &all_participants,
                                self.num_participants_per_epoch,
                                next_epoch,
                            )
                            .into_iter()
                            .collect::<Ordered<_>>()
                        };

                        // Register the players for the next epoch
                        //
                        // Any given peer set includes:
                        // - Dealers and players for the active epoch
                        // - Players for the next epoch
                        let next_peers = next_dealers
                            .clone()
                            .into_iter()
                            .chain(next_players.clone())
                            .chain(Self::choose_from_all(
                                &all_participants,
                                self.num_participants_per_epoch,
                                next_epoch + 1,
                            ))
                            .collect();
                        self.manager.update(next_epoch, next_peers).await;

                        // Inform the orchestrator of the epoch transition
                        let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
                            epoch: next_epoch,
                            poly: next_public.clone(),
                            share: next_share.clone(),
                            dealers: next_dealers.clone(),
                        };
                        orchestrator
                            .report(orchestrator::Message::Enter(transition))
                            .await;

                        // Rotate the manager to begin a new round.
                        manager = DkgManager::init(
                            &mut self.context,
                            self.namespace.clone(),
                            next_epoch,
                            next_public,
                            next_share,
                            &mut self.signer,
                            next_dealers,
                            next_players,
                            &mut dkg_mux,
                            self.rate_limit,
                            &mut self.round_metadata,
                        )
                        .await;
                    }

                    // Wait to acknowledge until the block has been processed by the application.
                    //
                    // If we did not block on processing the block, marshal could continue processing finalized blocks and start
                    // at a future block after restart (leaving the application in an unrecoverable state where we are beyond the last epoch height
                    // and not willing to enter the next epoch).
                    response.send(()).expect("response channel closed");
                    info!(epoch, relative_height, "finalized block");
                }
            }
        }

        // If the initial DKG was just performed, keep running until forcible exit.
        if is_dkg {
            // Close the mailbox to prevent accepting any new messages.
            drop(self.mailbox);

            // Exit last consensus instance to avoid useless work while we wait for shutdown (we
            // won't need to finalize further blocks after the DKG completes).
            orchestrator
                .report(orchestrator::Message::Exit(current_epoch))
                .await;

            // Keep running until killed to keep the orchestrator mailbox alive, allowing
            // peers that may have gone offline to catch up.
            //
            // The initial DKG process will never be exited automatically, assuming coordination
            // between participants is manual.
            info!("DKG complete...waiting for shutdown");
            futures::future::pending::<()>().await;
        }

        info!("mailbox closed, exiting.");
    }

    fn select_participants(
        current_epoch: u64,
        num_participants: usize,
        active_participants: Vec<C::PublicKey>,
        inactive_participants: Vec<C::PublicKey>,
    ) -> (Vec<C::PublicKey>, Vec<C::PublicKey>) {
        let epoch0_players = Self::players_for_initial_epoch(
            inactive_participants.clone(),
            &active_participants,
            num_participants,
        );
        if current_epoch == 0 {
            return (active_participants, epoch0_players);
        }

        let all_participants = Self::collect_all(&active_participants, &inactive_participants);
        let dealers = if current_epoch == 1 {
            epoch0_players.clone()
        } else {
            Self::choose_from_all(&all_participants, num_participants, current_epoch - 1)
        };
        let players = Self::choose_from_all(&all_participants, num_participants, current_epoch);

        (dealers, players)
    }

    fn players_for_initial_epoch(
        mut candidates: Vec<C::PublicKey>,
        fallback: &[C::PublicKey],
        target: usize,
    ) -> Vec<C::PublicKey> {
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

    fn choose_from_all(
        participants: &Ordered<C::PublicKey>,
        num_participants: usize,
        seed: u64,
    ) -> Vec<C::PublicKey> {
        let mut rng = StdRng::seed_from_u64(seed);
        participants
            .iter()
            .cloned()
            .choose_multiple(&mut rng, num_participants)
    }

    fn collect_all(
        active_participants: &[C::PublicKey],
        inactive_participants: &[C::PublicKey],
    ) -> Ordered<C::PublicKey> {
        active_participants
            .iter()
            .chain(inactive_participants.iter())
            .cloned()
            .collect::<Ordered<_>>()
    }
}

#[derive(Clone)]
struct EpochState<V: Variant> {
    epoch: u64,
    public: Option<Public<V>>,
    share: Option<Share>,
}

impl<V: Variant> Write for EpochState<V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.epoch).write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant> EncodeSize for EpochState<V> {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size() + self.public.encode_size() + self.share.encode_size()
    }
}

impl<V: Variant> Read for EpochState<V> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            epoch: UInt::read(buf)?.into(),
            public: Option::<Public<V>>::read_cfg(buf, cfg)?,
            share: Option::<Share>::read_cfg(buf, &())?,
        })
    }
}

#[allow(clippy::type_complexity)]
pub(crate) struct RoundInfo<V: Variant, C: Signer> {
    pub deal: Option<(Public<V>, Ordered<Share>, BTreeMap<u32, Ack<C::Signature>>)>,
    pub received_shares: Vec<(C::PublicKey, Public<V>, Share)>,
    pub local_outcome: Option<DealOutcome<C, V>>,
    pub outcomes: Vec<DealOutcome<C, V>>,
}

impl<V: Variant, C: Signer> Default for RoundInfo<V, C> {
    fn default() -> Self {
        Self {
            deal: None,
            received_shares: Vec::new(),
            local_outcome: None,
            outcomes: Vec::new(),
        }
    }
}

impl<V: Variant, C: Signer> Write for RoundInfo<V, C> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.deal.write(buf);
        self.received_shares.write(buf);
        self.local_outcome.write(buf);
        self.outcomes.write(buf);
    }
}

impl<V: Variant, C: Signer> EncodeSize for RoundInfo<V, C> {
    fn encode_size(&self) -> usize {
        self.deal.encode_size()
            + self.received_shares.encode_size()
            + self.local_outcome.encode_size()
            + self.outcomes.encode_size()
    }
}

impl<V: Variant, C: Signer> Read for RoundInfo<V, C> {
    // The consensus quorum
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            deal:
                Option::<(Public<V>, Ordered<Share>, BTreeMap<u32, Ack<C::Signature>>)>::read_cfg(
                    buf,
                    &(
                        *cfg,
                        (RangeCfg::from(0..usize::MAX), ()),
                        (RangeCfg::from(0..usize::MAX), ((), ())),
                    ),
                )?,
            received_shares: Vec::<(C::PublicKey, Public<V>, Share)>::read_cfg(
                buf,
                &(RangeCfg::from(0..usize::MAX), ((), *cfg, ())),
            )?,
            local_outcome: Option::<DealOutcome<C, V>>::read_cfg(buf, cfg)?,
            outcomes: Vec::<DealOutcome<C, V>>::read_cfg(
                buf,
                &(RangeCfg::from(0..usize::MAX), *cfg),
            )?,
        })
    }
}
