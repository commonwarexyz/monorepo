use super::{Mailbox, Message};
use crate::{
    dkg::{manager::RoundResult, DealOutcome, DkgManager},
    orchestrator::EpochTransition,
    utils::{is_last_block_in_epoch, BLOCKS_PER_EPOCH},
};
use commonware_codec::{varint::UInt, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::Reporter;
use commonware_cryptography::{
    bls12381::{
        dkg::{player::Output, types::Ack},
        primitives::{group::Share, poly::Public, variant::Variant},
    },
    Hasher, Signer,
};
use commonware_p2p::{utils::mux::Muxer, Receiver, Sender};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{
    quorum,
    sequence::{FixedBytes, U64},
    set::Set,
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
use std::{cmp::Ordering, collections::BTreeMap};
use tracing::info;

const EPOCH_METADATA_KEY: FixedBytes<1> = FixedBytes::new([0xFF]);

pub struct Config<C> {
    pub namespace: Vec<u8>,
    pub signer: C,
    pub num_participants_per_epoch: usize,
    pub mailbox_size: usize,
    pub rate_limit: Quota,

    pub partition_prefix: String,
}

pub struct Actor<E, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    namespace: Vec<u8>,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    num_participants_per_epoch: usize,
    rate_limit: Quota,
    round_metadata: Metadata<ContextCell<E>, U64, RoundInfo<V, C>>,
    epoch_metadata: Metadata<ContextCell<E>, FixedBytes<1>, EpochState<V>>,
    failed_rounds: Counter,
}

impl<E, H, C, V> Actor<E, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub async fn init(context: E, config: Config<C>) -> (Self, Mailbox<H, C, V>) {
        let context = ContextCell::new(context);

        // Initialize a metadata store for the round information.
        let round_metadata = Metadata::init(
            context.with_label("round_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_dkg_rounds", config.partition_prefix),
                codec_config: quorum(config.num_participants_per_epoch as u32) as usize,
            },
        )
        .await
        .expect("failed to initialize dkg round metadata");

        let epoch_metadata = Metadata::init(
            context.with_label("metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_current_epoch", config.partition_prefix),
                codec_config: quorum(config.num_participants_per_epoch as u32) as usize,
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

        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
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
        initial_public: Public<V>,
        initial_share: Option<Share>,
        active_participants: Vec<C::PublicKey>,
        inactive_participants: Vec<C::PublicKey>,
        orchestrator: impl Reporter<Activity = EpochTransition<V, C::PublicKey>>,
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
        initial_public: Public<V>,
        initial_share: Option<Share>,
        mut active_participants: Vec<C::PublicKey>,
        mut inactive_participants: Vec<C::PublicKey>,
        mut orchestrator: impl Reporter<Activity = EpochTransition<V, C::PublicKey>>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
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
        let (initial_epoch, current_public, current_share) = if let Some(state) =
            self.epoch_metadata
                .get(&EPOCH_METADATA_KEY)
                .cloned()
        {
            (state.epoch, state.public, state.share)
        } else {
            (0, initial_public, initial_share)
        };

        let all_participants = active_participants
            .iter()
            .chain(inactive_participants.iter())
            .cloned()
            .collect::<Set<_>>();

        let mut rng = StdRng::seed_from_u64(initial_epoch);

        if initial_epoch <= 1 {
            // Ensure the number of inactive participants is equal to the number of players per epoch.
            //
            // If there are too few, randomly select some from the active set to participate next epoch
            // as well.
            //
            // If there are too many, truncate the list.
            if inactive_participants.len() < self.num_participants_per_epoch {
                let dealer_players = active_participants
                    .choose_multiple(
                        &mut rng,
                        self.num_participants_per_epoch - inactive_participants.len(),
                    )
                    .cloned()
                    .collect::<Vec<_>>();
                inactive_participants.extend_from_slice(dealer_players.as_slice());
            } else if inactive_participants.len() > self.num_participants_per_epoch {
                // Truncate the number of players if there are too many.
                inactive_participants.truncate(self.num_participants_per_epoch);
            }

            // special case: If the starting epoch has already passed, we set the dealers for the current epoch
            // as the first epoch's players, and randomly select a new set of players for the next epoch as
            // usual.
            if initial_epoch == 1 {
                active_participants = inactive_participants.clone();
                inactive_participants = all_participants
                    .iter()
                    .cloned()
                    .choose_multiple(&mut rng, self.num_participants_per_epoch);
            }
        } else {
            // If we're starting from a later epoch, we need to pseudorandomly select both the dealers
            // and players for the current epoch, based on the epoch number as a seed.
            let mut last_epoch_rng = StdRng::seed_from_u64(initial_epoch - 1);
            active_participants = all_participants
                .iter()
                .cloned()
                .choose_multiple(&mut last_epoch_rng, self.num_participants_per_epoch);
            inactive_participants = all_participants
                .iter()
                .cloned()
                .choose_multiple(&mut rng, self.num_participants_per_epoch);
        }

        // Initialize the DKG manager for the first round.
        let mut manager = DkgManager::init(
            &mut self.context,
            self.namespace.clone(),
            initial_epoch,
            current_public.clone(),
            current_share.clone(),
            &mut self.signer,
            Set::from_iter(active_participants),
            Set::from_iter(inactive_participants),
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
                Message::Finalized { block } => {
                    let epoch = block.height / BLOCKS_PER_EPOCH;
                    let relative_height = block.height % BLOCKS_PER_EPOCH;

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

                    // Attempt to transition epochs.
                    if let Some(epoch) = is_last_block_in_epoch(block.height) {
                        let (next_participants, public, share, success) =
                            match manager.finalize(epoch).await {
                                (
                                    next_participants,
                                    RoundResult::Output(Output { public, share }),
                                    success,
                                ) => (next_participants, public, Some(share), success),
                                (next_participants, RoundResult::Polynomial(public), success) => {
                                    (next_participants, public, None, success)
                                }
                            };

                        if !success {
                            self.failed_rounds.inc();
                        }

                        info!(
                            epoch,
                            "finalized epoch's reshare; instructing reconfiguration after reshare."
                        );
                        let next_epoch = epoch + 1;

                        // Pseudorandomly select some random players to receive shares for the next epoch.
                        let mut rng = StdRng::seed_from_u64(next_epoch);
                        let next_players = all_participants
                            .iter()
                            .cloned()
                            .choose_multiple(&mut rng, self.num_participants_per_epoch)
                            .into_iter()
                            .collect::<Set<_>>();

                        let transition: EpochTransition<V, C::PublicKey> = EpochTransition {
                            epoch: next_epoch,
                            poly: public.clone(),
                            share: share.clone(),
                            participants: next_participants.clone(),
                        };
                        orchestrator.report(transition).await;

                        let next_public = public.clone();
                        let next_share = share.clone();
                        let epoch_state = EpochState {
                            epoch: next_epoch,
                            public: next_public.clone(),
                            share: next_share.clone(),
                        };

                        // Prune the round metadata for the previous epoch.
                        self.round_metadata.remove(&epoch.into());
                        self.round_metadata
                            .sync()
                            .await
                            .expect("metadata must sync");

                        self.epoch_metadata
                            .put_sync(EPOCH_METADATA_KEY, epoch_state)
                            .await
                            .expect("epoch metadata must update");

                        // Rotate the manager to begin a new round.
                        manager = DkgManager::init(
                            &mut self.context,
                            self.namespace.clone(),
                            next_epoch,
                            next_public,
                            next_share,
                            &mut self.signer,
                            next_participants,
                            next_players,
                            &mut dkg_mux,
                            self.rate_limit,
                            &mut self.round_metadata,
                        )
                        .await;
                    };

                    // Split the epoch into a "send" and "post" phase.
                    //
                    // In the first half of the epoch, dealers continuously distribute shares and process
                    // acknowledgements from players.
                    //
                    // In the second half of the epoch, dealers include their commitment, acknowledgements,
                    // and any share reveals in blocks. Players process these deal outcomes to gather
                    // all of the information needed to reconstruct their new shares and the new group
                    // polynomial.
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
                }
            }
        }

        info!("mailbox closed, exiting.");
    }
}

#[allow(clippy::type_complexity)]
pub(crate) struct RoundInfo<V: Variant, C: Signer> {
    pub deal: Option<(Public<V>, Set<Share>, BTreeMap<u32, Ack<C::Signature>>)>,
    pub received_shares: Vec<(C::PublicKey, Public<V>, Share)>,
    pub local_outcome: Option<DealOutcome<C, V>>,
    pub outcomes: Vec<DealOutcome<C, V>>,
}

#[derive(Clone)]
struct EpochState<V: Variant> {
    epoch: u64,
    public: Public<V>,
    share: Option<Share>,
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

impl<V: Variant> Write for EpochState<V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.epoch).write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant> EncodeSize for EpochState<V> {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size()
            + self.public.encode_size()
            + self.share.encode_size()
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
            public: Public::<V>::read_cfg(buf, cfg)?,
            share: Option::<Share>::read_cfg(buf, &())?,
        })
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
            deal: Option::<(Public<V>, Set<Share>, BTreeMap<u32, Ack<C::Signature>>)>::read_cfg(
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
