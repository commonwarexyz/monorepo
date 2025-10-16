use super::{Mailbox, Message};
use crate::{
    dkg::{manager::RoundResult, DealOutcome, DkgManager},
    utils::{is_last_block_in_epoch, BLOCKS_PER_EPOCH},
};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::{player::Output, types::Ack},
        primitives::{group::Share, poly::Public, variant::Variant},
    },
    Hasher, Signer,
};
use commonware_macros::select;
use commonware_p2p::{utils::mux::Muxer, Receiver, Sender};
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::{
    store::{self, Store},
    translator::TwoCap,
};
use commonware_utils::{quorum, sequence::FixedBytes, NZUsize};
use futures::{channel::mpsc, StreamExt};
use rand_core::CryptoRngCore;
use std::{cmp::Ordering, collections::BTreeMap, num::NonZero};
use tracing::info;

pub struct Config<C> {
    pub signer: C,
    pub num_participants: usize,
    pub mailbox_size: usize,

    pub partition_prefix: String,
    pub buffer_pool: PoolRef,
    pub log_items_per_section: NonZero<u64>,
    pub locations_items_per_blob: NonZero<u64>,
}

pub struct Actor<E, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + Storage,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<H, C, V>>,
    signer: C,
    num_participants_per_epoch: usize,
    store: Store<ContextCell<E>, FixedBytes<8>, RoundInfo<V, C>, TwoCap>,
}

impl<E, H, C, V> Actor<E, H, C, V>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + Storage,
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub async fn init(context: E, config: Config<C>) -> (Self, Mailbox<H, C, V>) {
        let context = ContextCell::new(context);

        // Initialize a store for round information, to recover in case of restarts.
        let store = Store::<_, FixedBytes<8>, RoundInfo<V, C>, _>::init(
            context.with_label("store"),
            store::Config {
                log_journal_partition: format!("{}_dkg_store", config.partition_prefix),
                log_write_buffer: NZUsize!(1024 * 1024),
                log_compression: None,
                log_codec_config: quorum(config.num_participants as u32) as usize,
                log_items_per_section: config.log_items_per_section,
                locations_journal_partition: format!(
                    "{}_dkg_store_locations",
                    config.partition_prefix
                ),
                locations_items_per_blob: config.locations_items_per_blob,
                translator: TwoCap,
                buffer_pool: config.buffer_pool,
            },
        )
        .await
        .expect("failed to initialize store");

        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                mailbox,
                signer: config.signer,
                num_participants_per_epoch: config.num_participants,
                store,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        mut self,
        active_participants: Vec<C::PublicKey>,
        inactive_participants: Vec<C::PublicKey>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                active_participants,
                inactive_participants,
                (sender, receiver)
            )
            .await
        )
    }

    async fn run(
        mut self,
        active_participants: Vec<C::PublicKey>,
        inactive_participants: Vec<C::PublicKey>,
        (sender, receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        // Start a muxer for the physical channel used by DKG/reshare
        let (mux, mut dkg_mux) =
            Muxer::new(self.context.with_label("dkg_mux"), sender, receiver, 100);
        mux.start();

        // Initialize the DKG manager for the first round.
        let mut manager = DkgManager::init(
            &mut self.context,
            0,
            &mut self.signer,
            active_participants,
            inactive_participants,
            &mut dkg_mux,
            &mut self.store,
        )
        .await;

        let stopped = &mut self.context.stopped();
        loop {
            select! {
                _ = stopped => {
                    info!("context stopped; exiting.");
                    break;
                },
                message = self.mailbox.next() => {
                    let Some(message) = message else {
                        info!("mailbox closed, exiting.");
                        break;
                    };

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

                            // Attempt to transition epochs.
                            if let Some(epoch) = is_last_block_in_epoch(block.height) {
                                let (next_participants, public, share) = match manager.finalize(epoch).await
                                {
                                    Some((
                                        next_participants,
                                        RoundResult::Output(Output { public, share }),
                                    )) => (next_participants, public, Some(share)),
                                    Some((next_participants, RoundResult::Polynomial(public))) => {
                                        (next_participants, public, None)
                                    }
                                    None => panic!("failed DKG"),
                                };

                                info!(
                                    epoch,
                                    "finalized epoch's reshare; instructing reconfiguration after reshare."
                                );

                                self.context.stop(0, None).await.unwrap();
                                break;
                                // todo!("Persist share + commitment info");
                            };

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
            }
        }
    }
}

#[allow(clippy::type_complexity)]
pub(crate) struct RoundInfo<V: Variant, C: Signer> {
    pub deal: Option<(Public<V>, Vec<Share>, BTreeMap<u32, Ack<C::Signature>>)>,
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
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            deal: Option::<(Public<V>, Vec<Share>, BTreeMap<u32, Ack<C::Signature>>)>::read_cfg(
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
