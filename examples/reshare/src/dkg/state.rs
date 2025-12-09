//! Persistent storage for DKG protocol state.
//!
//! Stores epoch state and per-epoch messages (dealer broadcasts, player acks, logs)
//! using append-only journals for crash recovery. In-memory BTreeMaps provide fast
//! lookups while the journal ensures durability.

use commonware_codec::{EncodeSize, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::{DealerLog, DealerPrivMsg, DealerPubMsg, Output, PlayerAck},
        primitives::{group::Share, variant::Variant},
    },
    transcript::Summary,
    PublicKey,
};
use commonware_runtime::{buffer::PoolRef, ContextCell, Metrics, Storage};
use commonware_storage::journal::{
    contiguous::variable::{Config as CVConfig, Journal as CVJournal},
    segmented::variable::{Config as SVConfig, Journal as SVJournal},
};
use commonware_utils::{NZUsize, NZU64};
use futures::StreamExt;
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroUsize},
};

const PAGE_SIZE: NonZeroUsize = NZUsize!(1 << 12);
const POOL_CAPACITY: NonZeroUsize = NZUsize!(1 << 20);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 12);
const READ_BUFFER: NonZeroUsize = NZUsize!(1 << 20);

/// Epoch-level DKG state persisted across restarts.
#[derive(Clone)]
pub struct DkgState<V: Variant, P: PublicKey> {
    pub round: u64,
    pub rng_seed: Summary,
    pub output: Option<Output<V, P>>,
    pub share: Option<Share>,
}

impl<V: Variant, P: PublicKey> EncodeSize for DkgState<V, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.rng_seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for DkgState<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.round.write(buf);
        self.rng_seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for DkgState<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            round: ReadExt::read(buf)?,
            rng_seed: ReadExt::read(buf)?,
            output: Read::read_cfg(buf, cfg)?,
            share: ReadExt::read(buf)?,
        })
    }
}

/// An event we want to record to replay later, if we crash.
enum DkgEvent<V: Variant, P: PublicKey> {
    /// A dealer message we received and committed to ack (as a player).
    /// Once persisted, we will always generate the same ack for this dealer.
    Dealer(P, DealerPubMsg<V>, DealerPrivMsg),
    /// A player ack we received (as a dealer).
    Player(P, PlayerAck<P>),
    /// A finalized dealer log.
    Log(P, DealerLog<V, P>),
}

impl<V: Variant, P: PublicKey> EncodeSize for DkgEvent<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealer(x0, x1, x2) => x0.encode_size() + x1.encode_size() + x2.encode_size(),
            Self::Player(x0, x1) => x0.encode_size() + x1.encode_size(),
            Self::Log(x0, x1) => x0.encode_size() + x1.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Write for DkgEvent<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Dealer(x0, x1, x2) => {
                0u8.write(buf);
                x0.write(buf);
                x1.write(buf);
                x2.write(buf);
            }
            Self::Player(x0, x1) => {
                1u8.write(buf);
                x0.write(buf);
                x1.write(buf);
            }
            Self::Log(x0, x1) => {
                2u8.write(buf);
                x0.write(buf);
                x1.write(buf);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> Read for DkgEvent<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Dealer(
                ReadExt::read(buf)?,
                Read::read_cfg(buf, cfg)?,
                ReadExt::read(buf)?,
            )),
            1 => Ok(Self::Player(ReadExt::read(buf)?, ReadExt::read(buf)?)),
            2 => Ok(Self::Log(ReadExt::read(buf)?, Read::read_cfg(buf, cfg)?)),
            other => Err(commonware_codec::Error::InvalidEnum(other)),
        }
    }
}

/// In-memory cache for a single epoch's DKG messages.
struct EpochCache<V: Variant, P: PublicKey> {
    dealer_msgs: BTreeMap<P, (DealerPubMsg<V>, DealerPrivMsg)>,
    player_acks: BTreeMap<P, PlayerAck<P>>,
    logs: BTreeMap<P, DealerLog<V, P>>,
}

impl<V: Variant, P: PublicKey> Default for EpochCache<V, P> {
    fn default() -> Self {
        Self {
            dealer_msgs: BTreeMap::new(),
            player_acks: BTreeMap::new(),
            logs: BTreeMap::new(),
        }
    }
}

/// DKG persistent storage.
///
/// Wraps journaled storage for epoch state and protocol messages,
/// with in-memory BTreeMaps for fast lookups. The journal ensures
/// durability while the maps provide O(log n) access.
pub struct State<E: Storage + Metrics, V: Variant, P: PublicKey> {
    dkg_states_journal: CVJournal<ContextCell<E>, DkgState<V, P>>,
    dkg_msgs_journal: SVJournal<ContextCell<E>, DkgEvent<V, P>>,

    // In-memory state
    current_dkg_state: Option<(Epoch, DkgState<V, P>)>,
    epoch_caches: BTreeMap<Epoch, EpochCache<V, P>>,
}

impl<E: Storage + Metrics, V: Variant, P: PublicKey> State<E, V, P> {
    /// Initialize storage, creating partitions if needed.
    /// Replays journals to populate in-memory caches.
    pub async fn init(context: E, partition_prefix: &str, max_read_size: NonZeroU32) -> Self {
        let cell = ContextCell::new(context);
        let buffer_pool = PoolRef::new(PAGE_SIZE, POOL_CAPACITY);

        let dkg_states_journal = CVJournal::init(
            cell.with_label("dkg-states"),
            CVConfig {
                partition: format!("{partition_prefix}_dkg_states"),
                compression: None,
                codec_config: max_read_size,
                buffer_pool: buffer_pool.clone(),
                write_buffer: WRITE_BUFFER,
                items_per_section: NZU64!(1),
            },
        )
        .await
        .expect("should be able to init dkg_states journal");

        let dkg_msgs_journal = SVJournal::init(
            cell.with_label("dkg-msgs"),
            SVConfig {
                partition: format!("{partition_prefix}_dkg_msgs"),
                compression: None,
                codec_config: max_read_size,
                buffer_pool,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("should be able to init dkg_msgs journal");

        // Replay dkg_states to get current state
        let current_dkg_state = {
            let size = dkg_states_journal.size();
            if size == 0 {
                None
            } else {
                Some((
                    Epoch::new(size - 1),
                    dkg_states_journal
                        .read(size - 1)
                        .await
                        .expect("should be able to read dkg_state"),
                ))
            }
        };

        // Replay dkg_msgs to populate epoch caches
        let mut epoch_caches = BTreeMap::<Epoch, EpochCache<V, P>>::new();
        {
            let replay = dkg_msgs_journal
                .replay(0, 0, READ_BUFFER)
                .await
                .expect("should be able to replay dkg_msgs");
            futures::pin_mut!(replay);

            while let Some(result) = replay.next().await {
                let (section, _, _, event) = result.expect("should be able to read dkg_msg");
                let epoch = Epoch::new(section);
                let cache = epoch_caches.entry(epoch).or_default();
                match event {
                    DkgEvent::Dealer(dealer, pub_msg, priv_msg) => {
                        cache.dealer_msgs.insert(dealer, (pub_msg, priv_msg));
                    }
                    DkgEvent::Player(player, ack) => {
                        cache.player_acks.insert(player, ack);
                    }
                    DkgEvent::Log(dealer, log) => {
                        cache.logs.insert(dealer, log);
                    }
                }
            }
        }

        Self {
            dkg_states_journal,
            dkg_msgs_journal,
            current_dkg_state,
            epoch_caches,
        }
    }

    /// Returns all dealer messages received during the given epoch.
    pub fn dealer_msgs(&self, epoch: Epoch) -> Vec<(P, DealerPubMsg<V>, DealerPrivMsg)> {
        self.epoch_caches
            .get(&epoch)
            .map(|cache| {
                cache
                    .dealer_msgs
                    .iter()
                    .map(|(k, (v1, v2))| (k.clone(), v1.clone(), v2.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all player acknowledgments received during the given epoch.
    pub fn player_acks(&self, epoch: Epoch) -> Vec<(P, PlayerAck<P>)> {
        self.epoch_caches
            .get(&epoch)
            .map(|cache| {
                cache
                    .player_acks
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all finalized dealer logs for the given epoch.
    pub fn logs(&self, epoch: Epoch) -> BTreeMap<P, DealerLog<V, P>> {
        self.epoch_caches
            .get(&epoch)
            .map(|cache| cache.logs.clone())
            .unwrap_or_default()
    }

    /// Checks if a dealer has already submitted a log this epoch.
    pub fn has_submitted_log(&self, epoch: Epoch, dealer: &P) -> bool {
        self.epoch_caches
            .get(&epoch)
            .map(|cache| cache.logs.contains_key(dealer))
            .unwrap_or(false)
    }

    /// Returns the current epoch and DKG state, if initialized.
    pub fn dkg_state(&self) -> Option<(Epoch, DkgState<V, P>)> {
        self.current_dkg_state
            .as_ref()
            .map(|(e, s)| (*e, s.clone()))
    }

    fn get_or_create_cache(&mut self, epoch: Epoch) -> &mut EpochCache<V, P> {
        self.epoch_caches.entry(epoch).or_default()
    }

    /// Persists a dealer message for crash recovery.
    pub async fn append_dealer_msg(
        &mut self,
        epoch: Epoch,
        dealer: P,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) {
        // Persist to journal
        let section = epoch.get();
        self.dkg_msgs_journal
            .append(
                section,
                DkgEvent::Dealer(dealer.clone(), pub_msg.clone(), priv_msg.clone()),
            )
            .await
            .expect("should be able to write to dkg_msgs");
        self.dkg_msgs_journal
            .sync(section)
            .await
            .expect("should be able to sync dkg_msgs");

        // Update in-memory cache
        self.get_or_create_cache(epoch)
            .dealer_msgs
            .insert(dealer, (pub_msg, priv_msg));
    }

    /// Persists a player acknowledgment we received (as a dealer) for crash recovery.
    pub async fn append_player_ack(&mut self, epoch: Epoch, player: P, ack: PlayerAck<P>) {
        // Persist to journal
        let section = epoch.get();
        self.dkg_msgs_journal
            .append(section, DkgEvent::Player(player.clone(), ack.clone()))
            .await
            .expect("should be able to write to dkg_msgs");
        self.dkg_msgs_journal
            .sync(section)
            .await
            .expect("should be able to sync dkg_msgs");

        // Update in-memory cache
        self.get_or_create_cache(epoch)
            .player_acks
            .insert(player, ack);
    }

    /// Persists a finalized dealer log.
    pub async fn append_log(&mut self, epoch: Epoch, dealer: P, log: DealerLog<V, P>) {
        // Persist to journal
        let section = epoch.get();
        self.dkg_msgs_journal
            .append(section, DkgEvent::Log(dealer.clone(), log.clone()))
            .await
            .expect("should be able to write to dkg_msgs");
        self.dkg_msgs_journal
            .sync(section)
            .await
            .expect("should be able to sync dkg_msgs");

        // Update in-memory cache
        self.get_or_create_cache(epoch).logs.insert(dealer, log);
    }

    /// Persists new epoch state, advancing to the next epoch.
    pub async fn append_dkg_state(&mut self, state: DkgState<V, P>) {
        // Update in-memory state first (clone before moving to journal)
        let size = self.dkg_states_journal.size();
        let epoch = Epoch::new(size);
        self.current_dkg_state = Some((epoch, state.clone()));

        // Persist to journal
        self.dkg_states_journal
            .append(state)
            .await
            .expect("should be able to write to dkg_state");
        self.dkg_states_journal
            .sync()
            .await
            .expect("should be able to sync dkg_state");
    }

    /// Removes all data from epochs older than `min`.
    pub async fn prune(&mut self, min: Epoch) {
        let section = min.get();
        self.dkg_msgs_journal
            .prune(section)
            .await
            .expect("should be able to prune dkg_msgs");
        self.dkg_states_journal
            .prune(section)
            .await
            .expect("should be able to prune dkg_states");

        // Remove old epoch caches
        self.epoch_caches.retain(|&epoch, _| epoch >= min);
    }
}
