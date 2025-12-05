//! Persistent storage for DKG protocol state.
//!
//! Stores epoch state and per-epoch messages (dealer broadcasts, player acks, logs)
//! using append-only journals for crash recovery.

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
use commonware_runtime::{buffer::PoolRef, ContextCell, Metrics, RwLock, Storage};
use commonware_storage::journal::{
    self,
    contiguous::variable::{Config as CVConfig, Journal as CVJournal},
    segmented::variable::{Config as SVConfig, Journal as SVJournal},
};
use commonware_utils::{NZUsize, NZU64};
use futures::{Stream, StreamExt};
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
};

const PAGE_SIZE: NonZeroUsize = NZUsize!(1 << 12);
const POOL_CAPACITY: NonZeroUsize = NZUsize!(1 << 20);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 12);
const READ_BUFFER: NonZeroUsize = NZUsize!(1 << 20);

/// Epoch-level DKG state persisted across restarts.
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
    Dealer(P, DealerPubMsg<V>, DealerPrivMsg),
    Player(P, PlayerAck<P>),
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

struct Inner<E: Storage + Metrics, V: Variant, P: PublicKey> {
    dkg_states: CVJournal<ContextCell<E>, DkgState<V, P>>,
    dkg_msgs: SVJournal<ContextCell<E>, DkgEvent<V, P>>,
}

impl<E: Storage + Metrics, V: Variant, P: PublicKey> Inner<E, V, P> {
    async fn init(
        context: E,
        partition_prefix: &str,
        max_read_size: NonZeroU32,
    ) -> Result<Self, journal::Error> {
        let cell = ContextCell::new(context);
        let buffer_pool = PoolRef::new(PAGE_SIZE, POOL_CAPACITY);
        Ok(Self {
            dkg_states: CVJournal::init(
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
            .await?,
            dkg_msgs: SVJournal::init(
                cell.with_label("dkg-msgs"),
                SVConfig {
                    partition: format!("{partition_prefix}_dkg_msgs"),
                    compression: None,
                    codec_config: max_read_size,
                    buffer_pool,
                    write_buffer: WRITE_BUFFER,
                },
            )
            .await?,
        })
    }

    async fn dkg_state(&self) -> Option<(Epoch, DkgState<V, P>)> {
        let size = self.dkg_states.size();
        if size == 0 {
            return None;
        }
        Some((
            // The first item should have epoch 0
            Epoch::new(size - 1),
            self.dkg_states
                .read(size - 1)
                .await
                .expect("should be able to read dkg_state"),
        ))
    }

    async fn append_dkg_state(&mut self, state: DkgState<V, P>) {
        self.dkg_states
            .append(state)
            .await
            .expect("should be able to write to dkg_state");
        self.dkg_states
            .sync()
            .await
            .expect("should be able to sync dkg_state");
    }

    async fn dkg_msgs(&self, epoch: Epoch) -> impl Stream<Item = DkgEvent<V, P>> + '_ {
        let section = epoch.get();
        self.dkg_msgs
            .replay(section, 0, READ_BUFFER)
            .await
            .expect("should be able to stream dkg_msgs")
            .map(|res| res.expect("should be able to stream dkg_msgs"))
            .take_while(move |(s, _, _, _)| futures::future::ready(*s == section))
            .map(|(_, _, _, dkg_msg)| dkg_msg)
    }

    async fn append_dkg_msg(&mut self, epoch: Epoch, msg: DkgEvent<V, P>) {
        let section = epoch.get();
        self.dkg_msgs
            .append(section, msg)
            .await
            .expect("should be able to write to dkg_msgs");
        self.dkg_msgs
            .sync(section)
            .await
            .expect("should be able to sync dkg_msgs");
    }

    async fn prune(&mut self, min: Epoch) {
        let section = min.get();
        self.dkg_msgs
            .prune(section)
            .await
            .expect("should be able to prune dkg_msgs");
        self.dkg_states
            .prune(section)
            .await
            .expect("should be able to prune dkg_states");
    }
}

/// Thread-safe handle to DKG persistent storage.
///
/// Wraps journaled storage for epoch state and protocol messages,
/// allowing concurrent read access and serialized writes.
pub struct State<E: Storage + Metrics, V: Variant, P: PublicKey> {
    inner: Arc<RwLock<Inner<E, V, P>>>,
}

impl<E: Storage + Metrics, V: Variant, P: PublicKey> Clone for State<E, V, P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<E: Storage + Metrics, V: Variant, P: PublicKey> State<E, V, P> {
    /// Initialize storage, creating partitions if needed.
    pub async fn init(context: E, partition_prefix: &str, max_read_size: NonZeroU32) -> Self {
        let inner = Inner::<E, V, P>::init(context, partition_prefix, max_read_size)
            .await
            .expect("should be able to init dkg storage");
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    /// Returns all dealer messages received during the given epoch.
    pub async fn dealer_msgs(&self, epoch: Epoch) -> Vec<(P, DealerPubMsg<V>, DealerPrivMsg)> {
        self.inner
            .read()
            .await
            .dkg_msgs(epoch)
            .await
            .filter_map(|x| {
                futures::future::ready(match x {
                    DkgEvent::Dealer(x0, x1, x2) => Some((x0, x1, x2)),
                    _ => None,
                })
            })
            .collect()
            .await
    }

    /// Returns all player acknowledgments received during the given epoch.
    pub async fn player_acks(&self, epoch: Epoch) -> Vec<(P, PlayerAck<P>)> {
        self.inner
            .read()
            .await
            .dkg_msgs(epoch)
            .await
            .filter_map(|x| {
                futures::future::ready(match x {
                    DkgEvent::Player(x0, x1) => Some((x0, x1)),
                    _ => None,
                })
            })
            .collect()
            .await
    }

    /// Returns all finalized dealer logs for the given epoch.
    pub async fn logs(&self, epoch: Epoch) -> BTreeMap<P, DealerLog<V, P>> {
        self.inner
            .read()
            .await
            .dkg_msgs(epoch)
            .await
            .filter_map(|x| {
                futures::future::ready(match x {
                    DkgEvent::Log(x0, x1) => Some((x0, x1)),
                    _ => None,
                })
            })
            .collect()
            .await
    }

    /// Checks if a dealer has already submitted a log this epoch.
    pub async fn has_submitted_log(&self, epoch: Epoch, dealer: &P) -> bool {
        self.inner
            .read()
            .await
            .dkg_msgs(epoch)
            .await
            .any(|x| futures::future::ready(matches!(x, DkgEvent::Log(d, _) if d == *dealer)))
            .await
    }

    /// Returns the current epoch and DKG state, if initialized.
    pub async fn dkg_state(&self) -> Option<(Epoch, DkgState<V, P>)> {
        self.inner.read().await.dkg_state().await
    }

    /// Persists a dealer message for crash recovery.
    pub async fn append_dealer_msg(
        &self,
        epoch: Epoch,
        dealer: P,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) {
        self.inner
            .write()
            .await
            .append_dkg_msg(epoch, DkgEvent::Dealer(dealer, pub_msg, priv_msg))
            .await;
    }

    /// Persists a player acknowledgment for crash recovery.
    pub async fn append_player_ack(&self, epoch: Epoch, player: P, ack: PlayerAck<P>) {
        self.inner
            .write()
            .await
            .append_dkg_msg(epoch, DkgEvent::Player(player, ack))
            .await;
    }

    /// Persists a finalized dealer log.
    pub async fn append_log(&self, epoch: Epoch, dealer: P, log: DealerLog<V, P>) {
        self.inner
            .write()
            .await
            .append_dkg_msg(epoch, DkgEvent::Log(dealer, log))
            .await;
    }

    /// Persists new epoch state, advancing to the next epoch.
    pub async fn append_dkg_state(&self, state: DkgState<V, P>) {
        self.inner.write().await.append_dkg_state(state).await;
    }

    /// Removes all data from epochs older than `min`.
    pub async fn prune(&self, min: Epoch) {
        self.inner.write().await.prune(min).await;
    }
}
