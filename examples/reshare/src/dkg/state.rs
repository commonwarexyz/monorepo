//! Persistent storage for DKG protocol state.
//!
//! Stores epoch state and per-epoch messages (dealer broadcasts, player acks, logs)
//! using append-only journals for crash recovery. In-memory BTreeMaps provide fast
//! lookups while the journal ensures durability.

use super::actor::Message;
use commonware_codec::{EncodeSize, Read, ReadExt, Write};
use commonware_consensus::types::Epoch as EpochNum;
use commonware_cryptography::{
    bls12381::{
        dkg::{
            Dealer as CryptoDealer, DealerLog, DealerPrivMsg, DealerPubMsg, Info, Output,
            Player as CryptoPlayer, PlayerAck, SignedDealerLog,
        },
        primitives::{group::Share, variant::Variant},
    },
    transcript::{Summary, Transcript},
    PublicKey, Signer,
};
use commonware_runtime::{buffer::PoolRef, Metrics, Storage as RuntimeStorage};
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
use tracing::debug;

const PAGE_SIZE: NonZeroUsize = NZUsize!(1 << 12);
const POOL_CAPACITY: NonZeroUsize = NZUsize!(1 << 20);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 12);
const READ_BUFFER: NonZeroUsize = NZUsize!(1 << 20);

/// Epoch-level DKG state persisted across restarts.
#[derive(Clone)]
pub struct Epoch<V: Variant, P: PublicKey> {
    pub round: u64,
    pub rng_seed: Summary,
    pub output: Option<Output<V, P>>,
    pub share: Option<Share>,
}

impl<V: Variant, P: PublicKey> EncodeSize for Epoch<V, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.rng_seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Epoch<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.round.write(buf);
        self.rng_seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for Epoch<V, P> {
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
enum Event<V: Variant, P: PublicKey> {
    /// A dealer message we received and committed to ack (as a player).
    /// Once persisted, we will always generate the same ack for this dealer.
    Dealer(P, DealerPubMsg<V>, DealerPrivMsg),
    /// A player ack we received (as a dealer).
    Player(P, PlayerAck<P>),
    /// A finalized dealer log.
    Log(P, DealerLog<V, P>),
}

impl<V: Variant, P: PublicKey> EncodeSize for Event<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealer(x0, x1, x2) => x0.encode_size() + x1.encode_size() + x2.encode_size(),
            Self::Player(x0, x1) => x0.encode_size() + x1.encode_size(),
            Self::Log(x0, x1) => x0.encode_size() + x1.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Write for Event<V, P> {
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

impl<V: Variant, P: PublicKey> Read for Event<V, P> {
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
pub struct Storage<E: RuntimeStorage + Metrics, V: Variant, P: PublicKey> {
    states: CVJournal<E, Epoch<V, P>>,
    msgs: SVJournal<E, Event<V, P>>,

    // In-memory state
    current_epoch: Option<(EpochNum, Epoch<V, P>)>,
    epoch_caches: BTreeMap<EpochNum, EpochCache<V, P>>,
}

impl<E: RuntimeStorage + Metrics, V: Variant, P: PublicKey> Storage<E, V, P> {
    /// Initialize storage, creating partitions if needed.
    /// Replays journals to populate in-memory caches.
    pub async fn init(context: E, partition_prefix: &str, max_read_size: NonZeroU32) -> Self {
        let buffer_pool = PoolRef::new(PAGE_SIZE, POOL_CAPACITY);

        let states = CVJournal::init(
            context.with_label("states"),
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

        let msgs = SVJournal::init(
            context.with_label("msgs"),
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

        // Replay states to get current epoch
        let current_epoch = {
            let size = states.size();
            if size == 0 {
                None
            } else {
                Some((
                    EpochNum::new(size - 1),
                    states
                        .read(size - 1)
                        .await
                        .expect("should be able to read epoch"),
                ))
            }
        };

        // Replay msgs to populate epoch caches
        let mut epoch_caches = BTreeMap::<EpochNum, EpochCache<V, P>>::new();
        {
            let replay = msgs
                .replay(0, 0, READ_BUFFER)
                .await
                .expect("should be able to replay msgs");
            futures::pin_mut!(replay);

            while let Some(result) = replay.next().await {
                let (section, _, _, event) = result.expect("should be able to read msg");
                let epoch = EpochNum::new(section);
                let cache = epoch_caches.entry(epoch).or_default();
                match event {
                    Event::Dealer(dealer, pub_msg, priv_msg) => {
                        cache.dealer_msgs.insert(dealer, (pub_msg, priv_msg));
                    }
                    Event::Player(player, ack) => {
                        cache.player_acks.insert(player, ack);
                    }
                    Event::Log(dealer, log) => {
                        cache.logs.insert(dealer, log);
                    }
                }
            }
        }

        Self {
            states,
            msgs,
            current_epoch,
            epoch_caches,
        }
    }

    /// Returns all dealer messages received during the given epoch.
    pub fn dealer_msgs(&self, epoch: EpochNum) -> Vec<(P, DealerPubMsg<V>, DealerPrivMsg)> {
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
    pub fn player_acks(&self, epoch: EpochNum) -> Vec<(P, PlayerAck<P>)> {
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
    pub fn logs(&self, epoch: EpochNum) -> BTreeMap<P, DealerLog<V, P>> {
        self.epoch_caches
            .get(&epoch)
            .map(|cache| cache.logs.clone())
            .unwrap_or_default()
    }

    /// Checks if a dealer has already submitted a log this epoch.
    pub fn has_submitted_log(&self, epoch: EpochNum, dealer: &P) -> bool {
        self.epoch_caches
            .get(&epoch)
            .map(|cache| cache.logs.contains_key(dealer))
            .unwrap_or(false)
    }

    /// Returns the current epoch state, if initialized.
    pub fn epoch(&self) -> Option<(EpochNum, Epoch<V, P>)> {
        self.current_epoch.as_ref().map(|(e, s)| (*e, s.clone()))
    }

    fn get_or_create_cache(&mut self, epoch: EpochNum) -> &mut EpochCache<V, P> {
        self.epoch_caches.entry(epoch).or_default()
    }

    /// Persists a dealer message for crash recovery.
    pub async fn append_dealer_msg(
        &mut self,
        epoch: EpochNum,
        dealer: P,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) {
        // Persist to journal
        let section = epoch.get();
        self.msgs
            .append(
                section,
                Event::Dealer(dealer.clone(), pub_msg.clone(), priv_msg.clone()),
            )
            .await
            .expect("should be able to write to msgs");
        self.msgs
            .sync(section)
            .await
            .expect("should be able to sync msgs");

        // Update in-memory cache
        self.get_or_create_cache(epoch)
            .dealer_msgs
            .insert(dealer, (pub_msg, priv_msg));
    }

    /// Persists a player acknowledgment we received (as a dealer) for crash recovery.
    pub async fn append_player_ack(&mut self, epoch: EpochNum, player: P, ack: PlayerAck<P>) {
        // Persist to journal
        let section = epoch.get();
        self.msgs
            .append(section, Event::Player(player.clone(), ack.clone()))
            .await
            .expect("should be able to write to msgs");
        self.msgs
            .sync(section)
            .await
            .expect("should be able to sync msgs");

        // Update in-memory cache
        self.get_or_create_cache(epoch)
            .player_acks
            .insert(player, ack);
    }

    /// Persists a finalized dealer log.
    pub async fn append_log(&mut self, epoch: EpochNum, dealer: P, log: DealerLog<V, P>) {
        // Persist to journal
        let section = epoch.get();
        self.msgs
            .append(section, Event::Log(dealer.clone(), log.clone()))
            .await
            .expect("should be able to write to msgs");
        self.msgs
            .sync(section)
            .await
            .expect("should be able to sync msgs");

        // Update in-memory cache
        self.get_or_create_cache(epoch).logs.insert(dealer, log);
    }

    /// Persists new epoch state, advancing to the next epoch.
    pub async fn append_epoch(&mut self, state: Epoch<V, P>) {
        // Persist to journal
        self.states
            .append(state.clone())
            .await
            .expect("should be able to write to state");
        self.states
            .sync()
            .await
            .expect("should be able to sync state");

        // Update in-memory state first (clone before moving to journal)
        let size = self.states.size();
        let epoch = EpochNum::new(size - 1);
        self.current_epoch = Some((epoch, state));
    }

    /// Removes all data from epochs older than `min`.
    pub async fn prune(&mut self, min: EpochNum) {
        let section = min.get();
        self.msgs
            .prune(section)
            .await
            .expect("should be able to prune msgs");
        self.states
            .prune(section)
            .await
            .expect("should be able to prune states");

        // Remove old epoch caches
        self.epoch_caches.retain(|&epoch, _| epoch >= min);
    }

    /// Create a Dealer for the given epoch, replaying any stored acks.
    /// Returns None if we've already submitted a log this epoch.
    pub fn create_dealer<C: Signer<PublicKey = P>>(
        &self,
        epoch: EpochNum,
        signer: C,
        round_info: Info<V, P>,
        share: Option<Share>,
        rng_seed: Summary,
    ) -> Option<Dealer<V, C>> {
        if self.has_submitted_log(epoch, &signer.public_key()) {
            return None;
        }

        let (mut crypto_dealer, pub_msg, priv_msgs) = CryptoDealer::start(
            Transcript::resume(rng_seed).noise(b"dealer-rng"),
            round_info,
            signer,
            share,
        )
        .expect("should be able to create dealer");

        // Replay stored acks
        let mut unsent: BTreeMap<P, DealerPrivMsg> = priv_msgs.into_iter().collect();
        for (player, ack) in self.player_acks(epoch) {
            if unsent.contains_key(&player)
                && crypto_dealer
                    .receive_player_ack(player.clone(), ack)
                    .is_ok()
            {
                unsent.remove(&player);
                debug!(?epoch, ?player, "replayed player ack");
            }
        }

        Some(Dealer::new(Some(crypto_dealer), pub_msg, unsent))
    }

    /// Create a Player for the given epoch, replaying any stored dealer messages.
    pub fn create_player<C: Signer<PublicKey = P>>(
        &self,
        epoch: EpochNum,
        signer: C,
        round_info: Info<V, P>,
    ) -> Option<Player<V, C>> {
        let crypto_player =
            CryptoPlayer::new(round_info, signer).expect("should be able to create player");
        let mut player = Player::new(crypto_player);

        // Replay persisted dealer messages (these will all be Cached responses)
        for (dealer, pub_msg, priv_msg) in self.dealer_msgs(epoch) {
            let _ = player.handle(dealer.clone(), pub_msg, priv_msg);
            debug!(?epoch, ?dealer, "replayed committed dealer message");
        }

        Some(player)
    }
}

/// Internal state for a dealer in the current round.
pub struct Dealer<V: Variant, C: Signer> {
    dealer: Option<CryptoDealer<V, C>>,
    pub_msg: DealerPubMsg<V>,
    unsent_priv_msgs: BTreeMap<C::PublicKey, DealerPrivMsg>,
    finalized_log: Option<SignedDealerLog<V, C>>,
}

impl<V: Variant, C: Signer> Dealer<V, C> {
    pub const fn new(
        dealer: Option<CryptoDealer<V, C>>,
        pub_msg: DealerPubMsg<V>,
        unsent_priv_msgs: BTreeMap<C::PublicKey, DealerPrivMsg>,
    ) -> Self {
        Self {
            dealer,
            pub_msg,
            unsent_priv_msgs,
            finalized_log: None,
        }
    }

    /// Handle an incoming ack from a player.
    /// Returns the ack if it was successfully processed (for persistence).
    pub fn handle(
        &mut self,
        player: C::PublicKey,
        ack: PlayerAck<C::PublicKey>,
    ) -> Option<PlayerAck<C::PublicKey>> {
        if !self.unsent_priv_msgs.contains_key(&player) {
            return None;
        }
        if let Some(ref mut dealer) = self.dealer {
            if dealer
                .receive_player_ack(player.clone(), ack.clone())
                .is_ok()
            {
                self.unsent_priv_msgs.remove(&player);
                return Some(ack);
            }
        }
        None
    }

    /// Finalize the dealer and produce a signed log for inclusion in a block.
    pub fn finalize(&mut self) -> Option<SignedDealerLog<V, C>> {
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

    /// Returns a clone of the finalized log if it exists.
    pub fn finalized_log(&self) -> Option<SignedDealerLog<V, C>> {
        self.finalized_log.clone()
    }

    /// Takes and returns the finalized log, leaving None in its place.
    pub const fn take_finalized_log(&mut self) -> Option<SignedDealerLog<V, C>> {
        self.finalized_log.take()
    }

    /// Returns shares to distribute to players.
    ///
    /// Returns an iterator of (player, pub_msg, priv_msg) tuples for each player
    /// that hasn't yet acknowledged their share.
    pub fn shares_to_distribute(
        &self,
    ) -> impl Iterator<Item = (C::PublicKey, DealerPubMsg<V>, DealerPrivMsg)> + '_ {
        self.unsent_priv_msgs
            .iter()
            .map(|(player, priv_msg)| (player.clone(), self.pub_msg.clone(), priv_msg.clone()))
    }
}

/// Result of handling a dealer message.
pub enum PlayerResponse<V: Variant, P: PublicKey> {
    /// New dealer message, ack generated. Caller should persist the dealer message.
    New(Message<V, P>),
    /// Already seen this dealer, returning cached ack.
    Cached(Message<V, P>),
    /// Invalid dealer message, no ack generated.
    Invalid,
}

/// Internal state for a player in the current round.
pub struct Player<V: Variant, C: Signer> {
    player: CryptoPlayer<V, C>,
    /// Acks we've generated, keyed by dealer. Once we generate an ack for a dealer,
    /// we will not generate a different one (to avoid conflicting votes).
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
}

impl<V: Variant, C: Signer> Player<V, C> {
    pub const fn new(player: CryptoPlayer<V, C>) -> Self {
        Self {
            player,
            acks: BTreeMap::new(),
        }
    }

    /// Handle an incoming dealer message.
    /// Returns whether this is a new commitment (should be persisted) or cached.
    pub fn handle(
        &mut self,
        dealer: C::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> PlayerResponse<V, C::PublicKey> {
        // If we've already generated an ack, return the cached version
        if let Some(ack) = self.acks.get(&dealer) {
            return PlayerResponse::Cached(Message::Ack(ack.clone()));
        }
        // Otherwise generate a new ack
        if let Some(ack) = self
            .player
            .dealer_message(dealer.clone(), pub_msg, priv_msg)
        {
            self.acks.insert(dealer, ack.clone());
            return PlayerResponse::New(Message::Ack(ack));
        }
        PlayerResponse::Invalid
    }

    /// Finalize the player's participation in the DKG round.
    pub fn finalize(
        self,
        logs: BTreeMap<C::PublicKey, DealerLog<V, C::PublicKey>>,
        threshold: usize,
    ) -> Result<(Output<V, C::PublicKey>, Share), commonware_cryptography::bls12381::dkg::Error>
    {
        self.player.finalize(logs, threshold)
    }
}
