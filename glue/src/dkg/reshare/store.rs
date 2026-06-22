//! DKG/reshare crash-recovery storage.
//!
//! This store exists only to recover state a restarted actor cannot otherwise
//! re-obtain. After a crash the actor does not re-receive P2P messages and
//! marshal does not re-deliver finalized blocks, so this store keeps a plaintext
//! journal of the public messages a restarted node would otherwise lose:
//!
//! - public dealer messages and player acknowledgements, so a player can rebuild
//!   the acks it already emitted (its private dealings are recovered from
//!   [`SecretStore`]);
//! - finalized dealer logs observed during inclusion.
//!
//! The current epoch's public state is not persisted here: it is re-derived from
//! the finalized boundary block that anchors the epoch (see the setup state), so
//! this store never caches public epoch info. Everything secret stays out of this
//! plaintext store and is held only through [`SecretStore`]: shares, private
//! dealings, and the dealer RNG seed (which seeds the dealer polynomial and so
//! reveals every share that dealer distributes).

use crate::dkg::{types::EpochInfo, SecretStore};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{
            Dealer as CryptoDealer, DealerLog, DealerPrivMsg, DealerPubMsg, Error as DkgError,
            Info, Logs, Output, Player as CryptoPlayer, PlayerAck, SignedDealerLog, Verdict,
        },
        primitives::{group, variant::Variant},
    },
    transcript::{Summary, Transcript},
    BatchVerifier, PublicKey, Signer,
};
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, BufferPooler, Clock, Metrics, Storage as RuntimeStorage,
};
use commonware_storage::journal::segmented::variable::{Config as JournalConfig, Journal};
use commonware_utils::{Faults, N3f1, NZUsize, NZU16};
use futures::StreamExt;
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
};
use tracing::debug;

const PAGE_SIZE: NonZeroU16 = NZU16!(1 << 12); // 4 KiB
const PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(1 << 13); // 8 KiB
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 12); // 4 KiB
const READ_BUFFER: NonZeroUsize = NZUsize!(1 << 20); // 1 MiB

enum Event<V: Variant, P: PublicKey> {
    Dealing(P, DealerPubMsg<V>),
    Ack(P, PlayerAck<P>),
    Log(P, DealerLog<V, P>),
}

impl<V: Variant, P: PublicKey> EncodeSize for Event<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing(dealer, public) => dealer.encode_size() + public.encode_size(),
            Self::Ack(player, ack) => player.encode_size() + ack.encode_size(),
            Self::Log(dealer, log) => dealer.encode_size() + log.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Write for Event<V, P> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Dealing(dealer, public) => {
                0u8.write(writer);
                dealer.write(writer);
                public.write(writer);
            }
            Self::Ack(player, ack) => {
                1u8.write(writer);
                player.write(writer);
                ack.write(writer);
            }
            Self::Log(dealer, log) => {
                2u8.write(writer);
                dealer.write(writer);
                log.write(writer);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> Read for Event<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Dealing(
                ReadExt::read(reader)?,
                Read::read_cfg(reader, cfg)?,
            )),
            1 => Ok(Self::Ack(ReadExt::read(reader)?, ReadExt::read(reader)?)),
            2 => Ok(Self::Log(
                ReadExt::read(reader)?,
                Read::read_cfg(reader, cfg)?,
            )),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, P: PublicKey> arbitrary::Arbitrary<'_> for Event<V, P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    DealerPubMsg<V>: for<'a> arbitrary::Arbitrary<'a>,
    DealerLog<V, P>: for<'a> arbitrary::Arbitrary<'a>,
    PlayerAck<P>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=2)? {
            0 => Self::Dealing(u.arbitrary()?, u.arbitrary()?),
            1 => Self::Ack(u.arbitrary()?, u.arbitrary()?),
            _ => Self::Log(u.arbitrary()?, u.arbitrary()?),
        })
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};

    commonware_conformance::conformance_tests! {
        CodecConformance<Event<MinSig, ed25519::PublicKey>>,
    }
}

struct EpochCache<V: Variant, P: PublicKey> {
    dealings: BTreeMap<P, (DealerPubMsg<V>, DealerPrivMsg)>,
    acks: BTreeMap<P, PlayerAck<P>>,
    logs: BTreeMap<P, DealerLog<V, P>>,
}

impl<V: Variant, P: PublicKey> Default for EpochCache<V, P> {
    fn default() -> Self {
        Self {
            dealings: BTreeMap::new(),
            acks: BTreeMap::new(),
            logs: BTreeMap::new(),
        }
    }
}

/// DKG/reshare crash-recovery store.
///
/// The plaintext side holds only the dealer-message, acknowledgement, and
/// finalized-log journal. The current epoch's public state is re-derived from
/// finalized boundary blocks, not cached here. All secret material (shares,
/// private dealings, and the dealer RNG seed) is held only through
/// [`SecretStore`], never in plaintext.
pub struct Store<E, SS, V, P>
where
    E: BufferPooler + Clock + RuntimeStorage + Metrics,
    SS: SecretStore,
    V: Variant,
    P: PublicKey,
{
    secret_store: SS,
    events: Journal<E, Event<V, P>>,
    current: Option<EpochInfo<V, P>>,
    epochs: BTreeMap<Epoch, EpochCache<V, P>>,
}

impl<E, SS, V, P> Store<E, SS, V, P>
where
    E: BufferPooler + Clock + RuntimeStorage + Metrics,
    SS: SecretStore,
    V: Variant,
    P: PublicKey,
{
    /// Initializes the store and replays durable crash-recovery state.
    pub async fn init(
        context: E,
        partition_prefix: &str,
        max_participants: NonZeroU32,
        mut secret_store: SS,
    ) -> Self {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_CAPACITY);
        let mut events = Journal::init(
            context.child("events"),
            JournalConfig {
                partition: format!("{partition_prefix}_events"),
                compression: None,
                codec_config: max_participants,
                page_cache,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize reshare event journal");

        // The current epoch is not persisted: it is re-derived from finalized
        // boundary blocks by the setup state, so a restarted store starts with no
        // current epoch.
        let current = None;

        let mut epochs = BTreeMap::<Epoch, EpochCache<V, P>>::new();
        {
            let replay = events
                .replay(0, 0, READ_BUFFER)
                .await
                .expect("failed to replay reshare events");
            futures::pin_mut!(replay);

            while let Some(result) = replay.next().await {
                let (section, _, _, event) = result.expect("failed to read reshare event");
                let epoch = Epoch::new(section);
                let cache = epochs.entry(epoch).or_default();
                match event {
                    Event::Dealing(dealer, public) => {
                        let private = secret_store.get_dealing(epoch, &dealer).await;
                        if let Some(private) = private {
                            cache.dealings.insert(dealer, (public, private));
                        }
                    }
                    Event::Ack(player, ack) => {
                        cache.acks.insert(player, ack);
                    }
                    Event::Log(dealer, log) => {
                        cache.logs.insert(dealer, log);
                    }
                }
            }
        }

        Self {
            secret_store,
            events,
            current,
            epochs,
        }
    }

    /// Returns the current epoch state, if one has been entered.
    pub fn current(&self) -> Option<EpochInfo<V, P>> {
        self.current.clone()
    }

    /// Returns the share for `epoch`, if any.
    pub async fn share(&mut self, epoch: Epoch) -> Option<group::Share> {
        self.secret_store.get_share(epoch).await
    }

    /// Returns the persisted dealer RNG seed for `epoch`, if any.
    ///
    /// A seed exists only for an epoch this node previously entered. Reusing it
    /// keeps dealer randomness identical across a restart.
    pub async fn seed(&mut self, epoch: Epoch) -> Option<Summary> {
        self.secret_store.get_seed(epoch).await
    }

    /// Returns the persisted dealer RNG seed for `epoch`, generating a fresh
    /// random seed from `rng` if none exists.
    pub(crate) async fn seed_or_random(
        &mut self,
        epoch: Epoch,
        rng: impl CryptoRngCore,
    ) -> Summary {
        self.seed(epoch)
            .await
            .unwrap_or_else(|| Summary::random(rng))
    }

    /// Persists the dealer RNG seed for `epoch`.
    pub(crate) async fn put_seed(&mut self, epoch: Epoch, rng_seed: Summary) {
        self.secret_store.put_seed(epoch, rng_seed).await;
    }

    /// Advances to `info`, persisting its secrets before the current epoch moves.
    ///
    /// The public artifact in `info` is read from the finalized boundary block,
    /// not from local state, and is held only in memory. The share is persisted
    /// only when it matches that finalized truth; otherwise the node continues as
    /// an observer.
    pub async fn commit_epoch(
        &mut self,
        info: EpochInfo<V, P>,
        rng_seed: Summary,
        share: Option<group::Share>,
    ) {
        let epoch = info.epoch;
        if let Some(share) = share {
            self.secret_store.put_share(epoch, share).await;
        }
        self.secret_store.put_seed(epoch, rng_seed).await;
        self.current = Some(info);
    }

    /// Prunes public recovery data and secret material older than `min`.
    pub async fn prune(&mut self, min: Epoch) {
        self.epochs.retain(|epoch, _| *epoch >= min);
        // Prune the recovery journal and the secret store concurrently; they are
        // independent backends.
        let events = &mut self.events;
        let secret = &mut self.secret_store;
        futures::join!(
            async {
                events
                    .prune(min.get())
                    .await
                    .expect("failed to prune reshare events")
            },
            secret.prune(min),
        );
    }

    fn cache(&mut self, epoch: Epoch) -> &mut EpochCache<V, P> {
        self.epochs.entry(epoch).or_default()
    }

    /// Returns finalized dealer logs for `epoch`.
    pub fn logs(&self, epoch: Epoch) -> BTreeMap<P, DealerLog<V, P>> {
        self.epochs
            .get(&epoch)
            .map(|cache| cache.logs.clone())
            .unwrap_or_default()
    }

    /// Returns true if `dealer` already has a finalized log recorded.
    pub fn has_log(&self, epoch: Epoch, dealer: &P) -> bool {
        self.epochs
            .get(&epoch)
            .is_some_and(|cache| cache.logs.contains_key(dealer))
    }

    fn dealings(&self, epoch: Epoch) -> Vec<(P, DealerPubMsg<V>, DealerPrivMsg)> {
        self.epochs
            .get(&epoch)
            .map(|cache| {
                cache
                    .dealings
                    .iter()
                    .map(|(dealer, (public, private))| {
                        (dealer.clone(), public.clone(), private.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn acks(&self, epoch: Epoch) -> Vec<(P, PlayerAck<P>)> {
        self.epochs
            .get(&epoch)
            .map(|cache| {
                cache
                    .acks
                    .iter()
                    .map(|(player, ack)| (player.clone(), ack.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn append_dealing(
        &mut self,
        epoch: Epoch,
        dealer: P,
        public: DealerPubMsg<V>,
        private: DealerPrivMsg,
    ) -> bool {
        if self
            .epochs
            .get(&epoch)
            .is_some_and(|cache| cache.dealings.contains_key(&dealer))
        {
            return false;
        }
        // Persist the private dealing (secret store) and the public dealer message
        // (recovery journal) concurrently. Both are durable before this returns, so
        // the ack the caller emits next is always backed by recoverable state. A
        // crash mid-write is safe: replay loads a dealing only when both its public
        // and private parts survived.
        let event = Event::Dealing(dealer.clone(), public.clone());
        let secret = &mut self.secret_store;
        let events = &mut self.events;
        futures::join!(
            secret.put_dealing(epoch, dealer.clone(), private.clone()),
            append_synced(events, epoch, &event),
        );
        self.cache(epoch).dealings.insert(dealer, (public, private));
        true
    }

    async fn append_ack(&mut self, epoch: Epoch, player: P, ack: PlayerAck<P>) -> bool {
        if self
            .epochs
            .get(&epoch)
            .is_some_and(|cache| cache.acks.contains_key(&player))
        {
            return false;
        }
        let event = Event::Ack(player.clone(), ack.clone());
        append_synced(&mut self.events, epoch, &event).await;
        self.cache(epoch).acks.insert(player, ack);
        true
    }

    /// Records a finalized dealer log.
    pub async fn append_log(&mut self, epoch: Epoch, dealer: P, log: DealerLog<V, P>) -> bool {
        if self.has_log(epoch, &dealer) {
            return false;
        }
        let event = Event::Log(dealer.clone(), log.clone());
        append_synced(&mut self.events, epoch, &event).await;
        self.cache(epoch).logs.insert(dealer, log);
        true
    }

    /// Replays dealer state for `epoch`.
    pub fn create_dealer<C, M>(
        &self,
        epoch: Epoch,
        signer: C,
        info: Info<V, P>,
        share: Option<group::Share>,
        rng_seed: Summary,
    ) -> Option<Dealer<V, C>>
    where
        C: Signer<PublicKey = P>,
        M: Faults,
    {
        if self.has_log(epoch, &signer.public_key()) {
            return None;
        }
        let (mut dealer, public, private) = CryptoDealer::start::<M>(
            Transcript::resume(rng_seed).noise(b"dealer-rng"),
            info,
            signer,
            share,
        )
        .expect("failed to create reshare dealer");
        let mut unsent: BTreeMap<P, DealerPrivMsg> = private.into_iter().collect();
        for (player, ack) in self.acks(epoch) {
            if unsent.contains_key(&player)
                && dealer.receive_player_ack(player.clone(), ack).is_ok()
            {
                unsent.remove(&player);
                debug!(?epoch, ?player, "replayed reshare ack");
            }
        }
        Some(Dealer {
            dealer: Some(dealer),
            public,
            unsent,
            finalized: None,
        })
    }

    /// Replays player state for `epoch`.
    pub fn create_player<C, M>(&self, epoch: Epoch, signer: C, info: Info<V, P>) -> Player<V, C>
    where
        C: Signer<PublicKey = P>,
        M: Faults,
    {
        let (player, acks) =
            CryptoPlayer::resume::<M>(info, signer, &self.logs(epoch), self.dealings(epoch))
                .expect("failed to resume reshare player");
        Player { player, acks }
    }

    /// Replays player state using a supplied, non-durable log view.
    pub fn create_player_with_logs<C, M>(
        &self,
        epoch: Epoch,
        signer: C,
        info: Info<V, P>,
        logs: &BTreeMap<P, DealerLog<V, P>>,
    ) -> Player<V, C>
    where
        C: Signer<PublicKey = P>,
        M: Faults,
    {
        let (player, acks) = CryptoPlayer::resume::<M>(info, signer, logs, self.dealings(epoch))
            .expect("failed to resume reshare player");
        Player { player, acks }
    }
}

/// Appends `event` to the recovery journal for `epoch` and flushes it durably.
async fn append_synced<E, V, P>(
    events: &mut Journal<E, Event<V, P>>,
    epoch: Epoch,
    event: &Event<V, P>,
) where
    E: BufferPooler + Clock + RuntimeStorage + Metrics,
    V: Variant,
    P: PublicKey,
{
    let section = epoch.get();
    events
        .append(section, event)
        .await
        .expect("failed to append reshare event");
    events
        .sync(section)
        .await
        .expect("failed to sync reshare event");
}

/// Dealer state for one epoch.
pub struct Dealer<V: Variant, C: Signer> {
    dealer: Option<CryptoDealer<V, C>>,
    public: DealerPubMsg<V>,
    unsent: BTreeMap<C::PublicKey, DealerPrivMsg>,
    finalized: Option<SignedDealerLog<V, C>>,
}

impl<V: Variant, C: Signer> Dealer<V, C> {
    /// Records a player ack.
    ///
    /// Returns [`Verdict::Fault`] if the player signed an invalid ack so the
    /// caller can penalize them. A duplicate or unsolicited ack, or one for a
    /// round we are not dealing in, is a benign [`Verdict::Skip`].
    pub async fn handle<E, SS>(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
        epoch: Epoch,
        player: C::PublicKey,
        ack: PlayerAck<C::PublicKey>,
    ) -> Verdict<()>
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics,
        SS: SecretStore,
    {
        if !self.unsent.contains_key(&player) {
            return Verdict::Skip;
        }
        let Some(dealer) = &mut self.dealer else {
            return Verdict::Skip;
        };
        match dealer.receive_player_ack(player.clone(), ack.clone()) {
            Ok(()) => {}
            Err(DkgError::InvalidAck) => return Verdict::Fault,
            Err(_) => return Verdict::Skip,
        }
        self.unsent.remove(&player);
        if store.append_ack(epoch, player, ack).await {
            Verdict::Valid(())
        } else {
            Verdict::Skip
        }
    }

    /// Finalizes once and returns true if a new log became available.
    pub fn finalize<M: Faults>(&mut self) -> bool {
        if self.finalized.is_some() {
            return false;
        }
        let Some(dealer) = self.dealer.take() else {
            return false;
        };
        self.finalized = Some(dealer.finalize::<M>());
        true
    }

    /// Returns a cloned finalized log.
    pub fn finalized(&self) -> Option<SignedDealerLog<V, C>> {
        self.finalized.clone()
    }

    /// Clears a finalized log after it is observed in a finalized block.
    pub fn clear_finalized(&mut self) {
        self.finalized = None;
    }

    /// Returns private dealings that still need to be sent.
    pub fn shares_to_distribute(
        &self,
    ) -> impl Iterator<Item = (C::PublicKey, DealerPubMsg<V>, DealerPrivMsg)> + '_ {
        self.unsent
            .iter()
            .map(|(player, private)| (player.clone(), self.public.clone(), private.clone()))
    }
}

/// Player state for one epoch.
pub struct Player<V: Variant, C: Signer> {
    player: CryptoPlayer<V, C>,
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
}

impl<V: Variant, C: Signer> Player<V, C> {
    /// Handles a dealer message, persisting it before returning the ack.
    ///
    /// Returns [`Verdict::Fault`] if the dealing is provably invalid so the
    /// caller can penalize the dealer. A duplicate dealing is a benign
    /// [`Verdict::Skip`].
    pub async fn handle<E, SS>(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
        epoch: Epoch,
        dealer: C::PublicKey,
        public: DealerPubMsg<V>,
        private: DealerPrivMsg,
    ) -> Verdict<PlayerAck<C::PublicKey>>
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics,
        SS: SecretStore,
    {
        if let Some(ack) = self.acks.get(&dealer) {
            return Verdict::Valid(ack.clone());
        }
        let ack = match self.player.dealer_message::<N3f1>(
            dealer.clone(),
            public.clone(),
            private.clone(),
        ) {
            Verdict::Valid(ack) => ack,
            Verdict::Skip => return Verdict::Skip,
            Verdict::Fault => return Verdict::Fault,
        };
        store
            .append_dealing(epoch, dealer.clone(), public, private)
            .await;
        self.acks.insert(dealer, ack.clone());
        Verdict::Valid(ack)
    }

    /// Finalizes and returns the public output plus local share.
    pub fn finalize<M, B>(
        self,
        rng: &mut impl CryptoRngCore,
        logs: Logs<V, C::PublicKey, M>,
        strategy: &impl Strategy,
    ) -> Result<(Output<V, C::PublicKey>, group::Share), DkgError>
    where
        M: Faults,
        B: BatchVerifier<PublicKey = C::PublicKey>,
    {
        self.player.finalize::<M, B>(rng, logs, strategy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        tests::mocks::MemorySecretStore,
        types::{EpochInfo, EpochOutcome},
    };
    use commonware_codec::FixedSize;
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        bls12381::{
            dkg::feldman_desmedt::{deal, Info, Output},
            primitives::{sharing::Mode, variant::MinPk},
        },
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{deterministic, Runner, Supervisor as _};
    use commonware_utils::{ordered::Set, test_rng_seeded, N3f1, NZU32};

    type TestStore<E> = Store<E, MemorySecretStore, MinPk, PublicKey>;

    fn summary(seed: u8) -> Summary {
        let bytes = [seed; Summary::SIZE];
        Summary::read(&mut bytes.as_ref()).expect("valid summary")
    }

    fn output(seed: u64) -> Output<MinPk, PublicKey> {
        let (output, _) = deal::<MinPk, _, N3f1>(
            test_rng_seeded(seed),
            Mode::NonZeroCounter,
            players(&signers()),
        )
        .expect("trusted deal");
        output
    }

    fn epoch_info(
        epoch: Epoch,
        round: u64,
        output: Output<MinPk, PublicKey>,
    ) -> EpochInfo<MinPk, PublicKey> {
        EpochInfo {
            outcome: EpochOutcome::Success,
            epoch,
            round,
            output,
            players: Set::default(),
            next_players: Set::default(),
        }
    }

    fn signers() -> Vec<PrivateKey> {
        (0..4).map(PrivateKey::from_seed).collect()
    }

    fn players(signers: &[PrivateKey]) -> Set<PublicKey> {
        Set::from_iter_dedup(signers.iter().map(Signer::public_key))
    }

    async fn init_store<E>(
        context: E,
        partition: &str,
        secret_store: MemorySecretStore,
    ) -> TestStore<E>
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics,
    {
        Store::init(context, partition, NZU32!(16), secret_store).await
    }

    #[test]
    fn commit_epoch_seeds_configured_epoch_and_round() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let secret_store = MemorySecretStore::default();
            let mut store =
                init_store(context.child("store"), "configured-start", secret_store).await;
            store
                .commit_epoch(epoch_info(Epoch::new(7), 3, output(1)), summary(1), None)
                .await;

            let info = store.current().expect("current epoch");
            assert_eq!(info.epoch, Epoch::new(7));
            assert_eq!(info.round, 3);
        });
    }

    #[test]
    fn replay_restores_dealings_acks_and_logs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let secret_store = MemorySecretStore::default();
            let mut store =
                init_store(context.child("store"), "replay", secret_store.clone()).await;
            let signers = signers();
            let players = players(&signers);
            let info = Info::new::<N3f1>(
                b"_COMMONWARE_GLUE_DKG_RESHARE_STORE_TEST",
                0,
                None,
                Mode::NonZeroCounter,
                players.clone(),
                players.clone(),
            )
            .expect("valid info");
            store
                .commit_epoch(epoch_info(Epoch::zero(), 0, output(1)), summary(1), None)
                .await;

            let dealer_pk = signers[0].public_key();
            let player_pk = signers[1].public_key();
            let mut dealer = store
                .create_dealer::<PrivateKey, N3f1>(
                    Epoch::zero(),
                    signers[0].clone(),
                    info.clone(),
                    None,
                    summary(2),
                )
                .expect("dealer");
            let mut player = store.create_player::<PrivateKey, N3f1>(
                Epoch::zero(),
                signers[1].clone(),
                info.clone(),
            );
            let (_, public, private) = dealer
                .shares_to_distribute()
                .find(|(recipient, _, _)| *recipient == player_pk)
                .expect("dealing for player");
            let Verdict::Valid(ack) = player
                .handle(
                    &mut store,
                    Epoch::zero(),
                    dealer_pk.clone(),
                    public,
                    private,
                )
                .await
            else {
                panic!("ack");
            };
            assert!(matches!(
                dealer
                    .handle(&mut store, Epoch::zero(), player_pk.clone(), ack)
                    .await,
                Verdict::Valid(())
            ));
            assert!(dealer.finalize::<N3f1>());
            let signed = dealer.finalized().expect("signed log");
            let (dealer, log) = signed.check(&info).expect("valid log");
            store.append_log(Epoch::zero(), dealer, log).await;
            drop(store);

            let store = init_store(context.child("restart"), "replay", secret_store).await;
            // The current epoch is not persisted; the setup state re-derives it from
            // finalized blocks, so a restarted store has no current epoch on its own.
            assert!(store.current().is_none());
            // The public recovery journal is replayed.
            assert_eq!(store.dealings(Epoch::zero()).len(), 1);
            assert_eq!(store.acks(Epoch::zero()).len(), 1);
            assert_eq!(store.logs(Epoch::zero()).len(), 1);
            let replayed_player =
                store.create_player::<PrivateKey, N3f1>(Epoch::zero(), signers[1].clone(), info);
            assert_eq!(replayed_player.acks.len(), 1);
        });
    }

    #[test]
    fn protocol_storage_does_not_restore_private_dealings() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let secret_store = MemorySecretStore::default();
            let mut store = init_store(
                context.child("store"),
                "private-dealing-boundary",
                secret_store,
            )
            .await;
            let signers = signers();
            let players = players(&signers);
            let info = Info::new::<N3f1>(
                b"_COMMONWARE_GLUE_DKG_RESHARE_STORE_TEST",
                0,
                None,
                Mode::NonZeroCounter,
                players.clone(),
                players,
            )
            .expect("valid info");
            store
                .commit_epoch(epoch_info(Epoch::zero(), 0, output(1)), summary(1), None)
                .await;

            let dealer_pk = signers[0].public_key();
            let player_pk = signers[1].public_key();
            let dealer = store
                .create_dealer::<PrivateKey, N3f1>(
                    Epoch::zero(),
                    signers[0].clone(),
                    info.clone(),
                    None,
                    summary(2),
                )
                .expect("dealer");
            let mut player = store.create_player::<PrivateKey, N3f1>(
                Epoch::zero(),
                signers[1].clone(),
                info.clone(),
            );
            let (_, public, private) = dealer
                .shares_to_distribute()
                .find(|(recipient, _, _)| *recipient == player_pk)
                .expect("dealing for player");
            assert!(matches!(
                player
                    .handle(&mut store, Epoch::zero(), dealer_pk, public, private)
                    .await,
                Verdict::Valid(_)
            ));
            assert_eq!(store.dealings(Epoch::zero()).len(), 1);
            drop(store);

            let empty_secret_store = MemorySecretStore::default();
            let restarted = init_store(
                context.child("restart"),
                "private-dealing-boundary",
                empty_secret_store,
            )
            .await;
            assert!(restarted.dealings(Epoch::zero()).is_empty());
            let replayed_player = restarted.create_player::<PrivateKey, N3f1>(
                Epoch::zero(),
                signers[1].clone(),
                info,
            );
            assert!(replayed_player.acks.is_empty());
        });
    }

    #[test]
    fn protocol_storage_does_not_restore_secret_shares() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let signers = signers();
            let (_, shares) =
                deal::<MinPk, _, N3f1>(test_rng_seeded(9), Mode::NonZeroCounter, players(&signers))
                    .expect("trusted deal");
            let share = shares
                .get_value(&signers[0].public_key())
                .expect("share")
                .clone();

            let secret_store = MemorySecretStore::default();
            let mut store =
                init_store(context.child("store"), "secret-boundary", secret_store).await;
            store
                .commit_epoch(
                    epoch_info(Epoch::zero(), 0, output(1)),
                    summary(1),
                    Some(share),
                )
                .await;
            assert!(store.share(Epoch::zero()).await.is_some());
            drop(store);

            let empty_secret_store = MemorySecretStore::default();
            let mut restarted = init_store(
                context.child("restart"),
                "secret-boundary",
                empty_secret_store,
            )
            .await;
            // The current epoch is never persisted; setup re-derives it from
            // finalized boundary blocks. The share lived only in the secret store,
            // which is now empty, so neither a current epoch nor the share survives.
            assert!(restarted.current().is_none());
            assert!(restarted.share(Epoch::zero()).await.is_none());
        });
    }

    #[test]
    fn prune_removes_old_protocol_state_and_secret_shares() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let secret_store = MemorySecretStore::default();
            let mut store = init_store(context.child("store"), "prune", secret_store.clone()).await;
            let signers = signers();
            let (next_output, shares) = deal::<MinPk, _, N3f1>(
                test_rng_seeded(10),
                Mode::NonZeroCounter,
                players(&signers),
            )
            .expect("trusted deal");
            let share = shares
                .get_value(&signers[0].public_key())
                .expect("share")
                .clone();

            store
                .commit_epoch(epoch_info(Epoch::zero(), 0, output(1)), summary(1), None)
                .await;
            store
                .commit_epoch(
                    epoch_info(Epoch::new(1), 1, next_output),
                    summary(2),
                    Some(share),
                )
                .await;

            store.prune(Epoch::new(1)).await;
            drop(store);

            let store = init_store(context.child("restart"), "prune", secret_store.clone()).await;
            // The current epoch is not persisted (the setup state re-derives it), and
            // the pruned epoch's public journal and secret material stay pruned across
            // the restart.
            assert!(store.current().is_none());
            assert!(!store.epochs.contains_key(&Epoch::zero()));
            assert_eq!(secret_store.prunes(), vec![Epoch::new(1)]);
            assert!(!secret_store.has_share(Epoch::zero()));
        });
    }
}
