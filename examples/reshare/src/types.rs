use crate::config::NetworkConfig;
use commonware_actor::Feedback;
use commonware_codec::{
    Decode as _, DecodeExt as _, Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    marshal::Update,
    simplex::{self, types::Context},
    types::{Epoch, Height, Round, View},
    Block as ConsensusBlock, CertifiableBlock, Epochable, Heightable, Reporter,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::DealerPrivMsg,
        primitives::{group::Share, variant::MinSig},
    },
    certificate::{Provider as CertificateProvider, Scoped},
    ed25519, sha256,
    transcript::Summary,
    Digest as _, Digestible, Hasher, Sha256,
};
use commonware_formatting::{from_hex, hex};
use commonware_glue::{
    dkg::{self, types::Payload, ParticipantsProvider, Registrar as RegistrarTrait, ReshareBlock},
    stateful::db::SyncEngineConfig,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, Buf, BufMut, Clock, Metrics, Storage};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedLogConfig,
    mmr::{self, full::Config as MmrJournalConfig, Location},
    qmdb::any::{unordered::fixed, FixedConfig},
    translator::TwoCap,
};
use commonware_utils::{
    non_empty_range,
    ordered::Set,
    range::NonEmptyRange,
    sequence::U64,
    sync::{Mutex, TracedAsyncRwLock},
    Acknowledgement, NZUsize, NZU64,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::info;

pub type Scheme = simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>;
pub type Qmdb<E> = fixed::Db<mmr::Family, E, U64, U64, Sha256, TwoCap, Sequential>;
pub type Database<E> = Arc<TracedAsyncRwLock<Qmdb<E>>>;
pub const NAMESPACE: &[u8] = b"_COMMONWARE_RESHARE_EXAMPLE";
pub const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(32);
pub const MAX_PARTICIPANTS: NonZeroU32 = commonware_utils::NZU32!(64);
pub const PAGE_SIZE: std::num::NonZeroU16 = commonware_utils::NZU16!(1024);
pub const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(16);
pub const IO_BUFFER_SIZE: std::num::NonZeroUsize = NZUsize!(2048);
pub const VOTE_CHANNEL: u64 = 0;
pub const CERTIFICATE_CHANNEL: u64 = 1;
pub const RESOLVER_CHANNEL: u64 = 2;
pub const BACKFILL_CHANNEL: u64 = 3;
pub const BROADCAST_CHANNEL: u64 = 4;
pub const QMDB_CHANNEL: u64 = 5;
pub const DKG_CHANNEL: u64 = 6;
pub const PROBE_CHANNEL: u64 = 7;
pub const ANCHOR_BOUNDARY_CHANNEL: u64 = 8;
pub const MAILBOX_SIZE: std::num::NonZeroUsize = NZUsize!(100);
pub const MESSAGE_BACKLOG: usize = 128;
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct Block {
    pub(crate) context: Context<sha256::Digest, ed25519::PublicKey>,
    pub(crate) parent: sha256::Digest,
    pub(crate) height: Height,
    pub(crate) state_root: sha256::Digest,
    pub(crate) range: NonEmptyRange<Location>,
    pub(crate) payload: Option<Payload<MinSig, ed25519::PrivateKey>>,
}

impl Block {
    pub fn genesis(
        leader: ed25519::PublicKey,
        info: dkg::types::EpochInfo<MinSig, ed25519::PublicKey>,
        state_root: sha256::Digest,
    ) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::zero(),
            state_root,
            range: non_empty_range!(Location::new(0), Location::new(1)),
            payload: Some(Payload::EpochInfo(info)),
        }
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.state_root.write(buf);
        self.range.write(buf);
        self.payload.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.state_root.encode_size()
            + self.range.encode_size()
            + self.payload.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: sha256::Digest::read(buf)?,
            height: Height::read(buf)?,
            state_root: sha256::Digest::read(buf)?,
            range: NonEmptyRange::read(buf)?,
            payload: Option::<Payload<MinSig, ed25519::PrivateKey>>::read_cfg(
                buf,
                &MAX_PARTICIPANTS,
            )?,
        })
    }
}

impl Digestible for Block {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        Sha256::hash(&self.encode())
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> sha256::Digest {
        self.parent
    }
}

impl CertifiableBlock for Block {
    type Context = Context<sha256::Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl ReshareBlock for Block {
    type Variant = MinSig;
    type Signer = ed25519::PrivateKey;

    fn payload(&self) -> Option<Payload<Self::Variant, Self::Signer>> {
        self.payload.clone()
    }
}

#[derive(Clone, Default)]
pub struct DynamicProvider {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<Scheme>>>>,
}

impl DynamicProvider {
    pub fn register(&self, epoch: Epoch, scheme: Scheme) {
        self.schemes.lock().insert(epoch, Arc::new(scheme));
    }
}

impl CertificateProvider for DynamicProvider {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned().map(Scoped::scheme)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned()
    }
}

#[derive(Clone)]
pub struct Registrar {
    provider: DynamicProvider,
}

impl Registrar {
    pub const fn new(provider: DynamicProvider) -> Self {
        Self { provider }
    }
}

impl RegistrarTrait for Registrar {
    type Variant = MinSig;
    type PublicKey = ed25519::PublicKey;

    async fn register(
        &self,
        epoch: Epoch,
        info: dkg::types::SchemeInfo<Self::Variant, Self::PublicKey>,
    ) {
        let scheme = match info {
            dkg::types::SchemeInfo::Verifier {
                participants,
                sharing,
            } => Scheme::verifier(NAMESPACE, participants, sharing),
            dkg::types::SchemeInfo::Signer {
                participants,
                sharing,
                share,
            } => Scheme::signer(NAMESPACE, participants, sharing, share)
                .expect("registered share must match participant set"),
        };
        self.provider.register(epoch, scheme);
    }
}

#[derive(Clone)]
pub struct Participants {
    ordered: Arc<Vec<ed25519::PublicKey>>,
    committee_size: usize,
}

impl Participants {
    pub fn new(config: &NetworkConfig) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self {
            ordered: Arc::new(config.participants.clone()),
            committee_size: config.committee_size,
        })
    }

    pub fn get(&self, epoch: Epoch) -> Set<ed25519::PublicKey> {
        let offset = epoch.get() as usize % self.ordered.len();
        let players = (0..self.committee_size)
            .map(|i| self.ordered[(offset + i) % self.ordered.len()].clone());
        Set::from_iter_dedup(players)
    }
}

impl ParticipantsProvider for Participants {
    type PublicKey = ed25519::PublicKey;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        self.get(epoch)
    }
}

#[derive(Clone)]
pub struct LogReporter;

impl Reporter for LogReporter {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(block, ack) = activity {
            info!(
                epoch = block.context().epoch().get(),
                height = block.height().get(),
                digest = %hex(&block.digest()),
                "finalized block"
            );
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

#[derive(Clone)]
pub struct FileSecretStore {
    path: PathBuf,
    inner: Arc<Mutex<SecretData>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SecretData {
    shares: BTreeMap<u64, String>,
    seeds: BTreeMap<u64, String>,
    dealings: BTreeMap<String, String>,
}

impl FileSecretStore {
    pub fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let inner = if path.exists() {
            let contents = fs::read_to_string(&path)?;
            serde_json::from_str(&contents)?
        } else {
            SecretData::default()
        };
        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub fn put_initial_share(&self, epoch: Epoch, share: Share) -> anyhow::Result<()> {
        self.inner
            .lock()
            .shares
            .insert(epoch.get(), hex(&share.encode()));
        self.flush()
    }

    fn flush(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(&*self.inner.lock())?;
        fs::write(&self.path, contents)?;
        Ok(())
    }

    fn dealing_key<P: commonware_cryptography::PublicKey>(epoch: Epoch, dealer: &P) -> String {
        format!("{}:{}", epoch.get(), hex(&dealer.encode()))
    }
}

impl dkg::SecretStore for FileSecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.inner
            .lock()
            .shares
            .insert(epoch.get(), hex(&share.encode()));
        self.flush().expect("failed to flush share");
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        let raw = self.inner.lock().shares.get(&epoch.get()).cloned()?;
        let bytes = from_hex(&raw)?;
        Share::decode(bytes.as_slice()).ok()
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.inner
            .lock()
            .seeds
            .insert(epoch.get(), hex(&seed.encode()));
        self.flush().expect("failed to flush seed");
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        let raw = self.inner.lock().seeds.get(&epoch.get()).cloned()?;
        let bytes = from_hex(&raw)?;
        Summary::decode(bytes.as_slice()).ok()
    }

    async fn put_dealing<P: commonware_cryptography::PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: P,
        private: DealerPrivMsg,
    ) {
        let key = Self::dealing_key(epoch, &dealer);
        self.inner
            .lock()
            .dealings
            .insert(key, hex(&private.encode()));
        self.flush().expect("failed to flush dealing");
    }

    async fn get_dealing<P: commonware_cryptography::PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        let key = Self::dealing_key(epoch, dealer);
        let raw = self.inner.lock().dealings.get(&key).cloned()?;
        let bytes = from_hex(&raw)?;
        DealerPrivMsg::decode(bytes.as_slice()).ok()
    }

    async fn prune(&mut self, min: Epoch) {
        let mut inner = self.inner.lock();
        inner.shares.retain(|epoch, _| *epoch >= min.get());
        inner.seeds.retain(|epoch, _| *epoch >= min.get());
        inner.dealings.retain(|key, _| {
            key.split_once(':')
                .and_then(|(epoch, _)| epoch.parse::<u64>().ok())
                .is_some_and(|epoch| epoch >= min.get())
        });
        drop(inner);
        self.flush().expect("failed to flush prune");
    }
}

pub fn db_config(prefix: &str, page_cache: CacheRef) -> FixedConfig<TwoCap, Sequential> {
    FixedConfig {
        merkle_config: MmrJournalConfig {
            journal_partition: format!("{prefix}-qmdb-mmr-journal"),
            metadata_partition: format!("{prefix}-qmdb-mmr-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{prefix}-qmdb-log-journal"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(1024)),
    }
}

pub const fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: NZU64!(16),
        apply_batch_size: 64,
        max_outstanding_requests: 8,
        update_channel_size: NZUsize!(256),
        max_retained_roots: 8,
    }
}

pub async fn empty_db_root<E>(context: E, config: FixedConfig<TwoCap, Sequential>) -> sha256::Digest
where
    E: Storage + Clock + Metrics,
{
    Qmdb::init(context, config)
        .await
        .expect("failed to initialize empty QMDB")
        .root()
}

pub fn genesis_path(node_dir: &Path) -> PathBuf {
    node_dir.join("genesis.json")
}

#[derive(Serialize, Deserialize)]
struct EncodedGenesis {
    #[serde(with = "epoch_info_hex")]
    epoch_info: dkg::types::EpochInfo<MinSig, ed25519::PublicKey>,
}

impl EncodedGenesis {
    fn read(node_dir: &Path) -> anyhow::Result<Self> {
        crate::config::read_json(&genesis_path(node_dir))
    }

    fn write(
        node_dir: &Path,
        info: &dkg::types::EpochInfo<MinSig, ed25519::PublicKey>,
    ) -> anyhow::Result<()> {
        let path = genesis_path(node_dir);
        let encoded = Self {
            epoch_info: info.clone(),
        };
        if path.exists() {
            let existing = Self::read(node_dir)?;
            if existing.epoch_info != *info {
                anyhow::bail!("refusing to overwrite different genesis artifact");
            }
            return Ok(());
        }
        crate::config::write_json(&path, &encoded)
    }
}

pub fn read_genesis(
    node_dir: &Path,
) -> anyhow::Result<dkg::types::EpochInfo<MinSig, ed25519::PublicKey>> {
    Ok(EncodedGenesis::read(node_dir)?.epoch_info)
}

pub fn write_genesis(
    node_dir: &Path,
    info: &dkg::types::EpochInfo<MinSig, ed25519::PublicKey>,
) -> anyhow::Result<()> {
    EncodedGenesis::write(node_dir, info)
}

mod epoch_info_hex {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &dkg::types::EpochInfo<MinSig, ed25519::PublicKey>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<dkg::types::EpochInfo<MinSig, ed25519::PublicKey>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        dkg::types::EpochInfo::decode_cfg(bytes.as_slice(), &MAX_PARTICIPANTS)
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        bls12381::{dkg::feldman_desmedt::deal, primitives::group::Scalar},
        Signer as _,
    };
    use commonware_glue::dkg::SecretStore as _;
    use commonware_math::algebra::Random;
    use commonware_runtime::{Runner as _, Supervisor as _};
    use commonware_utils::{ordered::Set, test_rng, test_rng_seeded, N3f1};

    fn keys(n: usize) -> Vec<ed25519::PublicKey> {
        let mut rng = test_rng();
        (0..n)
            .map(|_| ed25519::PrivateKey::random(&mut rng).public_key())
            .collect()
    }

    #[test]
    fn participants_rotate_with_wraparound() {
        let participants = keys(4);
        let config = NetworkConfig {
            participants: participants.clone(),
            committee_size: 3,
            peers: Vec::new(),
        };
        let provider = Participants::new(&config).unwrap();
        assert_eq!(
            provider.get(Epoch::new(2)),
            Set::from_iter_dedup([
                participants[2].clone(),
                participants[3].clone(),
                participants[0].clone()
            ])
        );
    }

    #[test]
    fn invalid_committee_size_rejected() {
        let config = NetworkConfig {
            participants: keys(2),
            committee_size: 3,
            peers: Vec::new(),
        };
        assert!(Participants::new(&config).is_err());
    }

    #[test]
    fn genesis_conflict_detection() {
        let path =
            std::env::temp_dir().join(format!("commonware-reshare-genesis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();

        let participants = Set::from_iter_dedup(keys(2));
        let (output, _shares) =
            deal::<MinSig, _, N3f1>(test_rng_seeded(2), Default::default(), participants.clone())
                .unwrap();
        let mut info = dkg::types::EpochInfo {
            outcome: dkg::types::EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players: participants.clone(),
            next_players: participants,
        };

        write_genesis(&path, &info).unwrap();
        write_genesis(&path, &info).unwrap();
        info.epoch = Epoch::new(1);
        assert!(write_genesis(&path, &info).is_err());
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn empty_root_matches_qmdb_schema() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let root = empty_db_root(
                context.child("helper"),
                db_config("empty_root_matches_qmdb_schema_helper", page_cache.clone()),
            )
            .await;
            let db = Qmdb::init(
                context.child("direct"),
                db_config("empty_root_matches_qmdb_schema_direct", page_cache),
            )
            .await
            .unwrap();
            assert_eq!(db.root(), root);
        });
    }

    #[test]
    fn secret_store_roundtrip_and_prune() {
        let path = std::env::temp_dir().join(format!(
            "commonware-reshare-secrets-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = FileSecretStore::load(&path).unwrap();
        let player = keys(1).pop().unwrap();
        let players = Set::from_iter_dedup([player.clone()]);
        let (_output, shares) =
            deal::<MinSig, _, N3f1>(test_rng_seeded(1), Default::default(), players).unwrap();
        let share = shares.get_value(&player).unwrap().clone();

        commonware_runtime::deterministic::Runner::default().start(|_| {
            let mut store = store.clone();
            async move {
                store.put_share(Epoch::new(1), share.clone()).await;
                assert_eq!(store.get_share(Epoch::new(1)).await, Some(share));

                let seed = Summary::random(&mut test_rng());
                store.put_seed(Epoch::new(1), seed).await;
                assert_eq!(store.get_seed(Epoch::new(1)).await, Some(seed));

                let dealer = keys(1).pop().unwrap();
                let dealing = DealerPrivMsg::new(Scalar::random(&mut test_rng()));
                store
                    .put_dealing(Epoch::new(1), dealer.clone(), dealing.clone())
                    .await;
                assert_eq!(
                    store.get_dealing(Epoch::new(1), &dealer).await,
                    Some(dealing)
                );
                store.prune(Epoch::new(2)).await;
                assert_eq!(store.get_share(Epoch::new(1)).await, None);
            }
        });
        let _ = std::fs::remove_file(path);
    }
}
