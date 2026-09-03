//! Types, constants, and storage config shared across the example.

use crate::config::NetworkConfig;
use commonware_actor::Feedback;
use commonware_codec::{
    Decode as _, DecodeExt as _, Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Epochable, Heightable, Reporter, aggregation,
    marshal::Update,
    simplex::{self, types::Context},
    types::{Epoch, Epocher, FixedEpocher, Height, Round, View},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher, Sha256,
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, Reveal},
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion, Sharing},
            variant::MinSig,
        },
    },
    certificate::{Provider as CertificateProvider, Scoped},
    ed25519, sha256,
    transcript::Summary,
};
use commonware_formatting::{from_hex, hex};
use commonware_glue::{
    dkg::{self, ParticipantsProvider, Registrar as RegistrarTrait, ReshareBlock, types::Payload},
    stateful::db::{Shared, SyncEngineConfig},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Buf, BufMut, Quota, buffer::paged::CacheRef};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedLogConfig,
    mmr::{self, Location, full::Config as MmrJournalConfig},
    qmdb::{
        any::{FixedConfig, unordered::fixed},
        sync::Target,
    },
    translator::TwoCap,
};
use commonware_utils::{
    Acknowledgement, NZU32, NZU64, NZUsize, TryCollect,
    ordered::{Committee, Set},
    range::NonEmptyRange,
    sequence::{U64, Unit},
    sync::Mutex,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::Write as _,
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::info;

/// Builds the uniform threshold committee used by this example.
pub fn committee(participants: &Set<ed25519::PublicKey>) -> Committee<ed25519::PublicKey> {
    participants
        .iter()
        .cloned()
        .map(|participant| (participant, 1))
        .try_collect()
        .expect("participants form a committee")
}

/// Threshold certificate scheme used for consensus votes and certificates.
pub type Scheme = simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>;
/// Threshold scheme used to certify post-execution state roots.
pub type AggregationScheme =
    aggregation::scheme::bls12381_threshold::Scheme<ed25519::PublicKey, MinSig>;
/// QMDB holding the application state.
pub type Qmdb<E> = fixed::Db<mmr::Family, E, U64, U64, Sha256, TwoCap, Sequential>;
/// Shared handle to the application QMDB.
pub type Database<E> = Shared<Qmdb<E>>;
/// Globally unique namespace for every message signed by this example.
pub const NAMESPACE: &[u8] = b"_COMMONWARE_RESHARE_EXAMPLE";
/// Namespace for post-execution state-root certificates.
pub const AGGREGATION_NAMESPACE: &[u8] = b"_COMMONWARE_RESHARE_EXAMPLE_STATE_ROOT";
/// Number of blocks in each epoch.
pub const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(64);
/// Maximum entries accepted in each DKG participant set.
pub const MAX_PARTICIPANTS: NonZeroU32 = commonware_utils::NZU32!(64);
/// Share derivation mode used by DKG and reshare ceremonies.
pub const SHARING_MODE: Mode = Mode::NonZeroCounter;
/// Revealed-share calculation used by DKG and reshare ceremonies.
pub const REVEAL: Reveal = Reveal::V1;
/// Newest sharing mode version this binary accepts.
pub const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v0();
/// Page size for storage page caches.
pub const PAGE_SIZE: std::num::NonZeroU16 = commonware_utils::NZU16!(1024);
/// Number of pages held by each page cache.
pub const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(16);
/// Buffer size for journal replay and writes.
pub const IO_BUFFER_SIZE: std::num::NonZeroUsize = NZUsize!(2048);
/// P2P channel carrying simplex votes.
pub const VOTE_CHANNEL: u64 = 0;
/// P2P channel carrying simplex certificates.
pub const CERTIFICATE_CHANNEL: u64 = 1;
/// P2P channel for orchestrator resolver traffic.
pub const RESOLVER_CHANNEL: u64 = 2;
/// P2P channel for marshal block backfill.
pub const BACKFILL_CHANNEL: u64 = 3;
/// P2P channel for proposed block broadcast.
pub const BROADCAST_CHANNEL: u64 = 4;
/// P2P channel for QMDB state sync.
pub const QMDB_CHANNEL: u64 = 5;
/// P2P channel for private reshare dealings and acks.
pub const DKG_CHANNEL: u64 = 6;
/// P2P channel for the DKG probe.
pub const DKG_PROBE_CHANNEL: u64 = 7;
/// P2P channel carrying epoch-multiplexed aggregation shares.
pub const AGGREGATION_ACK_CHANNEL: u64 = 8;
/// P2P channel serving aggregation certificate recovery.
pub const AGGREGATION_RECOVERY_CHANNEL: u64 = 9;
/// Current epoch plus two draining aggregation epochs remain network-active.
pub const AGGREGATION_ACTIVE_EPOCHS: std::num::NonZeroUsize = NZUsize!(3);
/// Mailbox capacity for every actor.
pub const MAILBOX_SIZE: std::num::NonZeroUsize = NZUsize!(100);
/// Per-peer message quota for every P2P channel.
pub const MESSAGE_RATE: Quota = Quota::per_second(NZU32!(128));
/// Maximum P2P message size in bytes.
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// Chain block carrying the QMDB state root and an optional reshare payload.
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
    /// Construct the genesis block from the epoch-0 info and initial QMDB sync target.
    pub const fn genesis(
        leader: ed25519::PublicKey,
        info: dkg::types::EpochInfo<MinSig, ed25519::PublicKey>,
        target: Target<mmr::Family, sha256::Digest>,
    ) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::zero(),
            state_root: target.root,
            range: target.range,
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
                &(MAX_PARTICIPANTS, MAX_SUPPORTED_MODE),
            )?,
        })
    }
}

impl Digestible for Block {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        Sha256::hash(&[&self.encode()])
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
    type Directory = Unit;

    fn payload(&self) -> Option<Payload<Self::Variant, Self::Signer>> {
        self.payload.clone()
    }
}

impl commonware_glue::dkg::orchestrator::checkpoints::FinalizedBlock for Block {
    type Checkpoint = sha256::Digest;

    fn finalized_checkpoint(&self) -> (Height, Self::Checkpoint) {
        (self.height, self.state_root)
    }
}

/// Certificate provider whose per-epoch schemes are registered as ceremonies complete.
#[derive(Clone)]
pub struct DynamicProvider<S = Scheme> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
    descriptors: Option<FileSecretStore>,
}

impl<S> Default for DynamicProvider<S> {
    fn default() -> Self {
        Self {
            schemes: Arc::default(),
            descriptors: None,
        }
    }
}

impl<S> DynamicProvider<S> {
    /// Register the certificate scheme for `epoch`.
    pub fn register(&self, epoch: Epoch, scheme: S) {
        self.schemes.lock().insert(epoch, Arc::new(scheme));
    }

    /// Return the newest registered epoch.
    pub fn latest_epoch(&self) -> Option<Epoch> {
        self.schemes.lock().keys().copied().max()
    }
}

impl<S> CertificateProvider for DynamicProvider<S>
where
    S: commonware_cryptography::certificate::Scheme,
{
    type Scope = Epoch;
    type Scheme = S;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned().map(Scoped::scheme)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned()
    }
}

impl commonware_glue::dkg::orchestrator::aggregation::Provider<AggregationScheme>
    for DynamicProvider<AggregationScheme>
{
    fn epoch(
        &self,
        namespace: aggregation::types::RecoveryNamespace,
        epoch: Epoch,
    ) -> Option<
        commonware_glue::dkg::orchestrator::aggregation::AuthenticatedEpoch<AggregationScheme>,
    > {
        let scheme = self.schemes.lock().get(&epoch).cloned()?;
        if <AggregationScheme as aggregation::scheme::Scheme<sha256::Digest>>::recovery_namespace(
            &scheme,
        ) != namespace
        {
            return None;
        }
        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        commonware_glue::dkg::orchestrator::aggregation::AuthenticatedEpoch::new(
            scheme,
            epocher.first(epoch)?,
            epocher.last(epoch)?,
        )
    }

    fn oldest_epoch(&self, namespace: aggregation::types::RecoveryNamespace) -> Option<Epoch> {
        let oldest = self
            .schemes
            .lock()
            .iter()
            .filter(|(_, scheme)| {
                <AggregationScheme as aggregation::scheme::Scheme<sha256::Digest>>::recovery_namespace(
                    scheme,
                ) == namespace
            })
            .map(|(epoch, _)| *epoch)
            .min()?;
        Some(
            self.descriptors
                .as_ref()
                .and_then(FileSecretStore::aggregation_floor)
                .map_or(oldest, |floor| oldest.max(floor)),
        )
    }
}

impl DynamicProvider<AggregationScheme> {
    /// Reconstruct every durably described aggregation epoch from `store`.
    #[allow(dead_code, reason = "used by validator startup integration")]
    pub fn load(store: FileSecretStore) -> anyhow::Result<Self> {
        let provider = Self {
            schemes: Arc::default(),
            descriptors: Some(store.clone()),
        };
        for (epoch, descriptor) in store.descriptors() {
            let share = store.share(epoch)?;
            provider.register(epoch, descriptor.scheme(epoch, share)?);
        }
        Ok(provider)
    }

    /// Register and durably describe an authenticated aggregation epoch.
    pub fn register_authenticated(
        &self,
        epoch: Epoch,
        participants: Set<ed25519::PublicKey>,
        sharing: Sharing<MinSig>,
        share: Option<Share>,
    ) -> anyhow::Result<()> {
        let is_verifier = share.is_none();
        let scheme = match share {
            Some(share) => AggregationScheme::signer(
                AGGREGATION_NAMESPACE,
                participants.clone(),
                sharing.clone(),
                share,
            )
            .ok_or_else(|| anyhow::anyhow!("share does not match aggregation epoch {epoch}"))?,
            None => AggregationScheme::verifier(
                AGGREGATION_NAMESPACE,
                participants.clone(),
                sharing.clone(),
            ),
        };
        if let Some(store) = &self.descriptors {
            store.put_descriptor(epoch, &participants, &sharing)?;
        }
        let mut schemes = self.schemes.lock();
        if is_verifier
            && schemes
                .get(&epoch)
                .is_some_and(|existing| existing.share().is_some())
        {
            return Ok(());
        }
        schemes.insert(epoch, Arc::new(scheme));
        Ok(())
    }

    fn erase_private_before(&self, min: Epoch) -> anyhow::Result<()> {
        let Some(store) = &self.descriptors else {
            anyhow::bail!("aggregation provider has no durable descriptor store");
        };
        let replacements = store
            .descriptors()
            .into_iter()
            .filter(|(epoch, _)| *epoch < min)
            .map(|(epoch, descriptor)| Ok((epoch, descriptor.scheme(epoch, None)?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut schemes = self.schemes.lock();
        for (epoch, verifier) in replacements {
            if schemes
                .get(&epoch)
                .is_some_and(|scheme| scheme.share().is_some())
            {
                schemes.insert(epoch, Arc::new(verifier));
            }
        }
        Ok(())
    }

    /// Persist the first aggregation epoch recoverable after state sync.
    pub fn set_discovery_floor(&self, epoch: Epoch) -> anyhow::Result<()> {
        let Some(store) = &self.descriptors else {
            anyhow::bail!("aggregation provider has no durable descriptor store");
        };
        store.set_aggregation_floor(epoch)
    }
}

/// Adapter that registers reshare outputs with the [`DynamicProvider`].
#[derive(Clone)]
pub struct Registrar {
    provider: DynamicProvider,
    aggregation_provider: DynamicProvider<AggregationScheme>,
}

impl Registrar {
    /// Wrap the consensus and aggregation providers for registration by the reshare actor.
    pub const fn new(
        provider: DynamicProvider,
        aggregation_provider: DynamicProvider<AggregationScheme>,
    ) -> Self {
        Self {
            provider,
            aggregation_provider,
        }
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
        match &info {
            dkg::types::SchemeInfo::Verifier {
                participants,
                sharing,
            } => self.aggregation_provider.register_authenticated(
                epoch,
                participants.clone(),
                sharing.clone(),
                None,
            ),
            dkg::types::SchemeInfo::Signer {
                participants,
                sharing,
                share,
            } => self.aggregation_provider.register_authenticated(
                epoch,
                participants.clone(),
                sharing.clone(),
                Some(share.clone()),
            ),
        }
        .expect("failed to persist aggregation epoch");
        let scheme = match info {
            dkg::types::SchemeInfo::Verifier {
                participants,
                sharing,
            } => Scheme::verifier(NAMESPACE, committee(&participants), sharing)
                .expect("threshold committees must be uniform"),
            dkg::types::SchemeInfo::Signer {
                participants,
                sharing,
                share,
            } => Scheme::signer(NAMESPACE, committee(&participants), sharing, share)
                .expect("registered share must match participant set"),
        };
        self.provider.register(epoch, scheme);
    }
}

/// Deterministic committee rotation over the ordered participant list.
#[derive(Clone)]
pub struct Participants {
    ordered: Arc<Vec<ed25519::PublicKey>>,
    committee_size: usize,
}

impl Participants {
    /// Build the rotation from a validated network config.
    pub fn new(config: &NetworkConfig) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self {
            ordered: Arc::new(config.participants.clone()),
            committee_size: config.committee_size,
        })
    }

    /// Committee for `epoch`: `committee_size` consecutive participants starting
    /// at offset `epoch % participants.len()` with wraparound.
    pub fn get(&self, epoch: Epoch) -> Set<ed25519::PublicKey> {
        let offset = epoch.get() as usize % self.ordered.len();
        let players = (0..self.committee_size)
            .map(|i| self.ordered[(offset + i) % self.ordered.len()].clone());
        Set::from_iter_dedup(players)
    }
}

impl ParticipantsProvider for Participants {
    type PublicKey = ed25519::PublicKey;
    type Directory = Unit;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        self.get(epoch)
    }

    async fn directory(&mut self, _: Epoch, _: Set<Self::PublicKey>) -> Self::Directory {
        Unit
    }
}

/// Reporter that logs every finalized block.
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

/// JSON-file-backed [`dkg::SecretStore`] holding shares, dealer seeds, and dealings.
///
/// Material is stored as plaintext JSON, which is suitable for this example only.
#[derive(Clone)]
pub struct FileSecretStore {
    path: PathBuf,
    inner: Arc<Mutex<SecretData>>,
}

/// Secret-store wrapper that honors aggregation's durable discovery floor.
#[derive(Clone)]
pub struct RetainedSecretStore {
    inner: FileSecretStore,
    history: commonware_glue::dkg::orchestrator::aggregation::Handler,
    namespace: aggregation::types::RecoveryNamespace,
    provider: DynamicProvider<AggregationScheme>,
}

impl RetainedSecretStore {
    /// Retains every epoch that may still need an aggregation signer after restart.
    pub const fn new(
        inner: FileSecretStore,
        history: commonware_glue::dkg::orchestrator::aggregation::Handler,
        namespace: aggregation::types::RecoveryNamespace,
        provider: DynamicProvider<AggregationScheme>,
    ) -> Self {
        Self {
            inner,
            history,
            namespace,
            provider,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SecretData {
    shares: BTreeMap<u64, String>,
    seeds: BTreeMap<u64, String>,
    dealings: BTreeMap<String, String>,
    #[serde(default)]
    aggregation_epochs: BTreeMap<u64, AggregationEpochDescriptor>,
    #[serde(default)]
    aggregation_floor: Option<u64>,
}

/// Minimum authenticated public material needed to rebuild an aggregation epoch.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct AggregationEpochDescriptor {
    participants: String,
    sharing: String,
}

impl AggregationEpochDescriptor {
    fn decode(&self) -> anyhow::Result<(Set<ed25519::PublicKey>, Sharing<MinSig>)> {
        let participants = from_hex(&self.participants)
            .ok_or_else(|| anyhow::anyhow!("invalid aggregation participants hex"))?;
        let sharing = from_hex(&self.sharing)
            .ok_or_else(|| anyhow::anyhow!("invalid aggregation sharing hex"))?;
        Ok((
            Set::decode_cfg(
                participants.as_slice(),
                &(
                    commonware_codec::RangeCfg::new(1..=MAX_PARTICIPANTS.get() as usize),
                    (),
                ),
            )?,
            Sharing::decode_cfg(sharing.as_slice(), &(MAX_PARTICIPANTS, MAX_SUPPORTED_MODE))?,
        ))
    }

    fn scheme(&self, epoch: Epoch, share: Option<Share>) -> anyhow::Result<AggregationScheme> {
        let (participants, sharing) = self.decode()?;
        Ok(match share {
            Some(share) => {
                AggregationScheme::signer(AGGREGATION_NAMESPACE, participants, sharing, share)
                    .ok_or_else(|| {
                        anyhow::anyhow!("stored share does not match aggregation epoch {epoch}")
                    })?
            }
            None => AggregationScheme::verifier(AGGREGATION_NAMESPACE, participants, sharing),
        })
    }
}

impl FileSecretStore {
    /// Open the store at `path`, starting empty if the file does not exist.
    pub fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let _lock = SecretStoreLock::acquire(&path)?;
        let temp = secret_temp_path(&path)?;
        if temp.exists() {
            fs::remove_file(&temp)?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            sync_directory(parent)?;
        }
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

    /// Seed the store with a trusted-setup share for `epoch`.
    pub fn put_initial_share(&self, epoch: Epoch, share: Share) -> anyhow::Result<()> {
        self.update(|inner| {
            inner.shares.insert(epoch.get(), hex(&share.encode()));
            Ok(())
        })
    }

    fn update(
        &self,
        mutate: impl FnOnce(&mut SecretData) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let _lock = SecretStoreLock::acquire(&self.path)?;
        let mut inner = self.inner.lock();
        let mut next = if self.path.exists() {
            serde_json::from_str(&fs::read_to_string(&self.path)?)?
        } else {
            inner.clone()
        };
        mutate(&mut next)?;
        self.flush(&next)?;
        *inner = next;
        Ok(())
    }

    fn flush(&self, data: &SecretData) -> anyhow::Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temp = secret_temp_path(&self.path)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp)?;
        #[cfg(unix)]
        if let Ok(metadata) = fs::metadata(&self.path) {
            file.set_permissions(fs::Permissions::from_mode(metadata.permissions().mode()))?;
        }
        let result = (|| {
            serde_json::to_writer_pretty(&mut file, data)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temp, &self.path)?;
            sync_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn put_descriptor(
        &self,
        epoch: Epoch,
        participants: &Set<ed25519::PublicKey>,
        sharing: &Sharing<MinSig>,
    ) -> anyhow::Result<()> {
        let descriptor = AggregationEpochDescriptor {
            participants: hex(&participants.encode()),
            sharing: hex(&sharing.encode()),
        };
        self.update(|inner| {
            if inner
                .aggregation_epochs
                .get(&epoch.get())
                .is_some_and(|existing| existing != &descriptor)
            {
                anyhow::bail!("refusing to replace aggregation epoch {epoch}");
            }
            inner.aggregation_epochs.insert(epoch.get(), descriptor);
            Ok(())
        })
    }

    fn descriptors(&self) -> Vec<(Epoch, AggregationEpochDescriptor)> {
        self.inner
            .lock()
            .aggregation_epochs
            .iter()
            .map(|(&epoch, descriptor)| (Epoch::new(epoch), descriptor.clone()))
            .collect()
    }

    fn aggregation_floor(&self) -> Option<Epoch> {
        self.inner.lock().aggregation_floor.map(Epoch::new)
    }

    fn set_aggregation_floor(&self, epoch: Epoch) -> anyhow::Result<()> {
        self.update(|inner| {
            inner.aggregation_floor = Some(
                inner
                    .aggregation_floor
                    .map_or(epoch.get(), |floor| floor.max(epoch.get())),
            );
            Ok(())
        })
    }

    fn share(&self, epoch: Epoch) -> anyhow::Result<Option<Share>> {
        let Some(raw) = self.inner.lock().shares.get(&epoch.get()).cloned() else {
            return Ok(None);
        };
        let bytes = from_hex(&raw).ok_or_else(|| anyhow::anyhow!("invalid share hex"))?;
        Ok(Some(Share::decode(bytes.as_slice())?))
    }

    fn dealing_key<P: commonware_cryptography::PublicKey>(epoch: Epoch, dealer: &P) -> String {
        format!("{}:{}", epoch.get(), hex(&dealer.encode()))
    }
}

struct SecretStoreLock(File);

impl SecretStoreLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("secret store path has no file name"))?
            .to_string_lossy();
        let lock_path = parent.join(format!(".{file_name}.lock"));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(lock_path)?;
        file.lock()?;
        Ok(Self(file))
    }
}

impl Drop for SecretStoreLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn secret_temp_path(path: &Path) -> anyhow::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("secret store path has no file name"))?
        .to_string_lossy();
    Ok(parent.join(format!(".{file_name}.tmp")))
}

impl dkg::SecretStore for FileSecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.update(|inner| {
            inner.shares.insert(epoch.get(), hex(&share.encode()));
            Ok(())
        })
        .expect("failed to flush share");
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        let raw = self.inner.lock().shares.get(&epoch.get()).cloned()?;
        let bytes = from_hex(&raw)?;
        Share::decode(bytes.as_slice()).ok()
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.update(|inner| {
            inner.seeds.insert(epoch.get(), hex(&seed.encode()));
            Ok(())
        })
        .expect("failed to flush seed");
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
        self.update(|inner| {
            inner.dealings.insert(key, hex(&private.encode()));
            Ok(())
        })
        .expect("failed to flush dealing");
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
        self.update(|inner| {
            inner.shares.retain(|epoch, _| *epoch >= min.get());
            inner.seeds.retain(|epoch, _| *epoch >= min.get());
            inner.dealings.retain(|key, _| {
                key.split_once(':')
                    .and_then(|(epoch, _)| epoch.parse::<u64>().ok())
                    .is_some_and(|epoch| epoch >= min.get())
            });
            Ok(())
        })
        .expect("failed to flush prune");
    }
}

impl dkg::SecretStore for RetainedSecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.inner.put_share(epoch, share).await;
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        self.inner.get_share(epoch).await
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.inner.put_seed(epoch, seed).await;
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        self.inner.get_seed(epoch).await
    }

    async fn put_dealing<P: commonware_cryptography::PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: P,
        private: DealerPrivMsg,
    ) {
        self.inner.put_dealing(epoch, dealer, private).await;
    }

    async fn get_dealing<P: commonware_cryptography::PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        self.inner.get_dealing(epoch, dealer).await
    }

    async fn prune(&mut self, requested: Epoch) {
        let floor = self
            .history
            .oldest_unretired(self.namespace)
            .await
            .map_err(|_| ());
        let cleanup = self
            .history
            .pending_cleanups(self.namespace, NZUsize!(1))
            .await
            .map(|cleanups| cleanups.first().map(|cleanup| cleanup.retirement.epoch))
            .map_err(|_| ());
        let safe = retained_prune_epoch(requested, floor, cleanup);
        self.inner.prune(safe).await;
        self.provider
            .erase_private_before(safe)
            .expect("failed to erase retired aggregation schemes");
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> anyhow::Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn retained_prune_epoch(
    requested: Epoch,
    floor: Result<Option<Epoch>, ()>,
    cleanup: Result<Option<Epoch>, ()>,
) -> Epoch {
    let (Ok(floor), Ok(cleanup)) = (floor, cleanup) else {
        return Epoch::zero();
    };
    [floor, cleanup]
        .into_iter()
        .flatten()
        .fold(requested, Epoch::min)
}

/// Application QMDB config with partitions derived from `prefix`.
pub fn db_config(prefix: &str, page_cache: CacheRef) -> FixedConfig<TwoCap, Sequential> {
    FixedConfig {
        merkle_config: MmrJournalConfig {
            journal_partition: format!("{prefix}-qmdb-mmr-journal"),
            metadata_partition: format!("{prefix}-qmdb-mmr-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{prefix}-qmdb-log-journal"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// QMDB state sync engine tuning.
pub const fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: NZU64!(16),
        apply_batch_size: NZU64!(64),
        max_outstanding_requests: 8,
        update_channel_size: NZUsize!(256),
        max_retained_roots: 8,
    }
}

/// Path of the genesis artifact inside `node_dir`.
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
            if fs::metadata(&path)?.len() == 0 {
                return crate::config::write_json(&path, &encoded);
            }
            let existing = Self::read(node_dir)?;
            if existing.epoch_info != *info {
                anyhow::bail!("refusing to overwrite different genesis artifact");
            }
            return Ok(());
        }
        crate::config::write_json(&path, &encoded)
    }
}

/// Read the genesis epoch info from `node_dir`.
pub fn read_genesis(
    node_dir: &Path,
) -> anyhow::Result<dkg::types::EpochInfo<MinSig, ed25519::PublicKey>> {
    Ok(EncodedGenesis::read(node_dir)?.epoch_info)
}

/// Write the genesis epoch info into `node_dir`, refusing to overwrite a
/// different existing artifact.
pub fn write_genesis(
    node_dir: &Path,
    info: &dkg::types::EpochInfo<MinSig, ed25519::PublicKey>,
) -> anyhow::Result<()> {
    EncodedGenesis::write(node_dir, info)
}

/// Serde codec for a hex-encoded [`dkg::types::EpochInfo`].
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
        dkg::types::EpochInfo::decode_cfg(bytes.as_slice(), &(MAX_PARTICIPANTS, MAX_SUPPORTED_MODE))
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer as _,
        bls12381::{dkg::feldman_desmedt::deal, primitives::group::Scalar},
    };
    use commonware_glue::dkg::SecretStore as _;
    use commonware_math::algebra::Random;
    use commonware_runtime::Runner as _;
    use commonware_utils::{N3f1, TestRng, ordered::Set, test_rng};

    fn keys(n: usize) -> Vec<ed25519::PublicKey> {
        let mut rng = test_rng();
        (0..n)
            .map(|_| ed25519::PrivateKey::random(&mut rng).public_key())
            .collect()
    }

    fn aggregation_material(seed: u64) -> (Set<ed25519::PublicKey>, Sharing<MinSig>, Share) {
        let participants = Set::from_iter_dedup(keys(4));
        let (output, shares) =
            deal::<MinSig, _, N3f1>(TestRng::new(seed), SHARING_MODE, participants.clone())
                .unwrap();
        let share = shares
            .get_value(participants.iter().next().unwrap())
            .unwrap()
            .clone();
        (participants, output.public().clone(), share)
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
            deal::<MinSig, _, N3f1>(TestRng::new(2), SHARING_MODE, participants.clone()).unwrap();
        let mut info = dkg::types::EpochInfo {
            outcome: dkg::types::EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players: participants.clone(),
            next_players: participants,
            directory: Unit,
        };

        write_genesis(&path, &info).unwrap();
        write_genesis(&path, &info).unwrap();
        info.epoch = Epoch::new(1);
        assert!(write_genesis(&path, &info).is_err());
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn genesis_replaces_empty_artifact() {
        let path = std::env::temp_dir().join(format!(
            "commonware-reshare-empty-genesis-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(genesis_path(&path), []).unwrap();

        let participants = Set::from_iter_dedup(keys(2));
        let (output, _shares) =
            deal::<MinSig, _, N3f1>(TestRng::new(2), SHARING_MODE, participants.clone()).unwrap();
        let info = dkg::types::EpochInfo {
            outcome: dkg::types::EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players: participants.clone(),
            next_players: participants,
            directory: Unit,
        };

        write_genesis(&path, &info).unwrap();
        assert_eq!(read_genesis(&path).unwrap(), info);
        let _ = std::fs::remove_dir_all(path);
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
            deal::<MinSig, _, N3f1>(TestRng::new(1), SHARING_MODE, players).unwrap();
        let share = shares.get_value(&player).unwrap().clone();

        commonware_runtime::deterministic::Runner::default().start(|_| {
            let mut store = store.clone();
            async move {
                store.put_share(Epoch::new(1), share.clone()).await;
                assert_eq!(store.get_share(Epoch::new(1)).await, Some(share));

                let seed = Summary::random(test_rng());
                store.put_seed(Epoch::new(1), seed).await;
                assert_eq!(store.get_seed(Epoch::new(1)).await, Some(seed));

                let dealer = keys(1).pop().unwrap();
                let dealing = DealerPrivMsg::new(Scalar::random(test_rng()));
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

    #[test]
    fn secret_store_updates_are_atomic_and_reloadable() {
        let directory = std::env::temp_dir().join(format!(
            "commonware-reshare-atomic-secrets-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.json");
        let store = FileSecretStore::load(&path).unwrap();
        let epoch = Epoch::new(7);
        let (_, _, share) = aggregation_material(27);

        store.put_initial_share(epoch, share.clone()).unwrap();
        store.set_aggregation_floor(epoch).unwrap();

        let contents = std::fs::read(&path).unwrap();
        serde_json::from_slice::<SecretData>(&contents).unwrap();
        let reloaded = FileSecretStore::load(&path).unwrap();
        assert_eq!(reloaded.share(epoch).unwrap(), Some(share.clone()));
        assert_eq!(reloaded.aggregation_floor(), Some(epoch));
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);

        let temp = secret_temp_path(&path).unwrap();
        std::fs::write(&temp, b"stale secret material").unwrap();
        let reloaded = FileSecretStore::load(&path).unwrap();
        assert_eq!(reloaded.share(epoch).unwrap(), Some(share));
        assert!(!temp.exists());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn independently_loaded_secret_stores_serialize_updates() {
        let directory = std::env::temp_dir().join(format!(
            "commonware-reshare-concurrent-secrets-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.json");
        let (_, _, share) = aggregation_material(29);
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut threads = Vec::new();

        for epoch in 1..=4 {
            let store = FileSecretStore::load(&path).unwrap();
            let barrier = barrier.clone();
            let share = share.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.put_initial_share(Epoch::new(epoch), share).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let reloaded = FileSecretStore::load(&path).unwrap();
        for epoch in 1..=4 {
            assert!(reloaded.share(Epoch::new(epoch)).unwrap().is_some());
        }
        assert!(!secret_temp_path(&path).unwrap().exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn secret_store_updates_preserve_restrictive_permissions() {
        let directory = std::env::temp_dir().join(format!(
            "commonware-reshare-secret-permissions-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secrets.json");
        let store = FileSecretStore::load(&path).unwrap();
        let (_, _, share) = aggregation_material(28);

        store
            .put_initial_share(Epoch::new(1), share.clone())
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        store.put_initial_share(Epoch::new(2), share).unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn aggregation_provider_reconstructs_signers_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "commonware-reshare-aggregation-restart-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = FileSecretStore::load(&path).unwrap();
        let epoch = Epoch::new(3);
        let (participants, sharing, share) = aggregation_material(31);
        store.put_initial_share(epoch, share.clone()).unwrap();

        let provider = DynamicProvider::<AggregationScheme>::load(store).unwrap();
        provider
            .register_authenticated(epoch, participants.clone(), sharing.clone(), Some(share))
            .unwrap();
        provider
            .register_authenticated(epoch, participants, sharing, None)
            .unwrap();
        assert!(provider.scheme(epoch).unwrap().share().is_some());
        let verifier_epoch = Epoch::new(4);
        let (participants, sharing, _) = aggregation_material(32);
        provider
            .register_authenticated(verifier_epoch, participants, sharing, None)
            .unwrap();
        let (participants, sharing, _) = aggregation_material(33);
        assert!(
            provider
                .register_authenticated(epoch, participants, sharing, None)
                .is_err()
        );
        let namespace =
            <AggregationScheme as aggregation::scheme::Scheme<sha256::Digest>>::recovery_namespace(
                &provider.scheme(epoch).unwrap(),
            );
        assert_eq!(
            commonware_glue::dkg::orchestrator::aggregation::Provider::oldest_epoch(
                &provider, namespace,
            ),
            Some(epoch)
        );
        provider.set_discovery_floor(verifier_epoch).unwrap();
        drop(provider);

        let provider =
            DynamicProvider::<AggregationScheme>::load(FileSecretStore::load(&path).unwrap())
                .unwrap();
        assert!(provider.scheme(epoch).unwrap().share().is_some());
        assert!(provider.scheme(verifier_epoch).unwrap().share().is_none());
        let authenticated = commonware_glue::dkg::orchestrator::aggregation::Provider::epoch(
            &provider, namespace, epoch,
        )
        .unwrap();
        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        assert_eq!(authenticated.first(), epocher.first(epoch).unwrap());
        assert_eq!(authenticated.last(), epocher.last(epoch).unwrap());
        assert_eq!(
            commonware_glue::dkg::orchestrator::aggregation::Provider::oldest_epoch(
                &provider, namespace,
            ),
            Some(verifier_epoch)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn aggregation_descriptors_survive_secret_pruning() {
        let path = std::env::temp_dir().join(format!(
            "commonware-reshare-aggregation-prune-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut store = FileSecretStore::load(&path).unwrap();
        let provider = DynamicProvider::<AggregationScheme>::load(store.clone()).unwrap();
        for (epoch, seed) in [(Epoch::new(1), 41), (Epoch::new(2), 42)] {
            let (participants, sharing, share) = aggregation_material(seed);
            store.put_initial_share(epoch, share.clone()).unwrap();
            provider
                .register_authenticated(epoch, participants, sharing, Some(share))
                .unwrap();
        }

        commonware_runtime::deterministic::Runner::default().start(|_| async {
            store.prune(Epoch::new(1)).await;
        });
        let restarted =
            DynamicProvider::<AggregationScheme>::load(FileSecretStore::load(&path).unwrap())
                .unwrap();
        assert!(restarted.scheme(Epoch::new(1)).is_some());
        assert!(restarted.scheme(Epoch::new(2)).is_some());

        let mut store = FileSecretStore::load(&path).unwrap();
        commonware_runtime::deterministic::Runner::default().start(|_| async {
            store.prune(Epoch::new(2)).await;
        });
        provider.erase_private_before(Epoch::new(2)).unwrap();
        assert!(provider.scheme(Epoch::new(1)).unwrap().share().is_none());
        assert!(provider.scheme(Epoch::new(2)).unwrap().share().is_some());
        let restarted =
            DynamicProvider::<AggregationScheme>::load(FileSecretStore::load(&path).unwrap())
                .unwrap();
        assert!(restarted.scheme(Epoch::new(1)).unwrap().share().is_none());
        assert!(restarted.scheme(Epoch::new(2)).unwrap().share().is_some());

        let mut store = FileSecretStore::load(&path).unwrap();
        commonware_runtime::deterministic::Runner::default().start(|_| async {
            store.prune(Epoch::new(3)).await;
        });
        provider.erase_private_before(Epoch::new(3)).unwrap();
        let restarted =
            DynamicProvider::<AggregationScheme>::load(FileSecretStore::load(&path).unwrap())
                .unwrap();
        assert!(restarted.scheme(Epoch::new(1)).unwrap().share().is_none());
        assert!(restarted.scheme(Epoch::new(2)).unwrap().share().is_none());

        restarted.set_discovery_floor(Epoch::new(2)).unwrap();
        let namespace =
            <AggregationScheme as aggregation::scheme::Scheme<sha256::Digest>>::recovery_namespace(
                &restarted.scheme(Epoch::new(1)).unwrap(),
            );
        assert_eq!(
            commonware_glue::dkg::orchestrator::aggregation::Provider::oldest_epoch(
                &restarted, namespace
            ),
            Some(Epoch::new(2))
        );

        assert_eq!(
            retained_prune_epoch(Epoch::new(9), Ok(Some(Epoch::new(2))), Ok(None)),
            Epoch::new(2)
        );
        assert_eq!(
            retained_prune_epoch(
                Epoch::new(9),
                Ok(Some(Epoch::new(3))),
                Ok(Some(Epoch::new(2)))
            ),
            Epoch::new(2)
        );
        assert_eq!(
            retained_prune_epoch(Epoch::new(9), Ok(None), Ok(None)),
            Epoch::new(9)
        );
        assert_eq!(
            retained_prune_epoch(Epoch::new(9), Err(()), Ok(None)),
            Epoch::zero()
        );
        let _ = std::fs::remove_file(path);
    }
}
