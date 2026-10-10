//! Types, constants, and storage config shared across the example.

use crate::config::NetworkConfig;
use commonware_actor::Feedback;
use commonware_codec::{
    Buf, Copying, Decode as _, DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, Read,
    ReadExt as _, Write,
};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Epochable, Heightable, Reporter,
    marshal::Update,
    simplex::{self, types::Context},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher, Sha256,
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, Reveal},
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion},
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
use commonware_runtime::{BufMut, Quota, buffer::paged::CacheRef};
use commonware_storage::{
    Context as StorageContext,
    journal::{authenticated::Config as MerkleConfig, contiguous::fixed::Config as FixedLogConfig},
    metadata::{self, Metadata},
    mmr::{self, Location},
    qmdb::{
        any::{FixedConfig, unordered::fixed},
        sync::Target,
    },
    translator::TwoCap,
};
use commonware_utils::{
    Acknowledgement, NZU32, NZU64, NZUsize,
    ordered::Set,
    range::NonEmptyRange,
    sequence::{FixedBytes, U64, Unit},
    sync::{AsyncMutex, Mutex},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{
    collections::HashMap,
    fs, io,
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::info;

/// Threshold certificate scheme used for consensus votes and certificates.
pub type Scheme = simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>;
/// QMDB holding the application state.
pub type Qmdb<E> = fixed::Db<mmr::Family, E, U64, U64, Sha256, TwoCap, Sequential>;
/// Shared handle to the application QMDB.
pub type Database<E> = Shared<Qmdb<E>>;
/// Globally unique namespace for every message signed by this example.
pub const NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_DKG";
/// Number of blocks in each epoch.
pub const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(64);
/// Maximum entries accepted in each DKG participant set.
pub const MAX_PARTICIPANTS: NonZeroU32 = commonware_utils::NZU32!(64);
/// Share derivation mode used by bootstrap and reshare ceremonies.
pub const SHARING_MODE: Mode = Mode::NonZeroCounter;
/// Revealed-share calculation used by bootstrap and reshare ceremonies.
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
/// Mailbox capacity for every actor.
pub const MAILBOX_SIZE: std::num::NonZeroUsize = NZUsize!(100);
/// Message buffer size for every P2P channel muxer.
pub const MUXER_SIZE: usize = 128;
/// Finalized blocks and certificates per archive section.
pub const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(10);
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

/// Certificate provider whose per-epoch schemes are registered as ceremonies complete.
#[derive(Clone, Default)]
pub struct DynamicProvider {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<Scheme>>>>,
}

impl DynamicProvider {
    /// Register the certificate scheme for `epoch`.
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

/// Adapter that registers reshare outputs with the [`DynamicProvider`].
#[derive(Clone)]
pub struct Registrar {
    provider: DynamicProvider,
}

impl Registrar {
    /// Wrap `provider` for registration by the reshare actor.
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

/// Key kind of a share.
const SHARE: u8 = 0;

/// Key kind of a dealer seed.
const SEED: u8 = 1;

/// Key kind of a received dealing.
const DEALING: u8 = 2;

/// Size of a [`Secrets`] key: the kind, the big-endian epoch, and the SHA-256
/// digest of the dealer's public key (zero for shares and seeds).
const KEY: usize = 1 + u64::SIZE + sha256::Digest::SIZE;

/// Key of one entry in [`Secrets`].
type Key = FixedBytes<KEY>;

/// Metadata store backing [`Secrets`].
type Store<E> = Metadata<E, Key, Vec<u8>>;

/// Key of the `kind` entry for `epoch` and, for a dealing, `dealer`.
fn key(kind: u8, epoch: Epoch, dealer: Option<sha256::Digest>) -> Key {
    let mut key = [0; KEY];
    key[0] = kind;
    key[1..9].copy_from_slice(&epoch.get().to_be_bytes());
    if let Some(dealer) = dealer {
        key[9..].copy_from_slice(&dealer);
    }
    Key::new(key)
}

/// Epoch encoded in `key`.
fn epoch(key: &Key) -> Epoch {
    Epoch::new(u64::from_be_bytes(key[1..9].try_into().unwrap()))
}

/// Runtime storage partition of a [`Secrets`] store.
///
/// The bootstrap and the validator's first reshare both persist dealer seeds
/// and received dealings for epoch 0, so each uses its own partition.
#[derive(Clone, Copy)]
pub enum Partition {
    /// `bootstrap-secrets`, used by `bootstrap`.
    Bootstrap,

    /// `secrets`, used by `validator` for the epoch-0 share that `bootstrap` hands
    /// over and for every reshare's material.
    Validator,
}

/// [`dkg::SecretStore`] holding shares, dealer seeds, and dealings in one
/// [`Partition`] of the node's runtime storage.
///
/// Clones share one store. Material is stored unencrypted, which is suitable
/// for this example only. Every put and prune is synced before it returns, and
/// every get reads from memory.
pub struct Secrets<E: StorageContext> {
    /// Taken during writes and destruction. Interrupted writes leave the store unusable.
    metadata: Arc<AsyncMutex<Option<Store<E>>>>,
}

impl<E: StorageContext> Clone for Secrets<E> {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
        }
    }
}

impl<E: StorageContext> Secrets<E> {
    /// Open the store in `partition`, starting empty if nothing was stored.
    pub async fn init(context: E, partition: Partition) -> Self {
        let partition = match partition {
            Partition::Bootstrap => "bootstrap-secrets",
            Partition::Validator => "secrets",
        };
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition: partition.to_string(),
                codec_config: ((..).into(), ()),
            },
        )
        .await
        .expect("failed to load secrets");
        Self {
            metadata: Arc::new(AsyncMutex::new(Some(metadata))),
        }
    }

    async fn get<T: DecodeExt<()>>(&self, key: &Key) -> Option<T> {
        let metadata = self.metadata.lock().await;
        let value = metadata
            .as_ref()
            .expect("secrets used after an interrupted sync")
            .get(key)?;
        Some(T::decode(Copying(value)).expect("stored secret must decode"))
    }

    async fn put(&mut self, key: Key, value: impl Encode) {
        let mut guard = self.metadata.lock().await;
        let metadata = guard
            .take()
            .expect("secrets used after an interrupted sync");
        let metadata = metadata
            .put_sync(key, value.encode().into())
            .await
            .expect("failed to sync secrets");
        *guard = Some(metadata);
    }

    /// Remove the store's partition and everything in it.
    pub async fn destroy(self) {
        let metadata = self
            .metadata
            .lock()
            .await
            .take()
            .expect("secrets used after an interrupted sync");
        metadata.destroy().await.expect("failed to destroy secrets");
    }
}

impl<E: StorageContext> dkg::SecretStore for Secrets<E> {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.put(key(SHARE, epoch, None), share).await;
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        self.get(&key(SHARE, epoch, None)).await
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.put(key(SEED, epoch, None), seed).await;
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        self.get(&key(SEED, epoch, None)).await
    }

    async fn put_dealing<P: commonware_cryptography::PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: P,
        private: DealerPrivMsg,
    ) {
        let dealer = Sha256::hash(&[&dealer]);
        self.put(key(DEALING, epoch, Some(dealer)), private).await;
    }

    async fn get_dealing<P: commonware_cryptography::PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        let dealer = Sha256::hash(&[dealer]);
        self.get(&key(DEALING, epoch, Some(dealer))).await
    }

    async fn prune(&mut self, min: Epoch) {
        let mut guard = self.metadata.lock().await;
        let mut metadata = guard
            .take()
            .expect("secrets used after an interrupted sync");
        metadata.retain(|key, _| epoch(key) >= min);
        let metadata = metadata.sync().await.expect("failed to sync secrets");
        *guard = Some(metadata);
    }
}

/// Application QMDB config with partitions derived from `prefix`.
pub fn db_config(prefix: &str, page_cache: CacheRef) -> FixedConfig<TwoCap, Sequential> {
    FixedConfig {
        merkle_config: MerkleConfig {
            metadata_partition: format!("{prefix}-qmdb-mmr-metadata"),
            replay_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            cache: Default::default(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{prefix}-qmdb-log-journal"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
        translator: TwoCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// Operations per state sync request. Validators fetch and serve the same size, since peers
/// ignore requests larger than they serve.
pub const SYNC_BATCH_SIZE: NonZeroU64 = NZU64!(16);

/// QMDB state sync engine tuning.
pub const fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: SYNC_BATCH_SIZE,
        apply_batch_size: NZU64!(64),
        max_outstanding_requests: NZUsize!(8),
        update_channel_size: NZUsize!(256),
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
        // Overwrite an artifact that cannot be parsed, such as one torn by a crash
        // mid-write. `bootstrap` re-derives the artifact from its own finalized chain.
        let path = genesis_path(node_dir);
        match fs::read(&path) {
            Ok(contents) => {
                if let Ok(existing) = serde_json::from_slice::<Self>(&contents) {
                    if existing.epoch_info != *info {
                        anyhow::bail!("refusing to overwrite different genesis artifact");
                    }
                    return Ok(());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let encoded = Self {
            epoch_info: info.clone(),
        };
        crate::config::write_json(&path, &encoded)
    }
}

/// Read the genesis epoch info from `node_dir`.
pub fn read_genesis(
    node_dir: &Path,
) -> anyhow::Result<dkg::types::EpochInfo<MinSig, ed25519::PublicKey>> {
    Ok(EncodedGenesis::read(node_dir)?.epoch_info)
}

/// Write the genesis epoch info into `node_dir`, overwriting an existing
/// artifact that cannot be parsed and refusing to overwrite a different one.
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
        dkg::types::EpochInfo::decode_cfg(bytes, &(MAX_PARTICIPANTS, MAX_SUPPORTED_MODE))
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
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{N3f1, TestRng, ordered::Set, test_rng};

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
            std::env::temp_dir().join(format!("commonware-dkg-genesis-{}", std::process::id()));
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
    fn genesis_replaces_unreadable_artifact() {
        let path = std::env::temp_dir().join(format!(
            "commonware-dkg-torn-genesis-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();

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

        // An empty or truncated artifact, as a crash mid-write leaves, is overwritten.
        write_genesis(&path, &info).unwrap();
        let contents = std::fs::read(genesis_path(&path)).unwrap();
        for len in [0, contents.len() / 2] {
            std::fs::write(genesis_path(&path), &contents[..len]).unwrap();
            write_genesis(&path, &info).unwrap();
            assert_eq!(read_genesis(&path).unwrap(), info);
        }
        let _ = std::fs::remove_dir_all(path);
    }

    /// Every put survives an unclean restart, and a prune durably removes only
    /// the material below its epoch.
    #[test]
    fn secrets_survive_restart_and_prune() {
        // Deal a share and draw a seed and one dealing from each of two dealers.
        let player = keys(1).pop().unwrap();
        let players = Set::from_iter_dedup([player.clone()]);
        let (_output, shares) =
            deal::<MinSig, _, N3f1>(TestRng::new(1), SHARING_MODE, players).unwrap();
        let share = shares.get_value(&player).unwrap().clone();
        let mut rng = test_rng();
        let seed = Summary::random(&mut rng);
        let dealings = keys(2)
            .into_iter()
            .map(|dealer| (dealer, DealerPrivMsg::new(Scalar::random(&mut rng))))
            .collect::<Vec<_>>();

        // Store material for epochs 1 and 2, with a dealing from each dealer, then crash.
        let (_, checkpoint) = deterministic::Runner::default().start_and_recover({
            let (share, dealings) = (share.clone(), dealings.clone());
            |context| async move {
                let mut secrets =
                    Secrets::init(context.child("secrets"), Partition::Validator).await;
                for epoch in [Epoch::new(1), Epoch::new(2)] {
                    secrets.put_share(epoch, share.clone()).await;
                    secrets.put_seed(epoch, seed).await;
                    for (dealer, dealing) in &dealings {
                        secrets
                            .put_dealing(epoch, dealer.clone(), dealing.clone())
                            .await;
                    }
                }
                assert_eq!(secrets.get_share(Epoch::new(1)).await, Some(share));
            }
        });

        // Every put survives the restart. Prune below epoch 2, then crash again.
        let (_, checkpoint) = deterministic::Runner::from(checkpoint).start_and_recover({
            let (share, dealings) = (share.clone(), dealings.clone());
            |context| async move {
                let mut secrets =
                    Secrets::init(context.child("secrets"), Partition::Validator).await;
                for epoch in [Epoch::new(1), Epoch::new(2)] {
                    assert_eq!(secrets.get_share(epoch).await, Some(share.clone()));
                    assert_eq!(secrets.get_seed(epoch).await, Some(seed));
                    for (dealer, dealing) in &dealings {
                        assert_eq!(
                            secrets.get_dealing(epoch, dealer).await,
                            Some(dealing.clone())
                        );
                    }
                }
                secrets.prune(Epoch::new(2)).await;
            }
        });

        // The prune survives the restart: epoch 1 is gone and epoch 2 remains.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let mut secrets = Secrets::init(context.child("secrets"), Partition::Validator).await;
            assert_eq!(secrets.get_share(Epoch::new(1)).await, None);
            assert_eq!(secrets.get_seed(Epoch::new(1)).await, None);
            assert_eq!(secrets.get_share(Epoch::new(2)).await, Some(share));
            assert_eq!(secrets.get_seed(Epoch::new(2)).await, Some(seed));
            for (dealer, dealing) in dealings {
                assert_eq!(secrets.get_dealing(Epoch::new(1), &dealer).await, None);
                assert_eq!(
                    secrets.get_dealing(Epoch::new(2), &dealer).await,
                    Some(dealing)
                );
            }
        });
    }

    /// The `bootstrap` handoff copies only the epoch-0 share from the bootstrap
    /// partition into the validator partition, and the share survives an
    /// unclean restart.
    #[test]
    fn handoff_carries_only_share() {
        // Deal a share and draw a seed and one dealing.
        let participants = keys(2);
        let (player, dealer) = (participants[0].clone(), participants[1].clone());
        let players = Set::from_iter_dedup([player.clone()]);
        let (_output, shares) =
            deal::<MinSig, _, N3f1>(TestRng::new(1), SHARING_MODE, players).unwrap();
        let share = shares.get_value(&player).unwrap().clone();
        let mut rng = test_rng();
        let seed = Summary::random(&mut rng);
        let dealing = DealerPrivMsg::new(Scalar::random(&mut rng));

        let (_, checkpoint) = deterministic::Runner::default().start_and_recover({
            let (share, dealer) = (share.clone(), dealer.clone());
            |context| async move {
                // The engine's clone of the bootstrap store persists the
                // ceremony's epoch-0 share, seed, and dealing.
                let mut bootstrap =
                    Secrets::init(context.child("secrets"), crate::bootstrap::PARTITION).await;
                let mut engine = bootstrap.clone();
                engine.put_share(Epoch::zero(), share).await;
                engine.put_seed(Epoch::zero(), seed).await;
                engine.put_dealing(Epoch::zero(), dealer, dealing).await;

                // Hand over the share as `bootstrap` does, then crash.
                let share = bootstrap.get_share(Epoch::zero()).await.unwrap();
                let mut handoff =
                    Secrets::init(context.child("handoff"), crate::validator::PARTITION).await;
                handoff.put_share(Epoch::zero(), share).await;
            }
        });

        // The validator partition holds the share and none of the ceremony's
        // seed or dealing.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let mut secrets =
                Secrets::init(context.child("secrets"), crate::validator::PARTITION).await;
            assert_eq!(secrets.get_share(Epoch::zero()).await, Some(share));
            assert_eq!(secrets.get_seed(Epoch::zero()).await, None);
            assert_eq!(secrets.get_dealing(Epoch::zero(), &dealer).await, None);
        });
    }

    /// Destroying the bootstrap partition erases the ceremony's share, seed,
    /// and dealing across a restart.
    #[test]
    fn destroy_erases_bootstrap() {
        // Deal a share and draw a seed and one dealing.
        let participants = keys(2);
        let (player, dealer) = (participants[0].clone(), participants[1].clone());
        let players = Set::from_iter_dedup([player.clone()]);
        let (_output, shares) =
            deal::<MinSig, _, N3f1>(TestRng::new(1), SHARING_MODE, players).unwrap();
        let share = shares.get_value(&player).unwrap().clone();
        let mut rng = test_rng();
        let seed = Summary::random(&mut rng);
        let dealing = DealerPrivMsg::new(Scalar::random(&mut rng));

        // Persist the ceremony's material, then destroy the partition.
        let (_, checkpoint) = deterministic::Runner::default().start_and_recover({
            let dealer = dealer.clone();
            |context| async move {
                let mut bootstrap =
                    Secrets::init(context.child("secrets"), crate::bootstrap::PARTITION).await;
                bootstrap.put_share(Epoch::zero(), share).await;
                bootstrap.put_seed(Epoch::zero(), seed).await;
                bootstrap.put_dealing(Epoch::zero(), dealer, dealing).await;
                drop(bootstrap);

                // Reopen and erase the partition, as `validator` does.
                Secrets::init(context.child("bootstrap"), crate::bootstrap::PARTITION)
                    .await
                    .destroy()
                    .await;
            }
        });

        // Nothing survives in the bootstrap partition.
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let mut bootstrap =
                Secrets::init(context.child("secrets"), crate::bootstrap::PARTITION).await;
            assert_eq!(bootstrap.get_share(Epoch::zero()).await, None);
            assert_eq!(bootstrap.get_seed(Epoch::zero()).await, None);
            assert_eq!(bootstrap.get_dealing(Epoch::zero(), &dealer).await, None);
        });
    }
}
