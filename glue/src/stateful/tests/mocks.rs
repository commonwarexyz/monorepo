use crate::stateful::{
    Application, Input, Proposed,
    db::{
        DatabaseSet, ManagedDb, Merkleized, MerkleizedOf, SetReader, Unmerkleized, UnmerkleizedOf,
    },
};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
    marshal::{ancestry::Ancestry, standard::Standard},
    simplex::{mocks::scheme as scheme_mocks, types::Context as SimplexContext},
    types::{Epoch, Height, View},
};
use commonware_cryptography::{
    Digest as _, Digestible, Signer as _, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_runtime::{Buf, BufMut, Error as RuntimeError, Handle};
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{convert::Infallible, sync::Arc};

/// The generation served by `source`, or `None` before the first publish and
/// after the publisher drops.
pub(crate) fn served_generation(source: &SetReader<()>) -> Option<u64> {
    source.latest().map(|generation| generation.number())
}

pub(crate) type TestDatabases = crate::stateful::db::Single<TestDb>;
pub(crate) type TestScheme = scheme_mocks::Scheme<ed25519::PublicKey>;
pub(crate) type TestVariant = Standard<TestBlock>;

/// No-op batch for mock databases. Merkleizes against any database type.
#[derive(Clone, Copy)]
pub(crate) struct TestUnmerkleized;

/// Merkleized counterpart of [`TestUnmerkleized`].
#[derive(Clone, Copy)]
pub(crate) struct TestMerkleized;

impl<D: Sync> Unmerkleized<D> for TestUnmerkleized {
    type Merkleized = TestMerkleized;
    type Error = Infallible;

    async fn merkleize(self, _db: &D) -> Result<Self::Merkleized, Self::Error> {
        Ok(TestMerkleized)
    }
}

impl Merkleized for TestMerkleized {
    type Digest = Sha256Digest;
    type Unmerkleized = TestUnmerkleized;

    fn root(&self) -> Self::Digest {
        Sha256Digest::from([0; 32])
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        TestUnmerkleized
    }
}

/// Completes one parked flush when released by the test.
pub(crate) type FlushRelease = oneshot::Sender<Result<(), RuntimeError>>;

/// Shared observer for a gated [`TestDb`]: parked flush releases and recorded
/// prune targets.
#[derive(Clone, Default)]
pub(crate) struct FlushControl {
    pub(crate) flushes: Arc<Mutex<Vec<FlushRelease>>>,
    pub(crate) pruned: Arc<Mutex<Vec<u64>>>,
}

#[derive(Default)]
pub(crate) struct TestDb {
    finalize: Mutex<Option<Handle<()>>>,
    control: Option<FlushControl>,
}

impl TestDb {
    pub(crate) fn with_finalize(handle: Handle<()>) -> Self {
        Self {
            finalize: Mutex::new(Some(handle)),
            control: None,
        }
    }

    /// A database whose every finalize flush parks until the test releases it and whose
    /// prune records its target immediately, isolating the caller's own scheduling.
    pub(crate) fn gated(control: FlushControl) -> Self {
        Self {
            finalize: Mutex::new(None),
            control: Some(control),
        }
    }
}

impl<E: Send> ManagedDb<E> for TestDb {
    type Unmerkleized = TestUnmerkleized;
    type Merkleized = TestMerkleized;
    type Error = Infallible;
    type Config = ();
    type SyncTarget = u64;
    type Snapshot = ();

    async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
        Ok((self, ()))
    }

    fn initial_sync_target() -> Self::SyncTarget {
        unreachable!("TestDb is constructed directly in tests")
    }

    async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        TestUnmerkleized
    }

    fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
        true
    }

    async fn finalize(
        self,
        _batch: Self::Merkleized,
    ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
        if let Some(control) = &self.control {
            let (release, released) = oneshot::channel();
            control.flushes.lock().push(release);
            return Ok((self, (), Handle::from_receiver(released)));
        }
        let handle = self
            .finalize
            .lock()
            .take()
            .unwrap_or_else(|| Handle::ready(Ok(())));
        Ok((self, (), handle))
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Self::Error> {
        if let Some(control) = &self.control {
            control.pruned.lock().push(*target);
        }
        Ok(self)
    }

    fn sync_target(&self) -> Self::SyncTarget {
        0
    }

    async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TestBlock {
    context: SimplexContext<Sha256Digest, ed25519::PublicKey>,
    height: Height,
    digest: Sha256Digest,
}

impl TestBlock {
    pub(crate) fn new(height: u64, digest_byte: u8) -> Self {
        Self {
            context: SimplexContext {
                round: commonware_consensus::types::Round::new(Epoch::zero(), View::new(height)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), Sha256Digest::EMPTY),
            },
            height: Height::new(height),
            digest: Sha256Digest::from([digest_byte; 32]),
        }
    }
}

impl Write for TestBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        buf.put_u64(self.height.get());
        buf.put_slice(self.digest.as_ref());
    }
}

impl EncodeSize for TestBlock {
    fn encode_size(&self) -> usize {
        self.context.encode_size() + 8 + 32
    }
}

impl Read for TestBlock {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let context = SimplexContext::read(buf)?;
        let height = Height::new(buf.get_u64());
        let mut digest = [0u8; 32];
        buf.copy_to_slice(&mut digest);
        Ok(Self {
            context,
            height,
            digest: Sha256Digest::from(digest),
        })
    }
}

impl Digestible for TestBlock {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Heightable for TestBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for TestBlock {
    fn parent(&self) -> Self::Digest {
        Sha256Digest::EMPTY
    }
}

impl CertifiableBlock for TestBlock {
    type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

#[derive(Clone)]
pub(crate) struct TestApp;

impl<
    E: rand_core::Rng
        + commonware_runtime::Spawner
        + commonware_runtime::Metrics
        + commonware_runtime::Clock
        + Send
        + Sync,
> Application<E> for TestApp
{
    type SigningScheme = TestScheme;
    type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
    type Block = TestBlock;
    type Databases = TestDatabases;
    type Provider = ();
    type Input = ();

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        block.height().get()
    }

    async fn genesis(&mut self) -> Self::Block {
        TestBlock::new(0, 0)
    }

    async fn propose(
        &mut self,
        _context: (E, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _databases: &Self::Databases,
        _batches: UnmerkleizedOf<Self::Databases, E>,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        None
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _databases: &Self::Databases,
        _batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> Option<MerkleizedOf<Self::Databases, E>> {
        None
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _databases: &Self::Databases,
        _batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> MerkleizedOf<Self::Databases, E> {
        TestMerkleized
    }
}

pub(crate) fn test_databases() -> TestDatabases {
    TestDb::default().into()
}

pub(crate) fn anchor(height: u64, digest_byte: u8) -> crate::stateful::db::Anchor<Sha256Digest> {
    crate::stateful::db::Anchor {
        height: Height::new(height),
        round: commonware_consensus::types::Round::new(Epoch::zero(), View::new(height)),
        digest: Sha256Digest::from([digest_byte; 32]),
    }
}
