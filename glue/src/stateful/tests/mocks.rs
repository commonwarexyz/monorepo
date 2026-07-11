use crate::stateful::{
    db::{DatabaseSet, ManagedDb, Merkleized, Unmerkleized},
    Application, Proposed,
};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    marshal::standard::Standard,
    simplex::{mocks::scheme as scheme_mocks, types::Context as SimplexContext},
    types::{Epoch, Height, View},
    Block as ConsensusBlock, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    ed25519, sha256::Digest as Sha256Digest, Digest as _, Digestible, Signer as _,
};
use commonware_runtime::{deterministic, Buf, BufMut};
use commonware_utils::sync::TracedAsyncRwLock;
use futures::Stream;
use std::{convert::Infallible, sync::Arc};

pub(crate) type TestDatabases = Arc<TracedAsyncRwLock<TestDb>>;
pub(crate) type TestScheme = scheme_mocks::Scheme<ed25519::PublicKey>;
pub(crate) type TestVariant = Standard<TestBlock>;

#[derive(Clone, Copy)]
pub(crate) struct TestUnmerkleized;

#[derive(Clone, Copy)]
pub(crate) struct TestMerkleized(pub(crate) u64);

impl Unmerkleized for TestUnmerkleized {
    type Merkleized = TestMerkleized;
    type Error = Infallible;

    async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
        Ok(TestMerkleized(0))
    }
}

impl Merkleized for TestMerkleized {
    type Digest = Sha256Digest;
    type Unmerkleized = TestUnmerkleized;

    fn root(&self) -> Self::Digest {
        Sha256Digest::from([self.0 as u8; 32])
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        TestUnmerkleized
    }
}

#[derive(Default)]
pub(crate) struct TestDb {
    target: u64,
}

impl TestDb {
    pub(crate) const fn new(target: u64) -> Self {
        Self { target }
    }

    pub(crate) const fn target(&self) -> u64 {
        self.target
    }
}

impl<E: Send> ManagedDb<E> for TestDb {
    type Unmerkleized = TestUnmerkleized;
    type Merkleized = TestMerkleized;
    type Error = Infallible;
    type Config = u64;
    type SyncTarget = u64;

    async fn init(_context: E, target: Self::Config) -> Result<Self, Self::Error> {
        Ok(Self::new(target))
    }

    async fn new_batch(_db: &Arc<TracedAsyncRwLock<Self>>) -> Self::Unmerkleized {
        TestUnmerkleized
    }

    fn matches_sync_target(batch: &Self::Merkleized, target: &Self::SyncTarget) -> bool {
        batch.0 == *target
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Self::Error> {
        self.target = batch.0;
        Ok(())
    }

    fn sync_target(&self) -> Self::SyncTarget {
        self.target
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Self::Error> {
        assert!(
            target <= self.target,
            "cannot rewind forward: target {target} above committed {}",
            self.target
        );
        self.target = target;
        Ok(())
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

impl Application<deterministic::Context> for TestApp {
    type SigningScheme = TestScheme;
    type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
    type Block = TestBlock;
    type Databases = TestDatabases;
    type InputProvider = ();

    fn sync_targets(
        block: &Self::Block,
    ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
        block.height().get()
    }

    async fn genesis(&mut self) -> Self::Block {
        TestBlock::new(0, 0)
    }

    async fn propose(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Stream<Item = Self::Block> + Send,
        _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        _input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        None
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        _ancestry: impl Stream<Item = Self::Block> + Send,
        _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
        None
    }

    async fn apply(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
        TestMerkleized(block.height().get())
    }
}

pub(crate) fn test_databases() -> TestDatabases {
    Arc::new(TracedAsyncRwLock::new("test", TestDb::default()))
}

pub(crate) fn anchor(height: u64, digest_byte: u8) -> crate::stateful::db::Anchor<Sha256Digest> {
    crate::stateful::db::Anchor {
        height: Height::new(height),
        round: commonware_consensus::types::Round::new(Epoch::zero(), View::new(height)),
        digest: Sha256Digest::from([digest_byte; 32]),
    }
}
