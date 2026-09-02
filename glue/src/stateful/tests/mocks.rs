use crate::stateful::{
    Application, ExecutionError, Input, Proposed,
    db::{
        DatabaseSet, ManagedDb, Merkleized, MerkleizedOf, Reader, Single, Unmerkleized,
        UnmerkleizedOf, Writer,
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
use commonware_runtime::{Buf, BufMut, Error as RuntimeError, Handle, deterministic};
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{
    cell::RefCell,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(crate) type TestDatabases = Single<TestDb>;
pub(crate) type TestScheme = scheme_mocks::Scheme<ed25519::PublicKey>;
pub(crate) type TestVariant = Standard<TestBlock>;

#[derive(Clone, Copy)]
pub(crate) struct TestUnmerkleized;

#[derive(Clone, Copy)]
pub(crate) struct TestMerkleized;

impl Unmerkleized for TestUnmerkleized {
    type Merkleized = TestMerkleized;
    type Error = Infallible;

    async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
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

/// Signals that pruning has started, then blocks it until the test releases it.
struct PruneGate {
    started: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

/// Signals that a snapshot capture has started, then blocks it until the test releases it.
struct SnapshotGate {
    started: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

thread_local! {
    /// Single-use gate consumed by the next [`TestDb`] snapshot capture. Parks an actor's
    /// startup publish between database recovery and mailbox polling.
    static SNAPSHOT_GATE: RefCell<Option<SnapshotGate>> = const { RefCell::new(None) };
}

/// Shared observer for a gated [`TestDb`]: parked flush releases and recorded
/// prune targets.
#[derive(Clone, Default)]
pub(crate) struct FlushControl {
    pub(crate) flushes: Arc<Mutex<Vec<FlushRelease>>>,
    pub(crate) pruned: Arc<Mutex<Vec<u64>>>,
    pub(crate) applied: Arc<AtomicUsize>,
    prune_gate: Arc<Mutex<Option<PruneGate>>>,
}

impl FlushControl {
    /// Gates the next prune. The receiver reports entry, and sending on the
    /// returned sender lets pruning continue. Only one gate may be active.
    pub(crate) fn gate_prune(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        assert!(
            self.prune_gate
                .lock()
                .replace(PruneGate {
                    started,
                    release: release_rx,
                })
                .is_none(),
            "prune gate already installed",
        );
        (started_rx, release)
    }
}

#[derive(Default)]
pub(crate) struct TestDb {
    sync: Mutex<Option<Handle<()>>>,
    control: Option<FlushControl>,
    finalized: u64,
}

impl TestDb {
    pub(crate) fn with_sync(handle: Handle<()>) -> Self {
        Self {
            sync: Mutex::new(Some(handle)),
            control: None,
            finalized: 0,
        }
    }

    pub(crate) fn gated(control: FlushControl) -> Self {
        Self {
            sync: Mutex::new(None),
            control: Some(control),
            finalized: 0,
        }
    }

    /// Gates the next snapshot capture on this thread. The receiver reports entry, and
    /// sending on the returned sender lets the capture continue.
    pub(crate) fn gate_next_snapshot() -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        SNAPSHOT_GATE.with(|gate| {
            assert!(
                gate.borrow_mut()
                    .replace(SnapshotGate {
                        started,
                        release: release_rx,
                    })
                    .is_none(),
                "snapshot gate already installed",
            );
        });
        (started_rx, release)
    }
}

impl<E: Send> ManagedDb<E> for TestDb {
    type Unmerkleized = TestUnmerkleized;
    type Merkleized = TestMerkleized;
    type Error = Infallible;
    type Config = ();
    type SyncTarget = u64;
    type Snapshot = u64;

    async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
        if let Some(mut gate) = SNAPSHOT_GATE.with(|gate| gate.borrow_mut().take()) {
            gate.started
                .send(())
                .expect("test must await the snapshot gate");
            let _ = (&mut gate.release).await;
        }
        let snapshot = self.finalized;
        Ok((self, snapshot))
    }

    fn initial_sync_target() -> Self::SyncTarget {
        unreachable!("TestDb is constructed directly in tests")
    }

    async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }

    async fn new_batch(_reader: Reader<Self>) -> Self::Unmerkleized {
        TestUnmerkleized
    }

    fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
        true
    }

    async fn apply(mut self, _batch: Self::Merkleized) -> Result<Self, Self::Error> {
        self.finalized += 1;
        if let Some(control) = &self.control {
            control.applied.fetch_add(1, Ordering::Relaxed);
        }
        Ok(self)
    }

    async fn finalize(self) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
        let snapshot = self.finalized;
        if let Some(control) = &self.control {
            let (release, released) = oneshot::channel();
            control.flushes.lock().push(release);
            return Ok((self, snapshot, Handle::from_receiver(released)));
        }
        let handle = self
            .sync
            .lock()
            .take()
            .unwrap_or_else(|| Handle::ready(Ok(())));
        Ok((self, snapshot, handle))
    }

    async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Self::Error> {
        if let Some(control) = &self.control {
            let gate = control.prune_gate.lock().take();
            if let Some(mut gate) = gate {
                gate.started.send(()).expect("test must await prune");
                let _ = (&mut gate.release).await;
            }
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

    pub(crate) fn child(parent: &Self, digest_byte: u8) -> Self {
        let height = parent.height.next();
        Self {
            context: SimplexContext {
                round: commonware_consensus::types::Round::new(
                    Epoch::zero(),
                    View::new(height.get()),
                ),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (parent.context.round.view(), parent.digest),
            },
            height,
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
        self.context.parent.1
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
        _batches: UnmerkleizedOf<Self::Databases, E>,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Result<Option<Proposed<Self, E>>, ExecutionError> {
        Ok(None)
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> Result<Option<MerkleizedOf<Self::Databases, E>>, ExecutionError> {
        Ok(None)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> Result<MerkleizedOf<Self::Databases, E>, ExecutionError> {
        Ok(TestMerkleized)
    }
}

pub(crate) fn test_databases() -> TestDatabases {
    TestDb::default().into()
}

/// Finalize `batch` through the cell, returning the snapshot and flush handle.
pub(crate) async fn apply_and_finalize<D: ManagedDb<deterministic::Context>>(
    writer: Writer<D>,
    batch: D::Merkleized,
) -> (Writer<D>, D::Snapshot, Handle<()>) {
    let (writer, (snapshot, handle)) = writer
        .mutate(|db| async move {
            let db = D::apply(db, batch)
                .await
                .unwrap_or_else(|err| panic!("apply failed: {err:?}"));
            let (db, snapshot, handle) = D::finalize(db)
                .await
                .unwrap_or_else(|err| panic!("finalize failed: {err:?}"));
            (db, (snapshot, handle))
        })
        .await;
    (writer, snapshot, handle)
}

pub(crate) fn anchor(height: u64, digest_byte: u8) -> crate::stateful::db::Anchor<Sha256Digest> {
    crate::stateful::db::Anchor {
        height: Height::new(height),
        round: commonware_consensus::types::Round::new(Epoch::zero(), View::new(height)),
        digest: Sha256Digest::from([digest_byte; 32]),
    }
}
