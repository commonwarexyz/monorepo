use commonware_consensus::{
    marshal::{
        core::{Actor, Buffer, Mailbox},
        mocks::{application::Application, block::Block},
        resolver::handler::Request,
        standard::Standard,
        store::{Blocks, Certificates},
        Config, Identifier,
    },
    simplex::{
        mocks::scheme as scheme_mocks,
        types::{Activity, Context, Finalization, Finalize, Proposal},
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    Heightable, Reporter,
};
use commonware_cryptography::{
    certificate::ConstantProvider,
    ed25519::PublicKey,
    sha256::{Digest as Sha256Digest, Sha256},
    Digestible, Hasher as _,
};
use commonware_parallel::Sequential;
use commonware_resolver::Resolver;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Clock, Metrics as _, Runner as _, Spawner as _,
};
use commonware_storage::archive::Identifier as ArchiveID;
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
    NZUsize, NZU16, NZU64,
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{Display, Formatter},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

type D = Sha256Digest;
type K = PublicKey;
type Ctx = Context<D, K>;
type B = Block<D, Ctx>;
type V = Standard<B>;
type S = scheme_mocks::Scheme<K>;

const NAMESPACE: &[u8] = b"marshal_bench";
const BLOCKS: u64 = 32;
const VALIDATORS: u32 = 4;
const QUORUM: usize = 3;

#[derive(Clone, Copy)]
enum Workload {
    Finalize,
    InfoLatest,
    BlockLatest,
}

impl Workload {
    const ALL: [Self; 3] = [Self::Finalize, Self::InfoLatest, Self::BlockLatest];

    const fn name(self) -> &'static str {
        match self {
            Self::Finalize => "finalize",
            Self::InfoLatest => "finalize_info_latest",
            Self::BlockLatest => "finalize_block_latest",
        }
    }
}

#[derive(Debug)]
struct SyntheticError;

impl Display for SyntheticError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("synthetic storage error")
    }
}

impl Error for SyntheticError {}

struct SyntheticBlocks {
    context: deterministic::Context,
    latency: Duration,
    by_height: BTreeMap<Height, B>,
    by_digest: BTreeMap<D, Height>,
}

impl SyntheticBlocks {
    fn new(context: deterministic::Context, latency: Duration) -> Self {
        Self {
            context,
            latency,
            by_height: BTreeMap::new(),
            by_digest: BTreeMap::new(),
        }
    }

    async fn delay(&self) {
        self.context.sleep(self.latency).await;
    }
}

impl Blocks for SyntheticBlocks {
    type Block = B;
    type Error = SyntheticError;

    async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
        self.delay().await;
        let height = block.height();
        let digest = block.digest();
        self.by_height.entry(height).or_insert(block);
        self.by_digest.entry(digest).or_insert(height);
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        self.delay().await;
        Ok(())
    }

    async fn get(&self, id: ArchiveID<'_, D>) -> Result<Option<Self::Block>, Self::Error> {
        self.delay().await;
        let block = match id {
            ArchiveID::Index(index) => self.by_height.get(&Height::new(index)).cloned(),
            ArchiveID::Key(digest) => self
                .by_digest
                .get(digest)
                .and_then(|height| self.by_height.get(height))
                .cloned(),
        };
        Ok(block)
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        self.delay().await;
        self.by_height.retain(|height, _| *height >= min);
        self.by_digest.retain(|_, height| *height >= min);
        Ok(())
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        let mut missing = Vec::new();
        let mut next = start.get();
        for height in self.by_height.keys().map(|height| height.get()) {
            if height < next {
                continue;
            }
            while next < height && missing.len() < max {
                missing.push(Height::new(next));
                next += 1;
            }
            if missing.len() == max {
                return missing;
            }
            next = height.saturating_add(1);
        }
        missing
    }

    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        if !self.by_height.contains_key(&value) {
            return (
                None,
                self.by_height
                    .range(value..)
                    .next()
                    .map(|(height, _)| *height),
            );
        }

        let mut end = value;
        while self.by_height.contains_key(&end.next()) {
            end = end.next();
        }
        let next = self
            .by_height
            .range(end.next()..)
            .next()
            .map(|(height, _)| *height);
        (Some(end), next)
    }

    fn last_index(&self) -> Option<Height> {
        self.by_height.keys().next_back().copied()
    }
}

struct SyntheticCertificates {
    context: deterministic::Context,
    latency: Duration,
    by_height: BTreeMap<Height, Finalization<S, D>>,
    by_digest: BTreeMap<D, Height>,
}

impl SyntheticCertificates {
    fn new(context: deterministic::Context, latency: Duration) -> Self {
        Self {
            context,
            latency,
            by_height: BTreeMap::new(),
            by_digest: BTreeMap::new(),
        }
    }

    async fn delay(&self) {
        self.context.sleep(self.latency).await;
    }
}

impl Certificates for SyntheticCertificates {
    type BlockDigest = D;
    type Commitment = D;
    type Scheme = S;
    type Error = SyntheticError;

    async fn put(
        &mut self,
        height: Height,
        digest: Self::BlockDigest,
        finalization: Finalization<Self::Scheme, Self::Commitment>,
    ) -> Result<(), Self::Error> {
        self.delay().await;
        self.by_height.entry(height).or_insert(finalization);
        self.by_digest.entry(digest).or_insert(height);
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        self.delay().await;
        Ok(())
    }

    async fn get(
        &self,
        id: ArchiveID<'_, Self::BlockDigest>,
    ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
        self.delay().await;
        let finalization = match id {
            ArchiveID::Index(index) => self.by_height.get(&Height::new(index)).cloned(),
            ArchiveID::Key(digest) => self
                .by_digest
                .get(digest)
                .and_then(|height| self.by_height.get(height))
                .cloned(),
        };
        Ok(finalization)
    }

    async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
        self.delay().await;
        self.by_height.retain(|height, _| *height >= min);
        self.by_digest.retain(|_, height| *height >= min);
        Ok(())
    }

    fn last_index(&self) -> Option<Height> {
        self.by_height.keys().next_back().copied()
    }

    fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
        let mut ranges = Vec::new();
        let mut current: Option<(Height, Height)> = None;
        for height in self.by_height.range(from..).map(|(height, _)| *height) {
            match current {
                Some((start, end)) if height == end.next() => {
                    current = Some((start, height));
                }
                Some(range) => {
                    ranges.push(range);
                    current = Some((height, height));
                }
                None => current = Some((height, height)),
            }
        }
        if let Some(range) = current {
            ranges.push(range);
        }
        ranges.into_iter()
    }
}

#[derive(Clone, Default)]
struct MemoryBuffer {
    blocks: Arc<Mutex<BTreeMap<D, B>>>,
}

impl MemoryBuffer {
    fn insert(&self, block: B) {
        self.blocks.lock().insert(block.digest(), block);
    }
}

impl Buffer<V> for MemoryBuffer {
    type PublicKey = K;

    async fn find_by_digest(&self, digest: D) -> Option<B> {
        self.blocks.lock().get(&digest).cloned()
    }

    async fn find_by_commitment(&self, commitment: D) -> Option<B> {
        self.find_by_digest(commitment).await
    }

    async fn subscribe_by_digest(&self, _digest: D) -> oneshot::Receiver<B> {
        let (_, rx) = oneshot::channel();
        rx
    }

    async fn subscribe_by_commitment(&self, _commitment: D) -> oneshot::Receiver<B> {
        let (_, rx) = oneshot::channel();
        rx
    }

    async fn finalized(&self, _commitment: D) {}

    async fn send(
        &self,
        _round: Round,
        _block: B,
        _recipients: commonware_p2p::Recipients<Self::PublicKey>,
    ) {
    }
}

#[derive(Clone)]
struct NoopResolver<P> {
    _peer: PhantomData<P>,
}

impl<P> Default for NoopResolver<P> {
    fn default() -> Self {
        Self { _peer: PhantomData }
    }
}

impl Resolver for NoopResolver<K> {
    type Key = Request<D>;
    type PublicKey = K;

    async fn fetch(&mut self, _key: Self::Key) {}

    async fn fetch_all(&mut self, _keys: Vec<Self::Key>) {}

    async fn fetch_targeted(
        &mut self,
        _key: Self::Key,
        _targets: commonware_utils::vec::NonEmptyVec<Self::PublicKey>,
    ) {
    }

    async fn fetch_all_targeted(
        &mut self,
        _requests: Vec<(
            Self::Key,
            commonware_utils::vec::NonEmptyVec<Self::PublicKey>,
        )>,
    ) {
    }

    async fn cancel(&mut self, _key: Self::Key) {}

    async fn clear(&mut self) {}

    async fn retain(&mut self, _predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {}
}

fn make_block(parent: D, height: Height, leader: K) -> B {
    let parent_view = height
        .previous()
        .map(|height| View::new(height.get()))
        .unwrap_or(View::zero());
    let context = Ctx {
        round: Round::new(Epoch::zero(), View::new(height.get())),
        leader,
        parent: (parent_view, parent),
    };
    B::new::<Sha256>(context, parent, height, height.get())
}

fn make_finalization(block: &B, schemes: &[S]) -> Finalization<S, D> {
    let round = Round::new(Epoch::zero(), View::new(block.height().get()));
    let proposal = Proposal::new(
        round,
        block
            .height()
            .previous()
            .map(|height| View::new(height.get()))
            .unwrap_or(View::zero()),
        block.digest(),
    );
    let finalizes: Vec<_> = schemes
        .iter()
        .take(QUORUM)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
        .collect();
    Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
}

async fn start_actor(
    context: deterministic::Context,
    latency: Duration,
    scheme: S,
) -> (Mailbox<S, V>, MemoryBuffer, Application<B>) {
    let config = Config {
        provider: ConstantProvider::new(scheme),
        epocher: FixedEpocher::new(NZU64!(1_000_000)),
        partition_prefix: "marshal-bench".into(),
        mailbox_size: 4096,
        view_retention_timeout: ViewDelta::new(10),
        prunable_items_per_section: NZU64!(1024),
        page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(1024)),
        replay_buffer: NZUsize!(1024),
        key_write_buffer: NZUsize!(1024),
        value_write_buffer: NZUsize!(1024),
        block_codec_config: (),
        max_repair: NZUsize!(32),
        max_pending_acks: NZUsize!(32),
        strategy: Sequential,
    };
    let finalizations =
        SyntheticCertificates::new(context.with_label("synthetic_finalizations"), latency);
    let blocks = SyntheticBlocks::new(context.with_label("synthetic_blocks"), latency);
    let (actor, mailbox, _) = Actor::init(context.clone(), finalizations, blocks, config).await;
    let application = Application::<B>::default();
    let buffer = MemoryBuffer::default();
    let (_resolver_tx, resolver_rx) = mpsc::channel(4096);
    actor.start(
        application.clone(),
        buffer.clone(),
        (resolver_rx, NoopResolver::<K>::default()),
    );
    (mailbox, buffer, application)
}

fn run(latency: Duration, workload: Workload) -> Duration {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xDA5A)
            .with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let start = context.current();
        let fixture = scheme_mocks::fixture(&mut context, NAMESPACE, VALIDATORS);
        let leader = fixture.participants[0].clone();
        let (mailbox, buffer, application) = start_actor(
            context.with_label("actor"),
            latency,
            fixture.schemes[0].clone(),
        )
        .await;
        let mut reporter = mailbox.clone();

        let mut parent = Sha256::hash(b"");
        let mut handles = Vec::new();
        for height in 1..=BLOCKS {
            let block = make_block(parent, Height::new(height), leader.clone());
            parent = block.digest();
            buffer.insert(block.clone());
            let finalization = make_finalization(&block, &fixture.schemes);
            reporter.report(Activity::Finalization(finalization)).await;
            match workload {
                Workload::Finalize => {}
                Workload::InfoLatest => {
                    let mailbox = mailbox.clone();
                    handles.push(context.with_label("get_info").spawn(move |_| async move {
                        let _ = mailbox.get_info(Identifier::Latest).await;
                    }));
                }
                Workload::BlockLatest => {
                    let mailbox = mailbox.clone();
                    handles.push(context.with_label("get_block").spawn(move |_| async move {
                        let _ = mailbox.get_block(Identifier::Latest).await;
                    }));
                }
            }
        }

        while application.blocks().len() < BLOCKS as usize {
            context.sleep(Duration::from_millis(1)).await;
        }
        for handle in handles {
            let _ = handle.await;
        }
        context.current().duration_since(start).unwrap()
    })
}

fn bench_marshal(c: &mut Criterion) {
    for latency in [Duration::from_millis(1), Duration::from_millis(5)] {
        for workload in Workload::ALL {
            let label = format!(
                "{}/workload={} blocks={} disk_ms={}",
                module_path!(),
                workload.name(),
                BLOCKS,
                latency.as_millis(),
            );
            c.bench_function(&label, |b| {
                b.iter_custom(|iters| {
                    let started = Instant::now();
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iters {
                        elapsed += run(latency, workload);
                    }
                    elapsed + started.elapsed()
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_marshal
}
criterion_main!(benches);
