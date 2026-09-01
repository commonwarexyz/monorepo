//! Marshal custody intake: producer blocks staged through the public mailbox until each is
//! durable.
//!
//! Every staged block travels the router and the catalog's admission path (batching, pending
//! writes, and durability cuts) on the deterministic runtime's in-memory storage, so the
//! measurement is host time spent in marshal rather than disk latency.
//!
//! The timer stops only after the downstream work settles: once every custody token resolves,
//! a short simulated sleep lets the deterministic executor run every task left ready (the
//! router's admitted-block notices and backfill's bookkeeping) before the clock advances. Without
//! it, whether that work lands inside the measured interval depends on the seed-shuffled order of
//! the executor's ready queue.

use bytes::{Buf as _, BufMut};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Reporter,
    multimmit::{
        marshal::{ArchiveConfig, Config, LqcVerifier, Start, Update, open},
        mocks::{
            Committee,
            cluster::{QUOTA, start_network},
        },
        types::{ChainId, Lqc, PathLimits, TransactionBlock},
    },
};
use commonware_cryptography::{
    Digestible, Hasher, Sha256, bls12381::primitives::variant::MinPk,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_resolver::p2p;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{Config as RuntimeConfig, Runner as DeterministicRunner},
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{Acknowledgement as _, NZU16, NZU64, NZUsize, Participant};
use criterion::{Criterion, Throughput, criterion_group};
use futures::future::try_join_all;
use std::{
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};

const PARTICIPANTS: u32 = 6;
const CHAINS: u32 = 4;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MARSHAL_BENCH";
const BLOCKS: usize = 512;
const BODY_BYTES: usize = 1_024;
const RESOLVER_CHANNEL: u64 = 0;
const BROADCAST_CHANNEL: u64 = 1;
const RUNTIME_SEED: u64 = 0x5eed_c0de;
/// Admission cuts the deterministic schedule needs to make every staged block durable.
const ADMISSION_CUTS: u64 = 1;

type Block = TransactionBlock<Sha256, Body>;

/// A fixed-size application body identified by its seed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Body {
    seed: u64,
    payload: [u8; BODY_BYTES],
}

impl Body {
    fn new(seed: u64) -> Self {
        let mut payload = [0u8; BODY_BYTES];
        payload[..u64::SIZE].copy_from_slice(&seed.to_be_bytes());
        Self { seed, payload }
    }
}

impl Write for Body {
    fn write(&self, buf: &mut impl BufMut) {
        self.seed.write(buf);
        buf.put_slice(&self.payload);
    }
}

impl EncodeSize for Body {
    fn encode_size(&self) -> usize {
        u64::SIZE + BODY_BYTES
    }
}

impl Read for Body {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let seed = u64::read(buf)?;
        if buf.remaining() < BODY_BYTES {
            return Err(CodecError::EndOfBuffer);
        }
        let mut payload = [0u8; BODY_BYTES];
        buf.copy_to_slice(&mut payload);
        Ok(Self { seed, payload })
    }
}

impl Digestible for Body {
    type Digest = Sha256Digest;

    fn digest(&self) -> Sha256Digest {
        Sha256::hash(&[&self.seed.to_be_bytes(), &self.payload])
    }
}

/// Accepts every finality proof; the benchmark stages blocks without finalizing them.
#[derive(Clone)]
struct AcceptAll;

impl LqcVerifier<Sha256, MinPk> for AcceptAll {
    type Error = Infallible;

    async fn verify(&mut self, _: &Lqc<MinPk, Sha256Digest>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Acknowledges every delivered block at once.
#[derive(Clone)]
struct Acknowledge;

impl Reporter for Acknowledge {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update {
            acknowledgement, ..
        } = activity;
        acknowledgement.acknowledge();
        Feedback::Ok
    }
}

/// Opens one marshal, stages every block concurrently, and returns the host time until each
/// block is durable custody and the work it triggered has settled.
fn stage_blocks() -> Duration {
    let runtime = DeterministicRunner::new(
        RuntimeConfig::default()
            .with_seed(RUNTIME_SEED)
            .with_timeout(Some(Duration::from_secs(60))),
    );
    runtime.start(|context| async move {
        let committee = Committee::<MinPk>::builder(RUNTIME_SEED, PARTICIPANTS)
            .namespace(NAMESPACE)
            .producers((0..CHAINS).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let chains = committee.codec().chains();
        let blocks = (0..BLOCKS)
            .map(|index| {
                let seed = u64::try_from(index).unwrap();
                let chain = ChainId::new(u32::try_from(index % chains).unwrap());
                let body = Body::new(seed);
                let header = committee.transaction_header(chain, body.digest());
                Arc::new(Block::new(header, body).unwrap())
            })
            .collect::<Vec<_>>();

        let identity = committee.identities[0].clone();
        let oracle = start_network(&context, vec![identity.clone()], 4 * 1024 * 1024).await;
        let control = oracle.control(identity.clone());
        let resolver_network = control.register(RESOLVER_CHANNEL, QUOTA).await.unwrap();
        let broadcast_network = control.register(BROADCAST_CHANNEL, QUOTA).await.unwrap();
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(1024),
                ingress_size: NZUsize!(1024),
                deque_size: 16,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
                blocker: control.clone(),
                strategy: Sequential,
            },
        );
        let broadcast = broadcast_engine.start(broadcast_network);
        let archive = ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(64)),
        );
        let mut config = Config::new(
            Start::Genesis(committee.config.genesis().clone()),
            "multimmit_marshal_bench".into(),
            committee.codec(),
            (),
            archive,
        );
        config.capacities.pending_segment_items = NZU64!(4096);
        let (service, bridge) =
            open::<_, TwoCap, Sha256, MinPk, Body, _>(context.child("marshal"), config, buffer)
                .await
                .unwrap();
        let (resolver_engine, resolver) = p2p::Engine::new(
            context.child("resolver"),
            p2p::Config {
                peer_provider: oracle.manager(),
                blocker: control,
                consumer: bridge.clone(),
                producer: bridge,
                mailbox_size: NZUsize!(1024),
                me: Some(identity),
                timeout: Duration::from_secs(1),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let resolver_handle = resolver_engine.start(resolver_network);
        let (mailbox, mut marshal) = service.start(resolver, AcceptAll, Acknowledge);

        let started = Instant::now();
        let custody = try_join_all(
            blocks
                .iter()
                .map(|block| mailbox.stage_block(Arc::clone(block))),
        )
        .await
        .unwrap();
        try_join_all(custody.into_iter().map(|token| token.wait()))
            .await
            .unwrap();
        // Settle: every task left ready runs before the clock reaches the end of this sleep.
        context.sleep(Duration::from_millis(1)).await;
        let elapsed = started.elapsed();
        let metrics = context.encode();
        let items = counter_total(&metrics, "admission_cut_scheduled_items_total");
        let cuts = counter_total(&metrics, "admission_cut_triggers_total");
        // Storage is in memory, so the timing shows intake CPU only; the cut count shows batching.
        assert_eq!(items, u64::try_from(BLOCKS).unwrap());
        assert_eq!(
            cuts, ADMISSION_CUTS,
            "admission cuts lost batching: {items} items in {cuts} cuts"
        );

        marshal.abort();
        marshal.join().await.unwrap();
        resolver_handle.abort();
        broadcast.abort();
        elapsed
    })
}

/// Returns the total of every sample whose metric name ends with `suffix`.
fn counter_total(metrics: &str, suffix: &str) -> u64 {
    metrics
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (sample, value) = line.rsplit_once(' ')?;
            let name = sample.split_once('{').map_or(sample, |(name, _)| name);
            name.ends_with(suffix)
                .then(|| value.parse::<u64>().ok())
                .flatten()
        })
        .sum()
}

fn bench_stage_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::stage_blocks", module_path!()));
    group.throughput(Throughput::Elements(u64::try_from(BLOCKS).unwrap()));
    group.bench_function(format!("blocks={BLOCKS} body_bytes={BODY_BYTES}"), |b| {
        b.iter_custom(|iterations| (0..iterations).map(|_| stage_blocks()).sum::<Duration>());
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_stage_blocks
}
