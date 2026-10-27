//! Benchmarks the transfer pipeline on the tokio runtime.
//!
//! In every mode but "cpu", each iteration plans, stages, settles, merkleizes, applies, and commits
//! a batch of random payments against a seeded balance database, then prints its phase latencies
//! and the batch root. The roots must match across these modes for the same arguments. A summary
//! line follows the iterations.
//!
//! Usage:
//!
//! ```text
//! cargo bench -p commonware-glue --bench transfers -- <mode> [iters] [keys] [transfers] \
//!     [threads] [page_cache]
//! ```
//!
//! - mode (required):
//!   - "pipeline" plans and settles on the runtime's strategy pool.
//!   - "sequential" plans and settles on the calling thread.
//!   - "select" runs the proposer's path: touches every key, stages them, applies each payment in
//!     order, and settles the accepted ones on the pool. The plan phase covers the touch, and the
//!     settle phase covers the apply and settle.
//!   - "staged" sums each key's changes in a map, reads every key through `stage`, and settles
//!     each key from the map: the staged API as a caller writes against it without the
//!     pipeline's plan.
//!   - "cpu" times only the plan and settle stages back to back, without a database, on the pool
//!     and on the calling thread.
//! - iters: timed iterations (default 20)
//! - keys: seeded balances (default 1,000,000)
//! - transfers: payments per batch (default 32,768)
//! - threads: strategy pool threads (default 8)
//! - page_cache: page cache capacity in 4096-byte pages (default 131,072 = 512MiB)

use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_glue::transfers::{Account, Change, Plan, Selection, Transfer};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{
    BLOB_PAGE_SIZE, Runner as _, Strategizer as _, Supervisor as _,
    buffer::paged::{CacheRef, page_size},
    tokio::{Config as RConfig, Context, Runner},
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{full, mmb},
    qmdb::{
        any::{FixedConfig, batch::Slot},
        floor::Proportional,
    },
    translator::EightCap,
};
use commonware_utils::{NZU64, NZUsize, TestRng};
use rand::RngExt as _;
use std::{
    collections::HashMap,
    convert::Infallible,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

type Db = commonware_storage::qmdb::any::unordered::fixed::Db<
    mmb::Family,
    Context,
    Digest,
    Balance,
    Sha256,
    EightCap,
    Rayon,
>;
type Merkleized = std::sync::Arc<
    commonware_storage::qmdb::any::batch::MerkleizedBatch<
        mmb::Family,
        Digest,
        commonware_storage::qmdb::any::unordered::fixed::Update<Digest, Balance>,
        Rayon,
    >,
>;

/// Logical page size of the page cache, chosen so each page occupies one blob page on disk.
const PAGE_SIZE: NonZeroU16 = page_size(BLOB_PAGE_SIZE);

/// Default page cache capacity, in pages.
const PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(131_072);

/// Items per blob of the Merkle and operation journals.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);

/// Write buffer size of each journal, in bytes.
const WRITE_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

/// Replay buffer size of each journal, in bytes.
const REPLAY_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

/// Starting balance of every seeded key.
const SEED_BALANCE: u64 = 1_000_000;

/// An account that holds only a balance, encoded as its `u64`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Balance(u64);

impl Account for Balance {
    type Effect = Infallible;

    fn balance(&self) -> u64 {
        self.0
    }

    fn set_balance(&mut self, balance: u64) {
        self.0 = balance;
    }

    fn apply(&mut self, effect: Infallible) -> bool {
        match effect {}
    }
}

impl FixedSize for Balance {
    const SIZE: usize = u64::SIZE;
}

impl Write for Balance {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Balance {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(u64::read(buf)?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Pipeline,
    Sequential,
    Select,
    Staged,
    Cpu,
}

impl Mode {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "pipeline" => Some(Self::Pipeline),
            "sequential" => Some(Self::Sequential),
            "select" => Some(Self::Select),
            "staged" => Some(Self::Staged),
            "cpu" => Some(Self::Cpu),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Pipeline => "pipeline",
            Self::Sequential => "sequential",
            Self::Select => "select",
            Self::Staged => "staged",
            Self::Cpu => "cpu",
        }
    }
}

struct Payment {
    from: Digest,
    to: Digest,
    amount: u64,
}

impl Transfer for Payment {
    type Key = Digest;
    type Account = Balance;

    fn changes(&self) -> impl Iterator<Item = (&Digest, Change)> {
        [
            (&self.from, Change::Debit(self.amount)),
            (&self.to, Change::Credit(self.amount)),
        ]
        .into_iter()
    }
}

fn key(i: u64) -> Digest {
    Sha256::hash(&[&i.to_be_bytes()])
}

fn payments(rng: &mut TestRng, transfers: u64, keys: u64) -> Vec<Payment> {
    (0..transfers)
        .map(|_| Payment {
            from: key(rng.random_range(0..keys)),
            to: key(rng.random_range(0..keys)),
            amount: rng.random_range(1..10),
        })
        .collect()
}

/// The phases of one batch, in microseconds.
#[derive(Clone, Copy, Default)]
struct Phases {
    plan: f64,
    stage: f64,
    settle: f64,
    merkleize: f64,
    apply: f64,
    commit: f64,
}

impl Phases {
    fn total(&self) -> f64 {
        self.plan + self.stage + self.settle + self.merkleize + self.apply + self.commit
    }
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e6
}

/// Plans, stages, settles, and merkleizes `payments` with `strategy`, timing each phase.
async fn pipeline<S: Strategy>(
    db: &Db,
    strategy: &S,
    payments: &[Payment],
    phases: &mut Phases,
) -> Merkleized {
    let start = Instant::now();
    let plan = Plan::new(payments, strategy).expect("debit and credit sums must fit in u64");
    phases.plan = micros(start.elapsed());

    let start = Instant::now();
    let keys: Vec<&Digest> = plan.keys().iter().collect();
    let (reads, staged) = db.new_batch().stage(&keys, db).await.unwrap();
    phases.stage = micros(start.elapsed());

    let start = Instant::now();
    let slots = plan
        .settle(&reads, strategy)
        .expect("seeded balances must afford every payment");
    phases.settle = micros(start.elapsed());

    let start = Instant::now();
    let merkleized = staged
        .merkleize(slots, Vec::new(), None, db, &mut Proportional)
        .await
        .unwrap();
    phases.merkleize = micros(start.elapsed());
    merkleized
}

/// Selects from `payments` as a proposer would: touches the keys, stages them, applies the
/// payments in order, and settles with `strategy`, timing each phase.
async fn select<S: Strategy>(
    db: &Db,
    strategy: &S,
    payments: &[Payment],
    phases: &mut Phases,
) -> Merkleized {
    let start = Instant::now();
    let mut selection = Selection::new();
    let touched = selection.touch(payments);
    phases.plan = micros(start.elapsed());

    let start = Instant::now();
    let keys: Vec<&Digest> = selection.keys()[touched].iter().collect();
    let (reads, staged) = db.new_batch().stage(&keys, db).await.unwrap();
    phases.stage = micros(start.elapsed());

    // Seeded balances afford every payment, so the accepted body is the whole batch and its root
    // must match the pipeline's.
    let start = Instant::now();
    selection.register(&reads);
    let accepted = selection.apply(payments);
    assert!(
        accepted.iter().all(|&accepted| accepted),
        "seeded balances must afford every payment"
    );
    let slots = selection.settle(strategy);
    phases.settle = micros(start.elapsed());

    let start = Instant::now();
    let merkleized = staged
        .merkleize(slots, Vec::new(), None, db, &mut Proportional)
        .await
        .unwrap();
    phases.merkleize = micros(start.elapsed());
    merkleized
}

/// Sums each key's changes in a map, stages every key, and settles each key from the map, timing
/// each phase.
async fn staged(db: &Db, payments: &[Payment], phases: &mut Phases) -> Merkleized {
    // Sum each key's debits and credits in a map whose keys are the distinct keys to stage.
    let start = Instant::now();
    let mut changes: HashMap<Digest, (u64, u64), ahash::RandomState> =
        HashMap::with_capacity_and_hasher(payments.len() * 2, ahash::RandomState::new());
    for payment in payments {
        changes.entry(payment.from).or_default().0 += payment.amount;
        changes.entry(payment.to).or_default().1 += payment.amount;
    }
    let keys: Vec<&Digest> = changes.keys().collect();
    phases.plan = micros(start.elapsed());

    // Read every key's starting balance.
    let start = Instant::now();
    let (balances, staged) = db.new_batch().stage(&keys, db).await.unwrap();
    phases.stage = micros(start.elapsed());

    // Write each changed balance through its slot, deleting balances settled to zero.
    let start = Instant::now();
    let slots: Vec<Slot<Balance>> = keys
        .iter()
        .zip(&balances)
        .map(|(key, balance)| {
            let (debit, credit) = changes[*key];
            let settled = balance.map_or(0, |balance| balance.0) - debit + credit;
            match (settled, balance) {
                (0, Some(_)) => Slot::Delete,
                (0, None) => Slot::Keep,
                (settled, Some(start)) if settled == start.0 => Slot::Keep,
                (settled, _) => Slot::Put(Balance(settled)),
            }
        })
        .collect();
    phases.settle = micros(start.elapsed());

    let start = Instant::now();
    let merkleized = staged
        .merkleize(slots, Vec::new(), None, db, &mut Proportional)
        .await
        .unwrap();
    phases.merkleize = micros(start.elapsed());
    merkleized
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * q) as usize]
}

/// Times planning and settling each batch with `strategy`, returning the median plan and settle
/// latencies in microseconds.
fn cpu_medians<S: Strategy>(strategy: &S, batches: &[Vec<Payment>], balances: u64) -> (f64, f64) {
    let mut plans = Vec::with_capacity(batches.len());
    let mut settles = Vec::with_capacity(batches.len());
    for payments in batches {
        let start = Instant::now();
        let plan = Plan::new(payments, strategy).expect("debit and credit sums must fit in u64");
        plans.push(micros(start.elapsed()));
        let reads = vec![Some(Balance(balances)); plan.len()];

        // Settle once untimed, so the timed run does not pay to pull the plan's output from
        // another core's cache.
        plan.settle(&reads, strategy)
            .expect("balances must afford every payment");

        let start = Instant::now();
        plan.settle(&reads, strategy)
            .expect("balances must afford every payment");
        settles.push(micros(start.elapsed()));
    }
    for values in [&mut plans, &mut settles] {
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    }
    (percentile(&plans, 0.5), percentile(&settles, 0.5))
}

fn main() {
    let raw: Vec<String> = std::env::args().filter(|a| a != "--bench").collect();

    // Run only when given a mode. Blanket harness runs (no positional arguments, or libtest flags
    // such as `--list`) do nothing, so `cargo bench --benches` neither seeds a million keys nor
    // panics on the flags.
    let Some(mode) = raw.get(1) else {
        return;
    };
    if mode.starts_with("--") {
        return;
    }
    let mode =
        Mode::parse(mode).expect("mode must be pipeline, sequential, select, staged, or cpu");
    let iters: usize = raw.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
    let keys: u64 = raw.get(3).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let transfers: u64 = raw.get(4).and_then(|s| s.parse().ok()).unwrap_or(32_768);
    let threads: NonZeroUsize = raw
        .get(5)
        .and_then(|s| s.parse().ok())
        .unwrap_or(NZUsize!(8));
    let page_cache: NonZeroUsize = raw
        .get(6)
        .and_then(|s| s.parse().ok())
        .unwrap_or(PAGE_CACHE_PAGES);
    assert!(
        iters > 0 && keys > 0 && transfers > 0,
        "iters, keys, and transfers must be non-zero"
    );
    eprintln!(
        "transfers mode={} iters={iters} keys={keys} transfers={transfers} threads={threads} page_cache={page_cache}",
        mode.name()
    );

    Runner::new(RConfig::default()).start(|ctx| async move {
        let pc = CacheRef::new(PAGE_SIZE, page_cache);
        let strategy = ctx.strategy(threads);
        if mode == Mode::Cpu {
            // Each iteration plans and settles a distinct batch, so its inputs start out of cache
            // as a new block's would.
            let mut rng = TestRng::new(99);
            let batches: Vec<Vec<Payment>> = (0..iters)
                .map(|_| payments(&mut rng, transfers, keys))
                .collect();
            let (plan, settle) = cpu_medians(&strategy, &batches, SEED_BALANCE);
            let (plan_seq, settle_seq) = cpu_medians(&Sequential, &batches, SEED_BALANCE);
            println!(
                "RESULT mode=cpu keys={keys} transfers={transfers} threads={threads} p50: plan={plan:.0} settle={settle:.0} sequential: plan={plan_seq:.0} settle={settle_seq:.0}"
            );
            return;
        }
        let cfg = FixedConfig {
            merkle_config: full::Config {
                journal_partition: "transfers-merkle-journal".into(),
                metadata_partition: "transfers-merkle-metadata".into(),
                items_per_blob: ITEMS_PER_BLOB,
                write_buffer: WRITE_BUFFER,
                replay_buffer: REPLAY_BUFFER,
                strategy: strategy.clone(),
                page_cache: pc.clone(),
            },
            journal_config: FConfig {
                partition: "transfers-log".into(),
                items_per_blob: ITEMS_PER_BLOB,
                page_cache: pc,
                write_buffer: WRITE_BUFFER,
                replay_buffer: REPLAY_BUFFER,
            },
            translator: EightCap,
            init_cache: Some(NZUsize!(1 << 18)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
        };
        let db = Db::init(ctx.child("db"), cfg, None).await.unwrap();

        // Seed every key with the same balance in one committed batch.
        let seed_start = Instant::now();
        let mut batch = db.new_batch();
        for i in 0..keys {
            batch = batch.write(key(i), Some(Balance(SEED_BALANCE)));
        }
        let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        let db = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        let mut db = db.sync().await.unwrap();
        eprintln!("seeded in {:?}", seed_start.elapsed());

        // Settle, apply, and commit a fresh batch of payments in each iteration.
        let mut rng = TestRng::new(99);
        let mut totals: Vec<f64> = Vec::with_capacity(iters);
        let mut all: Vec<Phases> = Vec::with_capacity(iters);
        for iter in 0..iters {
            let payments = payments(&mut rng, transfers, keys);
            let mut phases = Phases::default();
            let merkleized = match mode {
                Mode::Pipeline => pipeline(&db, &strategy, &payments, &mut phases).await,
                Mode::Sequential => pipeline(&db, &Sequential, &payments, &mut phases).await,
                Mode::Select => select(&db, &strategy, &payments, &mut phases).await,
                Mode::Staged => staged(&db, &payments, &mut phases).await,
                Mode::Cpu => unreachable!("the cpu mode must return before the database opens"),
            };
            let root = merkleized.root();

            let start = Instant::now();
            db = db.apply_batch(merkleized).await.unwrap();
            phases.apply = micros(start.elapsed());
            let start = Instant::now();
            db = db.commit().await.unwrap();
            phases.commit = micros(start.elapsed());

            println!(
                "iter={iter} total_us={:.0} plan={:.0} stage={:.0} settle={:.0} merkleize={:.0} apply={:.0} commit={:.0} root={root}",
                phases.total(),
                phases.plan,
                phases.stage,
                phases.settle,
                phases.merkleize,
                phases.apply,
                phases.commit,
            );
            totals.push(phases.total());
            all.push(phases);
        }

        // Summarize the totals by percentile and each phase by its median.
        totals.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = |select: fn(&Phases) -> f64| {
            let mut values: Vec<f64> = all.iter().map(select).collect();
            values.sort_by(|a, b| a.partial_cmp(b).unwrap());
            percentile(&values, 0.5)
        };
        println!(
            "RESULT mode={} keys={keys} transfers={transfers} threads={threads} p10_us={:.0} p50_us={:.0} mean_us={:.0} max_us={:.0} p50: plan={:.0} stage={:.0} settle={:.0} merkleize={:.0} apply={:.0} commit={:.0}",
            mode.name(),
            percentile(&totals, 0.1),
            percentile(&totals, 0.5),
            totals.iter().sum::<f64>() / totals.len() as f64,
            totals[totals.len() - 1],
            median(|p| p.plan),
            median(|p| p.stage),
            median(|p| p.settle),
            median(|p| p.merkleize),
            median(|p| p.apply),
            median(|p| p.commit),
        );
        db.destroy().await.unwrap();
    });
}
