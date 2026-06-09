//! Constantinople-shape harness: load+write+merkleize at 32k updates / 1M keys.
//!
//! Times the full per-block state pipeline (get_many load, batch writes, merkleize, root) on the
//! tokio runtime against `any::unordered::fixed::Db<mmr>` with EightCap, matching the production
//! validator shape. Prints per-iteration latency and the speculative root (a cross-binary parity
//! check: any optimization must reproduce identical roots).
//!
//! Usage:
//!   cargo bench -p commonware-storage --bench merkbench -- [mode] [depth] [iters] [keys] [updates]
//!
//! - mode: "plain" or "fused" (identical since reads always retain resolved locations; both
//!   accepted for output compatibility with older binaries)
//! - depth: number of pending ancestor batches under the timed batch (0 or 1)
//! - iters: timed iterations (default 15)
//! - keys: total seeded keys (default 1,000,000)
//! - updates: keys written per batch (default 32,768)

use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Rayon;
use commonware_runtime::{
    buffer::paged::CacheRef,
    tokio::{Config as RConfig, Context, Runner},
    Runner as _, Supervisor as _, ThreadPooler as _,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{full, mmr},
    qmdb::any::FixedConfig,
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    hint::black_box,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Instant,
};

type Digest = <Sha256 as Hasher>::Digest;
type Db = commonware_storage::qmdb::any::unordered::fixed::Db<
    mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type Merkleized = std::sync::Arc<
    commonware_storage::qmdb::any::batch::MerkleizedBatch<
        mmr::Family,
        Digest,
        commonware_storage::qmdb::any::unordered::fixed::Update<Digest, Digest>,
        Rayon,
    >,
>;

const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
// 512MB page cache, the production validator config (active window fully warm).
const PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(131_072);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const THREADS: NonZeroUsize = NZUsize!(8);
const CHURN_BATCHES: u64 = 4;

fn key(i: u64) -> Digest {
    Sha256::hash(&i.to_be_bytes())
}

fn gen_muts(rng: &mut StdRng, num_updates: u64, num_keys: u64) -> Vec<(Digest, Digest)> {
    (0..num_updates)
        .map(|_| {
            let idx = rng.next_u64() % num_keys;
            (key(idx), Sha256::hash(&rng.next_u32().to_be_bytes()))
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().filter(|a| a != "--bench").collect();
    let mode = args.get(1).cloned().unwrap_or_else(|| "fused".into());
    let depth: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let iters: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15);
    let num_keys: u64 = args
        .get(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let num_updates: u64 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(32_768);
    assert!(mode == "plain" || mode == "fused", "mode: plain|fused");

    eprintln!(
        "merkbench mode={mode} depth={depth} iters={iters} keys={num_keys} updates={num_updates}"
    );

    Runner::new(RConfig::default()).start(|ctx| async move {
        let pc = CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_PAGES);
        let cfg = FixedConfig {
            merkle_config: full::Config {
                journal_partition: "merkbench-merkle-journal".into(),
                metadata_partition: "merkbench-merkle-metadata".into(),
                items_per_blob: ITEMS_PER_BLOB,
                write_buffer: WRITE_BUFFER,
                strategy: ctx.create_strategy(THREADS).unwrap(),
                page_cache: pc.clone(),
            },
            journal_config: FConfig {
                partition: "merkbench-log".into(),
                items_per_blob: ITEMS_PER_BLOB,
                page_cache: pc,
                write_buffer: WRITE_BUFFER,
            },
            translator: EightCap,
        };
        let mut db = Db::init(ctx.child("db"), cfg).await.unwrap();

        // Seed all keys in one committed batch.
        let seed_start = Instant::now();
        let mut rng = StdRng::seed_from_u64(42);
        let mut batch = db.new_batch();
        for i in 0..num_keys {
            batch = batch.write(key(i), Some(Sha256::hash(&rng.next_u32().to_be_bytes())));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Churn: overwrite batches so inactive ops accumulate above the floor.
        for _ in 0..CHURN_BATCHES {
            let mut batch = db.new_batch();
            for (k, v) in gen_muts(&mut rng, num_updates, num_keys) {
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
        db.commit().await.unwrap();
        db.sync().await.unwrap();
        eprintln!("seed+churn done in {:?}", seed_start.elapsed());

        let mut rng = StdRng::seed_from_u64(99);
        let mut times_ms: Vec<f64> = Vec::with_capacity(iters);
        for iter in 0..iters {
            // Pending ancestors are rebuilt per iteration and never applied (untimed).
            let mut parent: Option<Merkleized> = None;
            for _ in 0..depth {
                let mut b = match &parent {
                    None => db.new_batch(),
                    Some(p) => p.new_batch::<Sha256>(),
                };
                for (k, v) in gen_muts(&mut rng, num_updates, num_keys) {
                    b = b.write(k, Some(v));
                }
                parent = Some(b.merkleize(&db, None).await.unwrap());
            }

            let muts = gen_muts(&mut rng, num_updates, num_keys);
            let keys: Vec<&Digest> = muts.iter().map(|(k, _)| k).collect();
            let new_batch = || match &parent {
                None => db.new_batch(),
                Some(p) => p.new_batch::<Sha256>(),
            };

            // Timed: load all touched keys, write them, merkleize, read root. Reads retain
            // resolved locations on the batch, so merkleize skips re-reading those keys. Load
            // and writes must share one batch for that retention to apply.
            let start = Instant::now();
            let mut b = new_batch();
            let values = b.get_many(&keys, &db).await.unwrap();
            black_box(&values);
            for (k, v) in &muts {
                b = b.write(*k, Some(*v));
            }
            let merkleized = b.merkleize(&db, None).await.unwrap();
            let root = merkleized.root();
            let elapsed = start.elapsed();

            times_ms.push(elapsed.as_secs_f64() * 1000.0);
            println!("iter={iter} ms={:.2} root={root}", times_ms[iter]);
        }

        times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p = |q: f64| times_ms[((times_ms.len() - 1) as f64 * q) as usize];
        let mean: f64 = times_ms.iter().sum::<f64>() / times_ms.len() as f64;
        println!(
            "RESULT mode={mode} depth={depth} p10={:.2} p50={:.2} mean={:.2} max={:.2}",
            p(0.1),
            p(0.5),
            mean,
            times_ms[times_ms.len() - 1]
        );

        db.destroy().await.unwrap();
    });
}
