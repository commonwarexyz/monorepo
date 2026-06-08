//! Gungraun benchmark entry point for tracked QMDB benchmarks.

use common::Digest;
use commonware_runtime::{
    tokio::{Config, Context, Runner},
    Runner as _, Supervisor as _,
};
use commonware_storage::{
    merkle,
    qmdb::any::traits::{DbAny, MerkleizedBatch},
};
use gungraun::{
    library_benchmark, library_benchmark_group, main, Callgrind, EntryPoint, LibraryBenchmarkConfig,
};
use merkleize_workload::{
    any_fix_cfg, cur_fix_cfg, prepare_db, run_bench_once, run_chained_bench_once, AnyUFix,
    CurOFix256Mmb, Variant, LARGE_PAGE_CACHE_SIZE, TRACKED_NUM_KEYS,
};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

#[allow(dead_code, unused_imports, unused_macros)]
mod common;
#[allow(dead_code, unused_imports, unused_macros)]
mod merkleize_workload;

fn toggle_collection() {
    gungraun::client_requests::callgrind::toggle_collect();
}

async fn run_single_merkleize<F, C>(mut db: C, seed_sync: bool) -> Digest
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    C::Merkleized: MerkleizedBatch<Digest = Digest>,
{
    prepare_db::<F, _>(&mut db, TRACKED_NUM_KEYS, seed_sync).await;

    let mut rng = StdRng::seed_from_u64(99);
    toggle_collection();
    let merkleized = run_bench_once::<F, _>(&db, TRACKED_NUM_KEYS, &mut rng).await;
    let root = merkleized.root();
    toggle_collection();

    db.destroy().await.unwrap();
    black_box(root)
}

async fn run_chained_merkleize<F, C, Fork>(mut db: C, seed_sync: bool, fork_child: Fork) -> Digest
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    C::Merkleized: MerkleizedBatch<Digest = Digest>,
    Fork: Fn(&C::Merkleized) -> C::Batch,
{
    prepare_db::<F, _>(&mut db, TRACKED_NUM_KEYS, seed_sync).await;

    let mut rng = StdRng::seed_from_u64(99);
    let parent = run_bench_once::<F, _>(&db, TRACKED_NUM_KEYS, &mut rng).await;

    toggle_collection();
    let child =
        run_chained_bench_once::<F, _, _>(&db, &parent, TRACKED_NUM_KEYS, &mut rng, &fork_child)
            .await;
    let root = child.root();
    toggle_collection();

    db.destroy().await.unwrap();
    black_box(root)
}

async fn run_variant(context: Context, variant: Variant) -> Digest {
    match variant {
        Variant::AnyFixed => {
            let cfg = any_fix_cfg(&context, LARGE_PAGE_CACHE_SIZE);
            let db = AnyUFix::init(context.child("storage"), cfg).await.unwrap();
            run_single_merkleize::<commonware_storage::merkle::mmr::Family, _>(db, false).await
        }
        Variant::CurrentOrderedFixed256Mmb => {
            let cfg = cur_fix_cfg(&context, LARGE_PAGE_CACHE_SIZE);
            let db = CurOFix256Mmb::init(context.child("storage"), cfg)
                .await
                .unwrap();
            run_chained_merkleize::<commonware_storage::merkle::mmb::Family, _, _>(
                db,
                false,
                |parent| parent.new_batch(),
            )
            .await
        }
        _ => unreachable!("Gungraun tracking only registers the two tracked variants"),
    }
}

#[library_benchmark]
#[bench::any_unordered_fixed_mmr(args = (Variant::AnyFixed))]
#[bench::current_ordered_fixed_mmb_chunk_256(args = (Variant::CurrentOrderedFixed256Mmb))]
fn bench_merkleize(variant: Variant) -> Digest {
    Runner::new(Config::default()).start(|context| run_variant(context, variant))
}

library_benchmark_group!(
    name = qmdb_merkleize;
    benchmarks = bench_merkleize
);

main!(
    config = LibraryBenchmarkConfig::default().tool(
        Callgrind::with_args(["--collect-atstart=no", "--cache-sim=yes"])
            .entry_point(EntryPoint::None),
    );
    library_benchmark_groups = qmdb_merkleize
);
