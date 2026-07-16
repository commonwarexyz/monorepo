//! Gungraun benchmark for speculative batch merkleization.
//!
//! Reuses the criterion [`merkleize`] module's workloads and variant dispatch,
//! selecting a subset of variants for callgrind tracking.

use crate::{
    common::Digest,
    merkleize::{
        any_fix_cfg_with_cache, cur_fix_cfg_with_cache, AnyUFix, BenchOptions, CurOFix256Mmb,
        MerkleizeWorkload, Variant, LARGE_PAGE_CACHE_SIZE, PAGE_SIZE,
    },
};
use commonware_runtime::{
    buffer::paged::CacheRef,
    tokio::{Config, Context, Runner},
    Runner as _, Supervisor as _,
};
use commonware_storage::merkle::mmr::Family as MmrFamily;
use gungraun::{library_benchmark, library_benchmark_group};

const ANY_UNORDERED_FIXED_MMR: BenchOptions = BenchOptions {
    variant: Variant::AnyFixed,
    num_keys: 10_000,
    chained: false,
    seed_sync: true,
    clear_cache: true,
};

const CURRENT_ORDERED_FIXED_MMB_CHUNK_256: BenchOptions = BenchOptions {
    variant: Variant::CurrentOrderedFixed256Mmb,
    num_keys: 10_000,
    chained: false,
    seed_sync: true,
    clear_cache: true,
};

async fn run(context: Context, options: BenchOptions) -> Digest {
    match options.variant {
        Variant::AnyFixed => {
            let metrics_context = context.child("metrics");
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, LARGE_PAGE_CACHE_SIZE);
            let cfg = any_fix_cfg_with_cache(&context, page_cache.clone());
            let db = AnyUFix::init(context.child("storage"), cfg).await.unwrap();
            options
                .benchmark()
                .gungraun(MerkleizeWorkload::<MmrFamily, _>::new(
                    metrics_context,
                    db,
                    page_cache,
                    options,
                    |parent| parent.new_batch(),
                ))
                .await
        }
        Variant::CurrentOrderedFixed256Mmb => {
            let metrics_context = context.child("metrics");
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, LARGE_PAGE_CACHE_SIZE);
            let cfg = cur_fix_cfg_with_cache(&context, page_cache.clone());
            let db = CurOFix256Mmb::init(context.child("storage"), cfg)
                .await
                .unwrap();
            options
                .benchmark()
                .gungraun(MerkleizeWorkload::<
                    commonware_storage::merkle::mmb::Family,
                    _,
                >::new(
                    metrics_context,
                    db,
                    page_cache,
                    options,
                    |parent| parent.new_batch(),
                ))
                .await
        }
        _ => unreachable!("benchmark-tracking config only selects registered QMDB variants"),
    }
}

#[library_benchmark]
#[bench::any_unordered_fixed_mmr(args = (ANY_UNORDERED_FIXED_MMR))]
#[bench::current_ordered_fixed_mmb_chunk_256(args = (CURRENT_ORDERED_FIXED_MMB_CHUNK_256))]
fn bench_merkleize(options: BenchOptions) -> Digest {
    Runner::new(Config::default()).start(|context| run(context, options))
}

library_benchmark_group!(
    name = qmdb_merkleize;
    benchmarks = bench_merkleize
);
