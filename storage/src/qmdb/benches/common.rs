//! Shared infrastructure for QMDB benchmarks: constants, config builders, type aliases, dispatch
//! macros, and the common `gen_random_kv` helper.

use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Rayon;
use commonware_runtime::{buffer::paged::CacheRef, tokio::Context, BufferPooler, ThreadPooler};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{self, full::Config as MerkleConfig, Family},
    qmdb::{
        any::{
            ordered::{fixed::Db as OFixed, variable::Db as OVariable},
            traits::{DbAny, UnmerkleizedBatch},
            unordered::{fixed::Db as UFixed, variable::Db as UVariable},
            FixedConfig as AnyFixedConfig, VariableConfig as AnyVariableConfig,
        },
        current::{
            ordered::{fixed::Db as OCFixed, variable::Db as OCVariable},
            unordered::{fixed::Db as UCFixed, variable::Db as UCVariable},
            FixedConfig as CurrentFixedConfig, VariableConfig as CurrentVariableConfig,
        },
        keyless::variable::{Config as KeylessConfig, Db as Keyless},
    },
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

pub type Digest = <Sha256 as Hasher>::Digest;

pub const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
pub const CHUNK_SIZE: usize = 32;
pub const THREADS: NonZeroUsize = NZUsize!(8);
pub const PAGE_SIZE: NonZeroU16 = NZU16!(16384);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);
pub const DELETE_FREQUENCY: u32 = 10;
pub const VARIABLE_VALUE_MAX_LEN: usize = 256;
pub const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

// -- Fixed value (Digest), fixed storage layout --

pub type AnyUFixDb<F> = UFixed<F, Context, Digest, Digest, Sha256, EightCap, Rayon>;
pub type AnyOFixDb<F> = OFixed<F, Context, Digest, Digest, Sha256, EightCap, Rayon>;
pub type CurUFixDb<F> = UCFixed<F, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;
pub type CurOFixDb<F> = OCFixed<F, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;

// -- Fixed value (Digest), variable storage layout --
// Measures overhead of variable-capable storage when values are fixed-size.

pub type AnyUVarDigestDb<F> = UVariable<F, Context, Digest, Digest, Sha256, EightCap, Rayon>;
pub type AnyOVarDigestDb<F> = OVariable<F, Context, Digest, Digest, Sha256, EightCap, Rayon>;
pub type CurUVarDigestDb<F> =
    UCVariable<F, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;
pub type CurOVarDigestDb<F> =
    OCVariable<F, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;

// -- Variable value (Vec<u8>), variable storage layout --

pub type AnyUVarVecDb<F> = UVariable<F, Context, Digest, Vec<u8>, Sha256, EightCap, Rayon>;
pub type AnyOVarVecDb<F> = OVariable<F, Context, Digest, Vec<u8>, Sha256, EightCap, Rayon>;
pub type CurUVarVecDb<F> =
    UCVariable<F, Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE, Rayon>;
pub type CurOVarVecDb<F> =
    OCVariable<F, Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE, Rayon>;

// -- Keyless --

pub type KeylessDb<F> = Keyless<F, Context, Vec<u8>, Sha256, Rayon>;

pub async fn open_keyless_db<F: Family>(ctx: Context) -> KeylessDb<F> {
    let cfg = keyless_cfg(&ctx);
    KeylessDb::<F>::init(ctx, cfg).await.unwrap()
}

// -- Config builders --

const PARTITION_FIX: &str = "bench-fixed";
const PARTITION_VAR: &str = "bench-variable";
const PARTITION_KEYLESS: &str = "bench-keyless";

fn merkle_cfg(
    suffix: &str,
    ctx: &(impl BufferPooler + ThreadPooler),
    page_cache: CacheRef,
) -> MerkleConfig<Rayon> {
    MerkleConfig {
        journal_partition: format!("journal-{suffix}"),
        metadata_partition: format!("metadata-{suffix}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        strategy: ctx.create_strategy(THREADS).unwrap(),
        page_cache,
    }
}

fn fix_log_cfg(suffix: &str, page_cache: CacheRef) -> FConfig {
    FConfig {
        partition: format!("log-journal-{suffix}"),
        items_per_blob: ITEMS_PER_BLOB,
        page_cache,
        write_buffer: WRITE_BUFFER_SIZE,
    }
}

fn var_log_cfg<C>(suffix: &str, page_cache: CacheRef, codec_config: C) -> VConfig<C> {
    VConfig {
        partition: format!("log-journal-{suffix}"),
        items_per_section: ITEMS_PER_BLOB,
        compression: None,
        codec_config,
        page_cache,
        write_buffer: WRITE_BUFFER_SIZE,
    }
}

pub fn any_fix_cfg(ctx: &(impl BufferPooler + ThreadPooler)) -> AnyFixedConfig<EightCap, Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    AnyFixedConfig {
        merkle_config: merkle_cfg(PARTITION_FIX, ctx, page_cache.clone()),
        journal_config: fix_log_cfg(PARTITION_FIX, page_cache),
        translator: EightCap,
    }
}

pub fn cur_fix_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> CurrentFixedConfig<EightCap, Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    CurrentFixedConfig {
        merkle_config: merkle_cfg(PARTITION_FIX, ctx, page_cache.clone()),
        journal_config: fix_log_cfg(PARTITION_FIX, page_cache),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION_FIX}"),
        translator: EightCap,
    }
}

pub fn any_var_digest_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> AnyVariableConfig<EightCap, ((), ()), Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    AnyVariableConfig {
        merkle_config: merkle_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ())),
        translator: EightCap,
    }
}

pub fn cur_var_digest_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> CurrentVariableConfig<EightCap, ((), ()), Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    CurrentVariableConfig {
        merkle_config: merkle_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ())),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION_VAR}"),
        translator: EightCap,
    }
}

/// Codec config for variable-length `Vec<u8>` values.
type VarVecCfg = ((), (commonware_codec::RangeCfg<usize>, ()));

pub fn any_var_vec_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> AnyVariableConfig<EightCap, VarVecCfg, Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    AnyVariableConfig {
        merkle_config: merkle_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ((0..=10000).into(), ()))),
        translator: EightCap,
    }
}

pub fn cur_var_vec_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> CurrentVariableConfig<EightCap, VarVecCfg, Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    CurrentVariableConfig {
        merkle_config: merkle_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ((0..=10000).into(), ()))),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION_VAR}"),
        translator: EightCap,
    }
}

pub fn keyless_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> KeylessConfig<(commonware_codec::RangeCfg<usize>, ()), Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    KeylessConfig {
        merkle: merkle_cfg(PARTITION_KEYLESS, ctx, page_cache.clone()),
        log: var_log_cfg(PARTITION_KEYLESS, page_cache, ((0..=10000).into(), ())),
    }
}

// -- Shared variant definitions --

macro_rules! define_db_variants {
    (
        enum $enum_name:ident;
        const $variants_name:ident;
        dispatch $dispatch_name:ident;
        timed_dispatch $timed_dispatch_name:ident;
        entries = [
            $(
                {
                    entry: $entry:ident,
                    name: $name:literal,
                    db: $db:ty,
                    cfg: $cfg:path,
                }
            )+
        ];
    ) => {
        #[derive(Debug, Clone, Copy)]
        enum $enum_name {
            $($entry),+
        }

        impl $enum_name {
            const fn name(self) -> &'static str {
                match self {
                    $(Self::$entry => $name),+
                }
            }
        }

        const $variants_name: &[$enum_name] = &[$($enum_name::$entry),+];

        macro_rules! $dispatch_name {
            ($ctx_expr:expr, $variant_expr:expr, |$db_name:ident| $body:expr) => {
                match $variant_expr {
                    $(
                        $enum_name::$entry => {
                            let ctx = $ctx_expr;
                            let cfg = $cfg(&ctx);
                            #[allow(unused_mut)]
                            let mut $db_name = <$db>::init(ctx.clone(), cfg).await.unwrap();
                            $body
                        }
                    )+
                }
            };
        }

        #[allow(unused_macros)]
        macro_rules! $timed_dispatch_name {
            ($ctx_expr:expr, $variant_expr:expr, $iters:expr, |$db_name:ident| $body:expr) => {
                match $variant_expr {
                    $(
                        $enum_name::$entry => {
                            let ctx = $ctx_expr;
                            let cfg = $cfg(&ctx);
                            let start = std::time::Instant::now();
                            for _ in 0..$iters {
                                #[allow(unused_mut)]
                                let mut $db_name =
                                    <$db>::init(ctx.clone(), cfg.clone()).await.unwrap();
                                $body
                            }
                            start.elapsed()
                        }
                    )+
                }
            };
        }
    };
}

pub(crate) use define_db_variants;

macro_rules! define_fixed_variants {
    (
        enum $enum_name:ident;
        const $variants_name:ident;
        dispatch $dispatch_name:ident;
        timed_dispatch $timed_dispatch_name:ident;
    ) => {
        $crate::common::define_db_variants! {
            enum $enum_name;
            const $variants_name;
            dispatch $dispatch_name;
            timed_dispatch $timed_dispatch_name;
            entries = [
                {
                    entry: AnyUnorderedFixedMmr,
                    name: "any::unordered::fixed::mmr",
                    db: $crate::common::AnyUFixDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::any_fix_cfg,
                }
                {
                    entry: AnyUnorderedFixedMmb,
                    name: "any::unordered::fixed::mmb",
                    db: $crate::common::AnyUFixDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::any_fix_cfg,
                }
                {
                    entry: AnyOrderedFixedMmr,
                    name: "any::ordered::fixed::mmr",
                    db: $crate::common::AnyOFixDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::any_fix_cfg,
                }
                {
                    entry: AnyOrderedFixedMmb,
                    name: "any::ordered::fixed::mmb",
                    db: $crate::common::AnyOFixDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::any_fix_cfg,
                }
                {
                    entry: AnyUnorderedVariableMmr,
                    name: "any::unordered::variable::mmr",
                    db: $crate::common::AnyUVarDigestDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::any_var_digest_cfg,
                }
                {
                    entry: AnyUnorderedVariableMmb,
                    name: "any::unordered::variable::mmb",
                    db: $crate::common::AnyUVarDigestDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::any_var_digest_cfg,
                }
                {
                    entry: AnyOrderedVariableMmr,
                    name: "any::ordered::variable::mmr",
                    db: $crate::common::AnyOVarDigestDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::any_var_digest_cfg,
                }
                {
                    entry: AnyOrderedVariableMmb,
                    name: "any::ordered::variable::mmb",
                    db: $crate::common::AnyOVarDigestDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::any_var_digest_cfg,
                }
                {
                    entry: CurrentUnorderedFixedMmr,
                    name: "current::unordered::fixed::mmr",
                    db: $crate::common::CurUFixDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::cur_fix_cfg,
                }
                {
                    entry: CurrentUnorderedFixedMmb,
                    name: "current::unordered::fixed::mmb",
                    db: $crate::common::CurUFixDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::cur_fix_cfg,
                }
                {
                    entry: CurrentOrderedFixedMmr,
                    name: "current::ordered::fixed::mmr",
                    db: $crate::common::CurOFixDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::cur_fix_cfg,
                }
                {
                    entry: CurrentOrderedFixedMmb,
                    name: "current::ordered::fixed::mmb",
                    db: $crate::common::CurOFixDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::cur_fix_cfg,
                }
                {
                    entry: CurrentUnorderedVariableMmr,
                    name: "current::unordered::variable::mmr",
                    db: $crate::common::CurUVarDigestDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::cur_var_digest_cfg,
                }
                {
                    entry: CurrentUnorderedVariableMmb,
                    name: "current::unordered::variable::mmb",
                    db: $crate::common::CurUVarDigestDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::cur_var_digest_cfg,
                }
                {
                    entry: CurrentOrderedVariableMmr,
                    name: "current::ordered::variable::mmr",
                    db: $crate::common::CurOVarDigestDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::cur_var_digest_cfg,
                }
                {
                    entry: CurrentOrderedVariableMmb,
                    name: "current::ordered::variable::mmb",
                    db: $crate::common::CurOVarDigestDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::cur_var_digest_cfg,
                }
            ];
        }
    };
}

pub(crate) use define_fixed_variants;

macro_rules! define_vec_variants {
    (
        enum $enum_name:ident;
        const $variants_name:ident;
        dispatch $dispatch_name:ident;
        timed_dispatch $timed_dispatch_name:ident;
    ) => {
        $crate::common::define_db_variants! {
            enum $enum_name;
            const $variants_name;
            dispatch $dispatch_name;
            timed_dispatch $timed_dispatch_name;
            entries = [
                {
                    entry: AnyUnorderedMmr,
                    name: "any::unordered::variable-vec::mmr",
                    db: $crate::common::AnyUVarVecDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::any_var_vec_cfg,
                }
                {
                    entry: AnyUnorderedMmb,
                    name: "any::unordered::variable-vec::mmb",
                    db: $crate::common::AnyUVarVecDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::any_var_vec_cfg,
                }
                {
                    entry: AnyOrderedMmr,
                    name: "any::ordered::variable-vec::mmr",
                    db: $crate::common::AnyOVarVecDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::any_var_vec_cfg,
                }
                {
                    entry: AnyOrderedMmb,
                    name: "any::ordered::variable-vec::mmb",
                    db: $crate::common::AnyOVarVecDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::any_var_vec_cfg,
                }
                {
                    entry: CurrentUnorderedMmr,
                    name: "current::unordered::variable-vec::mmr",
                    db: $crate::common::CurUVarVecDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::cur_var_vec_cfg,
                }
                {
                    entry: CurrentUnorderedMmb,
                    name: "current::unordered::variable-vec::mmb",
                    db: $crate::common::CurUVarVecDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::cur_var_vec_cfg,
                }
                {
                    entry: CurrentOrderedMmr,
                    name: "current::ordered::variable-vec::mmr",
                    db: $crate::common::CurOVarVecDb<commonware_storage::merkle::mmr::Family>,
                    cfg: $crate::common::cur_var_vec_cfg,
                }
                {
                    entry: CurrentOrderedMmb,
                    name: "current::ordered::variable-vec::mmb",
                    db: $crate::common::CurOVarVecDb<commonware_storage::merkle::mmb::Family>,
                    cfg: $crate::common::cur_var_vec_cfg,
                }
            ];
        }
    };
}

pub(crate) use define_vec_variants;

// -- Data generation --

/// Seed a database with `num_elements` entries, then perform `num_operations` random
/// updates/deletes. Commits periodically when `commit_frequency` is `Some`.
pub async fn gen_random_kv<F, M>(
    db: &mut M,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
    make_value: impl Fn(&mut StdRng) -> M::Value,
) where
    F: Family,
    M: DbAny<F, Key = Digest>,
{
    let mut rng = StdRng::seed_from_u64(42);

    // Seed the db with `num_elements` entries.
    {
        let mut batch = db.new_batch();
        for i in 0u64..num_elements {
            let k = Sha256::hash(&i.to_be_bytes());
            batch = batch.write(k, Some(make_value(&mut rng)));
        }
        let merkleized = batch.merkleize(db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
    }

    // Perform `num_operations` random updates/deletes, committing periodically.
    {
        let mut batch = db.new_batch();
        for _ in 0u64..num_operations {
            let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % DELETE_FREQUENCY == 0 {
                batch = batch.write(rand_key, None);
                continue;
            }
            batch = batch.write(rand_key, Some(make_value(&mut rng)));
            if let Some(freq) = commit_frequency {
                if rng.next_u32() % freq == 0 {
                    let merkleized = batch.merkleize(db, None).await.unwrap();
                    db.apply_batch(merkleized).await.unwrap();
                    batch = db.new_batch();
                }
            }
        }
        let merkleized = batch.merkleize(db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
    }
}

/// Generate a fixed-size digest value.
pub fn make_fixed_value(rng: &mut StdRng) -> Digest {
    Sha256::hash(&rng.next_u32().to_be_bytes())
}

/// Pre-populate the database with `num_keys` unique keys, then commit.
pub async fn seed_db<F: merkle::Family, C: DbAny<F, Key = Digest, Value = Digest>>(
    db: &mut C,
    num_keys: u64,
) {
    let mut rng = StdRng::seed_from_u64(42);
    let mut batch = db.new_batch();
    for i in 0u64..num_keys {
        let k = Sha256::hash(&i.to_be_bytes());
        batch = batch.write(k, Some(make_fixed_value(&mut rng)));
    }
    let merkleized = batch.merkleize(db, None).await.unwrap();
    db.apply_batch(merkleized).await.unwrap();
    db.commit().await.unwrap();
}

/// Write `num_updates` random key updates into a batch.
pub fn write_random_updates<B, Db>(
    mut batch: B,
    num_updates: u64,
    num_keys: u64,
    rng: &mut StdRng,
) -> B
where
    B: UnmerkleizedBatch<Db, K = Digest, V = Digest>,
    Db: ?Sized,
{
    for _ in 0..num_updates {
        let idx = rng.next_u64() % num_keys;
        let k = Sha256::hash(&idx.to_be_bytes());
        batch = batch.write(k, Some(make_fixed_value(rng)));
    }
    batch
}

/// Generate a variable-size `Vec<u8>` value (1-256 bytes).
pub fn make_var_value(rng: &mut StdRng) -> Vec<u8> {
    let len = (rng.next_u32() as usize) % VARIABLE_VALUE_MAX_LEN + 1;
    vec![rng.next_u32() as u8; len]
}
