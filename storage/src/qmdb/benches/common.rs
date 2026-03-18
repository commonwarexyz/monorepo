//! Shared infrastructure for QMDB benchmarks: constants, config builders, type aliases, dispatch
//! macros, and the common `gen_random_kv` helper.

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, tokio::Context, BufferPooler, ThreadPooler};
use commonware_storage::{
    qmdb::{
        any::{
            ordered::{fixed::Db as OFixed, variable::Db as OVariable},
            traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
            unordered::{fixed::Db as UFixed, variable::Db as UVariable},
            FixedConfig as AnyFixedConfig, VariableConfig as AnyVariableConfig,
        },
        current::{
            ordered::{fixed::Db as OCFixed, variable::Db as OCVariable},
            unordered::{fixed::Db as UCFixed, variable::Db as UCVariable},
            FixedConfig as CurrentFixedConfig, VariableConfig as CurrentVariableConfig,
        },
        keyless::{Config as KeylessConfig, Keyless},
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
pub const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

// -- Type aliases for fixed-value databases --

pub type UFixedDb = UFixed<Context, Digest, Digest, Sha256, EightCap>;
pub type OFixedDb = OFixed<Context, Digest, Digest, Sha256, EightCap>;
pub type UVAnyDb = UVariable<Context, Digest, Digest, Sha256, EightCap>;
pub type OVAnyDb = OVariable<Context, Digest, Digest, Sha256, EightCap>;
pub type UCFixedDb = UCFixed<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
pub type OCFixedDb = OCFixed<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
pub type UCVFixedDb = UCVariable<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
pub type OCVFixedDb = OCVariable<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;

// -- Type aliases for variable-value databases --

pub type UVarDb = UVariable<Context, Digest, Vec<u8>, Sha256, EightCap>;
pub type OVarDb = OVariable<Context, Digest, Vec<u8>, Sha256, EightCap>;
pub type UCVarDb = UCVariable<Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;
pub type OCVarDb = OCVariable<Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;

// -- Type alias for keyless database --

pub type KeylessDb = Keyless<Context, Vec<u8>, Sha256>;

// -- Variant enums --

#[derive(Debug, Clone, Copy)]
pub enum FixedVariant {
    AnyUnorderedFixed,
    AnyOrderedFixed,
    AnyUnorderedVariable,
    AnyOrderedVariable,
    CurrentUnorderedFixed,
    CurrentOrderedFixed,
    CurrentUnorderedVariable,
    CurrentOrderedVariable,
}

impl FixedVariant {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnyUnorderedFixed => "any::unordered::fixed",
            Self::AnyOrderedFixed => "any::ordered::fixed",
            Self::AnyUnorderedVariable => "any::unordered::variable",
            Self::AnyOrderedVariable => "any::ordered::variable",
            Self::CurrentUnorderedFixed => "current::unordered::fixed",
            Self::CurrentOrderedFixed => "current::ordered::fixed",
            Self::CurrentUnorderedVariable => "current::unordered::variable",
            Self::CurrentOrderedVariable => "current::ordered::variable",
        }
    }
}

pub const FIXED_VARIANTS: [FixedVariant; 8] = [
    FixedVariant::AnyUnorderedFixed,
    FixedVariant::AnyOrderedFixed,
    FixedVariant::AnyUnorderedVariable,
    FixedVariant::AnyOrderedVariable,
    FixedVariant::CurrentUnorderedFixed,
    FixedVariant::CurrentOrderedFixed,
    FixedVariant::CurrentUnorderedVariable,
    FixedVariant::CurrentOrderedVariable,
];

#[derive(Debug, Clone, Copy)]
pub enum VariableVariant {
    AnyUnordered,
    AnyOrdered,
    CurrentUnordered,
    CurrentOrdered,
}

impl VariableVariant {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnyUnordered => "any::unordered",
            Self::AnyOrdered => "any::ordered",
            Self::CurrentUnordered => "current::unordered",
            Self::CurrentOrdered => "current::ordered",
        }
    }
}

pub const VARIABLE_VARIANTS: [VariableVariant; 4] = [
    VariableVariant::AnyUnordered,
    VariableVariant::AnyOrdered,
    VariableVariant::CurrentUnordered,
    VariableVariant::CurrentOrdered,
];

// -- Config builders --

const PARTITION_FIXED: &str = "bench-fixed";
const PARTITION_VARIABLE: &str = "bench-variable";
const PARTITION_KEYLESS: &str = "bench-keyless";

pub fn any_fixed_cfg(ctx: &(impl BufferPooler + ThreadPooler)) -> AnyFixedConfig<EightCap> {
    AnyFixedConfig::<EightCap> {
        mmr_journal_partition: format!("journal-{PARTITION_FIXED}"),
        mmr_metadata_partition: format!("metadata-{PARTITION_FIXED}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_journal_partition: format!("log-journal-{PARTITION_FIXED}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        translator: EightCap,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

pub fn current_fixed_cfg(ctx: &(impl BufferPooler + ThreadPooler)) -> CurrentFixedConfig<EightCap> {
    CurrentFixedConfig::<EightCap> {
        mmr_journal_partition: format!("journal-{PARTITION_FIXED}"),
        mmr_metadata_partition: format!("metadata-{PARTITION_FIXED}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_journal_partition: format!("log-journal-{PARTITION_FIXED}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        grafted_mmr_metadata_partition: format!("grafted-mmr-metadata-{PARTITION_FIXED}"),
        translator: EightCap,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

pub fn variable_any_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> AnyVariableConfig<EightCap, ((), ())> {
    AnyVariableConfig::<EightCap, ((), ())> {
        mmr_journal_partition: format!("journal-{PARTITION_VARIABLE}"),
        mmr_metadata_partition: format!("metadata-{PARTITION_VARIABLE}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log-journal-{PARTITION_VARIABLE}"),
        log_codec_config: ((), ()),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        translator: EightCap,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

pub fn variable_current_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> CurrentVariableConfig<EightCap, ((), ())> {
    CurrentVariableConfig::<EightCap, ((), ())> {
        mmr_journal_partition: format!("journal-{PARTITION_VARIABLE}"),
        mmr_metadata_partition: format!("metadata-{PARTITION_VARIABLE}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log-journal-{PARTITION_VARIABLE}"),
        log_codec_config: ((), ()),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        grafted_mmr_metadata_partition: format!("grafted-mmr-metadata-{PARTITION_VARIABLE}"),
        translator: EightCap,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

pub fn variable_any_vec_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> AnyVariableConfig<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    AnyVariableConfig::<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
        mmr_journal_partition: format!("journal-{PARTITION_VARIABLE}"),
        mmr_metadata_partition: format!("metadata-{PARTITION_VARIABLE}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log-journal-{PARTITION_VARIABLE}"),
        log_codec_config: ((), ((0..=10000).into(), ())),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        translator: EightCap,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

pub fn variable_current_vec_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> CurrentVariableConfig<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    CurrentVariableConfig::<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
        mmr_journal_partition: format!("journal-{PARTITION_VARIABLE}"),
        mmr_metadata_partition: format!("metadata-{PARTITION_VARIABLE}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log-journal-{PARTITION_VARIABLE}"),
        log_codec_config: ((), ((0..=10000).into(), ())),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        grafted_mmr_metadata_partition: format!("grafted-mmr-metadata-{PARTITION_VARIABLE}"),
        translator: EightCap,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

pub fn keyless_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> KeylessConfig<(commonware_codec::RangeCfg<usize>, ())> {
    KeylessConfig::<(commonware_codec::RangeCfg<usize>, ())> {
        mmr_journal_partition: format!("journal-{PARTITION_KEYLESS}"),
        mmr_metadata_partition: format!("metadata-{PARTITION_KEYLESS}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log-journal-{PARTITION_KEYLESS}"),
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
        page_cache: CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

// -- Dispatch macros --

/// Internal helper: construct a db, bind it, execute body.
macro_rules! dispatch_arm {
    ($ctx:expr, $db:ident, $body:expr, $DbType:ty, $cfg_fn:ident) => {{
        #[allow(unused_mut)]
        let mut $db = <$DbType>::init($ctx.clone(), $crate::common::$cfg_fn(&$ctx))
            .await
            .unwrap();
        $body
    }};
}

/// Construct a fixed-value database for the given variant, bind it as `$db`, execute `$body`.
macro_rules! with_fixed_db {
    ($ctx:expr, $variant:expr, |mut $db:ident| $body:expr) => {{
        use $crate::common::FixedVariant::*;
        match $variant {
            AnyUnorderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::UFixedDb,
                any_fixed_cfg
            ),
            AnyOrderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::OFixedDb,
                any_fixed_cfg
            ),
            AnyUnorderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::UVAnyDb,
                variable_any_cfg
            ),
            AnyOrderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::OVAnyDb,
                variable_any_cfg
            ),
            CurrentUnorderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::UCFixedDb,
                current_fixed_cfg
            ),
            CurrentOrderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::OCFixedDb,
                current_fixed_cfg
            ),
            CurrentUnorderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::UCVFixedDb,
                variable_current_cfg
            ),
            CurrentOrderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::OCVFixedDb,
                variable_current_cfg
            ),
        }
    }};
}

/// Construct a variable-value database for the given variant, bind it as `$db`, execute `$body`.
macro_rules! with_variable_db {
    ($ctx:expr, $variant:expr, |mut $db:ident| $body:expr) => {{
        use $crate::common::VariableVariant::*;
        match $variant {
            AnyUnordered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::UVarDb,
                variable_any_vec_cfg
            ),
            AnyOrdered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::OVarDb,
                variable_any_vec_cfg
            ),
            CurrentUnordered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::UCVarDb,
                variable_current_vec_cfg
            ),
            CurrentOrdered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::OCVarDb,
                variable_current_vec_cfg
            ),
        }
    }};
}

pub(crate) use dispatch_arm;
pub(crate) use with_fixed_db;
pub(crate) use with_variable_db;

// -- Data generation --

/// Seed a database with `num_elements` entries, then perform `num_operations` random
/// updates/deletes. Commits periodically when `commit_frequency` is `Some`.
pub async fn gen_random_kv<M>(
    db: &mut M,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
    make_value: impl Fn(&mut StdRng) -> M::Value,
) where
    M: DbAny<Key = Digest>,
{
    let mut rng = StdRng::seed_from_u64(42);

    // Seed the db with `num_elements` entries.
    {
        let mut batch = db.new_batch();
        for i in 0u64..num_elements {
            let k = Sha256::hash(&i.to_be_bytes());
            batch = batch.write(k, Some(make_value(&mut rng)));
        }
        let finalized = batch.merkleize(None).await.unwrap().finalize();
        db.apply_batch(finalized).await.unwrap();
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
                    let finalized = batch.merkleize(None).await.unwrap().finalize();
                    db.apply_batch(finalized).await.unwrap();
                    batch = db.new_batch();
                }
            }
        }
        let finalized = batch.merkleize(None).await.unwrap().finalize();
        db.apply_batch(finalized).await.unwrap();
    }
}

/// Generate a fixed-size digest value.
pub fn make_fixed_value(rng: &mut StdRng) -> Digest {
    Sha256::hash(&rng.next_u32().to_be_bytes())
}

/// Generate a variable-size `Vec<u8>` value (1-256 bytes).
pub fn make_variable_value(rng: &mut StdRng) -> Vec<u8> {
    let len = (rng.next_u32() as usize) % VARIABLE_VALUE_MAX_LEN + 1;
    vec![rng.next_u32() as u8; len]
}
