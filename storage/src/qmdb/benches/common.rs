//! Shared infrastructure for QMDB benchmarks: constants, config builders, type aliases, dispatch
//! macros, and the common `gen_random_kv` helper.

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, tokio::Context, BufferPooler, ThreadPooler};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::mmr::{self, journaled::Config as MmrConfig},
    mmb,
    qmdb::{
        any::{
            ordered::{fixed::Db as OFixed, variable::Db as OVariable},
            traits::{DbAny, UnmerkleizedBatch as _},
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
pub const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

// -- Fixed value (Digest), fixed storage layout --

pub type AnyUFixDb = UFixed<mmr::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type AnyOFixDb = OFixed<mmr::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type CurUFixDb = UCFixed<mmr::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
pub type CurOFixDb = OCFixed<mmr::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;

pub type AnyMmbUFixDb = UFixed<mmb::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type AnyMmbOFixDb = OFixed<mmb::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type CurMmbUFixDb = UCFixed<mmb::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
pub type CurMmbOFixDb = OCFixed<mmb::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;

// -- Fixed value (Digest), variable storage layout --
// Measures overhead of variable-capable storage when values are fixed-size.

pub type AnyUVarDigestDb = UVariable<mmr::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type AnyOVarDigestDb = OVariable<mmr::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type CurUVarDigestDb =
    UCVariable<mmr::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
pub type CurOVarDigestDb =
    OCVariable<mmr::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;

pub type AnyMmbUVarDigestDb = UVariable<mmb::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type AnyMmbOVarDigestDb = OVariable<mmb::Family, Context, Digest, Digest, Sha256, EightCap>;
pub type CurMmbUVarDigestDb =
    UCVariable<mmb::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
pub type CurMmbOVarDigestDb =
    OCVariable<mmb::Family, Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;

// -- Variable value (Vec<u8>), variable storage layout --

pub type AnyUVarVecDb = UVariable<mmr::Family, Context, Digest, Vec<u8>, Sha256, EightCap>;
pub type AnyOVarVecDb = OVariable<mmr::Family, Context, Digest, Vec<u8>, Sha256, EightCap>;
pub type CurUVarVecDb =
    UCVariable<mmr::Family, Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;
pub type CurOVarVecDb =
    OCVariable<mmr::Family, Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;

pub type AnyMmbUVarVecDb = UVariable<mmb::Family, Context, Digest, Vec<u8>, Sha256, EightCap>;
pub type AnyMmbOVarVecDb = OVariable<mmb::Family, Context, Digest, Vec<u8>, Sha256, EightCap>;
pub type CurMmbUVarVecDb =
    UCVariable<mmb::Family, Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;
pub type CurMmbOVarVecDb =
    OCVariable<mmb::Family, Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;

// -- Keyless --

pub type KeylessMmrDb = Keyless<mmr::Family, Context, Vec<u8>, Sha256>;
pub type KeylessMmbDb = Keyless<mmb::Family, Context, Vec<u8>, Sha256>;

pub async fn open_keyless_db(ctx: Context) -> KeylessDb {
    let cfg = keyless_cfg(&ctx);
    KeylessDb::init(ctx, cfg).await.unwrap()
}

// -- Variant enums --

#[derive(Debug, Clone, Copy)]
pub enum FixedValueVariant {
    AnyUnorderedFixed,
    AnyOrderedFixed,
    AnyUnorderedVariable,
    AnyOrderedVariable,
    CurrentUnorderedFixed,
    CurrentOrderedFixed,
    CurrentUnorderedVariable,
    CurrentOrderedVariable,
    AnyMmbUnorderedFixed,
    AnyMmbOrderedFixed,
    AnyMmbUnorderedVariable,
    AnyMmbOrderedVariable,
    CurrentMmbUnorderedFixed,
    CurrentMmbOrderedFixed,
    CurrentMmbUnorderedVariable,
    CurrentMmbOrderedVariable,
}

impl FixedValueVariant {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnyUnorderedFixed => "any::mmr::unordered::fixed",
            Self::AnyOrderedFixed => "any::mmr::ordered::fixed",
            Self::AnyUnorderedVariable => "any::mmr::unordered::variable",
            Self::AnyOrderedVariable => "any::mmr::ordered::variable",
            Self::CurrentUnorderedFixed => "current::mmr::unordered::fixed",
            Self::CurrentOrderedFixed => "current::mmr::ordered::fixed",
            Self::CurrentUnorderedVariable => "current::mmr::unordered::variable",
            Self::CurrentOrderedVariable => "current::mmr::ordered::variable",
            Self::AnyMmbUnorderedFixed => "any::mmb::unordered::fixed",
            Self::AnyMmbOrderedFixed => "any::mmb::ordered::fixed",
            Self::AnyMmbUnorderedVariable => "any::mmb::unordered::variable",
            Self::AnyMmbOrderedVariable => "any::mmb::ordered::variable",
            Self::CurrentMmbUnorderedFixed => "current::mmb::unordered::fixed",
            Self::CurrentMmbOrderedFixed => "current::mmb::ordered::fixed",
            Self::CurrentMmbUnorderedVariable => "current::mmb::unordered::variable",
            Self::CurrentMmbOrderedVariable => "current::mmb::ordered::variable",
        }
    }
}

pub const FIXED_VALUE_VARIANTS: [FixedValueVariant; 16] = [
    FixedValueVariant::AnyUnorderedFixed,
    FixedValueVariant::AnyOrderedFixed,
    FixedValueVariant::AnyUnorderedVariable,
    FixedValueVariant::AnyOrderedVariable,
    FixedValueVariant::CurrentUnorderedFixed,
    FixedValueVariant::CurrentOrderedFixed,
    FixedValueVariant::CurrentUnorderedVariable,
    FixedValueVariant::CurrentOrderedVariable,
    FixedValueVariant::AnyMmbUnorderedFixed,
    FixedValueVariant::AnyMmbOrderedFixed,
    FixedValueVariant::AnyMmbUnorderedVariable,
    FixedValueVariant::AnyMmbOrderedVariable,
    FixedValueVariant::CurrentMmbUnorderedFixed,
    FixedValueVariant::CurrentMmbOrderedFixed,
    FixedValueVariant::CurrentMmbUnorderedVariable,
    FixedValueVariant::CurrentMmbOrderedVariable,
];

#[derive(Debug, Clone, Copy)]
pub enum VarValueVariant {
    AnyUnordered,
    AnyOrdered,
    CurrentUnordered,
    CurrentOrdered,
    AnyMmbUnordered,
    AnyMmbOrdered,
    CurrentMmbUnordered,
    CurrentMmbOrdered,
}

impl VarValueVariant {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnyUnordered => "any::mmr::unordered",
            Self::AnyOrdered => "any::mmr::ordered",
            Self::CurrentUnordered => "current::mmr::unordered",
            Self::CurrentOrdered => "current::mmr::ordered",
            Self::AnyMmbUnordered => "any::mmb::unordered",
            Self::AnyMmbOrdered => "any::mmb::ordered",
            Self::CurrentMmbUnordered => "current::mmb::unordered",
            Self::CurrentMmbOrdered => "current::mmb::ordered",
        }
    }
}

pub const VAR_VALUE_VARIANTS: [VarValueVariant; 8] = [
    VarValueVariant::AnyUnordered,
    VarValueVariant::AnyOrdered,
    VarValueVariant::CurrentUnordered,
    VarValueVariant::CurrentOrdered,
    VarValueVariant::AnyMmbUnordered,
    VarValueVariant::AnyMmbOrdered,
    VarValueVariant::CurrentMmbUnordered,
    VarValueVariant::CurrentMmbOrdered,
];

// -- Config builders --

const PARTITION_FIX: &str = "bench-fixed";
const PARTITION_VAR: &str = "bench-variable";
const PARTITION_KEYLESS: &str = "bench-keyless";

fn mmr_cfg(
    suffix: &str,
    ctx: &(impl BufferPooler + ThreadPooler),
    page_cache: CacheRef,
) -> MmrConfig {
    MmrConfig {
        journal_partition: format!("journal-{suffix}"),
        metadata_partition: format!("metadata-{suffix}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
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

pub fn any_fix_cfg(ctx: &(impl BufferPooler + ThreadPooler)) -> AnyFixedConfig<EightCap> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    AnyFixedConfig {
        merkle_config: mmr_cfg(PARTITION_FIX, ctx, page_cache.clone()),
        journal_config: fix_log_cfg(PARTITION_FIX, page_cache),
        translator: EightCap,
    }
}

pub fn cur_fix_cfg(ctx: &(impl BufferPooler + ThreadPooler)) -> CurrentFixedConfig<EightCap> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    CurrentFixedConfig {
        merkle_config: mmr_cfg(PARTITION_FIX, ctx, page_cache.clone()),
        journal_config: fix_log_cfg(PARTITION_FIX, page_cache),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION_FIX}"),
        translator: EightCap,
    }
}

pub fn any_var_digest_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> AnyVariableConfig<EightCap, ((), ())> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    AnyVariableConfig {
        merkle_config: mmr_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ())),
        translator: EightCap,
    }
}

pub fn cur_var_digest_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> CurrentVariableConfig<EightCap, ((), ())> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    CurrentVariableConfig {
        merkle_config: mmr_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ())),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION_VAR}"),
        translator: EightCap,
    }
}

pub fn any_var_vec_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> AnyVariableConfig<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    AnyVariableConfig {
        merkle_config: mmr_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ((0..=10000).into(), ()))),
        translator: EightCap,
    }
}

pub fn cur_var_vec_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> CurrentVariableConfig<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    CurrentVariableConfig {
        merkle_config: mmr_cfg(PARTITION_VAR, ctx, page_cache.clone()),
        journal_config: var_log_cfg(PARTITION_VAR, page_cache, ((), ((0..=10000).into(), ()))),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION_VAR}"),
        translator: EightCap,
    }
}

pub fn keyless_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> KeylessConfig<(commonware_codec::RangeCfg<usize>, ())> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    KeylessConfig {
        merkle: mmr_cfg(PARTITION_KEYLESS, ctx, page_cache.clone()),
        log: var_log_cfg(PARTITION_KEYLESS, page_cache, ((0..=10000).into(), ())),
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
macro_rules! with_fixed_value_db {
    ($ctx:expr, $variant:expr, |mut $db:ident| $body:expr) => {{
        use $crate::common::FixedValueVariant::*;
        match $variant {
            AnyUnorderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyUFixDb,
                any_fix_cfg
            ),
            AnyOrderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyOFixDb,
                any_fix_cfg
            ),
            AnyUnorderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyUVarDigestDb,
                any_var_digest_cfg
            ),
            AnyOrderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyOVarDigestDb,
                any_var_digest_cfg
            ),
            CurrentUnorderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurUFixDb,
                cur_fix_cfg
            ),
            CurrentOrderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurOFixDb,
                cur_fix_cfg
            ),
            CurrentUnorderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurUVarDigestDb,
                cur_var_digest_cfg
            ),
            CurrentOrderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurOVarDigestDb,
                cur_var_digest_cfg
            ),
            AnyMmbUnorderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbUFixDb,
                any_fix_cfg
            ),
            AnyMmbOrderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbOFixDb,
                any_fix_cfg
            ),
            AnyMmbUnorderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbUVarDigestDb,
                any_var_digest_cfg
            ),
            AnyMmbOrderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbOVarDigestDb,
                any_var_digest_cfg
            ),
            CurrentMmbUnorderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbUFixDb,
                cur_fix_cfg
            ),
            CurrentMmbOrderedFixed => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbOFixDb,
                cur_fix_cfg
            ),
            CurrentMmbUnorderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbUVarDigestDb,
                cur_var_digest_cfg
            ),
            CurrentMmbOrderedVariable => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbOVarDigestDb,
                cur_var_digest_cfg
            ),
        }
    }};
}

/// Construct a variable-value (Vec<u8>) database for the given variant, bind it as `$db`,
/// execute `$body`.
macro_rules! with_var_value_db {
    ($ctx:expr, $variant:expr, |mut $db:ident| $body:expr) => {{
        use $crate::common::VarValueVariant::*;
        match $variant {
            AnyUnordered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyUVarVecDb,
                any_var_vec_cfg
            ),
            AnyOrdered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyOVarVecDb,
                any_var_vec_cfg
            ),
            CurrentUnordered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurUVarVecDb,
                cur_var_vec_cfg
            ),
            CurrentOrdered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurOVarVecDb,
                cur_var_vec_cfg
            ),
            AnyMmbUnordered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbUVarVecDb,
                any_var_vec_cfg
            ),
            AnyMmbOrdered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbOVarVecDb,
                any_var_vec_cfg
            ),
            CurrentMmbUnordered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbUVarVecDb,
                cur_var_vec_cfg
            ),
            CurrentMmbOrdered => $crate::common::dispatch_arm!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbOVarVecDb,
                cur_var_vec_cfg
            ),
        }
    }};
}

pub(crate) use dispatch_arm;
pub(crate) use with_fixed_value_db;
pub(crate) use with_var_value_db;

/// Internal helper: construct a db from a pre-built config, bind it, execute body.
macro_rules! dispatch_arm_with_cfg {
    ($ctx:expr, $db:ident, $body:expr, $DbType:ty, $cfg:expr) => {{
        #[allow(unused_mut)]
        let mut $db = <$DbType>::init($ctx.clone(), $cfg.clone()).await.unwrap();
        $body
    }};
}

/// Like `with_fixed_value_db!` but takes pre-built configs to avoid rebuilding them each call.
macro_rules! with_fixed_value_db_cfg {
    ($ctx:expr, $variant:expr, $any_fixed:expr, $current_fixed:expr,
     $any_var:expr, $current_var:expr, |mut $db:ident| $body:expr) => {{
        use $crate::common::FixedValueVariant::*;
        match $variant {
            AnyUnorderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyUFixDb,
                $any_fixed
            ),
            AnyOrderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyOFixDb,
                $any_fixed
            ),
            AnyUnorderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyUVarDigestDb,
                $any_var
            ),
            AnyOrderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyOVarDigestDb,
                $any_var
            ),
            CurrentUnorderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurUFixDb,
                $current_fixed
            ),
            CurrentOrderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurOFixDb,
                $current_fixed
            ),
            CurrentUnorderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurUVarDigestDb,
                $current_var
            ),
            CurrentOrderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurOVarDigestDb,
                $current_var
            ),
            AnyMmbUnorderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbUFixDb,
                $any_fixed
            ),
            AnyMmbOrderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbOFixDb,
                $any_fixed
            ),
            AnyMmbUnorderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbUVarDigestDb,
                $any_var
            ),
            AnyMmbOrderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbOVarDigestDb,
                $any_var
            ),
            CurrentMmbUnorderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbUFixDb,
                $current_fixed
            ),
            CurrentMmbOrderedFixed => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbOFixDb,
                $current_fixed
            ),
            CurrentMmbUnorderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbUVarDigestDb,
                $current_var
            ),
            CurrentMmbOrderedVariable => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbOVarDigestDb,
                $current_var
            ),
        }
    }};
}

/// Like `with_var_value_db!` but takes pre-built configs to avoid rebuilding them each call.
macro_rules! with_var_value_db_cfg {
    ($ctx:expr, $variant:expr, $any_var:expr, $current_var:expr,
     |mut $db:ident| $body:expr) => {{
        use $crate::common::VarValueVariant::*;
        match $variant {
            AnyUnordered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyUVarVecDb,
                $any_var
            ),
            AnyOrdered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyOVarVecDb,
                $any_var
            ),
            CurrentUnordered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurUVarVecDb,
                $current_var
            ),
            CurrentOrdered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurOVarVecDb,
                $current_var
            ),
            AnyMmbUnordered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbUVarVecDb,
                $any_var
            ),
            AnyMmbOrdered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::AnyMmbOVarVecDb,
                $any_var
            ),
            CurrentMmbUnordered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbUVarVecDb,
                $current_var
            ),
            CurrentMmbOrdered => $crate::common::dispatch_arm_with_cfg!(
                $ctx,
                $db,
                $body,
                $crate::common::CurMmbOVarVecDb,
                $current_var
            ),
        }
    }};
}

pub(crate) use dispatch_arm_with_cfg;
pub(crate) use with_fixed_value_db_cfg;
pub(crate) use with_var_value_db_cfg;

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
    F: commonware_storage::merkle::Family,
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

/// Generate a variable-size `Vec<u8>` value (1-256 bytes).
pub fn make_var_value(rng: &mut StdRng) -> Vec<u8> {
    let len = (rng.next_u32() as usize) % VARIABLE_VALUE_MAX_LEN + 1;
    vec![rng.next_u32() as u8; len]
}
