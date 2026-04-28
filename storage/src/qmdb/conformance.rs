//! Root stability and order-independence tests for all QMDB database variants.
//!
//! **Conformance tests** hash the Merkle root produced by a deterministic workload across 200
//! seeds. Any change to the root computation algorithm will cause the stored hash to diverge.
//!
//! **Order-independence tests** verify that the insertion order of operations within a single
//! batch does not affect the resulting root. Each test applies the same set of mutations in
//! forward and reverse order to two separate databases and asserts root equality.

use crate::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{full::Config as MerkleConfig, mmb, mmr, Family},
    qmdb::{
        any::{
            self,
            traits::{DbAny, UnmerkleizedBatch as _},
        },
        current, immutable, keyless,
    },
    translator::{OneCap, TwoCap},
};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
#[cfg(test)]
use commonware_runtime::Supervisor as _;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _};
use commonware_utils::{sequence::U64, NZUsize, NZU16, NZU64};
use std::num::{NonZeroU16, NonZeroUsize};

// Type aliases

type Ctx = deterministic::Context;

type AnyMmrUnorderedFixed =
    any::unordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap>;
type AnyMmrUnorderedVariable =
    any::unordered::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap>;
type AnyMmrOrderedFixed = any::ordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap>;
type AnyMmrOrderedVariable =
    any::ordered::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap>;

type AnyMmbUnorderedFixed =
    any::unordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap>;
type AnyMmbUnorderedVariable =
    any::unordered::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap>;
type AnyMmbOrderedFixed = any::ordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap>;
type AnyMmbOrderedVariable =
    any::ordered::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap>;

type CurrentMmrUnorderedFixed =
    current::unordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;
type CurrentMmrUnorderedVariable =
    current::unordered::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;
type CurrentMmrOrderedFixed =
    current::ordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;
type CurrentMmrOrderedVariable =
    current::ordered::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;

type CurrentMmbUnorderedFixed =
    current::unordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;
type CurrentMmbUnorderedVariable =
    current::unordered::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;
type CurrentMmbOrderedFixed =
    current::ordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;
type CurrentMmbOrderedVariable =
    current::ordered::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, 32>;

type ImmutableMmrFixed = immutable::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, TwoCap>;
type ImmutableMmbFixed = immutable::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, TwoCap>;
type ImmutableMmrVariable =
    immutable::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, TwoCap>;
type ImmutableMmbVariable =
    immutable::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, TwoCap>;

type KeylessMmrFixed = keyless::fixed::Db<mmr::Family, Ctx, U64, Sha256>;
type KeylessMmbFixed = keyless::fixed::Db<mmb::Family, Ctx, U64, Sha256>;
type KeylessMmrVariable = keyless::variable::Db<mmr::Family, Ctx, Vec<u8>, Sha256>;
type KeylessMmbVariable = keyless::variable::Db<mmb::Family, Ctx, Vec<u8>, Sha256>;

type ImmutableMmrCompactFixed =
    immutable::fixed::CompactDb<mmr::Family, Ctx, Digest, Digest, Sha256>;
type ImmutableMmbCompactFixed =
    immutable::fixed::CompactDb<mmb::Family, Ctx, Digest, Digest, Sha256>;
type ImmutableMmrCompactVariable =
    immutable::variable::CompactDb<mmr::Family, Ctx, Digest, Digest, Sha256, ((), ())>;
type ImmutableMmbCompactVariable =
    immutable::variable::CompactDb<mmb::Family, Ctx, Digest, Digest, Sha256, ((), ())>;

type KeylessMmrCompactFixed = keyless::fixed::CompactDb<mmr::Family, Ctx, U64, Sha256>;
type KeylessMmbCompactFixed = keyless::fixed::CompactDb<mmb::Family, Ctx, U64, Sha256>;
type KeylessMmrCompactVariable = keyless::variable::CompactDb<
    mmr::Family,
    Ctx,
    Vec<u8>,
    Sha256,
    (commonware_codec::RangeCfg<usize>, ()),
>;
type KeylessMmbCompactVariable = keyless::variable::CompactDb<
    mmb::Family,
    Ctx,
    Vec<u8>,
    Sha256,
    (commonware_codec::RangeCfg<usize>, ()),
>;

// Config constructors

const PAGE_SIZE: NonZeroU16 = NZU16!(101);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

fn merkle_config(suffix: &str, page_cache: &CacheRef) -> MerkleConfig {
    MerkleConfig {
        journal_partition: format!("{suffix}-mj"),
        metadata_partition: format!("{suffix}-mm"),
        items_per_blob: NZU64!(11),
        write_buffer: NZUsize!(1024),
        thread_pool: None,
        page_cache: page_cache.clone(),
    }
}

fn fixed_log_config(suffix: &str, page_cache: CacheRef) -> FConfig {
    FConfig {
        partition: format!("{suffix}-log"),
        items_per_blob: NZU64!(7),
        page_cache,
        write_buffer: NZUsize!(1024),
    }
}

fn variable_log_config<C>(suffix: &str, page_cache: CacheRef, codec_config: C) -> VConfig<C> {
    VConfig {
        partition: format!("{suffix}-log"),
        items_per_section: NZU64!(7),
        compression: None,
        codec_config,
        page_cache,
        write_buffer: NZUsize!(1024),
    }
}

fn any_fixed_config(suffix: &str, pooler: &impl BufferPooler) -> any::FixedConfig<OneCap> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    any::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: fixed_log_config(suffix, pc),
        translator: OneCap,
    }
}

fn any_variable_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> any::VariableConfig<OneCap, ((), ())> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    any::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: variable_log_config(suffix, pc, ((), ())),
        translator: OneCap,
    }
}

fn current_fixed_config(suffix: &str, pooler: &impl BufferPooler) -> current::FixedConfig<OneCap> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    current::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: fixed_log_config(suffix, pc),
        grafted_metadata_partition: format!("{suffix}-graft"),
        translator: OneCap,
    }
}

fn current_variable_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> current::VariableConfig<OneCap, ((), ())> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    current::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: variable_log_config(suffix, pc, ((), ())),
        grafted_metadata_partition: format!("{suffix}-graft"),
        translator: OneCap,
    }
}

fn immutable_fixed_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> immutable::fixed::Config<TwoCap> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    immutable::Config {
        merkle_config: merkle_config(suffix, &pc),
        log: fixed_log_config(suffix, pc),
        translator: TwoCap,
    }
}

fn immutable_variable_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> immutable::variable::Config<TwoCap, ((), ())> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    immutable::Config {
        merkle_config: merkle_config(suffix, &pc),
        log: variable_log_config(suffix, pc, ((), ())),
        translator: TwoCap,
    }
}

fn keyless_fixed_config(suffix: &str, pooler: &impl BufferPooler) -> keyless::fixed::Config {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    keyless::Config {
        merkle: merkle_config(suffix, &pc),
        log: fixed_log_config(suffix, pc),
    }
}

fn keyless_variable_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> keyless::variable::Config<(commonware_codec::RangeCfg<usize>, ())> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    keyless::Config {
        merkle: merkle_config(suffix, &pc),
        log: variable_log_config(suffix, pc, ((0..=10000).into(), ())),
    }
}

fn compact_merkle_config(suffix: &str) -> crate::merkle::compact::Config {
    crate::merkle::compact::Config {
        partition: format!("{suffix}-compact"),
        thread_pool: None,
    }
}

fn immutable_fixed_compact_config(
    suffix: &str,
    _pooler: &impl BufferPooler,
) -> immutable::fixed::CompactConfig {
    immutable::CompactConfig {
        merkle: compact_merkle_config(suffix),
        commit_codec_config: (),
    }
}

fn immutable_variable_compact_config(
    suffix: &str,
    _pooler: &impl BufferPooler,
) -> immutable::variable::CompactConfig<((), ())> {
    immutable::CompactConfig {
        merkle: compact_merkle_config(suffix),
        commit_codec_config: ((), ()),
    }
}

fn keyless_fixed_compact_config(
    suffix: &str,
    _pooler: &impl BufferPooler,
) -> keyless::fixed::CompactConfig {
    keyless::CompactConfig {
        merkle: compact_merkle_config(suffix),
        commit_codec_config: (),
    }
}

fn keyless_variable_compact_config(
    suffix: &str,
    _pooler: &impl BufferPooler,
) -> keyless::variable::CompactConfig<(commonware_codec::RangeCfg<usize>, ())> {
    keyless::CompactConfig {
        merkle: compact_merkle_config(suffix),
        commit_codec_config: ((0..=10000usize).into(), ()),
    }
}

// Workloads

fn to_digest(i: u64) -> Digest {
    Sha256::hash(&i.to_be_bytes())
}

fn to_val(i: u64, salt: u64) -> Digest {
    Sha256::hash(&[i.to_be_bytes(), salt.wrapping_add(1).to_be_bytes()].concat())
}

/// Digest whose first byte is `prefix`, guaranteeing translator collisions under OneCap.
fn colliding_digest(prefix: u8, suffix: u64) -> Digest {
    crate::qmdb::any::test::colliding_digest(prefix, suffix)
}

/// Deterministically select ~20% of keys for deletion. XOR with the seed ensures
/// the set of deleted indices varies across seeds.
fn is_deleted(seed: u64, i: u64) -> bool {
    (seed ^ i).is_multiple_of(5)
}

/// Apply a batch of keyed writes (creates, updates, or deletes) to the database.
async fn apply_writes<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
    db: &mut D,
    writes: Vec<(Digest, Option<Digest>)>,
) {
    let mut batch = db.new_batch();
    for (k, v) in writes {
        batch = batch.write(k, v);
    }
    let merkleized = batch.merkleize(db, None).await.unwrap();
    db.apply_batch(merkleized).await.unwrap();
}

/// Apply a batch of immutable sets to the database.
macro_rules! apply_sets {
    ($db:ident, $ops:expr) => {{
        let floor = $db.inactivity_floor_loc();
        let mut batch = $db.new_batch();
        for (k, v) in $ops {
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&$db, None, floor);
        $db.apply_batch(merkleized).await.unwrap();
    }};
}

/// Immutable-set variant for the compact db. Identical to [`apply_sets`] except that
/// [`CompactDb::apply_batch`] is synchronous.
macro_rules! apply_sets_compact {
    ($db:ident, $ops:expr) => {{
        let floor = $db.inactivity_floor_loc();
        let mut batch = $db.new_batch();
        for (k, v) in $ops {
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&$db, None, floor);
        $db.apply_batch(merkleized).unwrap();
    }};
}

/// Keyless-append variant for the compact db. Identical to [`apply_appends`] except
/// that [`CompactDb::apply_batch`] is synchronous.
macro_rules! apply_appends_compact {
    ($db:ident, $vals:expr) => {{
        let floor = $db.inactivity_floor_loc();
        let mut batch = $db.new_batch();
        for v in $vals {
            batch = batch.append(v);
        }
        let merkleized = batch.merkleize(&$db, None, floor);
        $db.apply_batch(merkleized).unwrap();
    }};
}

/// Apply a batch of keyless appends to the database.
macro_rules! apply_appends {
    ($db:ident, $vals:expr) => {{
        let floor = $db.inactivity_floor_loc();
        let mut batch = $db.new_batch();
        for v in $vals {
            batch = batch.append(v);
        }
        let merkleized = batch.merkleize(&$db, None, floor);
        $db.apply_batch(merkleized).await.unwrap();
    }};
}

/// 4-batch keyed workload exercising every mutation type.
///
/// 1. Create n keys with initial values.
/// 2. Delete ~20% of keys, update the rest.
/// 3. Recreate the deleted keys alongside new keys that collide under the translator.
/// 4. Update original keys; delete odd-indexed colliding keys, update even-indexed ones.
async fn keyed_root<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
    db: &mut D,
    seed: u64,
) -> Vec<u8> {
    let n = seed % 50 + 5;

    // Choose a translator bucket for colliding keys (varies per seed).
    let prefix = (seed % 256) as u8;

    // 1. Create n keys.
    let writes: Vec<_> = (0..n).map(|i| (to_digest(i), Some(to_val(i, 1)))).collect();
    apply_writes(db, writes).await;

    // 2. Delete ~20% of keys, update the rest with new values.
    let writes: Vec<_> = (0..n)
        .map(|i| {
            let key = to_digest(i);
            if is_deleted(seed, i) {
                (key, None)
            } else {
                (key, Some(to_val(i, 2)))
            }
        })
        .collect();
    apply_writes(db, writes).await;

    // 3. Recreate every deleted key, and introduce new keys that share a translator
    //    bucket (offset by 10000 to avoid overlapping with the original key range).
    let mut writes = Vec::new();
    for i in 0..n {
        if is_deleted(seed, i) {
            writes.push((to_digest(i), Some(to_val(i, 3))));
        }
    }
    for i in 0..n / 2 {
        writes.push((colliding_digest(prefix, 10000 + i), Some(to_val(i, 4))));
    }
    apply_writes(db, writes).await;

    // 4. Update original keys; delete odd-indexed colliding keys, update even-indexed.
    let mut writes = Vec::new();
    for i in 0..n {
        writes.push((to_digest(i), Some(to_val(i, 5))));
    }
    for i in 0..n / 2 {
        let key = colliding_digest(prefix, 10000 + i);
        if i % 2 == 1 {
            writes.push((key, None));
        } else {
            writes.push((key, Some(to_val(i, 6))));
        }
    }
    apply_writes(db, writes).await;

    db.root().to_vec()
}

/// 3-batch immutable workload. Each batch inserts a disjoint set of keys (immutable
/// databases are write-once). Macro because the Db types share no common trait.
///
/// 1. Insert n hash-distributed keys.
/// 2. Insert n more hash-distributed keys (disjoint range).
/// 3. Insert keys that share a translator bucket.
macro_rules! immutable_root {
    ($db:ident, $seed:ident) => {{
        let n = $seed % 30 + 5;
        let prefix = ($seed % 256) as u8;

        // 1. Keys 0..n.
        apply_sets!($db, (0..n).map(|i| (to_digest(i), to_val(i, 1))));

        // 2. Keys n..2n (disjoint from batch 1).
        apply_sets!($db, (n..2 * n).map(|i| (to_digest(i), to_val(i, 2))));

        // 3. Colliding keys (offset by 10000 to avoid overlap).
        apply_sets!(
            $db,
            (0..n / 2).map(|i| (colliding_digest(prefix, 10000 + i), to_val(i, 3)))
        );

        $db.root().to_vec()
    }};
}

/// Compact-db variant of [`immutable_root`].
macro_rules! immutable_root_compact {
    ($db:ident, $seed:ident) => {{
        let n = $seed % 30 + 5;
        let prefix = ($seed % 256) as u8;

        apply_sets_compact!($db, (0..n).map(|i| (to_digest(i), to_val(i, 1))));
        apply_sets_compact!($db, (n..2 * n).map(|i| (to_digest(i), to_val(i, 2))));
        apply_sets_compact!(
            $db,
            (0..n / 2).map(|i| (colliding_digest(prefix, 10000 + i), to_val(i, 3)))
        );

        $db.root().to_vec()
    }};
}

/// Compact-db variant of [`keyless_root`].
macro_rules! keyless_root_compact {
    ($db:ident, $seed:ident, |$x:ident| $make_val:expr) => {{
        let n = $seed % 30 + 5;

        apply_appends_compact!(
            $db,
            (0..n).map(|i| {
                let $x = $seed.wrapping_add(i);
                $make_val
            })
        );
        apply_appends_compact!(
            $db,
            (0..n).map(|i| {
                let $x = $seed.wrapping_add(n + i);
                $make_val
            })
        );
        apply_appends_compact!(
            $db,
            (0..n / 2).map(|i| {
                let $x = (!$seed).wrapping_add(i);
                $make_val
            })
        );

        $db.root().to_vec()
    }};
}

/// 3-batch keyless workload. The `$make_val` expression converts a `u64` into the
/// appropriate value type (`U64` for fixed, `Vec<u8>` for variable).
///
/// 1. Append n values.
/// 2. Append n more values.
/// 3. Append n/2 values derived from a different base.
macro_rules! keyless_root {
    ($db:ident, $seed:ident, |$x:ident| $make_val:expr) => {{
        let n = $seed % 30 + 5;

        // 1.
        apply_appends!(
            $db,
            (0..n).map(|i| {
                let $x = $seed.wrapping_add(i);
                $make_val
            })
        );

        // 2.
        apply_appends!(
            $db,
            (0..n).map(|i| {
                let $x = $seed.wrapping_add(n + i);
                $make_val
            })
        );

        // 3. Different base to avoid repeating batch 1 values.
        apply_appends!(
            $db,
            (0..n / 2).map(|i| {
                let $x = (!$seed).wrapping_add(i);
                $make_val
            })
        );

        $db.root().to_vec()
    }};
}

// Conformance tests (run via `just test-conformance`, not `just test`)

macro_rules! db_conformance {
    ($name:ident, $db:ty, $cfg_fn:expr, |$d:ident, $s:ident| $body:expr) => {
        struct $name;
        impl Conformance for $name {
            async fn commit($s: u64) -> Vec<u8> {
                deterministic::Runner::seeded($s).start(|ctx| async move {
                    let mut $d = <$db>::init(ctx.child("db"), ($cfg_fn)("cf", &ctx))
                        .await
                        .unwrap();
                    let root = $body;
                    $d.destroy().await.unwrap();
                    root
                })
            }
        }
    };
}

macro_rules! keyed_conformance {
    ($name:ident, $db:ty, $cfg_fn:expr) => {
        db_conformance!($name, $db, $cfg_fn, |db, seed| keyed_root(&mut db, seed)
            .await);
    };
}

macro_rules! immutable_conformance {
    ($name:ident, $db:ty, $cfg_fn:expr) => {
        db_conformance!($name, $db, $cfg_fn, |db, seed| immutable_root!(db, seed));
    };
}

macro_rules! immutable_compact_conformance {
    ($name:ident, $db:ty, $cfg_fn:expr) => {
        db_conformance!($name, $db, $cfg_fn, |db, seed| immutable_root_compact!(
            db, seed
        ));
    };
}

keyed_conformance!(
    AnyMmrUnorderedFixedConf,
    AnyMmrUnorderedFixed,
    any_fixed_config
);
keyed_conformance!(
    AnyMmrUnorderedVariableConf,
    AnyMmrUnorderedVariable,
    any_variable_config
);
keyed_conformance!(AnyMmrOrderedFixedConf, AnyMmrOrderedFixed, any_fixed_config);
keyed_conformance!(
    AnyMmrOrderedVariableConf,
    AnyMmrOrderedVariable,
    any_variable_config
);
keyed_conformance!(
    AnyMmbUnorderedFixedConf,
    AnyMmbUnorderedFixed,
    any_fixed_config
);
keyed_conformance!(
    AnyMmbUnorderedVariableConf,
    AnyMmbUnorderedVariable,
    any_variable_config
);
keyed_conformance!(AnyMmbOrderedFixedConf, AnyMmbOrderedFixed, any_fixed_config);
keyed_conformance!(
    AnyMmbOrderedVariableConf,
    AnyMmbOrderedVariable,
    any_variable_config
);
keyed_conformance!(
    CurrentMmrUnorderedFixedConf,
    CurrentMmrUnorderedFixed,
    current_fixed_config
);
keyed_conformance!(
    CurrentMmrUnorderedVariableConf,
    CurrentMmrUnorderedVariable,
    current_variable_config
);
keyed_conformance!(
    CurrentMmrOrderedFixedConf,
    CurrentMmrOrderedFixed,
    current_fixed_config
);
keyed_conformance!(
    CurrentMmrOrderedVariableConf,
    CurrentMmrOrderedVariable,
    current_variable_config
);
keyed_conformance!(
    CurrentMmbUnorderedFixedConf,
    CurrentMmbUnorderedFixed,
    current_fixed_config
);
keyed_conformance!(
    CurrentMmbUnorderedVariableConf,
    CurrentMmbUnorderedVariable,
    current_variable_config
);
keyed_conformance!(
    CurrentMmbOrderedFixedConf,
    CurrentMmbOrderedFixed,
    current_fixed_config
);
keyed_conformance!(
    CurrentMmbOrderedVariableConf,
    CurrentMmbOrderedVariable,
    current_variable_config
);

immutable_conformance!(
    ImmutableMmrFixedConf,
    ImmutableMmrFixed,
    immutable_fixed_config
);
immutable_conformance!(
    ImmutableMmbFixedConf,
    ImmutableMmbFixed,
    immutable_fixed_config
);
immutable_conformance!(
    ImmutableMmrVariableConf,
    ImmutableMmrVariable,
    immutable_variable_config
);
immutable_conformance!(
    ImmutableMmbVariableConf,
    ImmutableMmbVariable,
    immutable_variable_config
);

db_conformance!(
    KeylessMmrFixedConf,
    KeylessMmrFixed,
    keyless_fixed_config,
    |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
);
db_conformance!(
    KeylessMmbFixedConf,
    KeylessMmbFixed,
    keyless_fixed_config,
    |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
);
db_conformance!(
    KeylessMmrVariableConf,
    KeylessMmrVariable,
    keyless_variable_config,
    |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
);
db_conformance!(
    KeylessMmbVariableConf,
    KeylessMmbVariable,
    keyless_variable_config,
    |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
);

immutable_compact_conformance!(
    ImmutableMmrCompactFixedConf,
    ImmutableMmrCompactFixed,
    immutable_fixed_compact_config
);
immutable_compact_conformance!(
    ImmutableMmbCompactFixedConf,
    ImmutableMmbCompactFixed,
    immutable_fixed_compact_config
);
immutable_compact_conformance!(
    ImmutableMmrCompactVariableConf,
    ImmutableMmrCompactVariable,
    immutable_variable_compact_config
);
immutable_compact_conformance!(
    ImmutableMmbCompactVariableConf,
    ImmutableMmbCompactVariable,
    immutable_variable_compact_config
);

db_conformance!(
    KeylessMmrCompactFixedConf,
    KeylessMmrCompactFixed,
    keyless_fixed_compact_config,
    |db, seed| { keyless_root_compact!(db, seed, |x| U64::new(x)) }
);
db_conformance!(
    KeylessMmbCompactFixedConf,
    KeylessMmbCompactFixed,
    keyless_fixed_compact_config,
    |db, seed| { keyless_root_compact!(db, seed, |x| U64::new(x)) }
);
db_conformance!(
    KeylessMmrCompactVariableConf,
    KeylessMmrCompactVariable,
    keyless_variable_compact_config,
    |db, seed| { keyless_root_compact!(db, seed, |x| x.to_be_bytes().to_vec()) }
);
db_conformance!(
    KeylessMmbCompactVariableConf,
    KeylessMmbCompactVariable,
    keyless_variable_compact_config,
    |db, seed| { keyless_root_compact!(db, seed, |x| x.to_be_bytes().to_vec()) }
);

conformance_tests! {
    AnyMmrUnorderedFixedConf => 200,
    AnyMmrUnorderedVariableConf => 200,
    AnyMmrOrderedFixedConf => 200,
    AnyMmrOrderedVariableConf => 200,
    AnyMmbUnorderedFixedConf => 200,
    AnyMmbUnorderedVariableConf => 200,
    AnyMmbOrderedFixedConf => 200,
    AnyMmbOrderedVariableConf => 200,
    CurrentMmrUnorderedFixedConf => 200,
    CurrentMmrUnorderedVariableConf => 200,
    CurrentMmrOrderedFixedConf => 200,
    CurrentMmrOrderedVariableConf => 200,
    CurrentMmbUnorderedFixedConf => 200,
    CurrentMmbUnorderedVariableConf => 200,
    CurrentMmbOrderedFixedConf => 200,
    CurrentMmbOrderedVariableConf => 200,
    ImmutableMmrFixedConf => 200,
    ImmutableMmbFixedConf => 200,
    ImmutableMmrVariableConf => 200,
    ImmutableMmbVariableConf => 200,
    KeylessMmrFixedConf => 200,
    KeylessMmbFixedConf => 200,
    KeylessMmrVariableConf => 200,
    KeylessMmbVariableConf => 200,
    ImmutableMmrCompactFixedConf => 200,
    ImmutableMmbCompactFixedConf => 200,
    ImmutableMmrCompactVariableConf => 200,
    ImmutableMmbCompactVariableConf => 200,
    KeylessMmrCompactFixedConf => 200,
    KeylessMmbCompactFixedConf => 200,
    KeylessMmrCompactVariableConf => 200,
    KeylessMmbCompactVariableConf => 200,
}

// Order-independence tests (run via `just test`, unlike the conformance tests above)
//
// Within a single batch, the insertion order of operations must not affect the root.
// Keyed and immutable variants sort operations internally (BTreeMap for keys, sorted
// locations for existing entries). Keyless variants preserve append order, so they
// are intentionally excluded.
//
// Each test creates two databases (`fwd` and `rev`) and applies the same set of
// operations in forward and reverse order, then asserts the roots are equal.

async fn apply_both_orders<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
    fwd: &mut D,
    rev: &mut D,
    ops: Vec<(Digest, Option<Digest>)>,
    msg: &str,
) {
    apply_writes(fwd, ops.clone()).await;
    let mut reversed = ops;
    reversed.reverse();
    apply_writes(rev, reversed).await;
    assert_eq!(fwd.root().to_vec(), rev.root().to_vec(), "{msg}");
}

async fn assert_keyed_order_independent<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
    fwd: &mut D,
    rev: &mut D,
) {
    let mut creates: Vec<_> = (0..20)
        .map(|i| (to_digest(i), Some(to_val(i, 0))))
        .collect();
    for i in 0..8u64 {
        creates.push((colliding_digest(0xAB, i), Some(to_val(i, 100))));
    }
    apply_both_orders(fwd, rev, creates, "create order must not affect root").await;

    let mut mixed: Vec<_> = (0..20)
        .map(|i| {
            if i % 2 == 1 {
                (to_digest(i), None)
            } else {
                (to_digest(i), Some(to_val(i, 200)))
            }
        })
        .collect();
    for i in 0..8u64 {
        mixed.push((colliding_digest(0xAB, i), Some(to_val(i, 300))));
    }
    apply_both_orders(fwd, rev, mixed, "delete+update order must not affect root").await;

    let mut recreates: Vec<_> = (0..20)
        .filter(|i| i % 2 == 1)
        .map(|i| (to_digest(i), Some(to_val(i, 400))))
        .collect();
    for i in 8..16u64 {
        recreates.push((colliding_digest(0xAB, i), Some(to_val(i, 500))));
    }
    apply_both_orders(
        fwd,
        rev,
        recreates,
        "recreate-after-delete order must not affect root",
    )
    .await;
}

// Macro rather than a generic function because compact immutable apply_batch is sync.
macro_rules! assert_immutable_order_independent_compact {
    ($fwd:ident, $rev:ident) => {{
        let mut ops: Vec<_> = (0..20).map(|i| (to_digest(i), to_val(i, 0))).collect();
        for i in 0..8u64 {
            ops.push((colliding_digest(0xCD, i), to_val(i, 100)));
        }

        let fwd_floor = $fwd.inactivity_floor_loc();
        let mut batch = $fwd.new_batch();
        for &(k, v) in &ops {
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&$fwd, None, fwd_floor);
        $fwd.apply_batch(merkleized).unwrap();

        let rev_floor = $rev.inactivity_floor_loc();
        let mut batch = $rev.new_batch();
        for &(k, v) in ops.iter().rev() {
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&$rev, None, rev_floor);
        $rev.apply_batch(merkleized).unwrap();

        assert_eq!(
            $fwd.root().to_vec(),
            $rev.root().to_vec(),
            "immutable set order must not affect root"
        );
    }};
}

// Macro rather than a generic function because immutable Db types don't implement DbAny.
macro_rules! assert_immutable_order_independent {
    ($fwd:ident, $rev:ident) => {{
        let mut ops: Vec<_> = (0..20).map(|i| (to_digest(i), to_val(i, 0))).collect();
        for i in 0..8u64 {
            ops.push((colliding_digest(0xCD, i), to_val(i, 100)));
        }

        let fwd_floor = $fwd.inactivity_floor_loc();
        let mut batch = $fwd.new_batch();
        for &(k, v) in &ops {
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&$fwd, None, fwd_floor);
        $fwd.apply_batch(merkleized).await.unwrap();

        let rev_floor = $rev.inactivity_floor_loc();
        let mut batch = $rev.new_batch();
        for &(k, v) in ops.iter().rev() {
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&$rev, None, rev_floor);
        $rev.apply_batch(merkleized).await.unwrap();

        assert_eq!(
            $fwd.root().to_vec(),
            $rev.root().to_vec(),
            "immutable set order must not affect root"
        );
    }};
}

macro_rules! order_test {
    ($name:ident, $db:ty, $cfg_fn:expr, |$fwd:ident, $rev:ident| $body:expr) => {
        #[test]
        fn $name() {
            deterministic::Runner::default().start(|ctx| async move {
                let mut $fwd = <$db>::init(ctx.child("fwd"), ($cfg_fn)("fwd", &ctx))
                    .await
                    .unwrap();
                let mut $rev = <$db>::init(ctx.child("rev"), ($cfg_fn)("rev", &ctx))
                    .await
                    .unwrap();
                $body;
                $fwd.destroy().await.unwrap();
                $rev.destroy().await.unwrap();
            });
        }
    };
}

order_test!(
    test_order_any_mmr_unordered_fixed,
    AnyMmrUnorderedFixed,
    any_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_any_mmr_unordered_variable,
    AnyMmrUnorderedVariable,
    any_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_any_mmr_ordered_fixed,
    AnyMmrOrderedFixed,
    any_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_any_mmr_ordered_variable,
    AnyMmrOrderedVariable,
    any_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_any_mmb_unordered_fixed,
    AnyMmbUnorderedFixed,
    any_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_any_mmb_unordered_variable,
    AnyMmbUnorderedVariable,
    any_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_any_mmb_ordered_fixed,
    AnyMmbOrderedFixed,
    any_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_any_mmb_ordered_variable,
    AnyMmbOrderedVariable,
    any_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmr_unordered_fixed,
    CurrentMmrUnorderedFixed,
    current_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmr_unordered_variable,
    CurrentMmrUnorderedVariable,
    current_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmr_ordered_fixed,
    CurrentMmrOrderedFixed,
    current_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmr_ordered_variable,
    CurrentMmrOrderedVariable,
    current_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmb_unordered_fixed,
    CurrentMmbUnorderedFixed,
    current_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmb_unordered_variable,
    CurrentMmbUnorderedVariable,
    current_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmb_ordered_fixed,
    CurrentMmbOrderedFixed,
    current_fixed_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_cur_mmb_ordered_variable,
    CurrentMmbOrderedVariable,
    current_variable_config,
    |fwd, rev| assert_keyed_order_independent(&mut fwd, &mut rev).await
);
order_test!(
    test_order_immutable_mmr_fixed,
    ImmutableMmrFixed,
    immutable_fixed_config,
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
order_test!(
    test_order_immutable_mmr_variable,
    ImmutableMmrVariable,
    immutable_variable_config,
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
order_test!(
    test_order_immutable_mmb_fixed,
    ImmutableMmbFixed,
    immutable_fixed_config,
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
order_test!(
    test_order_immutable_mmb_variable,
    ImmutableMmbVariable,
    immutable_variable_config,
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
order_test!(
    test_order_immutable_mmr_compact_fixed,
    ImmutableMmrCompactFixed,
    immutable_fixed_compact_config,
    |fwd, rev| assert_immutable_order_independent_compact!(fwd, rev)
);
order_test!(
    test_order_immutable_mmb_compact_fixed,
    ImmutableMmbCompactFixed,
    immutable_fixed_compact_config,
    |fwd, rev| assert_immutable_order_independent_compact!(fwd, rev)
);
order_test!(
    test_order_immutable_mmr_compact_variable,
    ImmutableMmrCompactVariable,
    immutable_variable_compact_config,
    |fwd, rev| assert_immutable_order_independent_compact!(fwd, rev)
);
order_test!(
    test_order_immutable_mmb_compact_variable,
    ImmutableMmbCompactVariable,
    immutable_variable_compact_config,
    |fwd, rev| assert_immutable_order_independent_compact!(fwd, rev)
);
