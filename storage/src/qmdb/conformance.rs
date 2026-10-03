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
    merkle::{Family, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        any::{
            self,
            traits::{DbAny, UnmerkleizedBatch as _},
        },
        current,
        floor::Proportional,
        immutable,
    },
    translator::{OneCap, TwoCap},
};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_macros::boxed;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use std::num::{NonZeroU16, NonZeroUsize};

// Type aliases

type Ctx = deterministic::Context;

type AnyMmrUnorderedFixed =
    any::unordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;
type AnyMmrUnorderedVariable =
    any::unordered::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;
type AnyMmrOrderedFixed =
    any::ordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;
type AnyMmrOrderedVariable =
    any::ordered::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;

type AnyMmbUnorderedFixed =
    any::unordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;
type AnyMmbUnorderedVariable =
    any::unordered::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;
type AnyMmbOrderedFixed =
    any::ordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;
type AnyMmbOrderedVariable =
    any::ordered::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, Sequential>;

type CurrentMmrUnorderedFixed =
    current::unordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, 32, Sequential>;
type CurrentMmrUnorderedVariable = current::unordered::variable::Db<
    mmr::Family,
    Ctx,
    Digest,
    Digest,
    Sha256,
    OneCap,
    32,
    Sequential,
>;
type CurrentMmrOrderedFixed =
    current::ordered::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, OneCap, 32, Sequential>;
type CurrentMmrOrderedVariable = current::ordered::variable::Db<
    mmr::Family,
    Ctx,
    Digest,
    Digest,
    Sha256,
    OneCap,
    32,
    Sequential,
>;

type CurrentMmbUnorderedFixed =
    current::unordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, 32, Sequential>;
type CurrentMmbUnorderedVariable = current::unordered::variable::Db<
    mmb::Family,
    Ctx,
    Digest,
    Digest,
    Sha256,
    OneCap,
    32,
    Sequential,
>;
type CurrentMmbOrderedFixed =
    current::ordered::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, OneCap, 32, Sequential>;
type CurrentMmbOrderedVariable = current::ordered::variable::Db<
    mmb::Family,
    Ctx,
    Digest,
    Digest,
    Sha256,
    OneCap,
    32,
    Sequential,
>;

type ImmutableMmrFixed =
    immutable::fixed::Db<mmr::Family, Ctx, Digest, Digest, Sha256, TwoCap, Sequential>;
type ImmutableMmbFixed =
    immutable::fixed::Db<mmb::Family, Ctx, Digest, Digest, Sha256, TwoCap, Sequential>;
type ImmutableMmrVariable =
    immutable::variable::Db<mmr::Family, Ctx, Digest, Digest, Sha256, TwoCap, Sequential>;
type ImmutableMmbVariable =
    immutable::variable::Db<mmb::Family, Ctx, Digest, Digest, Sha256, TwoCap, Sequential>;

type ImmutableMmrCompactFixed =
    immutable::fixed::CompactDb<mmr::Family, Ctx, Digest, Digest, Sha256, Sequential>;
type ImmutableMmbCompactFixed =
    immutable::fixed::CompactDb<mmb::Family, Ctx, Digest, Digest, Sha256, Sequential>;
type ImmutableMmrCompactVariable =
    immutable::variable::CompactDb<mmr::Family, Ctx, Digest, Digest, Sha256, ((), ()), Sequential>;
type ImmutableMmbCompactVariable =
    immutable::variable::CompactDb<mmb::Family, Ctx, Digest, Digest, Sha256, ((), ()), Sequential>;

// Config constructors

const PAGE_SIZE: NonZeroU16 = NZU16!(101);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

fn merkle_config(suffix: &str, page_cache: &CacheRef) -> MerkleConfig<Sequential> {
    MerkleConfig {
        journal_partition: format!("{suffix}-mj"),
        metadata_partition: format!("{suffix}-mm"),
        items_per_blob: NZU64!(11),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
        strategy: Sequential,
        page_cache: page_cache.clone(),
    }
}

fn fixed_log_config(suffix: &str, page_cache: CacheRef) -> FConfig {
    FConfig {
        partition: format!("{suffix}-log"),
        items_per_blob: NZU64!(7),
        page_cache,
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
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
        replay_buffer: NZUsize!(1024),
    }
}

fn any_fixed_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> any::FixedConfig<OneCap, Sequential> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    any::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: fixed_log_config(suffix, pc),
        translator: OneCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn any_variable_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> any::VariableConfig<OneCap, ((), ()), Sequential> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    any::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: variable_log_config(suffix, pc, ((), ())),
        translator: OneCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn current_fixed_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> current::FixedConfig<OneCap, Sequential> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    current::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: fixed_log_config(suffix, pc),
        grafted_metadata_partition: format!("{suffix}-graft"),
        translator: OneCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn current_variable_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> current::VariableConfig<OneCap, ((), ()), Sequential> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    current::Config {
        merkle_config: merkle_config(suffix, &pc),
        journal_config: variable_log_config(suffix, pc, ((), ())),
        grafted_metadata_partition: format!("{suffix}-graft"),
        translator: OneCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn immutable_fixed_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> immutable::fixed::Config<TwoCap, Sequential> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    immutable::Config {
        merkle_config: merkle_config(suffix, &pc),
        log: fixed_log_config(suffix, pc),
        translator: TwoCap,
        init_buffer: NZUsize!(1 << 21),
    }
}

fn immutable_variable_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> immutable::variable::Config<TwoCap, ((), ()), Sequential> {
    let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    immutable::Config {
        merkle_config: merkle_config(suffix, &pc),
        log: variable_log_config(suffix, pc, ((), ())),
        translator: TwoCap,
        init_buffer: NZUsize!(1 << 21),
    }
}

fn compact_witness_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> crate::journal::contiguous::variable::Config<()> {
    crate::journal::contiguous::variable::Config {
        partition: format!("{suffix}-compact-witness"),
        items_per_section: NZU64!(64),
        compression: None,
        codec_config: (),
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
    }
}

fn immutable_fixed_compact_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> immutable::fixed::CompactConfig<Sequential> {
    immutable::CompactConfig {
        strategy: Sequential,
        witness: compact_witness_config(suffix, pooler),
        commit_codec_config: (),
    }
}

fn immutable_variable_compact_config(
    suffix: &str,
    pooler: &impl BufferPooler,
) -> immutable::variable::CompactConfig<((), ()), Sequential> {
    immutable::CompactConfig {
        strategy: Sequential,
        witness: compact_witness_config(suffix, pooler),
        commit_codec_config: ((), ()),
    }
}

// Workloads

fn to_digest(i: u64) -> Digest {
    Sha256::hash(&[&i.to_be_bytes()])
}

fn to_val(i: u64, salt: u64) -> Digest {
    Sha256::hash(&[&i.to_be_bytes(), &salt.wrapping_add(1).to_be_bytes()])
}

/// Digest whose first byte is `prefix`, guaranteeing translator collisions under OneCap.
fn colliding_digest(prefix: u8, suffix: u64) -> Digest {
    crate::qmdb::any::test::colliding_digest(prefix, suffix)
}

/// Apply a batch of keyed writes (creates, updates, or deletes) to the database.
async fn apply_writes<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
    db: D,
    writes: Vec<(Digest, Option<Digest>)>,
) -> D {
    let mut batch = db.new_batch();
    for (k, v) in writes {
        batch = batch.write(k, v);
    }
    let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
    let (db, _) = db.apply_batch(merkleized).await.unwrap();
    db
}

#[cfg(feature = "arbitrary")]
mod tests {
    use super::*;
    use crate::qmdb::{
        floor::{Compact, Decision, Entry, Hold, Limits, Policy},
        keyless, store,
    };
    use commonware_conformance::{Conformance, conformance_tests};
    use commonware_runtime::conformance::{StorageConformance, StorageWorkload};
    use commonware_utils::sequence::U64;
    use core::mem;
    use std::collections::{BTreeMap, BTreeSet};

    type KeylessMmrFixed = keyless::fixed::Db<mmr::Family, Ctx, U64, Sha256, Sequential>;
    type KeylessMmbFixed = keyless::fixed::Db<mmb::Family, Ctx, U64, Sha256, Sequential>;
    type KeylessMmrVariable = keyless::variable::Db<mmr::Family, Ctx, Vec<u8>, Sha256, Sequential>;
    type KeylessMmbVariable = keyless::variable::Db<mmb::Family, Ctx, Vec<u8>, Sha256, Sequential>;

    type KeylessMmrCompactFixed =
        keyless::fixed::CompactDb<mmr::Family, Ctx, U64, Sha256, Sequential>;
    type KeylessMmbCompactFixed =
        keyless::fixed::CompactDb<mmb::Family, Ctx, U64, Sha256, Sequential>;
    type KeylessMmrCompactVariable = keyless::variable::CompactDb<
        mmr::Family,
        Ctx,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
        Sequential,
    >;
    type KeylessMmbCompactVariable = keyless::variable::CompactDb<
        mmb::Family,
        Ctx,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
        Sequential,
    >;

    fn keyless_fixed_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> keyless::fixed::Config<Sequential> {
        let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        keyless::Config {
            merkle: merkle_config(suffix, &pc),
            log: fixed_log_config(suffix, pc),
        }
    }

    fn keyless_variable_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> keyless::variable::Config<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        keyless::Config {
            merkle: merkle_config(suffix, &pc),
            log: variable_log_config(suffix, pc, ((0..=10000).into(), ())),
        }
    }

    fn keyless_fixed_compact_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> keyless::fixed::CompactConfig<Sequential> {
        keyless::CompactConfig {
            strategy: Sequential,
            witness: compact_witness_config(suffix, pooler),
            commit_codec_config: (),
        }
    }

    fn keyless_variable_compact_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> keyless::variable::CompactConfig<(commonware_codec::RangeCfg<usize>, ()), Sequential> {
        keyless::CompactConfig {
            strategy: Sequential,
            witness: compact_witness_config(suffix, pooler),
            commit_codec_config: ((0..=10000usize).into(), ()),
        }
    }

    type Store = store::db::Db<Ctx, Digest, Digest, OneCap>;

    fn store_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> store::db::Config<OneCap, ((), ())> {
        let pc = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        store::db::Config {
            log: variable_log_config(suffix, pc, ((), ())),
            translator: OneCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
        }
    }

    /// Deterministically select ~20% of keys for deletion. XOR with the seed ensures
    /// the set of deleted indices varies across seeds.
    const fn is_deleted(seed: u64, i: u64) -> bool {
        (seed ^ i).is_multiple_of(5)
    }

    /// Apply a batch of immutable sets to the database.
    macro_rules! apply_sets {
        ($db:ident, $ops:expr) => {{
            let floor = $db.inactivity_floor_loc();
            let mut batch = $db.new_batch();
            for (k, v) in $ops {
                batch = batch.set(k, v);
            }
            let merkleized = batch.merkleize(&$db, None, floor).await.unwrap();
            ($db, _) = $db.apply_batch(merkleized).await.unwrap();
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
            let merkleized = batch.merkleize(&$db, None, floor).await.unwrap();
            ($db, _) = $db.apply_batch(merkleized).await.unwrap();
        }};
    }

    /// 4-batch keyed workload exercising every mutation type.
    ///
    /// 1. Create n keys with initial values.
    /// 2. Delete ~20% of keys, update the rest.
    /// 3. Recreate the deleted keys alongside new keys that collide under the translator.
    /// 4. Update original keys; delete odd-indexed colliding keys, update even-indexed ones.
    async fn keyed_root<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
        db: D,
        seed: u64,
    ) -> (D, Vec<u8>) {
        let n = seed % 50 + 5;

        // Choose a translator bucket for colliding keys (varies per seed).
        let prefix = (seed % 256) as u8;

        // 1. Create n keys.
        let writes: Vec<_> = (0..n).map(|i| (to_digest(i), Some(to_val(i, 1)))).collect();
        let db = apply_writes(db, writes).await;

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
        let db = apply_writes(db, writes).await;

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
        let db = apply_writes(db, writes).await;

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
        let db = apply_writes(db, writes).await;

        let root = db.root().to_vec();
        (db, root)
    }

    /// The policy a batch of the floor workload advances its floor with.
    #[derive(Clone, Copy)]
    enum Rule {
        /// [`Proportional`].
        Proportional,
        /// [`Hold`].
        Hold,
        /// [`Compact`] with these limits.
        Compact { entries: usize, skips: u64 },
        /// [`Seeded`] with these limits.
        Seeded { entries: usize, skips: u64 },
    }

    /// The writes of a batch and the policy it advances its floor with.
    type Batch = (Vec<(Digest, Option<Digest>)>, Rule);

    /// A policy that keeps, evicts, replaces, or stops at each update by a rule over its
    /// location, its key, and `seed`.
    struct Seeded {
        seed: u64,
        entries: usize,
        skips: u64,
    }

    impl<F: Family> Policy<F, Digest, Digest> for Seeded {
        fn limits(&self) -> Limits {
            Limits::Fixed {
                entries: self.entries,
                skips: self.skips,
            }
        }

        fn decide<'a>(&mut self, entry: Entry<'a, F, Digest, Digest>) -> Decision<'a, Digest> {
            match (*entry.location() ^ self.seed ^ u64::from(entry.key()[31])) % 8 {
                0 => entry.evict().0,
                1 => {
                    let value = Sha256::hash(&[entry.value().as_ref()]);
                    entry.replace(value)
                }
                2 => entry.stop(),
                _ => entry.keep(),
            }
        }
    }

    /// The first id of the keys that share a translator bucket.
    const COLLIDING: u64 = 10_000;

    /// Builds the batches of [`floor_batches`] over key ids.
    struct Plan {
        seed: u64,
        prefix: u8,
        live: BTreeSet<u64>,
        dead: BTreeSet<u64>,
        writes: BTreeMap<Digest, Option<Digest>>,
        batches: Vec<Batch>,
    }

    impl Plan {
        /// The key with `id`. Keys with ids from [`COLLIDING`] share a translator bucket.
        fn key(&self, id: u64) -> Digest {
            if id >= COLLIDING {
                colliding_digest(self.prefix, id)
            } else {
                to_digest(id)
            }
        }

        /// Write a new value for `id` in the open batch.
        fn set(&mut self, id: u64) {
            let value = to_val(id, self.batches.len() as u64);
            self.writes.insert(self.key(id), Some(value));
            self.dead.remove(&id);
            self.live.insert(id);
        }

        /// Delete `id` in the open batch.
        fn delete(&mut self, id: u64) {
            self.writes.insert(self.key(id), None);
            if self.live.remove(&id) {
                self.dead.insert(id);
            }
        }

        /// The `j`th seeded pick from the `ids` the open batch does not write yet.
        fn pick(&self, ids: &BTreeSet<u64>, j: u64) -> Option<u64> {
            let ids: Vec<u64> = ids
                .iter()
                .copied()
                .filter(|id| !self.writes.contains_key(&self.key(*id)))
                .collect();
            if ids.is_empty() {
                return None;
            }
            let round = self.batches.len() as u64;
            let digest = Sha256::hash(&[
                &self.seed.to_be_bytes(),
                &round.to_be_bytes(),
                &j.to_be_bytes(),
            ]);
            let mix = u64::from_be_bytes(digest[..8].try_into().unwrap());
            Some(ids[(mix % ids.len() as u64) as usize])
        }

        /// The `j`th seeded pick from the live ids the open batch does not write yet.
        fn live(&self, j: u64) -> u64 {
            self.pick(&self.live, j).unwrap()
        }

        /// Close the open batch with `rule`.
        fn close(&mut self, rule: Rule) {
            let writes = mem::take(&mut self.writes).into_iter().collect();
            self.batches.push((writes, rule));
        }

        /// Close the open batch with the rule its index selects.
        fn push(&mut self) {
            let round = self.batches.len() as u64;
            let rule = match round % 8 {
                2 => Rule::Hold,
                4 => Rule::Compact {
                    entries: 1 + (self.seed % 3) as usize,
                    skips: round % 5,
                },
                6 => Rule::Seeded {
                    entries: 2 + (self.seed % 4) as usize,
                    skips: round % 7,
                },
                _ => Rule::Proportional,
            };
            self.close(rule);
        }
    }

    /// Floor-sensitive keyed workload. Returns the writes of each batch and the policy it advances
    /// its floor with.
    ///
    /// After the first, each batch writes a few of many live keys, so each floor advance moves
    /// updates of unwritten keys and the number it moves shows in the root. Unless a step names
    /// its policy, batches at indices 2, 4, and 6 modulo 8 use [`Hold`], [`Compact`] under small
    /// limits, and [`Seeded`], and the rest use [`Proportional`].
    ///
    /// 1. Create n keys and eight keys that share a translator bucket.
    /// 2. Update three live keys in each of 12 batches.
    /// 3. Delete two live keys, update one, and delete one missing key in each of 12 batches.
    /// 4. Recreate two deleted keys and update one live key in each of 8 batches.
    /// 5. Delete or recreate one colliding key, and update another if it is live, in each of 6
    ///    batches.
    /// 6. Commit a batch without writes under [`Proportional`], then another under [`Seeded`].
    /// 7. Delete four live keys in each batch until four keys remain.
    /// 8. Create 16 keys, then update two live keys in each of 4 batches.
    fn floor_batches(seed: u64) -> Vec<Batch> {
        let n = seed % 48 + 40;
        let mut plan = Plan {
            seed,
            prefix: (seed % 256) as u8,
            live: BTreeSet::new(),
            dead: BTreeSet::new(),
            writes: BTreeMap::new(),
            batches: Vec::new(),
        };

        // 1. Create n keys and eight colliding keys.
        for id in (0..n).chain(COLLIDING..COLLIDING + 8) {
            plan.set(id);
        }
        plan.close(Rule::Proportional);

        // 2. Update three live keys per batch.
        for _ in 0..12 {
            for j in 0..3 {
                plan.set(plan.live(j));
            }
            plan.push();
        }

        // 3. Delete two live keys, update one, and delete a missing key per batch. Missing keys
        //    alternate between fresh ids and fresh colliding ids.
        for round in 0..12 {
            for j in 0..2 {
                plan.delete(plan.live(j));
            }
            plan.set(plan.live(2));
            let missing = if round % 2 == 0 {
                5_000
            } else {
                COLLIDING + 5_000
            };
            plan.delete(missing + round);
            plan.push();
        }

        // 4. Recreate two deleted keys and update one live key per batch.
        for _ in 0..8 {
            for j in 0..2 {
                if let Some(id) = plan.pick(&plan.dead, j) {
                    plan.set(id);
                }
            }
            plan.set(plan.live(2));
            plan.push();
        }

        // 5. Toggle one colliding key and update another per batch.
        for round in 0..6 {
            let toggled = COLLIDING + (3 * round) % 8;
            if plan.live.contains(&toggled) {
                plan.delete(toggled);
            } else {
                plan.set(toggled);
            }
            let updated = COLLIDING + (3 * round + 1) % 8;
            if plan.live.contains(&updated) {
                plan.set(updated);
            }
            plan.push();
        }

        // 6. Commit two batches without writes.
        plan.close(Rule::Proportional);
        plan.close(Rule::Seeded {
            entries: 4,
            skips: 4,
        });

        // 7. Delete four live keys per batch until four remain.
        while plan.live.len() > 4 {
            for j in 0..4 {
                if plan.live.len() > 4 {
                    plan.delete(plan.live(j));
                }
            }
            plan.push();
        }

        // 8. Create 16 keys, then update two live keys per batch.
        for id in n..n + 16 {
            plan.set(id);
        }
        plan.push();
        for _ in 0..4 {
            for j in 0..2 {
                plan.set(plan.live(j));
            }
            plan.push();
        }
        plan.batches
    }

    /// Apply [`floor_batches`] for `seed` to `db` and return its root.
    async fn floor_root<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
        mut db: D,
        seed: u64,
    ) -> (D, Vec<u8>) {
        for (writes, rule) in floor_batches(seed) {
            let batch = writes
                .into_iter()
                .fold(db.new_batch(), |batch, (key, value)| {
                    batch.write(key, value)
                });
            let merkleized = match rule {
                Rule::Proportional => batch.merkleize(&db, None, &mut Proportional).await,
                Rule::Hold => batch.merkleize(&db, None, &mut Hold).await,
                Rule::Compact { entries, skips } => {
                    let mut policy = Compact { entries, skips };
                    batch.merkleize(&db, None, &mut policy).await
                }
                Rule::Seeded { entries, skips } => {
                    let mut policy = Seeded {
                        seed,
                        entries,
                        skips,
                    };
                    batch.merkleize(&db, None, &mut policy).await
                }
            }
            .unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }
        let root = db.root().to_vec();
        (db, root)
    }

    /// [`floor_batches`] on a store, applying every batch with its policy.
    struct StoreFloorStorage;

    impl StorageWorkload for StoreFloorStorage {
        type Error = crate::qmdb::Error<mmr::Family>;

        async fn run(context: Ctx, seed: u64) -> Result<(), Self::Error> {
            let cfg = store_config("store", &context);
            let mut db = Store::init(context.child("db"), cfg, None).await?;
            for (writes, rule) in floor_batches(seed) {
                let batch = writes.into_iter().collect();
                (db, _) = match rule {
                    Rule::Proportional => db.apply_batch(batch, &mut Proportional).await,
                    Rule::Hold => db.apply_batch(batch, &mut Hold).await,
                    Rule::Compact { entries, skips } => {
                        let mut policy = Compact { entries, skips };
                        db.apply_batch(batch, &mut policy).await
                    }
                    Rule::Seeded { entries, skips } => {
                        let mut policy = Seeded {
                            seed,
                            entries,
                            skips,
                        };
                        db.apply_batch(batch, &mut policy).await
                    }
                }?;
            }
            db.sync().await?;
            Ok(())
        }
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

    macro_rules! db_conformance {
        ($name:ident, $db:ty, $cfg_fn:expr, |$d:ident, $s:ident| $body:expr) => {
            struct $name;
            impl Conformance for $name {
                async fn commit($s: u64) -> Vec<u8> {
                    deterministic::Runner::seeded($s).start(|ctx| async move {
                        let mut $d = <$db>::init(ctx.child("db"), ($cfg_fn)("cf", &ctx), None)
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
            db_conformance!($name, $db, $cfg_fn, |db, seed| {
                let (d, root) = keyed_root(db, seed).await;
                db = d;
                root
            });
        };
    }

    macro_rules! floor_conformance {
        ($name:ident, $db:ty, $cfg_fn:expr) => {
            db_conformance!($name, $db, $cfg_fn, |db, seed| {
                let (d, root) = floor_root(db, seed).await;
                db = d;
                root
            });
        };
    }

    macro_rules! immutable_conformance {
        ($name:ident, $db:ty, $cfg_fn:expr) => {
            db_conformance!($name, $db, $cfg_fn, |db, seed| immutable_root!(db, seed));
        };
    }

    macro_rules! storage_audit_conformance {
        ($name:ident, $family:ty, $db:ty, $cfg_fn:expr, |$d:ident, $s:ident| $body:expr) => {
            struct $name;

            impl StorageWorkload for $name {
                type Error = crate::qmdb::Error<$family>;

                async fn run(context: Ctx, $s: u64) -> Result<(), Self::Error> {
                    let suffix = format!("{}-{}", stringify!($name), $s);
                    let mut $d =
                        <$db>::init(context.child("db"), ($cfg_fn)(&suffix, &context), None)
                            .await?;
                    let _root = $body;
                    $d.sync().await?;
                    Ok(())
                }
            }
        };
    }

    macro_rules! keyed_storage_audit {
        ($name:ident, $family:ty, $db:ty, $cfg_fn:expr) => {
            storage_audit_conformance!($name, $family, $db, $cfg_fn, |db, seed| {
                let (d, root) = keyed_root(db, seed).await;
                db = d;
                root
            });
        };
    }

    macro_rules! immutable_storage_audit {
        ($name:ident, $family:ty, $db:ty, $cfg_fn:expr) => {
            storage_audit_conformance!($name, $family, $db, $cfg_fn, |db, seed| {
                immutable_root!(db, seed)
            });
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

    floor_conformance!(
        AnyMmrUnorderedFixedFloorConf,
        AnyMmrUnorderedFixed,
        any_fixed_config
    );
    floor_conformance!(
        AnyMmrUnorderedVariableFloorConf,
        AnyMmrUnorderedVariable,
        any_variable_config
    );
    floor_conformance!(
        AnyMmrOrderedFixedFloorConf,
        AnyMmrOrderedFixed,
        any_fixed_config
    );
    floor_conformance!(
        AnyMmrOrderedVariableFloorConf,
        AnyMmrOrderedVariable,
        any_variable_config
    );
    floor_conformance!(
        AnyMmbUnorderedFixedFloorConf,
        AnyMmbUnorderedFixed,
        any_fixed_config
    );
    floor_conformance!(
        AnyMmbUnorderedVariableFloorConf,
        AnyMmbUnorderedVariable,
        any_variable_config
    );
    floor_conformance!(
        AnyMmbOrderedFixedFloorConf,
        AnyMmbOrderedFixed,
        any_fixed_config
    );
    floor_conformance!(
        AnyMmbOrderedVariableFloorConf,
        AnyMmbOrderedVariable,
        any_variable_config
    );
    floor_conformance!(
        CurrentMmrUnorderedFixedFloorConf,
        CurrentMmrUnorderedFixed,
        current_fixed_config
    );
    floor_conformance!(
        CurrentMmrUnorderedVariableFloorConf,
        CurrentMmrUnorderedVariable,
        current_variable_config
    );
    floor_conformance!(
        CurrentMmrOrderedFixedFloorConf,
        CurrentMmrOrderedFixed,
        current_fixed_config
    );
    floor_conformance!(
        CurrentMmrOrderedVariableFloorConf,
        CurrentMmrOrderedVariable,
        current_variable_config
    );
    floor_conformance!(
        CurrentMmbUnorderedFixedFloorConf,
        CurrentMmbUnorderedFixed,
        current_fixed_config
    );
    floor_conformance!(
        CurrentMmbUnorderedVariableFloorConf,
        CurrentMmbUnorderedVariable,
        current_variable_config
    );
    floor_conformance!(
        CurrentMmbOrderedFixedFloorConf,
        CurrentMmbOrderedFixed,
        current_fixed_config
    );
    floor_conformance!(
        CurrentMmbOrderedVariableFloorConf,
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

    immutable_conformance!(
        ImmutableMmrCompactFixedConf,
        ImmutableMmrCompactFixed,
        immutable_fixed_compact_config
    );
    immutable_conformance!(
        ImmutableMmbCompactFixedConf,
        ImmutableMmbCompactFixed,
        immutable_fixed_compact_config
    );
    immutable_conformance!(
        ImmutableMmrCompactVariableConf,
        ImmutableMmrCompactVariable,
        immutable_variable_compact_config
    );
    immutable_conformance!(
        ImmutableMmbCompactVariableConf,
        ImmutableMmbCompactVariable,
        immutable_variable_compact_config
    );

    db_conformance!(
        KeylessMmrCompactFixedConf,
        KeylessMmrCompactFixed,
        keyless_fixed_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
    );
    db_conformance!(
        KeylessMmbCompactFixedConf,
        KeylessMmbCompactFixed,
        keyless_fixed_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
    );
    db_conformance!(
        KeylessMmrCompactVariableConf,
        KeylessMmrCompactVariable,
        keyless_variable_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
    );
    db_conformance!(
        KeylessMmbCompactVariableConf,
        KeylessMmbCompactVariable,
        keyless_variable_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
    );

    keyed_storage_audit!(
        AnyMmrUnorderedFixedStorage,
        mmr::Family,
        AnyMmrUnorderedFixed,
        any_fixed_config
    );
    keyed_storage_audit!(
        AnyMmrUnorderedVariableStorage,
        mmr::Family,
        AnyMmrUnorderedVariable,
        any_variable_config
    );
    keyed_storage_audit!(
        AnyMmrOrderedFixedStorage,
        mmr::Family,
        AnyMmrOrderedFixed,
        any_fixed_config
    );
    keyed_storage_audit!(
        AnyMmrOrderedVariableStorage,
        mmr::Family,
        AnyMmrOrderedVariable,
        any_variable_config
    );
    keyed_storage_audit!(
        AnyMmbUnorderedFixedStorage,
        mmb::Family,
        AnyMmbUnorderedFixed,
        any_fixed_config
    );
    keyed_storage_audit!(
        AnyMmbUnorderedVariableStorage,
        mmb::Family,
        AnyMmbUnorderedVariable,
        any_variable_config
    );
    keyed_storage_audit!(
        AnyMmbOrderedFixedStorage,
        mmb::Family,
        AnyMmbOrderedFixed,
        any_fixed_config
    );
    keyed_storage_audit!(
        AnyMmbOrderedVariableStorage,
        mmb::Family,
        AnyMmbOrderedVariable,
        any_variable_config
    );
    keyed_storage_audit!(
        CurrentMmrUnorderedFixedStorage,
        mmr::Family,
        CurrentMmrUnorderedFixed,
        current_fixed_config
    );
    keyed_storage_audit!(
        CurrentMmrUnorderedVariableStorage,
        mmr::Family,
        CurrentMmrUnorderedVariable,
        current_variable_config
    );
    keyed_storage_audit!(
        CurrentMmrOrderedFixedStorage,
        mmr::Family,
        CurrentMmrOrderedFixed,
        current_fixed_config
    );
    keyed_storage_audit!(
        CurrentMmrOrderedVariableStorage,
        mmr::Family,
        CurrentMmrOrderedVariable,
        current_variable_config
    );
    keyed_storage_audit!(
        CurrentMmbUnorderedFixedStorage,
        mmb::Family,
        CurrentMmbUnorderedFixed,
        current_fixed_config
    );
    keyed_storage_audit!(
        CurrentMmbUnorderedVariableStorage,
        mmb::Family,
        CurrentMmbUnorderedVariable,
        current_variable_config
    );
    keyed_storage_audit!(
        CurrentMmbOrderedFixedStorage,
        mmb::Family,
        CurrentMmbOrderedFixed,
        current_fixed_config
    );
    keyed_storage_audit!(
        CurrentMmbOrderedVariableStorage,
        mmb::Family,
        CurrentMmbOrderedVariable,
        current_variable_config
    );

    immutable_storage_audit!(
        ImmutableMmrFixedStorage,
        mmr::Family,
        ImmutableMmrFixed,
        immutable_fixed_config
    );
    immutable_storage_audit!(
        ImmutableMmbFixedStorage,
        mmb::Family,
        ImmutableMmbFixed,
        immutable_fixed_config
    );
    immutable_storage_audit!(
        ImmutableMmrVariableStorage,
        mmr::Family,
        ImmutableMmrVariable,
        immutable_variable_config
    );
    immutable_storage_audit!(
        ImmutableMmbVariableStorage,
        mmb::Family,
        ImmutableMmbVariable,
        immutable_variable_config
    );

    storage_audit_conformance!(
        KeylessMmrFixedStorage,
        mmr::Family,
        KeylessMmrFixed,
        keyless_fixed_config,
        |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
    );
    storage_audit_conformance!(
        KeylessMmbFixedStorage,
        mmb::Family,
        KeylessMmbFixed,
        keyless_fixed_config,
        |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
    );
    storage_audit_conformance!(
        KeylessMmrVariableStorage,
        mmr::Family,
        KeylessMmrVariable,
        keyless_variable_config,
        |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
    );
    storage_audit_conformance!(
        KeylessMmbVariableStorage,
        mmb::Family,
        KeylessMmbVariable,
        keyless_variable_config,
        |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
    );

    immutable_storage_audit!(
        ImmutableMmrCompactFixedStorage,
        mmr::Family,
        ImmutableMmrCompactFixed,
        immutable_fixed_compact_config
    );
    immutable_storage_audit!(
        ImmutableMmbCompactFixedStorage,
        mmb::Family,
        ImmutableMmbCompactFixed,
        immutable_fixed_compact_config
    );
    immutable_storage_audit!(
        ImmutableMmrCompactVariableStorage,
        mmr::Family,
        ImmutableMmrCompactVariable,
        immutable_variable_compact_config
    );
    immutable_storage_audit!(
        ImmutableMmbCompactVariableStorage,
        mmb::Family,
        ImmutableMmbCompactVariable,
        immutable_variable_compact_config
    );

    storage_audit_conformance!(
        KeylessMmrCompactFixedStorage,
        mmr::Family,
        KeylessMmrCompactFixed,
        keyless_fixed_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
    );
    storage_audit_conformance!(
        KeylessMmbCompactFixedStorage,
        mmb::Family,
        KeylessMmbCompactFixed,
        keyless_fixed_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| U64::new(x)) }
    );
    storage_audit_conformance!(
        KeylessMmrCompactVariableStorage,
        mmr::Family,
        KeylessMmrCompactVariable,
        keyless_variable_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
    );
    storage_audit_conformance!(
        KeylessMmbCompactVariableStorage,
        mmb::Family,
        KeylessMmbCompactVariable,
        keyless_variable_compact_config,
        |db, seed| { keyless_root!(db, seed, |x| x.to_be_bytes().to_vec()) }
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
        AnyMmrUnorderedFixedFloorConf => 200,
        AnyMmrUnorderedVariableFloorConf => 200,
        AnyMmrOrderedFixedFloorConf => 200,
        AnyMmrOrderedVariableFloorConf => 200,
        AnyMmbUnorderedFixedFloorConf => 200,
        AnyMmbUnorderedVariableFloorConf => 200,
        AnyMmbOrderedFixedFloorConf => 200,
        AnyMmbOrderedVariableFloorConf => 200,
        CurrentMmrUnorderedFixedFloorConf => 200,
        CurrentMmrUnorderedVariableFloorConf => 200,
        CurrentMmrOrderedFixedFloorConf => 200,
        CurrentMmrOrderedVariableFloorConf => 200,
        CurrentMmbUnorderedFixedFloorConf => 200,
        CurrentMmbUnorderedVariableFloorConf => 200,
        CurrentMmbOrderedFixedFloorConf => 200,
        CurrentMmbOrderedVariableFloorConf => 200,
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
        StorageConformance<AnyMmrUnorderedFixedStorage> => 64,
        StorageConformance<AnyMmrUnorderedVariableStorage> => 64,
        StorageConformance<AnyMmrOrderedFixedStorage> => 64,
        StorageConformance<AnyMmrOrderedVariableStorage> => 64,
        StorageConformance<AnyMmbUnorderedFixedStorage> => 64,
        StorageConformance<AnyMmbUnorderedVariableStorage> => 64,
        StorageConformance<AnyMmbOrderedFixedStorage> => 64,
        StorageConformance<AnyMmbOrderedVariableStorage> => 64,
        StorageConformance<CurrentMmrUnorderedFixedStorage> => 64,
        StorageConformance<CurrentMmrUnorderedVariableStorage> => 64,
        StorageConformance<CurrentMmrOrderedFixedStorage> => 64,
        StorageConformance<CurrentMmrOrderedVariableStorage> => 64,
        StorageConformance<CurrentMmbUnorderedFixedStorage> => 64,
        StorageConformance<CurrentMmbUnorderedVariableStorage> => 64,
        StorageConformance<CurrentMmbOrderedFixedStorage> => 64,
        StorageConformance<CurrentMmbOrderedVariableStorage> => 64,
        StorageConformance<StoreFloorStorage> => 200,
        StorageConformance<ImmutableMmrFixedStorage> => 64,
        StorageConformance<ImmutableMmbFixedStorage> => 64,
        StorageConformance<ImmutableMmrVariableStorage> => 64,
        StorageConformance<ImmutableMmbVariableStorage> => 64,
        StorageConformance<KeylessMmrFixedStorage> => 64,
        StorageConformance<KeylessMmbFixedStorage> => 64,
        StorageConformance<KeylessMmrVariableStorage> => 64,
        StorageConformance<KeylessMmbVariableStorage> => 64,
        StorageConformance<ImmutableMmrCompactFixedStorage> => 64,
        StorageConformance<ImmutableMmbCompactFixedStorage> => 64,
        StorageConformance<ImmutableMmrCompactVariableStorage> => 64,
        StorageConformance<ImmutableMmbCompactVariableStorage> => 64,
        StorageConformance<KeylessMmrCompactFixedStorage> => 64,
        StorageConformance<KeylessMmbCompactFixedStorage> => 64,
        StorageConformance<KeylessMmrCompactVariableStorage> => 64,
        StorageConformance<KeylessMmbCompactVariableStorage> => 64,
    }
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
    fwd: D,
    rev: D,
    ops: Vec<(Digest, Option<Digest>)>,
    msg: &str,
) -> (D, D) {
    let fwd = apply_writes(fwd, ops.clone()).await;
    let mut reversed = ops;
    reversed.reverse();
    let rev = apply_writes(rev, reversed).await;
    assert_eq!(fwd.root().to_vec(), rev.root().to_vec(), "{msg}");
    (fwd, rev)
}

#[boxed]
async fn assert_keyed_order_independent<F: Family, D: DbAny<F, Key = Digest, Value = Digest>>(
    fwd: D,
    rev: D,
) -> (D, D) {
    let mut creates: Vec<_> = (0..20)
        .map(|i| (to_digest(i), Some(to_val(i, 0))))
        .collect();
    for i in 0..8u64 {
        creates.push((colliding_digest(0xAB, i), Some(to_val(i, 100))));
    }
    let (fwd, rev) =
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
    let (fwd, rev) =
        apply_both_orders(fwd, rev, mixed, "delete+update order must not affect root").await;

    let mut recreates: Vec<_> = (0..20)
        .filter(|i| i % 2 == 1)
        .map(|i| (to_digest(i), Some(to_val(i, 400))))
        .collect();
    for i in 8..16u64 {
        recreates.push((colliding_digest(0xAB, i), Some(to_val(i, 500))));
    }
    let (fwd, rev) = apply_both_orders(
        fwd,
        rev,
        recreates,
        "recreate-after-delete order must not affect root",
    )
    .await;
    (fwd, rev)
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
        let merkleized = batch.merkleize(&$fwd, None, fwd_floor).await.unwrap();
        ($fwd, _) = $fwd.apply_batch(merkleized).await.unwrap();

        let rev_floor = $rev.inactivity_floor_loc();
        let mut batch = $rev.new_batch();
        for &(k, v) in ops.iter().rev() {
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&$rev, None, rev_floor).await.unwrap();
        ($rev, _) = $rev.apply_batch(merkleized).await.unwrap();

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
                let mut $fwd = <$db>::init(ctx.child("fwd"), ($cfg_fn)("fwd", &ctx), None)
                    .await
                    .unwrap();
                let mut $rev = <$db>::init(ctx.child("rev"), ($cfg_fn)("rev", &ctx), None)
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
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_any_mmr_unordered_variable,
    AnyMmrUnorderedVariable,
    any_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_any_mmr_ordered_fixed,
    AnyMmrOrderedFixed,
    any_fixed_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_any_mmr_ordered_variable,
    AnyMmrOrderedVariable,
    any_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_any_mmb_unordered_fixed,
    AnyMmbUnorderedFixed,
    any_fixed_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_any_mmb_unordered_variable,
    AnyMmbUnorderedVariable,
    any_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_any_mmb_ordered_fixed,
    AnyMmbOrderedFixed,
    any_fixed_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_any_mmb_ordered_variable,
    AnyMmbOrderedVariable,
    any_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmr_unordered_fixed,
    CurrentMmrUnorderedFixed,
    current_fixed_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmr_unordered_variable,
    CurrentMmrUnorderedVariable,
    current_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmr_ordered_fixed,
    CurrentMmrOrderedFixed,
    current_fixed_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmr_ordered_variable,
    CurrentMmrOrderedVariable,
    current_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmb_unordered_fixed,
    CurrentMmbUnorderedFixed,
    current_fixed_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmb_unordered_variable,
    CurrentMmbUnorderedVariable,
    current_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmb_ordered_fixed,
    CurrentMmbOrderedFixed,
    current_fixed_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
);
order_test!(
    test_order_cur_mmb_ordered_variable,
    CurrentMmbOrderedVariable,
    current_variable_config,
    |fwd, rev| {
        (fwd, rev) = assert_keyed_order_independent(fwd, rev).await;
    }
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
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
order_test!(
    test_order_immutable_mmb_compact_fixed,
    ImmutableMmbCompactFixed,
    immutable_fixed_compact_config,
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
order_test!(
    test_order_immutable_mmr_compact_variable,
    ImmutableMmrCompactVariable,
    immutable_variable_compact_config,
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
order_test!(
    test_order_immutable_mmb_compact_variable,
    ImmutableMmbCompactVariable,
    immutable_variable_compact_config,
    |fwd, rev| assert_immutable_order_independent!(fwd, rev)
);
