#![no_main]

//! Commit fuzzed writes to a partitioned QMDB, then reopen it at a fuzzed snapshot-build
//! concurrency and check that the build, split across workers owning disjoint partition ranges
//! when the concurrency allows, recovers the root, inactivity floor, and live values the database
//! held before closing. Commits may hold the floor, keeping their deletes in the replay. A
//! follow-up batch merkleized before and after the reopen checks the rebuilt activity state, since
//! its floor walk moves the active operations it finds.

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::{authenticated::Config as MerkleConfig, contiguous::fixed::Config as FConfig},
    merkle::{Family as MerkleFamily, mmb, mmr},
    qmdb::{
        any::{
            ordered::fixed::partitioned::p256::Db as OrderedDb,
            traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
            unordered::fixed::partitioned::p256::{Config, Db as UnorderedDb},
        },
        floor::Hold,
    },
    translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type Unordered<F> = UnorderedDb<F, deterministic::Context, Key, Value, Sha256, OneCap, Sequential>;
type Ordered<F> = OrderedDb<F, deterministic::Context, Key, Value, Sha256, OneCap, Sequential>;

const PAGE_SIZE: NonZeroU16 = NZU16!(131);

/// Commits past this count are ignored.
const MAX_COMMITS: usize = 8;

/// Writes past this count in one batch are ignored.
const MAX_WRITES: usize = 32;

/// Keys written past this count across all commits are ignored, which bounds the cost of floods.
const MAX_KEYS_WRITTEN: usize = 1024;

/// Keys a flood sets in one partition, past the 512 entries at which an ordered partition spills
/// out of its sorted array.
const FLOOD: u16 = 520;

/// Translated keys per partition: [OneCap] keeps the byte after the one-byte partition prefix.
const BUCKETS: u8 = 4;

/// Distinct keys per translated key, which collide in the snapshot.
const SUFFIXES: u8 = 4;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Write {
    /// Set or delete one key.
    Key {
        partition: u8,
        bucket: u8,
        suffix: u8,
        value: Option<u8>,
    },
    /// Set [FLOOD] distinct keys in one partition.
    Flood { partition: u8, value: u8 },
}

#[derive(Arbitrary, Debug)]
struct Commit {
    /// Hold the floor at its inherited location instead of walking it forward.
    hold: bool,
    writes: Vec<Write>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Read first, so long inputs do not leave the build knobs at their zero defaults.
    init_concurrency: u8,
    init_cache: u8,
    commits: Vec<Commit>,
    probe: Vec<Write>,
}

/// The key writes that `writes` expand to, at most `budget` of them, deducted from it.
fn expand(writes: &[Write], budget: &mut usize) -> Vec<(Key, Option<Value>)> {
    let mut expanded = Vec::new();
    for write in writes.iter().take(MAX_WRITES) {
        match *write {
            Write::Key {
                partition,
                bucket,
                suffix,
                value,
            } => {
                let mut bytes = [0u8; 32];
                bytes[0] = partition;
                bytes[1] = bucket % BUCKETS;
                bytes[31] = suffix % SUFFIXES;
                expanded.push((Key::new(bytes), value.map(|byte| Value::new([byte; 32]))));
            }
            Write::Flood { partition, value } => {
                for i in 0..FLOOD {
                    // The low byte leads the sub-key, so flooded keys spread over every
                    // translated key and their collision chains stay short.
                    let [high, low] = i.to_be_bytes();
                    let mut bytes = [0u8; 32];
                    bytes[0] = partition;
                    bytes[1] = low;
                    bytes[2] = high;
                    expanded.push((Key::new(bytes), Some(Value::new([value; 32]))));
                }
            }
        }
    }
    expanded.truncate(*budget);
    *budget -= expanded.len();
    expanded
}

/// The build concurrency `seed` selects. `1` builds serially, `2` and `3` insert on one or two
/// workers, larger budgets also spawn decoders, and the maximum exceeds the partition count.
fn concurrency(seed: u8) -> NonZeroUsize {
    match seed {
        u8::MAX => NonZeroUsize::MAX,
        seed => NonZeroUsize::new(usize::from(seed) + 1).unwrap(),
    }
}

fn config(
    name: &str,
    init_cache: u8,
    init_concurrency: NonZeroUsize,
) -> Config<OneCap, Sequential> {
    let page_cache = CacheRef::new(PAGE_SIZE, NZUsize!(2));
    Config {
        merkle: MerkleConfig {
            partition: format!("{name}-meta"),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            resident_height: commonware_storage_fuzz::low_resident_height(),
        },
        log: FConfig {
            partition: format!("{name}-log"),
            items_per_blob: NZU64!(13),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            page_cache,
        },
        translator: OneCap,
        init_cache: NonZeroUsize::new(usize::from(init_cache)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency,
    }
}

/// A partitioned database the fuzzer opens at a chosen build concurrency.
trait Open: DbAny<Key = Key, Value = Value> {
    fn open(
        context: deterministic::Context,
        cfg: Config<OneCap, Sequential>,
    ) -> impl Future<Output = Self>;
}

impl<F: MerkleFamily> Open for Unordered<F> {
    async fn open(context: deterministic::Context, cfg: Config<OneCap, Sequential>) -> Self {
        Self::init(context, cfg, None)
            .await
            .expect("init unordered partitioned db")
    }
}

impl<F: MerkleFamily> Open for Ordered<F> {
    async fn open(context: deterministic::Context, cfg: Config<OneCap, Sequential>) -> Self {
        Self::init(context, cfg, None)
            .await
            .expect("init ordered partitioned db")
    }
}

/// Merkleize a batch of `db` holding `writes`, holding the floor if `hold` is set.
async fn merkleize<D: Open>(db: &D, writes: &[(Key, Option<Value>)], hold: bool) -> D::Merkleized {
    let mut batch = db.new_batch();
    for (key, value) in writes {
        batch = batch.write(key.clone(), value.clone());
    }
    let merkleized = if hold {
        batch.merkleize_with(db, &mut Hold).await
    } else {
        batch.merkleize(db).await
    };
    merkleized.expect("merkleize")
}

async fn check<D: Open>(context: deterministic::Context, input: &FuzzInput, name: &str) {
    let cfg = config(name, input.init_cache, NZUsize!(1));
    let mut db = D::open(context.child("populate"), cfg).await;
    let mut model = BTreeMap::new();
    let mut budget = MAX_KEYS_WRITTEN;
    for commit in input.commits.iter().take(MAX_COMMITS) {
        let writes = expand(&commit.writes, &mut budget);
        let batch = merkleize(&db, &writes, commit.hold).await;
        db = db.apply_batch(batch).await.expect("apply");
        db = db.commit().await.expect("commit");
        model.extend(writes);
    }
    let root = db.root();
    let floor = db.inactivity_floor();
    let mut probe_budget = MAX_WRITES;
    let probe_writes = expand(&input.probe, &mut probe_budget);
    let probe = merkleize(&db, &probe_writes, false).await.root();
    db.sync().await.expect("sync");

    let concurrency = concurrency(input.init_concurrency);
    let cfg = config(name, input.init_cache, concurrency);
    let db = D::open(context.child("reopen"), cfg).await;
    assert_eq!(
        db.root(),
        root,
        "root changed across reopen at {concurrency}"
    );
    assert_eq!(
        db.inactivity_floor(),
        floor,
        "floor changed across reopen at {concurrency}"
    );
    for (key, value) in &model {
        let got = db.get(key).await.expect("get");
        assert_eq!(
            &got, value,
            "value of {key:?} changed across reopen at {concurrency}"
        );
    }
    assert_eq!(
        merkleize(&db, &probe_writes, false).await.root(),
        probe,
        "follow-up batch root changed across reopen at {concurrency}"
    );
    db.destroy().await.expect("destroy");
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput, suffix: &str) {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let unordered = format!("unordered-{suffix}");
        check::<Unordered<F>>(context.child("unordered"), input, &unordered).await;
        let ordered = format!("ordered-{suffix}");
        check::<Ordered<F>>(context.child("ordered"), input, &ordered).await;
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input, "mmr");
    fuzz_family::<mmb::Family>(&input, "mmb");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
