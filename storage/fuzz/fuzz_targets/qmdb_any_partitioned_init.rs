#![no_main]

//! Commit fuzzed writes to a partitioned QMDB, then reopen it at a fuzzed snapshot-build
//! concurrency and check that the build, split across workers owning disjoint partition ranges
//! when the concurrency allows, recovers the root, inactivity floor, and live values the database
//! held before closing. Commits may hold the floor, keeping their deletes in the replay. A
//! follow-up batch merkleized before and after the reopen checks the rebuilt activity state, since
//! its floor walk moves the active operations it finds.

use arbitrary::{Arbitrary, Unstructured};
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
use commonware_storage_fuzz::stream;
use commonware_utils::{Entropy, FuzzRng, NZU16, NZU64, NZUsize, sequence::FixedBytes};
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

/// The most commits an input holds.
const MAX_COMMITS: usize = 8;

/// The most writes one batch holds.
const MAX_WRITES: usize = 32;

/// One write in this many is a [Write::Flood]. About half of all inputs flood, so ordered
/// partitions spill in the build, and about a third flood twice, which spends the key budget.
const FLOOD_ONE_IN: u32 = 64;

/// One key write in this many deletes its key, which often meets a key an earlier commit set.
const DELETE_ONE_IN: u32 = 4;

/// Partitions that writes use: both ends of the partition range and both sides of its quarter
/// boundaries, so writes collide in few partitions and straddle the ranges of two and four
/// build workers.
const PARTITIONS: [u8; 8] = [0, 1, 63, 64, 127, 128, 254, 255];

/// The concurrency seed that builds serially.
const SERIAL: u8 = 0;

/// The largest concurrency seed of the smallest parallel builds: seed 1 builds on one insert worker
/// that owns every partition, seed 2 on two workers that own half of the partitions each.
const MAX_FEW: u8 = 2;

/// The largest concurrency seed below the one [concurrency] maps to [NonZeroUsize::MAX]. Seeds
/// above [MAX_FEW] build on 2 to 128 insert workers, and the maximum on one worker per partition.
const MAX_MANY: u8 = u8::MAX - 1;

/// Bytes at the end of the stream that seed the runtime. The scenario is sampled from the start of
/// the stream and never reaches them.
const ENTROPY_BYTES: usize = 32;

/// Keys written past this count across all commits are ignored, which bounds the cost of floods.
const MAX_KEYS_WRITTEN: usize = 1024;

/// Keys a flood sets in one partition, past the 512 entries at which an ordered partition spills
/// out of its sorted array.
const FLOOD: u16 = 520;

/// Translated keys per partition: [OneCap] keeps the byte after the one-byte partition prefix.
const BUCKETS: u8 = 4;

/// Distinct keys per translated key, which collide in the snapshot.
const SUFFIXES: u8 = 4;

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug)]
struct Commit {
    /// Hold the floor at its inherited location instead of walking it forward.
    hold: bool,
    writes: Vec<Write>,
}

#[derive(Debug)]
struct FuzzInput {
    init_concurrency: u8,
    init_cache: u8,
    commits: Vec<Commit>,
    probe: Vec<Write>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for Write {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let partition = *u.choose(&PARTITIONS)?;
        if u.ratio(1, FLOOD_ONE_IN)? {
            return Ok(Self::Flood {
                partition,
                value: u.arbitrary()?,
            });
        }
        Ok(Self::Key {
            partition,
            bucket: u.int_in_range(0..=BUCKETS - 1)?,
            suffix: u.int_in_range(0..=SUFFIXES - 1)?,
            value: if u.ratio(1, DELETE_ONE_IN)? {
                None
            } else {
                Some(u.arbitrary()?)
            },
        })
    }
}

/// The build concurrency seed: serial 1 in 8, one or two workers 2 in 8, one worker per partition
/// 1 in 8, and 2 to 128 workers otherwise, so every build is common and two serial inputs are rare.
fn concurrency_seed(u: &mut Unstructured<'_>) -> arbitrary::Result<u8> {
    Ok(match u.int_in_range(0..=7)? {
        0 => SERIAL,
        1 | 2 => u.int_in_range(SERIAL + 1..=MAX_FEW)?,
        3 => u8::MAX,
        _ => u.int_in_range(MAX_FEW + 1..=MAX_MANY)?,
    })
}

/// Between `min` and [MAX_WRITES] writes.
fn writes(u: &mut Unstructured<'_>, min: usize) -> arbitrary::Result<Vec<Write>> {
    (0..u.int_in_range(min..=MAX_WRITES)?)
        .map(|_| u.arbitrary())
        .collect()
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let stream = stream(u)?;
        let (scenario, entropy) = stream.split_at(stream.len() - ENTROPY_BYTES);
        let u = &mut Unstructured::new(scenario);
        let init_concurrency = concurrency_seed(u)?;
        let init_cache = u.arbitrary()?;
        let commits = (0..u.int_in_range(1..=MAX_COMMITS)?)
            .map(|i| {
                Ok(Commit {
                    hold: u.arbitrary()?,
                    writes: writes(u, usize::from(i == 0))?,
                })
            })
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            init_concurrency,
            init_cache,
            commits,
            probe: writes(u, 0)?,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
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
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(input.entropy.clone()));
    deterministic::Runner::new(cfg).start(|context| async move {
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
