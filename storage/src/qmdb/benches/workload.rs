//! Workload harness for the keyed QMDB variants. It builds a database, drives it with batches of
//! staged updates, concurrent point reads, and prunes, and reports results as JSON lines.
//!
//! A batch reads all of its keys with one stage call, puts each key's new value, merkleizes,
//! applies, and awaits commit. Those calls are timed, along with each prune that `--prune-every`
//! triggers. The timed region also holds two passes over the batch between the calls: one counts
//! the staged keys that had a value and one wraps the new values for merkleize. Key sampling and
//! value generation are not timed. One batch is committed at a time, so every counted update is
//! durable before the next batch starts.
//!
//! The harness runs only when its first argument is one of two subcommands. With any other
//! arguments it returns without running, so blanket bench invocations skip it.
//!
//! - load: insert keys 0..N into an empty database in batches of `--load-batch` keys, committing
//!   each, then prune and sync.
//! - run: open the database once, check that key N - 1 exists, run the phases in order, then sync.
//!
//! ```text
//! cargo bench -p commonware-storage --bench workload -- load --dir <dir> [flags]
//! cargo bench -p commonware-storage --bench workload -- run --dir <dir> --phases <phases> [flags]
//! ```
//!
//! # Flags
//!
//! Every flag takes a value. The defaults are in parentheses.
//!
//! - `--dir`: storage directory of the database. Required.
//! - `--db` (any::unordered): any::unordered, any::ordered, current::unordered, or
//!   current::ordered.
//! - `--log` (fixed): fixed for the fixed-size journal with 32-byte values, or variable for the
//!   variable-size journal with values of `--value-size` bytes.
//! - `--key-size` (32): 32 with the fixed-size journal, and 20, 32, or 64 with the variable-size
//!   one.
//! - `--value-size` (32): length of a variable-size value, at most 1 MiB. It must be 32 with the
//!   fixed-size journal.
//! - `--index` (default): plain for the unpartitioned index, or p2 or p3 for an index partitioned
//!   by the first two or three key bytes. The default is p2 for unordered variants and p3 for
//!   ordered ones.
//! - `--translator` (eight): eight, four, or two, the number of key bytes the index keeps after any
//!   partition prefix.
//! - `--keys` (1000000): N, the number of keys that load inserts and that run expects to find.
//! - `--threads` (8): runtime worker threads, thread pool size, and open concurrency.
//! - `--cache-pages` (2097152): pages in the page cache.
//! - `--init-cache` (1048576): entries in the cache that resolves superseded operations while a
//!   database opens. 0 disables the cache.
//! - `--items-per-blob` (10000000): operations per journal blob. Run must use the value that load
//!   used.
//! - `--load-batch` (1000000): keys per batch during load.
//! - `--prune-every` (10000000): updates, counted across update phases, between prunes to the sync
//!   boundary.
//! - `--seed` (1): seed of the update key sampler. Read phases mix it with the clock.
//! - `--phases`: what run executes, described below.
//! - `--disk`: block device whose /proc/diskstats counters are reported, such as nvme1n1.
//! - `--tag`: copied into every output line.
//! - `--out`: file that every output line is appended to, in addition to stdout.
//!
//! Only the combinations of variant, journal, index, translator, and key size listed in the
//! `flavors!` table below are compiled in.
//!
//! # Phases
//!
//! Phases are separated by semicolons. Each is a kind, a colon, and comma-separated settings, for
//! example `update:active=0.01,batch=10000;read:readers=64`. Run rejects a kind or a setting it does
//! not know before it opens the database.
//!
//! An update phase runs batches of staged updates. It first warms up in short windows until
//! throughput and storage reads per key settle, then measures. Its durations count only the time
//! spent in timed calls.
//!
//! - `batch` (10000): keys per batch.
//! - `creates` (0): keys per batch that did not exist before, at most `batch`.
//! - `active` (1): share of the keys that uniform batches draw from. `active-keys` gives a count
//!   instead.
//! - `dist` (uniform): uniform over the active set, or zipf over all keys with exponent `zipf`
//!   (0.99).
//! - `secs` (20), `windows` (3), `min-batches` (30): length, number, and minimum batch count of the
//!   measured windows. `max-secs` (600) ends a window short of its batch count once it has run that
//!   long and completed five batches.
//! - `warm` (auto): auto to settle as described, none to skip warm-up, or a number of updates.
//! - `warm-secs` (5): length of a warm-up window.
//! - `warm-min-updates`: warm-up updates before settling is tested. The default is 30000000 under
//!   zipf, and otherwise three times the active set, capped at `warm-max-updates`.
//! - `warm-fill` (1.25): storage traffic since the database opened, in page cache capacities,
//!   before settling is tested.
//! - `warm-max-updates` (300000000), `warm-max-secs` (900): caps that end warm-up unsettled.
//!
//! A read phase runs concurrent readers that each get one uniformly random loaded key at a time.
//!
//! - `readers` (64): concurrent readers.
//! - `secs` (20): wall-clock length of the phase. `gets` gives a total number of gets instead,
//!   split evenly across readers and rounded up.
//!
//! A prune phase prunes to the sync boundary and reports the journal bounds and directory size.
//!
//! Update and read phases copy their `label` setting into their output lines.

use commonware_allocator::mimalloc;
use commonware_codec::RangeCfg;
use commonware_cryptography::Sha256;
use commonware_parallel::Rayon;
use commonware_runtime::{
    BLOB_PAGE_SIZE, Metrics as _, Runner as _, Spawner as _, Strategizer as _, Supervisor as _,
    buffer::paged::{CacheRef, page_size},
    tokio::{Config as RuntimeConfig, Context, Runner},
};
use commonware_storage::{
    journal::{
        authenticated::Config as MerkleConfig,
        contiguous::{fixed::Config as FixedLog, variable::Config as VariableLog},
    },
    merkle::mmb,
    qmdb::{any, any::batch::Slot, current},
    translator::{EightCap, FourCap, Translator, TwoCap},
};
use commonware_utils::sequence::FixedBytes;
use rand::{RngExt as _, SeedableRng as _, distr::Distribution as _, rngs::StdRng};
use rand_distr::Zipf;
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    future::Future,
    hint::black_box,
    io::Write as _,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

type Family = mmb::Family;

/// Bitmap chunk size of the current variants, in bytes.
const CHUNK: usize = 32;

/// Longest variable-size value, in bytes.
const MAX_VALUE: usize = 1 << 20;

/// Multiplier that scatters ranks over ids. It is prime, so [`scatter`] is a bijection on 0..keys
/// for every key count that is not a multiple of it.
const SCATTER: u64 = 982_451_653;

/// One SplitMix64 step, a bijection on u64 with well-mixed output.
const fn mix(z: u64) -> u64 {
    let z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fills out with bytes derived from seed. The first 8 bytes are a bijection of seed, so outputs
/// of at least 8 bytes differ for distinct seeds.
fn fill(seed: u64, out: &mut [u8]) {
    for (word, chunk) in out.chunks_mut(8).enumerate() {
        let bytes = mix(seed ^ (word as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93)).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// The id in 0..keys that rank maps to. Ranks 0..n spread across the whole insertion order, and
/// the set they select only grows as n grows.
const fn scatter(rank: u64, keys: u64) -> u64 {
    ((rank as u128 * SCATTER as u128) % keys as u128) as u64
}

/// Command-line flags. The module docs list each one with its default.
#[derive(Clone)]
struct Opts {
    command: String,
    dir: String,
    db: String,
    log: String,
    index: String,
    translator: String,
    key_size: usize,
    value_size: usize,
    keys: u64,
    threads: NonZeroUsize,
    cache_pages: NonZeroUsize,
    init_cache: usize,
    items_per_blob: NonZeroU64,
    load_batch: u64,
    prune_every: u64,
    seed: u64,
    phases: String,
    disk: String,
    tag: String,
    out: String,
}

impl Opts {
    fn parse(command: &str, args: &[String]) -> Self {
        let mut map: HashMap<String, String> = HashMap::new();
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            let name = flag
                .strip_prefix("--")
                .unwrap_or_else(|| panic!("arguments must be --flag value pairs, found {flag}"));
            let value = args
                .next()
                .unwrap_or_else(|| panic!("--{name} must have a value"));
            map.insert(name.to_string(), value.clone());
        }
        let mut take =
            |name: &str, default: &str| map.remove(name).unwrap_or_else(|| default.into());
        let opts = Self {
            command: command.into(),
            dir: take("dir", ""),
            db: take("db", "any::unordered"),
            log: take("log", "fixed"),
            index: take("index", "default"),
            translator: take("translator", "eight"),
            key_size: take("key-size", "32").parse().expect("key-size"),
            value_size: take("value-size", "32").parse().expect("value-size"),
            keys: take("keys", "1000000").parse().expect("keys"),
            threads: take("threads", "8").parse().expect("threads"),
            cache_pages: take("cache-pages", "2097152").parse().expect("cache-pages"),
            init_cache: take("init-cache", "1048576").parse().expect("init-cache"),
            items_per_blob: take("items-per-blob", "10000000")
                .parse()
                .expect("items-per-blob"),
            load_batch: take("load-batch", "1000000").parse().expect("load-batch"),
            prune_every: take("prune-every", "10000000")
                .parse()
                .expect("prune-every"),
            seed: take("seed", "1").parse().expect("seed"),
            phases: take("phases", ""),
            disk: take("disk", ""),
            tag: take("tag", ""),
            out: take("out", ""),
        };
        assert!(map.is_empty(), "flags must be known: {:?}", map.keys());
        assert!(!opts.dir.is_empty(), "--dir must be set");
        assert!(
            opts.keys > 0 && opts.load_batch > 0,
            "--keys and --load-batch must be greater than zero"
        );
        assert!(
            !opts.keys.is_multiple_of(SCATTER),
            "--keys must not be a multiple of {SCATTER}"
        );
        if opts.log == "fixed" {
            assert!(
                opts.value_size == 32,
                "--value-size must be 32 with the fixed-size journal"
            );
        } else {
            assert!(
                opts.value_size <= MAX_VALUE,
                "--value-size must be at most {MAX_VALUE}"
            );
        }
        opts
    }

    /// The index to use. The default resolves to p2 for unordered variants and p3 for ordered ones.
    fn index(&self) -> &str {
        match (self.index.as_str(), self.db.ends_with("unordered")) {
            ("default", true) => "p2",
            ("default", false) => "p3",
            (index, _) => index,
        }
    }

    /// The key of these settings in the flavors table.
    fn flavor(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.db,
            self.log,
            self.index(),
            self.translator,
            self.key_size
        )
    }

    /// A new page cache of `--cache-pages` pages.
    fn cache(&self) -> CacheRef {
        CacheRef::new(page_size(BLOB_PAGE_SIZE), self.cache_pages)
    }
}

/// One output line: a flat JSON object that opens with its type, a timestamp, and the run's
/// settings.
struct Line(String);

impl Line {
    fn new(kind: &str, opts: &Opts) -> Self {
        let mut line = Self(String::from("{"));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        line.text("type", kind);
        line.number("ts", now);
        line.text("tag", &opts.tag);
        line.text("db", &opts.db);
        line.text("log", &opts.log);
        line.text("index", opts.index());
        line.text("translator", &opts.translator);
        line.number("key_size", opts.key_size);
        line.number("value_size", opts.value_size);
        line.number("keys", opts.keys);
        line.number("threads", opts.threads);
        line.number("cache_pages", opts.cache_pages);
        line.number("init_cache", opts.init_cache);
        line
    }

    fn text(&mut self, key: &str, value: &str) {
        let comma = if self.0.len() > 1 { "," } else { "" };
        write!(self.0, "{comma}\"{key}\":\"").unwrap();
        for c in value.chars() {
            match c {
                '"' | '\\' => {
                    self.0.push('\\');
                    self.0.push(c);
                }
                c if c < ' ' => write!(self.0, "\\u{:04x}", c as u32).unwrap(),
                c => self.0.push(c),
            }
        }
        self.0.push('"');
    }

    fn number(&mut self, key: &str, value: impl std::fmt::Display) {
        let comma = if self.0.len() > 1 { "," } else { "" };
        write!(self.0, "{comma}\"{key}\":{value}").unwrap();
    }

    /// Writes value with six decimals, or null when it is not finite.
    fn float(&mut self, key: &str, value: f64) {
        if value.is_finite() {
            self.number(key, format!("{value:.6}"));
        } else {
            self.number(key, "null");
        }
    }

    /// Prints the line and appends it to `--out` when one is set.
    fn emit(mut self, opts: &Opts) {
        self.0.push('}');
        println!("{}", self.0);
        let _ = std::io::stdout().flush();
        if !opts.out.is_empty() {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&opts.out)
                .expect("--out must name a file that can be appended to");
            writeln!(file, "{}", self.0).expect("--out must accept writes");
        }
    }
}

/// Cumulative storage and disk counters, with the process's current and peak resident memory in
/// bytes.
#[derive(Clone, Copy, Default)]
struct Sample {
    storage_reads: u64,
    storage_read_bytes: u64,
    storage_writes: u64,
    storage_write_bytes: u64,
    storage_syncs: u64,
    disk_reads: u64,
    disk_read_sectors: u64,
    disk_writes: u64,
    disk_write_sectors: u64,
    disk_io_ms: u64,
    disk_flushes: u64,
    rss: u64,
    peak_rss: u64,
}

/// Reads the current counters. Storage counters sum every runtime metric named
/// `*storage_<counter>`, and values that /proc does not provide read as zero.
fn sample(ctx: &Context, opts: &Opts) -> Sample {
    let mut sample = Sample::default();
    for line in ctx.encode().lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let name = name.split('{').next().unwrap_or(name);
        let name = name.strip_suffix("_total").unwrap_or(name);
        let value: u64 = value.parse::<f64>().map_or(0, |v| v as u64);
        match name.rsplit_once("storage_").map(|(_, tail)| tail) {
            Some("reads") => sample.storage_reads += value,
            Some("read_bytes") => sample.storage_read_bytes += value,
            Some("writes") => sample.storage_writes += value,
            Some("write_bytes") => sample.storage_write_bytes += value,
            Some("syncs") => sample.storage_syncs += value,
            _ => {}
        }
    }
    if let Ok(stats) = std::fs::read_to_string("/proc/diskstats") {
        for line in stats.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 13 && fields[2] == opts.disk {
                let field = |i: usize| fields.get(i).and_then(|f| f.parse().ok()).unwrap_or(0);
                sample.disk_reads = field(3);
                sample.disk_read_sectors = field(5);
                sample.disk_writes = field(7);
                sample.disk_write_sectors = field(9);
                sample.disk_io_ms = field(12);
                sample.disk_flushes = field(18);
            }
        }
    }
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let kib = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
                .unwrap_or(0)
        };
        sample.rss = kib("VmRSS:") * 1024;
        sample.peak_rss = kib("VmHWM:") * 1024;
    }
    sample
}

/// Records how much each counter grew between two samples, with ratios per operation and per
/// batch, and the resident memory at the later sample.
fn counters(line: &mut Line, before: &Sample, after: &Sample, operations: u64, batches: u64) {
    let per = |value: u64, count: u64| {
        if count == 0 {
            0.0
        } else {
            value as f64 / count as f64
        }
    };
    let storage_reads = after.storage_reads - before.storage_reads;
    let storage_write_bytes = after.storage_write_bytes - before.storage_write_bytes;
    let storage_syncs = after.storage_syncs - before.storage_syncs;
    line.number("storage_reads", storage_reads);
    line.number(
        "storage_read_bytes",
        after.storage_read_bytes - before.storage_read_bytes,
    );
    line.number(
        "storage_writes",
        after.storage_writes - before.storage_writes,
    );
    line.number("storage_write_bytes", storage_write_bytes);
    line.number("storage_syncs", storage_syncs);
    line.float("storage_reads_per_op", per(storage_reads, operations));
    line.float(
        "storage_write_bytes_per_op",
        per(storage_write_bytes, operations),
    );
    line.float("storage_syncs_per_batch", per(storage_syncs, batches));
    line.number("disk_reads", after.disk_reads - before.disk_reads);
    line.number(
        "disk_read_bytes",
        (after.disk_read_sectors - before.disk_read_sectors) * 512,
    );
    line.number("disk_writes", after.disk_writes - before.disk_writes);
    line.number(
        "disk_write_bytes",
        (after.disk_write_sectors - before.disk_write_sectors) * 512,
    );
    line.number("disk_io_ms", after.disk_io_ms - before.disk_io_ms);
    line.number("disk_flushes", after.disk_flushes - before.disk_flushes);
    line.float(
        "disk_reads_per_op",
        per(after.disk_reads - before.disk_reads, operations),
    );
    line.number("rss", after.rss);
    line.number("peak_rss", after.peak_rss);
}

/// Total size of the files under dir.
fn dir_bytes(dir: &str) -> u64 {
    let mut total = 0;
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.metadata() {
                Ok(meta) if meta.is_dir() => stack.push(entry.path()),
                Ok(meta) => total += meta.len(),
                Err(_) => {}
            }
        }
    }
    total
}

/// The nearest-rank value at quantile q of sorted values, or NaN when there are none.
fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

/// How keys and values of one record shape are built from ids.
trait Shape: 'static {
    type Key: Clone + Send + Sync + 'static;
    type Value: Clone + Send + Sync + 'static;

    /// The key of an id.
    fn key(id: u64) -> Self::Key;

    /// The value an id takes at a version. Variable-size values are size bytes long.
    fn value(id: u64, version: u64, size: usize) -> Self::Value;
}

/// The K-byte key of an id.
fn key_of<const K: usize>(id: u64) -> FixedBytes<K> {
    let mut bytes = [0u8; K];
    fill(id, &mut bytes);
    FixedBytes::new(bytes)
}

/// The seed of the value an id takes at a version.
const fn value_seed(id: u64, version: u64) -> u64 {
    mix(id) ^ mix(version.wrapping_add(1)).rotate_left(17)
}

/// K-byte keys with 32-byte fixed-size values.
struct Fixed<const K: usize>;

impl<const K: usize> Shape for Fixed<K> {
    type Key = FixedBytes<K>;
    type Value = FixedBytes<32>;

    fn key(id: u64) -> Self::Key {
        key_of(id)
    }

    fn value(id: u64, version: u64, _size: usize) -> Self::Value {
        let mut bytes = [0u8; 32];
        fill(value_seed(id, version), &mut bytes);
        FixedBytes::new(bytes)
    }
}

/// K-byte keys with variable-size values of the requested length.
struct Variable<const K: usize>;

impl<const K: usize> Shape for Variable<K> {
    type Key = FixedBytes<K>;
    type Value = Vec<u8>;

    fn key(id: u64) -> Self::Key {
        key_of(id)
    }

    fn value(id: u64, version: u64, size: usize) -> Self::Value {
        let mut bytes = vec![0u8; size];
        fill(value_seed(id, version), &mut bytes);
        bytes
    }
}

/// Time spent in each call of one batch's update, and how many of its keys already existed.
#[derive(Clone, Copy, Default)]
struct Split {
    stage: Duration,
    merkleize: Duration,
    apply: Duration,
    found: usize,
}

/// The operations the harness needs from a keyed database. [`keyed!`] implements it for each
/// database type by forwarding to that type's own methods.
trait Keyed: Sized + Send + Sync + 'static {
    type Key: Clone + Send + Sync + 'static;
    type Value: Clone + Send + Sync + 'static;

    /// The key of an id.
    fn key(id: u64) -> Self::Key;

    /// The value an id takes at a version. Variable-size values are size bytes long.
    fn value(id: u64, version: u64, size: usize) -> Self::Value;

    /// Opens the database that opts configures, creating it if the directory is empty.
    async fn open_db(ctx: Context, opts: &Opts) -> Self;

    /// Writes each entry, merkleizes, and applies the batch without committing it.
    async fn load_entries(self, entries: Vec<(Self::Key, Self::Value)>) -> Self;

    /// Stages every key with one call, puts each key's value, merkleizes, and applies the batch
    /// without committing it, timing each step.
    async fn update_keys(self, keys: Vec<Self::Key>, values: Vec<Self::Value>) -> (Self, Split);

    /// Durably commits every applied batch.
    async fn commit_db(self) -> Self;

    /// Syncs all database state to disk.
    async fn sync_db(self) -> Self;

    /// Prunes to the sync boundary.
    async fn prune_db(self) -> Self;

    /// Gets key and reports whether it has a value.
    fn read_key<'a>(&'a self, key: &'a Self::Key) -> impl Future<Output = bool> + Send + 'a;

    /// The first retained operation location.
    fn log_start(&self) -> u64;

    /// The inactivity floor.
    fn log_floor(&self) -> u64;

    /// The location one past the last operation.
    fn log_end(&self) -> u64;

    /// The root, in hex.
    fn root_hex(&self) -> String;
}

/// Implements [`Keyed`] for database type `$db` with record shape `$shape`, opening it with the
/// config that `$config` builds.
macro_rules! keyed {
    ($db:ty, $shape:ty, $config:expr) => {
        impl Keyed for $db {
            type Key = <$shape as Shape>::Key;
            type Value = <$shape as Shape>::Value;

            fn key(id: u64) -> Self::Key {
                <$shape as Shape>::key(id)
            }

            fn value(id: u64, version: u64, size: usize) -> Self::Value {
                <$shape as Shape>::value(id, version, size)
            }

            async fn open_db(ctx: Context, opts: &Opts) -> Self {
                let config = ($config)(&ctx, opts);
                Self::init(ctx, config, None).await.expect("init")
            }

            async fn load_entries(self, entries: Vec<(Self::Key, Self::Value)>) -> Self {
                let mut batch = self.new_batch();
                for (key, value) in entries {
                    batch = batch.write(key, Some(value));
                }
                let merkleized = batch.merkleize(&self).await.expect("merkleize");
                self.apply_batch(merkleized).await.expect("apply")
            }

            async fn update_keys(
                self,
                keys: Vec<Self::Key>,
                values: Vec<Self::Value>,
            ) -> (Self, Split) {
                let start = Instant::now();
                let (staged, existing) = self.new_batch().stage(&keys, &self).await.expect("stage");
                let found = existing.iter().filter(|value| value.is_some()).count();
                let staged_at = start.elapsed();
                let slots = values.into_iter().map(Slot::Put).collect();
                let merkleized = staged
                    .merkleize(slots, Vec::new(), &self)
                    .await
                    .expect("merkleize");
                black_box(merkleized.root());
                let merkleized_at = start.elapsed();
                let db = self.apply_batch(merkleized).await.expect("apply");
                let split = Split {
                    stage: staged_at,
                    merkleize: merkleized_at - staged_at,
                    apply: start.elapsed() - merkleized_at,
                    found,
                };
                (db, split)
            }

            async fn commit_db(self) -> Self {
                self.commit().await.expect("commit")
            }

            async fn sync_db(self) -> Self {
                self.sync().await.expect("sync")
            }

            async fn prune_db(self) -> Self {
                let boundary = self.sync_boundary();
                self.prune(boundary).await.expect("prune")
            }

            fn read_key<'a>(
                &'a self,
                key: &'a Self::Key,
            ) -> impl Future<Output = bool> + Send + 'a {
                async move { self.get(key).await.expect("get").is_some() }
            }

            fn log_start(&self) -> u64 {
                *self.bounds().start
            }

            fn log_floor(&self) -> u64 {
                *self.inactivity_floor()
            }

            fn log_end(&self) -> u64 {
                *self.bounds().end
            }

            fn root_hex(&self) -> String {
                self.root().to_string()
            }
        }
    };
}

/// The Merkle structure config shared by every variant.
fn merkle_config(ctx: &Context, opts: &Opts) -> MerkleConfig<Rayon> {
    MerkleConfig {
        partition: "merkle".into(),
        resident_height: Default::default(),
        replay_buffer: NonZeroUsize::new(4 << 20).unwrap(),
        strategy: ctx.strategy(opts.threads),
    }
}

/// The fixed-size journal config.
fn fixed_log(opts: &Opts) -> FixedLog {
    FixedLog {
        partition: "log".into(),
        items_per_blob: opts.items_per_blob,
        page_cache: opts.cache(),
        write_buffer: NonZeroUsize::new(2 << 20).unwrap(),
        replay_buffer: NonZeroUsize::new(4 << 20).unwrap(),
    }
}

/// Codec config of a variable-size operation: none for the key, and a length range for the value.
type VariableCodec = ((), (RangeCfg<usize>, ()));

/// The variable-size journal config. Its codec reads values of at most 1 MiB.
fn variable_log(opts: &Opts) -> VariableLog<VariableCodec> {
    VariableLog {
        partition: "log".into(),
        items_per_section: opts.items_per_blob,
        compression: None,
        codec_config: ((), ((0..=MAX_VALUE).into(), ())),
        page_cache: opts.cache(),
        write_buffer: NonZeroUsize::new(2 << 20).unwrap(),
        replay_buffer: NonZeroUsize::new(4 << 20).unwrap(),
    }
}

/// The config of an any database on the given journal.
fn any_config<T: Translator + Default, J>(
    ctx: &Context,
    opts: &Opts,
    log: J,
) -> any::Config<T, J, Rayon> {
    any::Config {
        merkle: merkle_config(ctx, opts),
        log,
        translator: T::default(),
        init_cache: NonZeroUsize::new(opts.init_cache),
        init_buffer: NonZeroUsize::new(4 << 20).unwrap(),
        init_concurrency: opts.threads,
    }
}

/// The config of a current database on the given journal.
fn current_config<T: Translator + Default, J>(
    ctx: &Context,
    opts: &Opts,
    log: J,
) -> current::Config<T, J, Rayon> {
    current::Config {
        merkle: merkle_config(ctx, opts),
        log,
        grafted_metadata_partition: "grafted".into(),
        translator: T::default(),
        init_cache: NonZeroUsize::new(opts.init_cache),
        init_buffer: NonZeroUsize::new(4 << 20).unwrap(),
        init_concurrency: opts.threads,
    }
}

fn any_fixed<T: Translator + Default>(
    ctx: &Context,
    opts: &Opts,
) -> any::Config<T, FixedLog, Rayon> {
    any_config(ctx, opts, fixed_log(opts))
}

fn any_variable<T: Translator + Default>(
    ctx: &Context,
    opts: &Opts,
) -> any::Config<T, VariableLog<VariableCodec>, Rayon> {
    any_config(ctx, opts, variable_log(opts))
}

fn current_fixed<T: Translator + Default>(
    ctx: &Context,
    opts: &Opts,
) -> current::Config<T, FixedLog, Rayon> {
    current_config(ctx, opts, fixed_log(opts))
}

fn current_variable<T: Translator + Default>(
    ctx: &Context,
    opts: &Opts,
) -> current::Config<T, VariableLog<VariableCodec>, Rayon> {
    current_config(ctx, opts, variable_log(opts))
}

type Key<const K: usize> = FixedBytes<K>;
type Value32 = FixedBytes<32>;

/// Declares each database type the harness can drive under its flavor key,
/// "db/log/index/translator/key size". The generated `dispatch` drives the type whose key matches
/// [`Opts::flavor`].
macro_rules! flavors {
    ($( $name:literal => $alias:ident = $db:ty, $shape:ty, $config:expr; )+) => {
        $(
            type $alias = $db;
            keyed!($alias, $shape, $config);
        )+

        async fn dispatch(ctx: Context, opts: &Opts) {
            match opts.flavor().as_str() {
                $( $name => drive::<$alias>(ctx, opts).await, )+
                other => panic!("flavor {other} must be one of the compiled-in combinations"),
            }
        }
    };
}

flavors! {
    // The defaults: each variant on the fixed-size journal with 32-byte keys and values, its
    // default index, and the eight-byte translator.
    "any::unordered/fixed/p2/eight/32" => AuP2Eight =
        any::unordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, EightCap, 2, Rayon>,
        Fixed<32>, any_fixed::<EightCap>;
    "any::ordered/fixed/p3/eight/32" => AoP3Eight =
        any::ordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, EightCap, 3, Rayon>,
        Fixed<32>, any_fixed::<EightCap>;
    "current::unordered/fixed/p2/eight/32" => CuP2Eight =
        current::unordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, EightCap, 2, CHUNK, Rayon>,
        Fixed<32>, current_fixed::<EightCap>;
    "current::ordered/fixed/p3/eight/32" => CoP3Eight =
        current::ordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, EightCap, 3, CHUNK, Rayon>,
        Fixed<32>, current_fixed::<EightCap>;

    // Other indexes and translators, on the fixed-size journal.
    "any::unordered/fixed/plain/eight/32" => AuPlainEight =
        any::unordered::fixed::Db<Family, Context, Key<32>, Value32, Sha256, EightCap, Rayon>,
        Fixed<32>, any_fixed::<EightCap>;
    "any::unordered/fixed/p2/four/32" => AuP2Four =
        any::unordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, FourCap, 2, Rayon>,
        Fixed<32>, any_fixed::<FourCap>;
    "any::unordered/fixed/p2/two/32" => AuP2Two =
        any::unordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, TwoCap, 2, Rayon>,
        Fixed<32>, any_fixed::<TwoCap>;
    "any::ordered/fixed/plain/eight/32" => AoPlainEight =
        any::ordered::fixed::Db<Family, Context, Key<32>, Value32, Sha256, EightCap, Rayon>,
        Fixed<32>, any_fixed::<EightCap>;
    "any::ordered/fixed/p2/eight/32" => AoP2Eight =
        any::ordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, EightCap, 2, Rayon>,
        Fixed<32>, any_fixed::<EightCap>;
    "any::ordered/fixed/p3/four/32" => AoP3Four =
        any::ordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, FourCap, 3, Rayon>,
        Fixed<32>, any_fixed::<FourCap>;
    "any::ordered/fixed/p3/two/32" => AoP3Two =
        any::ordered::fixed::partitioned::Db<Family, Context, Key<32>, Value32, Sha256, TwoCap, 3, Rayon>,
        Fixed<32>, any_fixed::<TwoCap>;

    // The variable-size journal, for any value size and for 20-, 32-, or 64-byte keys.
    "any::unordered/variable/p2/eight/20" => AuVar20 =
        any::unordered::variable::partitioned::Db<Family, Context, Key<20>, Vec<u8>, Sha256, EightCap, 2, Rayon>,
        Variable<20>, any_variable::<EightCap>;
    "any::unordered/variable/p2/eight/32" => AuVar32 =
        any::unordered::variable::partitioned::Db<Family, Context, Key<32>, Vec<u8>, Sha256, EightCap, 2, Rayon>,
        Variable<32>, any_variable::<EightCap>;
    "any::unordered/variable/p2/eight/64" => AuVar64 =
        any::unordered::variable::partitioned::Db<Family, Context, Key<64>, Vec<u8>, Sha256, EightCap, 2, Rayon>,
        Variable<64>, any_variable::<EightCap>;
    "any::ordered/variable/p3/eight/20" => AoVar20 =
        any::ordered::variable::partitioned::Db<Family, Context, Key<20>, Vec<u8>, Sha256, EightCap, 3, Rayon>,
        Variable<20>, any_variable::<EightCap>;
    "any::ordered/variable/p3/eight/32" => AoVar32 =
        any::ordered::variable::partitioned::Db<Family, Context, Key<32>, Vec<u8>, Sha256, EightCap, 3, Rayon>,
        Variable<32>, any_variable::<EightCap>;
    "any::ordered/variable/p3/eight/64" => AoVar64 =
        any::ordered::variable::partitioned::Db<Family, Context, Key<64>, Vec<u8>, Sha256, EightCap, 3, Rayon>,
        Variable<64>, any_variable::<EightCap>;
    "current::unordered/variable/p2/eight/20" => CuVar20 =
        current::unordered::variable::partitioned::Db<Family, Context, Key<20>, Vec<u8>, Sha256, EightCap, 2, CHUNK, Rayon>,
        Variable<20>, current_variable::<EightCap>;
    "current::unordered/variable/p2/eight/32" => CuVar32 =
        current::unordered::variable::partitioned::Db<Family, Context, Key<32>, Vec<u8>, Sha256, EightCap, 2, CHUNK, Rayon>,
        Variable<32>, current_variable::<EightCap>;
    "current::unordered/variable/p2/eight/64" => CuVar64 =
        current::unordered::variable::partitioned::Db<Family, Context, Key<64>, Vec<u8>, Sha256, EightCap, 2, CHUNK, Rayon>,
        Variable<64>, current_variable::<EightCap>;
    "current::ordered/variable/p3/eight/20" => CoVar20 =
        current::ordered::variable::partitioned::Db<Family, Context, Key<20>, Vec<u8>, Sha256, EightCap, 3, CHUNK, Rayon>,
        Variable<20>, current_variable::<EightCap>;
    "current::ordered/variable/p3/eight/32" => CoVar32 =
        current::ordered::variable::partitioned::Db<Family, Context, Key<32>, Vec<u8>, Sha256, EightCap, 3, CHUNK, Rayon>,
        Variable<32>, current_variable::<EightCap>;
    "current::ordered/variable/p3/eight/64" => CoVar64 =
        current::ordered::variable::partitioned::Db<Family, Context, Key<64>, Vec<u8>, Sha256, EightCap, 3, CHUNK, Rayon>,
        Variable<64>, current_variable::<EightCap>;
}

/// Records the journal bounds, inactivity floor, directory size, and root.
fn state<D: Keyed>(line: &mut Line, db: &D, opts: &Opts) {
    line.number("log_start", db.log_start());
    line.number("log_floor", db.log_floor());
    line.number("log_end", db.log_end());
    line.number("dir_bytes", dir_bytes(&opts.dir));
    line.text("root", &db.root_hex());
}

/// Inserts keys 0..`--keys` into an empty database, committing each batch, then prunes and syncs
/// it.
async fn load<D: Keyed>(ctx: Context, opts: &Opts) {
    let mut db = D::open_db(ctx.child("db"), opts).await;
    assert_eq!(db.log_end(), 1, "load must start from an empty database");
    let before = sample(&ctx, opts);
    let mut timed = Duration::ZERO;
    let mut reported = (0u64, Duration::ZERO);
    let mut loaded = 0;
    while loaded < opts.keys {
        let end = (loaded + opts.load_batch).min(opts.keys);
        let entries: Vec<_> = (loaded..end)
            .map(|id| (D::key(id), D::value(id, 0, opts.value_size)))
            .collect();
        let start = Instant::now();
        db = db.load_entries(entries).await;
        db = db.commit_db().await;
        timed += start.elapsed();
        loaded = end;

        // Report every ten batches and after the last one, with the rate since the previous report.
        if loaded - reported.0 >= 10 * opts.load_batch || loaded == opts.keys {
            let mut line = Line::new("load_progress", opts);
            line.number("loaded", loaded);
            line.float("secs", timed.as_secs_f64());
            line.float(
                "keys_per_s",
                (loaded - reported.0) as f64 / (timed - reported.1).as_secs_f64(),
            );
            line.number("log_end", db.log_end());
            line.number("rss", sample(&ctx, opts).rss);
            line.emit(opts);
            reported = (loaded, timed);
        }
    }
    let start = Instant::now();
    let db = db.prune_db().await;
    let db = db.sync_db().await;
    let sync = start.elapsed();
    let after = sample(&ctx, opts);
    let mut line = Line::new("load", opts);
    line.float("secs", timed.as_secs_f64());
    line.float("sync_secs", sync.as_secs_f64());
    line.float("keys_per_s", opts.keys as f64 / timed.as_secs_f64());
    counters(
        &mut line,
        &before,
        &after,
        opts.keys,
        opts.keys.div_ceil(opts.load_batch),
    );
    state(&mut line, &db, opts);
    line.emit(opts);
}

/// Settings of one phase, parsed from "kind:name=value,...".
struct Phase {
    kind: String,
    settings: HashMap<String, String>,
}

impl Phase {
    /// Parses one phase, rejecting a kind, a setting name, or a `dist` or `warm` value that no
    /// phase reads. A misspelled setting would otherwise leave its default in place unnoticed.
    fn parse(spec: &str) -> Self {
        let (kind, rest) = spec.split_once(':').unwrap_or((spec, ""));
        let kind = kind.trim();
        let known: &[&str] = match kind {
            "update" => &[
                "active",
                "active-keys",
                "batch",
                "creates",
                "dist",
                "label",
                "max-secs",
                "min-batches",
                "secs",
                "warm",
                "warm-fill",
                "warm-max-secs",
                "warm-max-updates",
                "warm-min-updates",
                "warm-secs",
                "windows",
                "zipf",
            ],
            "read" => &["gets", "label", "readers", "secs"],
            "prune" => &[],
            other => panic!("phase kind {other} must be update, read, or prune"),
        };
        let settings: HashMap<String, String> = rest
            .split(',')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = pair
                    .split_once('=')
                    .unwrap_or_else(|| panic!("setting {pair} must have the form name=value"));
                assert!(
                    known.contains(&name),
                    "setting {name} must be one that a {kind} phase reads"
                );
                (name.to_string(), value.to_string())
            })
            .collect();
        if let Some(dist) = settings.get("dist") {
            assert!(
                matches!(dist.as_str(), "uniform" | "zipf"),
                "dist must be uniform or zipf, found {dist}"
            );
        }
        if let Some(warm) = settings.get("warm") {
            assert!(
                matches!(warm.as_str(), "auto" | "none") || warm.parse::<u64>().is_ok(),
                "warm must be auto, none, or a number of updates, found {warm}"
            );
        }
        Self {
            kind: kind.to_string(),
            settings,
        }
    }

    /// The setting called name parsed as T, or default when it is absent.
    fn get<T: std::str::FromStr>(&self, name: &str, default: T) -> T {
        self.settings.get(name).map_or(default, |value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("setting {name} must parse as its type, found {value}"))
        })
    }

    /// The setting called name, or default when it is absent.
    fn text(&self, name: &str, default: &str) -> String {
        self.settings
            .get(name)
            .cloned()
            .unwrap_or_else(|| default.into())
    }
}

/// Chooses the ids each batch touches.
struct Sampler {
    rng: StdRng,
    keys: u64,
    active: u64,
    zipf: Option<Zipf<f64>>,
    next_new: u64,
    seen: HashSet<u64>,
}

impl Sampler {
    /// Returns the ids of one batch: `existing` distinct ids drawn from the distribution, then
    /// `creates` ids that no batch has used.
    fn batch(&mut self, existing: usize, creates: usize) -> Vec<u64> {
        assert!(
            existing as u64 <= self.active,
            "existing keys per batch must not exceed the active set"
        );
        self.seen.clear();
        let mut ids = Vec::with_capacity(existing + creates);
        while ids.len() < existing {
            let rank = match &self.zipf {
                Some(zipf) => (zipf.sample(&mut self.rng) as u64).clamp(1, self.keys) - 1,
                None => self.rng.random_range(0..self.active),
            };
            if self.seen.insert(rank) {
                ids.push(scatter(rank, self.keys));
            }
        }
        for _ in 0..creates {
            ids.push(self.next_new);
            self.next_new += 1;
        }
        ids
    }
}

/// What one measured or warm-up window accumulated.
#[derive(Default)]
struct Window {
    batches: u64,
    updates: u64,
    found: u64,
    stage: Duration,
    merkleize: Duration,
    apply: Duration,
    commit: Duration,
    prune: Duration,
    prunes: u64,
    batch_ms: Vec<f64>,
}

impl Window {
    /// Time spent in the window's timed calls.
    fn timed(&self) -> Duration {
        self.stage + self.merkleize + self.apply + self.commit + self.prune
    }
}

/// Runs one update phase: warm-up windows until warm-up ends, then `windows` measured windows.
/// Each window reports one line.
#[allow(clippy::too_many_arguments)]
async fn update_phase<D: Keyed>(
    ctx: &Context,
    opts: &Opts,
    phase: &Phase,
    mut db: D,
    opened: &Sample,
    version: &mut u64,
    since_prune: &mut u64,
    next_new: &mut u64,
) -> D {
    let batch: usize = phase.get("batch", 10_000);
    let creates: usize = phase.get("creates", 0);
    let active = match phase.get("active-keys", 0u64) {
        0 => ((opts.keys as f64 * phase.get("active", 1.0f64)) as u64).clamp(1, opts.keys),
        count => count.min(opts.keys),
    };
    let dist = phase.text("dist", "uniform");
    let exponent: f64 = phase.get("zipf", 0.99);
    let secs = Duration::from_secs_f64(phase.get("secs", 20.0));
    let warm_secs = Duration::from_secs_f64(phase.get("warm-secs", 5.0));
    let max_secs = Duration::from_secs_f64(phase.get("max-secs", 600.0));
    let min_batches: u64 = phase.get("min-batches", 30);
    let windows: usize = phase.get("windows", 3);
    let warm = phase.text("warm", "auto");
    let warm_max_updates: u64 = phase.get("warm-max-updates", 300_000_000);

    // Until most of the active set has been rewritten at the tip of the journal, windows can agree
    // while the layout still drifts, so settling is tested only after this many updates.
    let warm_min_updates: u64 = phase.get(
        "warm-min-updates",
        if dist == "zipf" {
            30_000_000
        } else {
            (3 * active).min(warm_max_updates)
        },
    );
    let warm_max_secs = Duration::from_secs_f64(phase.get("warm-max-secs", 900.0));
    let label = phase.text("label", "");
    assert!(creates <= batch, "creates must not exceed batch");

    // Journal pages enter the page cache as they are read or written, so nothing has been evicted
    // until storage traffic since the open exceeds the cache's capacity. Until then, reads at the
    // inactivity floor still find their pages in memory, as they would not in a long-running
    // database, so settling is tested only after this much traffic.
    let fill: f64 = phase.get("warm-fill", 1.25);
    let fill_bytes = (opts.cache_pages.get() as f64 * 4096.0 * fill) as u64;

    let mut sampler = Sampler {
        rng: StdRng::seed_from_u64(opts.seed ^ mix(*version)),
        keys: opts.keys,
        active,
        zipf: (dist == "zipf").then(|| Zipf::new(opts.keys as f64, exponent).expect("zipf")),
        next_new: *next_new,
        seen: HashSet::with_capacity(batch * 2),
    };

    let mut warm_history: Vec<(f64, f64)> = Vec::new();
    let mut warm_updates = 0u64;
    let mut warm_timed = Duration::ZERO;
    let mut warming = warm != "none";
    let mut measured = 0;
    while measured < windows {
        // A warm-up window runs for `warm-secs` of timed calls. A measured one runs for `secs` and
        // at least `min-batches` batches, unless it reaches `max-secs` with at least five batches.
        let (target, needed) = if warming {
            (warm_secs, 1)
        } else {
            (secs, min_batches)
        };
        let before = sample(ctx, opts);
        let mut window = Window::default();
        while (window.timed() < target || window.batches < needed)
            && (window.timed() < max_secs || window.batches < 5)
        {
            let ids = sampler.batch(batch - creates, creates);
            *version += 1;
            let keys: Vec<_> = ids.iter().map(|id| D::key(*id)).collect();
            let values: Vec<_> = ids
                .iter()
                .map(|id| D::value(*id, *version, opts.value_size))
                .collect();
            let (next, split) = db.update_keys(keys, values).await;
            let start = Instant::now();
            db = next.commit_db().await;
            let commit = start.elapsed();
            window.batches += 1;
            window.updates += ids.len() as u64;
            window.found += split.found as u64;
            window.stage += split.stage;
            window.merkleize += split.merkleize;
            window.apply += split.apply;
            window.commit += commit;
            let mut total = split.stage + split.merkleize + split.apply + commit;
            *since_prune += ids.len() as u64;
            if *since_prune >= opts.prune_every {
                let start = Instant::now();
                db = db.prune_db().await;
                window.prune += start.elapsed();
                window.prunes += 1;
                total += start.elapsed();
                *since_prune = 0;
            }
            window.batch_ms.push(total.as_secs_f64() * 1e3);
        }
        let after = sample(ctx, opts);
        let timed = window.timed().as_secs_f64();
        let rate = window.updates as f64 / timed;
        let reads_per_key =
            (after.storage_reads - before.storage_reads) as f64 / window.updates as f64;

        let mut line = Line::new("update", opts);
        line.text("label", &label);
        line.number("warm", u8::from(warming));
        line.number(
            "window",
            if warming {
                warm_history.len()
            } else {
                measured
            },
        );
        line.number("batch", batch);
        line.number("creates", creates);
        line.number("active_keys", active);
        line.text("dist", &dist);
        line.float("zipf", if dist == "zipf" { exponent } else { 0.0 });
        line.number("batches", window.batches);
        line.number("updates", window.updates);
        line.number("found", window.found);
        line.float("secs", timed);
        line.float("updates_per_s", rate);
        let per_batch = |d: Duration| d.as_secs_f64() * 1e3 / window.batches as f64;
        line.float("stage_ms", per_batch(window.stage));
        line.float("merkleize_ms", per_batch(window.merkleize));
        line.float("apply_ms", per_batch(window.apply));
        line.float("commit_ms", per_batch(window.commit));
        line.float("prune_ms", per_batch(window.prune));
        line.number("prunes", window.prunes);
        window.batch_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        line.float("batch_ms_p50", quantile(&window.batch_ms, 0.5));
        line.float("batch_ms_p90", quantile(&window.batch_ms, 0.9));
        line.float("batch_ms_p99", quantile(&window.batch_ms, 0.99));
        line.float("batch_ms_max", quantile(&window.batch_ms, 1.0));
        counters(&mut line, &before, &after, window.updates, window.batches);
        state(&mut line, &db, opts);

        if warming {
            warm_history.push((rate, reads_per_key));
            warm_updates += window.updates;
            warm_timed += window.timed();
            let settled = match warm.as_str() {
                // Past the update and traffic minimums, the last three windows must agree. Their
                // throughput must be within 3% of the highest, and their storage reads per key
                // within 5% of the highest or 0.002.
                "auto" => {
                    warm_updates >= warm_min_updates
                        && (after.storage_read_bytes - opened.storage_read_bytes)
                            + (after.storage_write_bytes - opened.storage_write_bytes)
                            >= fill_bytes
                        && warm_history.len() >= 3
                        && {
                            let last = &warm_history[warm_history.len() - 3..];
                            let spread = |values: Vec<f64>, share: f64, slack: f64| {
                                let low = values.iter().copied().fold(f64::INFINITY, f64::min);
                                let high = values.iter().copied().fold(0.0, f64::max);
                                high - low <= (share * high).max(slack)
                            };
                            spread(last.iter().map(|w| w.0).collect(), 0.03, 0.0)
                                && spread(last.iter().map(|w| w.1).collect(), 0.05, 0.002)
                        }
                }
                count => warm_updates >= count.parse::<u64>().expect("warm"),
            };
            let capped = warm_updates >= warm_max_updates || warm_timed >= warm_max_secs;
            line.number("warm_settled", u8::from(settled));
            line.number("warm_updates", warm_updates);
            warming = !(settled || capped);
        } else {
            line.number("warm_updates", warm_updates);
            measured += 1;
        }
        line.emit(opts);
    }
    *next_new = sampler.next_new;
    db
}

/// Latencies in nanoseconds, in buckets whose width doubles every sixteen buckets. From 16 ns up,
/// each bucket is at most a sixteenth of its lower bound wide.
struct Histogram {
    counts: Vec<u64>,
    total: u64,
    max: u64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            counts: vec![0; 64 * 16],
            total: 0,
            max: 0,
        }
    }

    /// The bucket that holds a latency of nanos nanoseconds.
    const fn bucket(nanos: u64) -> usize {
        if nanos < 16 {
            return nanos as usize;
        }
        let top = 63 - nanos.leading_zeros() as usize;
        (top - 3) * 16 + ((nanos >> (top - 4)) & 15) as usize
    }

    /// The lower bound of a bucket, in nanoseconds.
    const fn floor(bucket: usize) -> u64 {
        if bucket < 16 {
            return bucket as u64;
        }
        let top = bucket / 16 + 3;
        (16 + (bucket % 16) as u64) << (top - 4)
    }

    fn record(&mut self, elapsed: Duration) {
        let nanos = elapsed.as_nanos() as u64;
        self.counts[Self::bucket(nanos)] += 1;
        self.total += 1;
        self.max = self.max.max(nanos);
    }

    fn merge(&mut self, other: &Self) {
        for (count, more) in self.counts.iter_mut().zip(&other.counts) {
            *count += more;
        }
        self.total += other.total;
        self.max = self.max.max(other.max);
    }

    /// The lower bound of the bucket holding quantile q, in milliseconds.
    fn quantile_ms(&self, q: f64) -> f64 {
        let rank = (self.total as f64 * q).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (bucket, count) in self.counts.iter().enumerate() {
            seen += count;
            if seen >= rank {
                return Self::floor(bucket) as f64 / 1e6;
            }
        }
        self.max as f64 / 1e6
    }
}

/// Runs one read phase: `readers` concurrent readers that each get one uniformly random loaded key
/// at a time, until the deadline or until each has done its share of `gets`.
async fn read_phase<D: Keyed>(ctx: &Context, opts: &Opts, phase: &Phase, db: D) -> D {
    let readers: u64 = phase.get("readers", 64);
    let secs = Duration::from_secs_f64(phase.get("secs", 20.0));
    let gets: u64 = phase.get("gets", 0);
    let label = phase.text("label", "");
    let db = Arc::new(db);
    let before = sample(ctx, opts);
    let start = Instant::now();
    let deadline = start + secs;
    let tasks: Vec<_> = (0..readers)
        .map(|reader| {
            let db = db.clone();
            let keys = opts.keys;
            let seed = opts.seed ^ mix(reader + 1) ^ mix(start.elapsed().as_nanos() as u64);

            // A count-bounded phase gives each reader an equal share of `gets`, rounded up. A timed
            // one runs each reader until the deadline.
            let quota = if gets > 0 {
                gets.div_ceil(readers)
            } else {
                u64::MAX
            };
            ctx.child("reader").spawn(move |_| async move {
                let mut rng = StdRng::seed_from_u64(seed);
                let mut histogram = Histogram::new();
                let mut found = 0u64;
                let mut done = 0u64;
                while done < quota {
                    let key = D::key(rng.random_range(0..keys));
                    let begin = Instant::now();
                    found += u64::from(db.read_key(&key).await);
                    let end = Instant::now();
                    histogram.record(end - begin);
                    done += 1;
                    if quota == u64::MAX && end >= deadline {
                        break;
                    }
                }
                (histogram, found)
            })
        })
        .collect();
    let mut histogram = Histogram::new();
    let mut found = 0;
    for task in tasks {
        let (part, hits) = task.await.expect("reader must finish");
        histogram.merge(&part);
        found += hits;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let after = sample(ctx, opts);
    let db = Arc::try_unwrap(db).ok().expect("readers must be done");

    let mut line = Line::new("read", opts);
    line.text("label", &label);
    line.number("readers", readers);
    line.number("reads", histogram.total);
    line.number("found", found);
    line.float("secs", elapsed);
    line.float("reads_per_s", histogram.total as f64 / elapsed);
    line.float("p50_ms", histogram.quantile_ms(0.5));
    line.float("p90_ms", histogram.quantile_ms(0.9));
    line.float("p99_ms", histogram.quantile_ms(0.99));
    line.float("p999_ms", histogram.quantile_ms(0.999));
    line.float("max_ms", histogram.max as f64 / 1e6);
    counters(&mut line, &before, &after, histogram.total, 0);
    line.emit(opts);
    db
}

/// Parses the phases, opens the database, checks that key `--keys` - 1 exists, runs every phase in
/// order, and syncs.
async fn run<D: Keyed>(ctx: Context, opts: &Opts) {
    let phases: Vec<Phase> = opts
        .phases
        .split(';')
        .filter(|spec| !spec.trim().is_empty())
        .map(Phase::parse)
        .collect();
    let before = sample(&ctx, opts);
    let start = Instant::now();
    let mut db = D::open_db(ctx.child("db"), opts).await;
    let opened = start.elapsed();
    let after = sample(&ctx, opts);
    let mut line = Line::new("open", opts);
    line.float("secs", opened.as_secs_f64());
    counters(&mut line, &before, &after, 0, 0);
    state(&mut line, &db, opts);
    line.emit(opts);
    assert!(
        db.read_key(&D::key(opts.keys - 1)).await,
        "--keys must match the number of keys loaded"
    );

    // Update phases share the value version, the prune countdown, and the next new id, so each
    // continues where the previous one stopped.
    let mut version = 0;
    let mut since_prune = 0;
    let mut next_new = opts.keys;
    for phase in &phases {
        db = match phase.kind.as_str() {
            "update" => {
                update_phase(
                    &ctx,
                    opts,
                    phase,
                    db,
                    &after,
                    &mut version,
                    &mut since_prune,
                    &mut next_new,
                )
                .await
            }
            "read" => read_phase(&ctx, opts, phase, db).await,
            "prune" => {
                let db = db.prune_db().await;
                let mut line = Line::new("prune", opts);
                state(&mut line, &db, opts);
                line.emit(opts);
                db
            }
            other => unreachable!("Phase::parse accepted kind {other}"),
        };
    }
    let db = db.sync_db().await;
    let mut line = Line::new("done", opts);
    state(&mut line, &db, opts);
    line.emit(opts);
}

/// Runs the subcommand on database type D.
async fn drive<D: Keyed>(ctx: Context, opts: &Opts) {
    match opts.command.as_str() {
        "load" => load::<D>(ctx, opts).await,
        "run" => run::<D>(ctx, opts).await,
        other => panic!("command {other} must be load or run"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--bench")
        .collect();

    // Blanket bench invocations pass libtest and Criterion flags or a benchmark name filter, none
    // of which is a subcommand.
    let command = match args.first().map(String::as_str) {
        Some(command @ ("load" | "run")) => command,
        _ => return,
    };
    let opts = Opts::parse(command, &args[1..]);
    let mut line = Line::new("start", &opts);
    line.text("command", &opts.command);
    line.text("flavor", &opts.flavor());
    line.text("dir", &opts.dir);
    line.text("phases", &opts.phases);
    line.number("items_per_blob", opts.items_per_blob);
    line.number("load_batch", opts.load_batch);
    line.number("prune_every", opts.prune_every);
    line.number("seed", opts.seed);
    line.emit(&opts);

    let config = RuntimeConfig::default()
        .with_worker_threads(opts.threads.get())
        .with_storage_directory(opts.dir.clone());
    Runner::new(config).start(|ctx| async move { dispatch(ctx, &opts).await });
}
