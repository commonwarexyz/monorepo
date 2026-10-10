//! Replays a recorded state-transition trace (a `statedump` `trace.bin`) into a
//! `current::ordered::variable` QMDB with a partitioned index (P=3), timing the
//! per-block read and write path. Durability is pipelined: each commit boundary
//! starts an in-flight `start_sync` whose fsync overlaps the next blocks' processing.
//!
//! The trace format is account-model state access: per-block groups of account and
//! storage reads, writes, balance/nonce/code updates. Any producer of the format
//! works; the reference producer is an instrumented Ethereum client, and the record
//! encodings carry that lineage (20-byte addresses, 32-byte slots and words).
//!
//! # Trace format
//!
//! A trace is a stream of record groups. Each group starts with a 16-byte header:
//!
//! ```text
//! block[8]  u64 LE  block number
//! tx[4]     u32 LE  transaction index (0xFFFFFFFF for a block-finalization group)
//! nrec[4]   u32 LE  number of records that follow
//! ```
//!
//! followed by `nrec` records, each a tag byte and fixed-width fields:
//!
//! ```text
//! 0x01 SREAD   addr[20] slot[32]           storage read
//! 0x02 SWRITE  addr[20] slot[32] word[32]  storage write (all-zero word = delete)
//! 0x03 AREAD   addr[20]                    account read
//! 0x04 BAL     addr[20] balance[32]        balance update
//! 0x05 NONCE   addr[20] nonce[8]           nonce update (u64 BE)
//! 0x06 CODE    addr[20] codehash[32]       code hash update
//! ```
//!
//! A block's groups must be contiguous and block numbers must not decrease. The
//! replayer folds all of a block's groups into one batch and ignores the tx index.
//!
//! Keys are `Sha256(addr)` (accounts) and `Sha256(addr || slot)` (storage): a
//! uniform, collision-free 32-byte mapping. Account values are the 72-byte record
//! `nonce[8] || balance[32] || codeHash[32]`; storage values are the 32-byte word.
//! A zero storage write is a delete.
//!
//! Usage:
//!   cargo bench -p commonware-storage --bench trace_replay -- \
//!     <trace.bin> [mode] [commit_every] [max_blocks] [page_cache_pages] [threads] [storage_dir] [prune_every]
//!
//! `mode` is `builder` (reads discovered serially during execution) or `follower`
//! (full access lists known up front). `<trace.bin>` may be `-` to stream from stdin.
//!
//! Environment:
//!   REPLAY_KEEP            keep (and reopen) an existing database instead of starting fresh
//!   REPLAY_INIT_CACHE      init-time location cache entries (default 1<<25)
//!   REPLAY_INIT_CONC       init concurrency (default: threads)
//!   REPLAY_POOL_TUNED      size the storage buffer pool to this run
//!   REPLAY_METRICS_ADDR    serve the metrics registry over HTTP (e.g. 127.0.0.1:9464)
//!   REPLAY_METRICS_OUT     write the full metrics dump to this path at exit
//!   REPLAY_TRACE           export OTLP spans; REPLAY_TRACE_ENDPOINT / _NAME / _RATE tune it

use commonware_codec::RangeCfg;
use commonware_cryptography::{DigestOf, Hasher as _, Sha256};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Clock as _, Handle, Runner as _, Strategizer as _, Supervisor as _,
    buffer::paged::CacheRef,
    tokio::{
        Config as RConfig, Context, Runner,
        telemetry::{self, Logs},
        tracing::Config as OtlpConfig,
    },
};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{full, mmb},
    qmdb::{current::VariableConfig, floor::Proportional},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use std::{
    collections::{HashMap, HashSet},
    io::{BufReader, Read},
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};
use tracing::Level;

type Digest = DigestOf<Sha256>;
type Key = Digest;
type Value = Vec<u8>;
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const P: usize = 3;
const N: usize = 32;

type Db = commonware_storage::qmdb::current::ordered::variable::partitioned::Db<
    mmb::Family,
    Context,
    Key,
    Value,
    Sha256,
    EightCap,
    P,
    N,
    Rayon,
>;

type ReplayConfig = VariableConfig<EightCap, ((), (RangeCfg<usize>, ())), Rayon, NonZeroUsize>;

const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(131_072); // 512 MiB
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const REPLAY_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

// Record tags in trace.bin.
const SREAD: u8 = 0x01;
const SWRITE: u8 = 0x02;
const AREAD: u8 = 0x03;
const BAL: u8 = 0x04;
const NONCE: u8 = 0x05;
const CODE: u8 = 0x06;

const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

fn account_key(addr: &[u8]) -> Key {
    Sha256::hash(&[addr])
}
fn storage_key(addr: &[u8], slot: &[u8]) -> Key {
    Sha256::hash(&[addr, slot])
}

/// A fresh account record: nonce 0, balance 0, empty-code hash. Overlaid with a block's field
/// changes for accounts that have no on-disk record yet.
fn default_account_record() -> Vec<u8> {
    let mut v = Vec::with_capacity(72);
    v.extend_from_slice(&[0u8; 8]);
    v.extend_from_slice(&[0u8; 32]);
    v.extend_from_slice(&EMPTY_CODE_HASH);
    v
}

/// The fields of one account changed within a block. Untouched fields are read from the
/// account's current on-disk record at flush, so no cross-block account state is kept in memory.
#[derive(Default)]
struct AccountDelta {
    nonce: Option<[u8; 8]>,
    balance: Option<[u8; 32]>,
    code_hash: Option<[u8; 32]>,
}

/// Overlay a block's field changes onto a 72-byte account record
/// (nonce[8] || balance[32] || codeHash[32]).
fn apply_account_delta(mut rec: Vec<u8>, d: &AccountDelta) -> Vec<u8> {
    if let Some(n) = &d.nonce {
        rec[0..8].copy_from_slice(n);
    }
    if let Some(b) = &d.balance {
        rec[8..40].copy_from_slice(b);
    }
    if let Some(c) = &d.code_hash {
        rec[40..72].copy_from_slice(c);
    }
    rec
}

/// One block's staged mutations. Storage writes carry a full value; account writes carry only
/// the changed fields, reconstructed into a full record from current state at flush.
struct BlockMuts {
    storage: HashMap<Key, Option<Value>>,
    accounts: HashMap<[u8; 20], AccountDelta>,
    reads: Vec<Key>,
}

// The per-block sync counter resets inside flush_block!; its reset is dead at the final
// (post-loop) flush since the drain + full sync below cover durability regardless.
#[allow(unused_assignments)]
fn main() {
    let raw: Vec<String> = std::env::args().filter(|a| a != "--bench").collect();
    let Some(trace_path) = raw.get(1).cloned() else {
        // Blanket `cargo bench --benches` invocation: no-op without an explicit trace path.
        return;
    };
    if trace_path.starts_with("--") {
        return;
    }
    let mode = raw.get(2).cloned().unwrap_or_else(|| "builder".into());
    let is_builder = match mode.as_str() {
        "builder" => true,
        "follower" => false,
        _ => panic!("mode must be 'builder' (no access lists) or 'follower' (full access lists)"),
    };
    let commit_every: u64 = raw.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
    let max_blocks: u64 = raw.get(4).and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
    let page_cache: NonZeroUsize = raw
        .get(5)
        .and_then(|s| s.parse().ok())
        .unwrap_or(PAGE_CACHE_PAGES);
    let threads: NonZeroUsize = raw
        .get(6)
        .and_then(|s| s.parse().ok())
        .unwrap_or(NZUsize!(8));
    let storage_dir = raw.get(7).cloned().unwrap_or_else(|| {
        std::env::temp_dir()
            .join("trace_replay_db")
            .to_string_lossy()
            .into_owned()
    });
    // Prune to the inactivity floor every N blocks (0 = never; unpruned = log-structured
    // worst case). A production node prunes, so the default replays realistically.
    let prune_every: u64 = raw.get(8).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    // Fresh DB each run so size + throughput reflect this corpus alone.
    if std::env::var("REPLAY_KEEP").is_err() {
        std::fs::remove_dir_all(&storage_dir).ok();
    }

    eprintln!(
        "trace_replay trace={trace_path} mode={mode} commit_every={commit_every} max_blocks={max_blocks} page_cache={page_cache} threads={threads} prune_every={prune_every} storage_dir={storage_dir}"
    );

    let sd_for_result = storage_dir.clone();
    // REPLAY_POOL_TUNED=1 sizes the storage buffer pool to this run: the page
    // cache parks one pooled buffer per resident page, so the default
    // 64-per-class pool exhausts immediately and every page fill falls back
    // to raw malloc (as do the physical-page write buffers in the 8KB class).
    let mut rcfg = RConfig::default().with_storage_directory(storage_dir);
    if std::env::var("REPLAY_POOL_TUNED").is_ok() {
        let nz = |v: u32| std::num::NonZeroU32::new(v).unwrap();
        let pages = u32::try_from(page_cache.get())
            .unwrap()
            .saturating_add(65_536);
        rcfg = rcfg.with_storage_buffer_pool_config(
            commonware_runtime::BufferPoolConfig::for_storage()
                .with_size_class(NZUsize!(4096), nz(pages))
                .with_size_class(NZUsize!(8192), nz(8192))
                .with_size_class(NZUsize!(2 * 1024 * 1024), nz(256))
                .with_prefill(true)
                .with_parallelism(std::thread::available_parallelism().unwrap_or(NZUsize!(8))),
        );
    }
    Runner::new(rcfg).start(|ctx| async move {
        // Optional OTLP trace export. Enable with REPLAY_TRACE=1 to ship the QMDB
        // #[tracing::instrument] spans (merkleize/apply_batch/commit/...) to a local
        // collector (Jaeger on :4318). Whole traces are sampled at REPLAY_TRACE_RATE
        // (default 1%); endpoint/service-name are overridable via env for A/B runs.
        let trace_on = std::env::var("REPLAY_TRACE").is_ok();
        // Optional live metrics endpoint. Set REPLAY_METRICS_ADDR=127.0.0.1:9464 to serve
        // the full registry (page-cache hits/misses, pool, journal counters) over HTTP
        // for mid-run scraping.
        let metrics_addr: Option<std::net::SocketAddr> = std::env::var("REPLAY_METRICS_ADDR")
            .ok()
            .and_then(|s| s.parse().ok());
        if trace_on || metrics_addr.is_some() {
            telemetry::init(
                ctx.child("telemetry"),
                Logs {
                    level: Level::INFO,
                    json: false,
                },
                metrics_addr,
                trace_on.then(|| OtlpConfig {
                    endpoint: std::env::var("REPLAY_TRACE_ENDPOINT")
                        .unwrap_or_else(|_| "http://localhost:4318/v1/traces".to_string()),
                    name: std::env::var("REPLAY_TRACE_NAME")
                        .unwrap_or_else(|_| "trace_replay".to_string()),
                    rate: std::env::var("REPLAY_TRACE_RATE")
                        .ok()
                        .and_then(|s| s.parse::<f64>().ok())
                        .and_then(commonware_utils::Probability::from_f64)
                        .unwrap_or_else(|| {
                            commonware_utils::Probability::from_f64(0.01).unwrap()
                        }),
                }),
            );
        }

        let pc = CacheRef::from_pooler(&ctx, PAGE_SIZE, page_cache);
        let merkle_config = full::Config {
            journal_partition: "eth-merkle-journal".into(),
            metadata_partition: "eth-merkle-metadata".into(),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
            strategy: ctx.strategy(threads),
            page_cache: pc.clone(),
        };
        let init_conc = std::env::var("REPLAY_INIT_CONC")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .and_then(NonZeroUsize::new)
            .unwrap_or(threads);
        let cfg: ReplayConfig = VariableConfig {
                merkle_config,
                journal_config: VConfig {
                    partition: "eth-var-log".into(),
                    items_per_section: ITEMS_PER_BLOB,
                    compression: None,
                    codec_config: ((), (RangeCfg::new(0..=256), ())),
                    page_cache: pc,
                    write_buffer: WRITE_BUFFER,
                    replay_buffer: REPLAY_BUFFER,
                },
                grafted_metadata_partition: "eth-grafted-metadata".into(),
                translator: EightCap,
                init_cache: Some(
                    std::env::var("REPLAY_INIT_CACHE")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .and_then(NonZeroUsize::new)
                        .unwrap_or(NZUsize!(1 << 25)),
                ),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: init_conc,
            };
        let init_start = Instant::now();
        let mut db = Db::init(ctx.child("db"), cfg, None).await.unwrap();
        eprintln!(
            "INIT init_concurrency={} elapsed={:.2}s",
            init_conc,
            init_start.elapsed().as_secs_f64()
        );

        // Stream the trace from a file, or from stdin when the path is "-"
        // (e.g. `zstd -dc trace.zst | trace_replay -`), so the whole file never
        // has to fit in RAM.
        let reader: Box<dyn Read> = if trace_path == "-" {
            Box::new(std::io::stdin())
        } else {
            Box::new(std::fs::File::open(&trace_path).expect("open trace file"))
        };
        let mut r = BufReader::with_capacity(1 << 20, reader);
        let mut cur_block: Option<u64> = None;
        let mut muts = BlockMuts {
            storage: HashMap::new(),
            accounts: HashMap::new(),
            reads: Vec::new(),
        };
        let mut blocks_done = 0u64;
        let mut total_writes = 0u64;
        let mut total_reads = 0u64;
        let mut pending_commit = 0u64;
        let start = Instant::now();
        let mut read_ns = 0u128;
        let mut write_ns = 0u128;
        let mut prune_ns = 0u128;
        // Write-path phase breakdown (subset of write_ns): merkleize + apply_batch + sync.
        let mut merkleize_ns = 0u128;
        let mut apply_ns = 0u128;
        let mut sync_ns = 0u128;
        // Pipelined durability: hold the in-flight sync started at the previous boundary so its
        // fsync overlaps the next batch of block processing (bounded to one in-flight sync).
        let mut pending_sync: Option<Handle<()>> = None;

        // Helper: flush the accumulated block into QMDB (merkleize + apply, commit every K).
        macro_rules! flush_block {
            () => {{
                // Ordered write set: account writes (reconstructed from current state) first,
                // then storage writes (full value). Parallel key/spec lists let one stage pass
                // cover both, rebuilding each account record from the value staging returns.
                let mut write_keys: Vec<Key> =
                    Vec::with_capacity(muts.accounts.len() + muts.storage.len());
                let mut account_specs: Vec<([u8; 20], AccountDelta)> =
                    Vec::with_capacity(muts.accounts.len());
                for (addr, delta) in muts.accounts.drain() {
                    write_keys.push(account_key(&addr));
                    account_specs.push((addr, delta));
                }
                let n_accounts = account_specs.len();
                let mut storage_vals: Vec<Option<Value>> = Vec::with_capacity(muts.storage.len());
                for (k, v) in muts.storage.drain() {
                    write_keys.push(k);
                    storage_vals.push(v);
                }

                // Distinct touched keys (reads plus writes).
                let mut touched: Vec<Key> = Vec::with_capacity(muts.reads.len() + write_keys.len());
                let mut seen: HashSet<Key> = HashSet::new();
                for k in muts.reads.iter().chain(write_keys.iter()) {
                    if seen.insert(k.clone()) {
                        touched.push(k.clone());
                    }
                }
                total_reads += touched.len() as u64;

                let rt = Instant::now();
                if is_builder {
                    // Builder (no access list): reads discovered serially during execution. Those
                    // reads of account keys double as the current records to overlay this block.
                    let acct_key_set: HashSet<Key> =
                        write_keys[..n_accounts].iter().cloned().collect();
                    let mut acct_cur: HashMap<Key, Option<Value>> = HashMap::new();
                    let rb = db.new_batch();
                    for k in &touched {
                        let v = rb.get(k, &db).await.unwrap();
                        if acct_key_set.contains(k) {
                            acct_cur.insert(k.clone(), v);
                        }
                    }
                    read_ns += rt.elapsed().as_nanos();
                    let wt = Instant::now();
                    let mut wb = db.new_batch();
                    for (i, (_addr, delta)) in account_specs.iter().enumerate() {
                        let rec = acct_cur
                            .get(&write_keys[i])
                            .and_then(|v| v.clone())
                            .unwrap_or_else(default_account_record);
                        wb = wb.write(write_keys[i].clone(), Some(apply_account_delta(rec, delta)));
                        total_writes += 1;
                    }
                    for (j, v) in storage_vals.into_iter().enumerate() {
                        wb = wb.write(write_keys[n_accounts + j].clone(), v);
                        total_writes += 1;
                    }
                    let mt = Instant::now();
                    let m = wb.merkleize(&db, None, &mut Proportional).await.unwrap();
                    merkleize_ns += mt.elapsed().as_nanos();
                    let at = Instant::now();
                    (db, _) = db.apply_batch(m).await.unwrap();
                    apply_ns += at.elapsed().as_nanos();
                    write_ns += wt.elapsed().as_nanos();
                } else {
                    // Follower (full access list): prefetch read-only keys, then stage the write
                    // keys. Staging returns their current values, which the account writes are
                    // rebuilt from, so no cross-block account state is held in memory.
                    let write_set: HashSet<Key> = write_keys.iter().cloned().collect();
                    let read_only: Vec<&Key> =
                        touched.iter().filter(|k| !write_set.contains(*k)).collect();
                    if !read_only.is_empty() {
                        let _ = db.new_batch().get_many(&read_only, &db).await.unwrap();
                    }
                    let key_refs: Vec<&Key> = write_keys.iter().collect();
                    let (vals, staged) = db.new_batch().stage(&key_refs, &db).await.unwrap();
                    read_ns += rt.elapsed().as_nanos();
                    let wt = Instant::now();
                    let mut updates: Vec<(usize, Option<Value>)> =
                        Vec::with_capacity(write_keys.len());
                    for (i, (_addr, delta)) in account_specs.iter().enumerate() {
                        let rec = vals[i].clone().unwrap_or_else(default_account_record);
                        updates.push((i, Some(apply_account_delta(rec, delta))));
                        total_writes += 1;
                    }
                    for (j, v) in storage_vals.into_iter().enumerate() {
                        updates.push((n_accounts + j, v));
                        total_writes += 1;
                    }
                    let mt = Instant::now();
                    let m = staged.merkleize(updates, Vec::new(), None, &db, &mut Proportional).await.unwrap();
                    merkleize_ns += mt.elapsed().as_nanos();
                    let at = Instant::now();
                    (db, _) = db.apply_batch(m).await.unwrap();
                    apply_ns += at.elapsed().as_nanos();
                    write_ns += wt.elapsed().as_nanos();
                }

                let ct = Instant::now();
                pending_commit += 1;
                if pending_commit >= commit_every {
                    // Await the prior boundary's sync (it ran while these blocks processed),
                    // then start this one in-flight instead of blocking on commit().
                    if let Some(prev) = pending_sync.take() {
                        prev.await.unwrap();
                    }
                    let (ndb, h) = db.start_sync().await.unwrap();
                    db = ndb;
                    pending_sync = Some(h);
                    pending_commit = 0;
                }
                let cd = ct.elapsed().as_nanos();
                write_ns += cd;
                sync_ns += cd;
                muts.reads.clear();
                blocks_done += 1;

                // Periodic prune to the inactivity floor: drop superseded history so the DB
                // stays near active-state size. Prune operates on committed state, so flush
                // any pending commit first (matches the qmdb bench idiom).
                if prune_every > 0 && blocks_done % prune_every == 0 {
                    let pt = Instant::now();
                    if pending_commit > 0 {
                        db = db.commit().await.unwrap();
                        pending_commit = 0;
                    }
                    let boundary = db.sync_boundary();
                    db = db.prune(boundary).await.unwrap();
                    prune_ns += pt.elapsed().as_nanos();
                }
            }};
        }

        let mut hdr = [0u8; 16];
        loop {
            // Read the next record-group header; a clean EOF here ends the stream.
            match r.read_exact(&mut hdr) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("read trace header: {e}"),
            }
            let block = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
            let nrec = u32::from_le_bytes(hdr[12..16].try_into().unwrap());

            if cur_block != Some(block) {
                if cur_block.is_some() {
                    flush_block!();
                    if blocks_done >= max_blocks {
                        break;
                    }
                }
                cur_block = Some(block);
            }

            for _ in 0..nrec {
                let mut tag = [0u8; 1];
                r.read_exact(&mut tag).expect("read record tag");
                match tag[0] {
                    SREAD => {
                        let mut b = [0u8; 52];
                        r.read_exact(&mut b).unwrap();
                        muts.reads.push(storage_key(&b[0..20], &b[20..52]));
                    }
                    AREAD => {
                        let mut b = [0u8; 20];
                        r.read_exact(&mut b).unwrap();
                        muts.reads.push(account_key(&b));
                    }
                    SWRITE => {
                        let mut b = [0u8; 84];
                        r.read_exact(&mut b).unwrap();
                        let key = storage_key(&b[0..20], &b[20..52]);
                        let val: [u8; 32] = b[52..84].try_into().unwrap();
                        if val == [0u8; 32] {
                            muts.storage.insert(key, None);
                        } else {
                            muts.storage.insert(key, Some(val.to_vec()));
                        }
                    }
                    BAL => {
                        let mut b = [0u8; 52];
                        r.read_exact(&mut b).unwrap();
                        let addr: [u8; 20] = b[0..20].try_into().unwrap();
                        muts.accounts.entry(addr).or_default().balance =
                            Some(b[20..52].try_into().unwrap());
                    }
                    NONCE => {
                        let mut b = [0u8; 28];
                        r.read_exact(&mut b).unwrap();
                        let addr: [u8; 20] = b[0..20].try_into().unwrap();
                        muts.accounts.entry(addr).or_default().nonce =
                            Some(b[20..28].try_into().unwrap());
                    }
                    CODE => {
                        let mut b = [0u8; 52];
                        r.read_exact(&mut b).unwrap();
                        let addr: [u8; 20] = b[0..20].try_into().unwrap();
                        muts.accounts.entry(addr).or_default().code_hash =
                            Some(b[20..52].try_into().unwrap());
                    }
                    t => panic!("bad record tag {t}"),
                }
            }
        }
        if cur_block.is_some() && !(muts.storage.is_empty() && muts.accounts.is_empty()) {
            flush_block!();
        }
        // Drain the last in-flight pipelined sync, then a full sync: it persists metadata, makes
        // the reported on-disk size reflect committed state, and covers any applied-but-unsynced
        // tail blocks (fewer than commit_every since the last sync).
        if let Some(prev) = pending_sync.take() {
            prev.await.unwrap();
        }
        let _db = db.sync().await.unwrap();
        eprintln!("FINAL_ROOT {}", _db.root());

        let elapsed = start.elapsed();
        let db_bytes = std::process::Command::new("du")
            .args(["-sb", &sd_for_result])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.split_whitespace().next().map(str::to_string))
            .unwrap_or_else(|| "?".into());
        eprintln!(
            "RESULT mode={mode} prune_every={prune_every} blocks={blocks_done} writes={total_writes} reads={total_reads} wall={:.2}s read={:.2}s write={:.2}s merkleize={:.2}s apply={:.2}s sync={:.2}s prune={:.2}s reads/s={:.0} writes/s={:.0} db_bytes={db_bytes} db_path={sd_for_result}",
            elapsed.as_secs_f64(),
            read_ns as f64 / 1e9,
            write_ns as f64 / 1e9,
            merkleize_ns as f64 / 1e9,
            apply_ns as f64 / 1e9,
            sync_ns as f64 / 1e9,
            prune_ns as f64 / 1e9,
            total_reads as f64 / (read_ns as f64 / 1e9).max(1e-9),
            total_writes as f64 / (write_ns as f64 / 1e9).max(1e-9),
        );

        // Post-run metrics: full dump to REPLAY_METRICS_OUT if set; buffer-pool
        // lines always echoed for pool-exhaustion checks.
        let metrics = commonware_runtime::Metrics::encode(&ctx);
        if let Ok(path) = std::env::var("REPLAY_METRICS_OUT") {
            std::fs::write(path, &metrics).unwrap();
        }
        for line in metrics.lines() {
            if line.contains("buffer_pool") {
                eprintln!("METRIC {line}");
            }
        }

        // Flush the OTLP batch span processor before the runtime (and its export task)
        // shut down; otherwise the final in-flight batch of spans is dropped. Kept after
        // the RESULT line so the reported wall time excludes this drain.
        if trace_on {
            ctx.sleep(Duration::from_secs(12)).await;
        }
    });
}
