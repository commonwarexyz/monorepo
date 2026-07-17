//! Volume blob-open microbenchmark: hydrate-and-first-read timing plus
//! resident memory for large committed blobs, over the tokio runtime's
//! volume-backed storage.
//!
//! Usage:
//!
//! ```text
//! volume_open create <dir> <gib>
//! volume_open open <dir> <gib> [reads]
//! ```
//!
//! `create` fills one blob with `gib` GiB of committed data. `open` runs a
//! fresh process over the same directory and reports recovery time, blob
//! open (hydration) time, first-read time, a small spread of further cold
//! 4 KiB reads, and the process's resident set size around each phase.

use commonware_runtime::{tokio as rt, Blob as _, Runner as _, Storage as _};
use std::time::Instant;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

const BLOCK: u64 = 4096;
const WRITE_CHUNK: u64 = 4 << 20;
const SYNC_EVERY_BYTES: u64 = 1 << 30;

/// Current resident set size of this process in bytes.
fn rss_bytes(system: &mut System) -> u64 {
    let pid = sysinfo::Pid::from_u32(std::process::id());
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    system.process(pid).map_or(0, sysinfo::Process::memory)
}

/// The deterministic byte pattern of the write chunk starting at `offset`.
fn pattern(offset: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, b) in out.iter_mut().enumerate() {
        let pos = offset + i as u64;
        *b = (pos ^ (pos >> 13) ^ (pos >> 27)) as u8;
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: volume_open <create|open> <dir> <gib> [reads]";
    let mode = args.get(1).expect(usage).clone();
    let dir = args.get(2).expect(usage).clone();
    let gib: u64 = args.get(3).expect(usage).parse().expect("gib");
    let reads: u64 = args.get(4).map_or(16, |r| r.parse().expect("reads"));
    let total = gib << 30;

    let cfg = rt::Config::new().with_storage_directory(dir);
    match mode.as_str() {
        "create" => rt::Runner::new(cfg).start(|context| async move {
            let started = Instant::now();
            let (blob, size) = context.open("bench", b"data").await.expect("open");
            assert_eq!(size, 0, "create expects a fresh directory");
            let mut offset = 0u64;
            let mut unsynced = 0u64;
            while offset < total {
                let len = WRITE_CHUNK.min(total - offset);
                blob.write_at(offset, pattern(offset, len as usize))
                    .await
                    .expect("write");
                offset += len;
                unsynced += len;
                if unsynced >= SYNC_EVERY_BYTES {
                    blob.sync().await.expect("sync");
                    unsynced = 0;
                }
            }
            blob.sync().await.expect("sync");
            // End on a tiny commit (steady-state shape): recovery verifies
            // only the final commit's delta manifest, so a huge final
            // manifest would both slow recovery and pre-verify every chunk,
            // hiding the hydration cost this bench measures.
            let last = total - BLOCK;
            blob.write_at(last, pattern(last, BLOCK as usize))
                .await
                .expect("write");
            blob.sync().await.expect("sync");
            println!(
                "RESULT create gib={gib} secs={:.3}",
                started.elapsed().as_secs_f64()
            );
        }),
        "open" => rt::Runner::new(cfg).start(|context| async move {
            let mut system = System::new();
            let rss_baseline = rss_bytes(&mut system);

            // Recovery (superblock + table) runs on the first operation.
            let started = Instant::now();
            context.scan("bench").await.expect("scan");
            let recover_ms = started.elapsed().as_secs_f64() * 1e3;

            // Hydration: dormant entry to live blob state.
            let started = Instant::now();
            let (blob, size) = context.open("bench", b"data").await.expect("open");
            let open_ms = started.elapsed().as_secs_f64() * 1e3;
            assert_eq!(size, total, "expected {gib} GiB of committed data");
            let rss_open = rss_bytes(&mut system);

            // First read: verifies its chunk (loading the covering CRCs).
            let started = Instant::now();
            let offset = (total / 2) & !(BLOCK - 1);
            let got = blob.read_at(offset, BLOCK as usize).await.expect("read");
            let first_read_ms = started.elapsed().as_secs_f64() * 1e3;
            assert_eq!(got.coalesce().as_ref(), &pattern(offset, BLOCK as usize));

            // A spread of further cold 4 KiB reads (each in a fresh region).
            let started = Instant::now();
            for i in 0..reads {
                let offset = ((total / (reads + 2)) * (i + 1)) & !(BLOCK - 1);
                let got = blob.read_at(offset, BLOCK as usize).await.expect("read");
                assert_eq!(got.coalesce().as_ref(), &pattern(offset, BLOCK as usize));
            }
            let spread_ms = started.elapsed().as_secs_f64() * 1e3;
            let rss_end = rss_bytes(&mut system);

            println!(
                "RESULT open gib={gib} recover_ms={recover_ms:.2} open_ms={open_ms:.2} \
                 first_read_ms={first_read_ms:.2} spread{reads}_ms={spread_ms:.2} \
                 rss_baseline={rss_baseline} rss_open={rss_open} rss_end={rss_end}"
            );
        }),
        _ => panic!("{usage}"),
    }
}
