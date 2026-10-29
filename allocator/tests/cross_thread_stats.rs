//! Allocation statistics while one live thread frees the huge blocks another
//! live thread allocated.

#![cfg(feature = "mimalloc")]

use commonware_allocator::mimalloc::{Config, Effective, LARGE_OBJECT_LIMIT, MiMalloc, Stats};
use std::{hint::black_box, sync::mpsc, thread};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc::new(Config::DEFAULT);

/// Every block is huge: above the largest object a shared page serves.
const SIZE: usize = 2 * LARGE_OBJECT_LIMIT;

/// Blocks the producer allocates and the consumer frees.
const BLOCKS: usize = 64;

/// Huge blocks the reading thread keeps alive, so the true page count stays
/// well above what a thread may hold back.
const HELD: usize = 8;

/// Regression test for https://github.com/commonwarexyz/monorepo/issues/5483.
///
/// While one live thread frees the huge blocks another live thread
/// allocated, `pages` and `allocated_bytes` stay within one merge threshold
/// of their true values.
#[test]
fn issue_5483_regression() {
    let threshold = Effective::read().stats_merge_threshold;
    let held: Vec<Vec<u8>> = (0..HELD).map(|_| black_box(vec![1u8; SIZE])).collect();
    let before = Stats::read().expect("stats must be available");

    // Both threads stay alive while the statistics are read, because a thread
    // merges its statistics into the totals when it exits.
    let (blocks, received) = mpsc::sync_channel::<Vec<u8>>(8);
    let (freed, all_freed) = mpsc::channel::<()>();
    let (stop_consumer, consumer_stop) = mpsc::channel::<()>();
    let consumer = thread::spawn(move || {
        // A thread that has allocated, as every runtime thread has, keeps its
        // statistics in a heap of its own. One that never allocated would
        // record its frees in the totals directly.
        drop(black_box(vec![0u8; 16]));
        for block in received {
            drop(block);
        }
        freed.send(()).unwrap();
        let _ = consumer_stop.recv();
    });
    let (stop_producer, producer_stop) = mpsc::channel::<()>();
    let producer = thread::spawn(move || {
        for _ in 0..BLOCKS {
            blocks.send(black_box(vec![1u8; SIZE])).unwrap();
        }
        drop(blocks);
        let _ = producer_stop.recv();
    });
    all_freed.recv().unwrap();

    // Each block's page is added to the producer's statistics and removed
    // from the totals when the consumer frees it, so the total runs low by
    // the pages the producer has not merged: fewer than a threshold's worth
    // of blocks.
    let unmerged = threshold.div_ceil(SIZE) as u64;
    let live = Stats::read().expect("stats must be available");
    assert!(
        live.pages + unmerged >= HELD as u64,
        "pages {} must include all but {unmerged} of the {HELD} pages the reader holds",
        live.pages
    );

    // The producer merges every allocation it made when it exits, so the
    // total returns near its starting value only if the consumer merged its
    // frees along the way, holding back less than one threshold of them. The
    // extra block covers the test's own small allocations.
    stop_producer.send(()).unwrap();
    producer.join().unwrap();
    let after = Stats::read().expect("stats must be available");
    assert!(
        after.allocated_bytes < before.allocated_bytes + (threshold + SIZE) as u64,
        "allocated bytes {} must return near {} once every block is freed",
        after.allocated_bytes,
        before.allocated_bytes
    );

    stop_consumer.send(()).unwrap();
    consumer.join().unwrap();
    drop(held);
}
