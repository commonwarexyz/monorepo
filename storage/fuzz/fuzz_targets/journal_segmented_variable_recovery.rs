#![no_main]

//! Segmented variable journal crash recovery under supported partial-write crash cuts.
//!
//! Replay repairs torn pages lazily, and a section retained from a previous execution panics on
//! append until a replay from offset zero validates it (pinned by the journal's should_panic
//! unit tests, which a panic-aborting fuzz target cannot probe). This target reconstructs each
//! section's expected item prefix directly from the post-recovery-crash image (the contiguous
//! valid-page prefix, cut at the last whole frame), drains a full replay against that prefix,
//! and reopens the repaired result. A section whose blob holds no valid page recovers to
//! logical size zero and skips the gate, so when the image contains one the target appends a
//! probe item to it before the replay to catch an init that over-blocks.
//!
//! The op stream can also prune sections, with remove faults armed only around each prune
//! drive. A completed prune durably removed every section blob below its floor and gates later
//! mutations below it, so the target routes later appends above the floor and drops the pruned
//! sections' expectations. A failed prune removed an oldest-first prefix of the live sections
//! below its floor, with the faulted removal leaving its own blob intact, so the oracle accepts
//! exactly the images whose surviving covered sections form a nonempty suffix.

use arbitrary::Arbitrary;
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, BufferPooler, ReadOptions, Runner, Storage as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
};
use commonware_storage::journal::{Error, segmented::variable};
use commonware_storage_fuzz::{bounded_entropy, faulted_recovery, release_oldest_pending_sync};
use commonware_utils::{FuzzRng, NZUsize, Probability};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU16,
};

type Journal = variable::Journal<DelayedSyncContext<deterministic::Context>, Vec<u8>>;

const PAGE_SIZE: usize = 128;
const PAGE_CHECKSUM_RECORD_SIZE: usize = commonware_runtime::buffer::paged::CHECKSUM_SIZE as usize;
const MAX_ITEM_LEN: usize = 48;
const SECTIONS: u64 = 4;

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    count: u8,
    baseline: u8,
    retention: u8,
    subset: bool,
    /// Per-item target section selector.
    routes: [u8; 32],
    /// Per-item action applied after its append: usually nothing, with one arm driving a
    /// prune whose floor the op's high bits select.
    ops: [u8; 32],
    /// Remove failure rate (percent) armed only around every prune drive, sampled per
    /// section-blob removal so a prune can fail partway through the manager's oldest-first
    /// removal sweep.
    remove_failure: u8,
    /// Whether the interrupted final sync is driven through the armed gate to
    /// completion before the crash, or left parked with one section's flush
    /// volatile so the crash tears it per the retention policy.
    final_polls: u8,
    /// Byte stream driving the runtime rng: all in-run randomness, fault sampling, and the
    /// faulted recovery chain's depth and shapes.
    #[arbitrary(with = bounded_entropy)]
    entropy: Vec<u8>,
}

fn config(
    context: &impl BufferPooler,
) -> variable::Config<(commonware_codec::RangeCfg<usize>, ())> {
    variable::Config {
        partition: "segmented-variable-recovery".into(),
        compression: None,
        codec_config: ((0..=MAX_ITEM_LEN).into(), ()),
        page_cache: CacheRef::from_pooler(
            context,
            NonZeroU16::new(PAGE_SIZE as u16).unwrap(),
            NZUsize!(8),
        ),
        write_buffer: NZUsize!(4096),
    }
}

/// The scripted append stream: `(section, item bytes)` per operation.
fn items(input: &FuzzInput) -> Vec<(u64, Vec<u8>)> {
    let count = usize::from(input.count % 32) + 1;
    (0..count)
        .map(|id| {
            let section = u64::from(input.routes[id % input.routes.len()]) % SECTIONS;
            let len = (id * 7) % MAX_ITEM_LEN;
            (section, vec![id as u8; len])
        })
        .collect()
}

/// Select a page's authoritative checksum slot, falling back to the other slot if a write tore.
fn valid_page_len(page: &[u8]) -> Option<usize> {
    let footer = page.get(PAGE_SIZE..)?;
    if footer.len() != PAGE_CHECKSUM_RECORD_SIZE {
        return None;
    }
    let slots = [
        (
            u16::from_be_bytes(footer[0..2].try_into().unwrap()) as usize,
            u32::from_be_bytes(footer[2..6].try_into().unwrap()),
        ),
        (
            u16::from_be_bytes(footer[6..8].try_into().unwrap()) as usize,
            u32::from_be_bytes(footer[8..12].try_into().unwrap()),
        ),
    ];
    let authoritative = usize::from(slots[1].0 > slots[0].0);
    for slot in [authoritative, authoritative ^ 1] {
        let (len, checksum) = slots[slot];
        if len > 0 && len <= PAGE_SIZE && Crc32::checksum(&page[..len]) == checksum {
            return Some(len);
        }
    }
    None
}

/// Decode a LEB128 varint u32 frame header, returning `(header len, data len)`.
fn read_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0u32;
    for (read, byte) in bytes.iter().take(5).enumerate() {
        value |= u32::from(byte & 0x7f)
            .checked_shl(7 * read as u32)
            .filter(|_| read < 4 || byte & 0x70 == 0)?;
        if byte & 0x80 == 0 {
            return Some((read + 1, usize::try_from(value).ok()?));
        }
    }
    None
}

/// Reconstruct each section's expected recovery outcome from the raw crash image without
/// repairing it.
///
/// Reads each blob's valid-page logical prefix, then walks frames (an outer varint length
/// header followed by the item's codec bytes) until the first incomplete frame. Maps each
/// section to the byte length of that whole-frame prefix, which recovery must retain, and to
/// the item payloads decoded from it in append order.
///
/// Also returns the smallest section whose blob holds no valid page. Init derives a section's
/// logical size from its last valid page, so such a section recovers to size zero and must
/// accept appends without a prior replay.
async fn recover_expected(
    context: &deterministic::Context,
    partition: &str,
) -> (BTreeMap<u64, (u64, Vec<Vec<u8>>)>, Option<u64>) {
    let physical_page_size = PAGE_SIZE + PAGE_CHECKSUM_RECORD_SIZE;
    let mut sections = BTreeMap::new();
    let mut empty: Option<u64> = None;
    for name in context.scan(partition).await.expect("oracle scan failed") {
        let section = u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
        let (blob, size) = context
            .open(partition, &name)
            .await
            .expect("oracle open failed");
        let pages = usize::try_from(size).expect("oracle size overflow") / physical_page_size;

        // Init sizes the section by the last valid page, so past the end of the valid
        // prefix the scan only needs to learn whether any later page validates.
        let mut logical = Vec::with_capacity(pages * PAGE_SIZE);
        let mut prefix_open = true;
        let mut any_valid = false;
        for page in 0..pages {
            if !prefix_open && any_valid {
                break;
            }
            let physical = blob
                .read_at(
                    (page * physical_page_size) as u64,
                    physical_page_size,
                    ReadOptions::default(),
                )
                .await
                .expect("oracle read failed")
                .coalesce();
            match valid_page_len(physical.as_ref()) {
                Some(len) => {
                    any_valid = true;
                    if prefix_open {
                        logical.extend_from_slice(&physical.as_ref()[..len]);
                        if len < PAGE_SIZE {
                            prefix_open = false;
                        }
                    }
                }
                None => prefix_open = false,
            }
        }

        // The expected prefix ends at the last whole frame inside the valid page prefix. A
        // frame's data is the codec encoding of the item, which embeds its own length.
        let mut frames = Vec::new();
        let mut offset = 0usize;
        while offset < logical.len() {
            let Some((header, data)) = read_varint(&logical[offset..]) else {
                break;
            };
            let end = offset + header + data;
            if end > logical.len() || data > MAX_ITEM_LEN + 1 {
                break;
            }
            let payload = &logical[offset + header..end];
            let (inner, item) = read_varint(payload)
                .expect("crash image contains a page-valid frame with unauthentic contents");
            assert_eq!(
                inner + item,
                data,
                "crash image contains a page-valid frame with a foreign layout"
            );
            frames.push(payload[inner..].to_vec());
            offset = end;
        }

        if !any_valid {
            empty = Some(empty.map_or(section, |current| current.min(section)));
        }
        sections.insert(section, (offset as u64, frames));
    }
    (sections, empty)
}

/// Drain a full replay, asserting it yields exactly the expected frames in order.
async fn assert_replay(journal: Journal, expected: &BTreeMap<u64, (u64, Vec<Vec<u8>>)>) -> Journal {
    let mut replay = journal
        .replay(0, 0, NZUsize!(1024), ReadOptions::default())
        .await
        .expect("replay start failed");
    let mut seen: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
    while let Some(result) = replay.next().await {
        let (section, _, _, item) = result.expect("replay yielded an error");
        seen.entry(section).or_default().push(item);
    }
    let journal = replay.finish().expect("replay finish failed");
    for (&section, (size, frames)) in expected {
        assert_eq!(
            seen.get(&section).map(Vec::as_slice).unwrap_or(&[]),
            frames.as_slice(),
            "replayed items diverge from the crash image in section {section}"
        );
        assert_eq!(
            journal.size(section).expect("size failed"),
            *size,
            "repair left the wrong logical size in section {section}"
        );
    }
    assert_eq!(
        seen.keys().copied().collect::<Vec<_>>(),
        expected
            .iter()
            .filter(|(_, (_, frames))| !frames.is_empty())
            .map(|(&section, _)| section)
            .collect::<Vec<_>>(),
        "replay visited unexpected sections"
    );
    journal
}

/// Drive the journal's lazy recovery through a complete replay.
async fn recover_once(context: deterministic::Context) -> Result<(), Error> {
    let pending = PendingSyncs::default();
    pending.unblock();
    let context = DelayedSyncContext {
        inner: context,
        pending,
    };
    let journal = Journal::init(context.child("journal"), config(&context)).await?;
    let mut replay = journal
        .replay(0, 0, NZUsize!(1024), ReadOptions::default())
        .await?;
    while let Some(result) = replay.next().await {
        result?;
    }
    drop(replay.finish()?);
    Ok(())
}

fn fuzz(input: FuzzInput) {
    let script = items(&input);
    let baseline = usize::from(input.baseline) % (script.len() + 1);
    let phase_script = script;
    let phase_input = input.clone();
    let cfg =
        deterministic::Config::default().with_rng(Box::new(FuzzRng::new(input.entropy.clone())));
    let runner = deterministic::Runner::new(cfg);
    let ((durable, effective, live, doomed), checkpoint) =
        runner.start_and_recover(move |context| async move {
            let fault_config = context.storage_fault_config();
            let remove_rate =
                Probability::new(u64::from(phase_input.remove_failure) % 101, 100).unwrap();
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let mut journal = Journal::init(context.child("journal"), config(&context))
                .await
                .expect("initial init failed");

            // Items covered by a completed sync per still-live section.
            let mut durable: BTreeMap<u64, usize> = BTreeMap::new();

            // The per-section append streams actually issued after prune-aware routing,
            // the model for every image authenticity check.
            let mut effective: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();

            // Sections whose blobs currently exist, mirroring the manager's map.
            let mut live: BTreeSet<u64> = BTreeSet::new();

            // The prune floor from completed prunes.
            let mut floor = 0u64;

            // Live sections a failed prune covered, oldest first, each removed or retained
            // depending on where the faulted removal stopped the sweep.
            let mut doomed: Vec<u64> = Vec::new();

            // The extra iteration reaches baseline == script length: everything synced,
            // with the crash tearing only the no-op final sync.
            for offset in 0..=phase_script.len() {
                if offset == baseline && baseline > 0 {
                    journal = drive_pending_syncs(&pending, journal.sync_all())
                        .await
                        .expect("baseline sync failed");
                    durable = live
                        .iter()
                        .map(|&section| (section, effective[&section].len()))
                        .collect();
                }
                let Some(&(section, ref item)) = phase_script.get(offset) else {
                    break;
                };

                // Route appends above the prune floor: appending below it fails with
                // AlreadyPrunedToSection.
                let section = if section < floor {
                    floor + section % (SECTIONS - floor)
                } else {
                    section
                };
                (journal, _, _) = journal.append(section, item).await.expect("append failed");
                effective.entry(section).or_default().push(item.clone());
                live.insert(section);

                // Prune arm: remove faults are armed only around the drive so a prune can
                // fail partway through the manager's oldest-first removal sweep.
                let op = phase_input.ops[offset % phase_input.ops.len()];
                if op & 0x07 == 7 {
                    let min = u64::from(op >> 3) % SECTIONS;
                    *fault_config.write() = deterministic::FaultConfig {
                        remove_rate: Some(remove_rate),
                        ..Default::default()
                    };
                    let result = drive_pending_syncs(&pending, journal.prune(min)).await;
                    *fault_config.write() = deterministic::FaultConfig::default();
                    match result {
                        Ok((next, did_prune)) => {
                            journal = next;
                            if did_prune {
                                // The completed prune durably removed every blob below the
                                // floor and gates later mutations below it.
                                floor = floor.max(min);
                                live.retain(|&candidate| candidate >= min);
                                durable.retain(|&candidate, _| candidate >= min);
                            }
                        }
                        Err(_) => {
                            // The failed prune consumed the journal after removing an
                            // oldest-first prefix of the live sections below the floor,
                            // with the faulted removal leaving its own blob intact. The
                            // run crashes here with those sections in an ambiguous state
                            // the oracle resolves from the image.
                            doomed = live
                                .iter()
                                .copied()
                                .filter(|&candidate| candidate < min)
                                .collect();
                            return (durable, effective, live, doomed);
                        }
                    }
                }
            }

            // Interrupt the final sync behind the armed one-shot gate: the first section's
            // durability barrier parks with its flush left volatile (every other section
            // syncs durably), so the crash tears that section's bytes per the retention
            // policy. Releasing the gate and polling again instead completes the sync.
            *fault_config.write() = deterministic::FaultConfig {
                write_rate: Some(WriteConfig {
                    failure_rate: Probability::new(0, 1).unwrap(),
                    retention_rate: Probability::new(u64::from(phase_input.retention % 101), 100)
                        .unwrap(),
                    mode: if phase_input.subset {
                        PartialWriteMode::Subset
                    } else {
                        PartialWriteMode::Prefix
                    },
                }),
                ..Default::default()
            };
            pending.arm();
            let mut sync = Box::pin(journal.sync_all());
            for _ in 0..usize::from(phase_input.final_polls) % 2 + 1 {
                if let Some(result) = futures::future::poll_immediate(sync.as_mut()).await {
                    // A sync that ran to completion is an observed barrier: it must
                    // succeed and every routed item in a live section becomes durable.
                    drop(result.expect("interrupted sync failed"));
                    durable = live
                        .iter()
                        .map(|&section| (section, effective[&section].len()))
                        .collect();
                    break;
                }
                release_oldest_pending_sync(&pending);
            }
            drop(sync);
            (durable, effective, live, doomed)
        });

    let checkpoint = faulted_recovery(checkpoint, recover_once);

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let (mut expected, empty) = recover_expected(&context, "segmented-variable-recovery").await;

        // Sections are created only by appends and removed only by prunes, and both effects
        // apply directly to storage and survive the crash. A section a completed prune
        // removed must be gone, a live section the failed prune did not cover must be
        // present, and nothing else may appear.
        for section in effective.keys() {
            if !live.contains(section) {
                assert!(
                    !expected.contains_key(section),
                    "a pruned section's blob survived the crash in section {section}"
                );
            }
        }
        for section in expected.keys() {
            assert!(
                effective.contains_key(section),
                "crash image contains a section never appended to: {section}"
            );
        }
        for &section in &live {
            if !doomed.contains(&section) {
                assert!(
                    expected.contains_key(&section),
                    "an unpruned section vanished from the crash image: {section}"
                );
            }
        }

        // The failed prune removes oldest first and stops at its faulted removal, which
        // leaves that blob intact, so the covered sections split into an absent prefix
        // and a nonempty present suffix.
        if !doomed.is_empty() {
            let survivors: Vec<u64> = doomed
                .iter()
                .copied()
                .filter(|section| expected.contains_key(section))
                .collect();
            assert!(
                !survivors.is_empty(),
                "the faulted removal must leave its own section behind"
            );
            assert_eq!(
                survivors.as_slice(),
                &doomed[doomed.len() - survivors.len()..],
                "a failed prune removed sections out of order"
            );
        }

        // Under the crash model every legal image is a per-section prefix of the routed
        // append stream (retention keeps subsets of submitted bytes, and a stale
        // checksum slot exposes an older prefix), so a flush path that rewrites,
        // reorders, or fabricates CRC-valid frames must be caught here.
        for (&section, (_, frames)) in &expected {
            let routed = effective.get(&section).map_or(&[][..], Vec::as_slice);
            assert!(
                frames.len() <= routed.len()
                    && frames.iter().zip(routed).all(|(frame, item)| frame == item),
                "crash image diverges from the scripted prefix in section {section}"
            );
        }

        // Every item covered by a completed sync must survive the crash in order, except
        // in a section the failed prune removed along with its durable prefix.
        for (section, count) in &durable {
            if doomed.contains(section) && !expected.contains_key(section) {
                continue;
            }
            let (_, frames) = expected
                .get(section)
                .expect("a synced section is missing from the crash image");
            let baseline_items = &effective[section][..*count];
            assert!(
                frames.len() >= baseline_items.len()
                    && frames[..baseline_items.len()] == *baseline_items,
                "a synced item was lost or reordered in section {section}"
            );
        }

        let pending = PendingSyncs::default();
        pending.unblock();
        let context = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };

        // A full replay repairs the torn suffix, matches the image-derived prefix exactly, and
        // unlocks appends.
        let mut journal = Journal::init(context.child("journal"), config(&context))
            .await
            .expect("recovery init failed");

        // A section recovered at logical size zero must stay outside the append gate: the
        // probe append must succeed without a replay and land at offset zero. The replay
        // below flushes and yields buffered items, so the probe frame (one outer varint,
        // one inner varint, five payload bytes) joins the section's expected outcome.
        if let Some(section) = empty {
            let offset;
            (journal, offset, _) = journal
                .append(section, &vec![0xAB; 5])
                .await
                .expect("append to a zero-size recovered section failed");
            assert_eq!(offset, 0, "zero-size section resumed at a nonzero offset");
            let entry = expected.get_mut(&section).unwrap();
            entry.0 = 7;
            entry.1.push(vec![0xAB; 5]);
        }
        let mut journal = assert_replay(journal, &expected).await;
        let mut sentinels = expected.clone();
        for (&section, (size, _)) in &expected {
            let offset;
            (journal, offset, _) = journal
                .append(section, &vec![0xCD; 9])
                .await
                .expect("append after replay failed");
            assert_eq!(
                offset, *size,
                "repaired section resumed at the wrong offset"
            );
            let entry = sentinels.get_mut(&section).unwrap();
            entry.0 = size + 11;
            entry.1.push(vec![0xCD; 9]);
        }
        journal = journal.sync_all().await.expect("sentinel sync failed");
        drop(journal);

        // A clean reopen replays the repaired image plus the sentinels.
        let journal = Journal::init(context.child("reopen"), config(&context))
            .await
            .expect("reopen failed");
        let journal = assert_replay(journal, &sentinels).await;
        journal.destroy().await.expect("destroy failed");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
