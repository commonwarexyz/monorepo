#![no_main]

//! Segmented variable journal crash recovery under supported partial-write crash cuts.
//!
//! Replay repairs torn pages lazily, and a section retained from a previous execution rejects
//! appends with [`Error::ReplayRequired`] until a replay from offset zero validates it. This
//! target reconstructs each section's expected item prefix directly from the post-recovery-crash
//! image (the contiguous valid-page prefix, cut at the last whole frame), asserts the append gate,
//! drains a full replay against that prefix, and reopens the repaired result.

use arbitrary::Arbitrary;
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob as _, BufferPooler, ReadOptions, Runner, Storage as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
};
use commonware_storage::journal::{Error, segmented::variable};
use commonware_storage_fuzz::faulted_recovery;
use commonware_utils::{NZUsize, Probability};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeMap, num::NonZeroU16};

type Journal = variable::Journal<DelayedSyncContext<deterministic::Context>, Vec<u8>>;

const PAGE_SIZE: usize = 128;
const PAGE_CHECKSUM_RECORD_SIZE: usize = commonware_runtime::buffer::paged::CHECKSUM_SIZE as usize;
const MAX_ITEM_LEN: usize = 48;

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    seed: u64,
    count: u8,
    baseline: u8,
    retention: u8,
    subset: bool,
    /// Per-item target section selector.
    routes: [u8; 32],
    /// How far the interrupted final sync is polled before the crash.
    final_polls: u8,
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
            let section = u64::from(input.routes[id % input.routes.len()] % 4);
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
async fn recover_expected(
    context: &deterministic::Context,
    partition: &str,
) -> BTreeMap<u64, (u64, Vec<Vec<u8>>)> {
    let physical_page_size = PAGE_SIZE + PAGE_CHECKSUM_RECORD_SIZE;
    let mut sections = BTreeMap::new();
    for name in context.scan(partition).await.expect("oracle scan failed") {
        let section = u64::from_be_bytes(name.as_slice().try_into().expect("invalid section name"));
        let (blob, size) = context
            .open(partition, &name)
            .await
            .expect("oracle open failed");
        let pages = usize::try_from(size).expect("oracle size overflow") / physical_page_size;
        let mut logical = Vec::with_capacity(pages * PAGE_SIZE);
        for page in 0..pages {
            let physical = blob
                .read_at(
                    (page * physical_page_size) as u64,
                    physical_page_size,
                    ReadOptions::default(),
                )
                .await
                .expect("oracle read failed")
                .coalesce();
            let Some(len) = valid_page_len(physical.as_ref()) else {
                break;
            };
            logical.extend_from_slice(&physical.as_ref()[..len]);
            if len < PAGE_SIZE {
                break;
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
        sections.insert(section, (offset as u64, frames));
    }
    sections
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
    let phase_script = script.clone();
    let phase_input = input.clone();
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let (durable, checkpoint) = runner.start_and_recover(move |context| async move {
        let fault_config = context.storage_fault_config();
        let pending = PendingSyncs::default();
        let context = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };
        let mut journal = Journal::init(context.child("journal"), config(&context))
            .await
            .expect("initial init failed");
        let mut durable: BTreeMap<u64, usize> = BTreeMap::new();
        for (offset, (section, item)) in phase_script.iter().enumerate() {
            if offset == baseline && baseline > 0 {
                journal = drive_pending_syncs(&pending, journal.sync_all())
                    .await
                    .expect("baseline sync failed");
                for (section, _) in &phase_script[..baseline] {
                    *durable.entry(*section).or_default() += 1;
                }
            }
            (journal, _, _) = journal.append(*section, item).await.expect("append failed");
        }

        // Flush buffered writes into storage behind held durability barriers, then crash: the
        // image retains an arbitrary byte subset of everything past the baseline.
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
        let mut sync = Box::pin(journal.sync_all());
        for _ in 0..usize::from(phase_input.final_polls) % 8 + 1 {
            if futures::future::poll_immediate(sync.as_mut())
                .await
                .is_some()
            {
                break;
            }
        }
        drop(sync);
        durable
    });

    let checkpoint = faulted_recovery(checkpoint, input.seed, recover_once);

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let expected = recover_expected(&context, "segmented-variable-recovery").await;

        // Every item covered by the completed baseline sync must survive the crash in order.
        for (section, count) in &durable {
            let baseline_items: Vec<Vec<u8>> = script
                .iter()
                .filter(|(candidate, _)| candidate == section)
                .take(*count)
                .map(|(_, item)| item.clone())
                .collect();
            let (_, frames) = expected
                .get(section)
                .expect("a synced section is missing from the crash image");
            assert!(
                frames.len() >= baseline_items.len()
                    && frames[..baseline_items.len()] == baseline_items[..],
                "a synced item was lost or reordered in section {section}"
            );
        }

        let pending = PendingSyncs::default();
        pending.unblock();
        let context = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };

        // Every section retained from the previous execution rejects appends until replayed.
        // Each probe consumes its journal (append takes self and returns it only on success).
        for (&section, _) in expected.iter().filter(|(_, (size, _))| *size > 0) {
            let journal = Journal::init(context.child("gate"), config(&context))
                .await
                .expect("gate init failed");
            match journal.append(section, &vec![0xAB; 8]).await {
                Err(Error::ReplayRequired(gated)) => assert_eq!(gated, section),
                other => panic!("append before replay must be rejected: {other:?}"),
            }
        }

        // A full replay repairs the torn suffix, matches the image-derived prefix exactly, and
        // unlocks appends.
        let journal = Journal::init(context.child("journal"), config(&context))
            .await
            .expect("recovery init failed");
        let mut journal = assert_replay(journal, &expected).await;
        let mut sentinels = expected.clone();
        for (&section, (size, frames)) in &expected {
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
            entry.1 = frames.clone();
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
