//! Append-only storage for epoch-atomic blobs.
//!
//! Payload bytes occupy their final logical offsets and are never copied. Appends may accumulate
//! until a sync publishes a new logical length. Rewinding unpublished appends may reuse their tail
//! immediately. Rewinding committed bytes fences further appends until the shorter length is
//! durably published, after which the file is truncated in place. This keeps physical and logical
//! offsets identical without an extent map, hole punching, or compaction.
//!
//! Recovery reads two fixed, self-contained roots. An unresolved speculative batch may
//! additionally checksum a bounded appended suffix, but never scans historical payload.
//! Append-heavy epochs start coalesced payload durability in the background without writing a
//! root. A completed durability operation establishes a trusted prefix; the remaining tail stays
//! under CRC32C. Thus a crash may retain any subset of later unsynchronized writes without making
//! a partially written epoch visible.
//!
//! # V2 root slots
//!
//! A V2 file reserves one immutable header page followed by one 4 KiB root page split into two
//! 2 KiB slots. Root generation parity selects the slot, so publishing a generation never
//! overwrites its immediate fallback. Payload begins after the root page.
//!
//! ```text
//! +----------------------+ offset 0
//! | immutable V2 header  | 4 KiB
//! +----------------------+ offset 4 KiB
//! | root slot 0          | 2 KiB
//! +----------------------+ offset 6 KiB
//! | root slot 1          | 2 KiB
//! +----------------------+ offset 8 KiB
//! | payload log          |
//! +----------------------+
//! ```
//!
//! The two logical slots share one physical page, so the crash model covers arbitrary subsets of
//! bytes from the writes requested for either slot. It does not claim recovery from unrelated
//! device corruption that overwrites bytes outside those requested ranges.
//!
//! An ordinary root slot contains a self-contained 92-byte root header: its spelling, generation,
//! logical length, 64 application-owned tag bytes, and a CRC32C over all preceding fields. A
//! batch-prepared slot also stores a 16-byte wrapper and the participant's local group link
//! immediately after the root. The wrapper contains magic, link length, and a domain-separated
//! CRC32C.
//!
//! ```text
//! +-------------+---------------+----------------------+--------------------+
//! | root header | magic/len/CRC | local linked witness |       unused       |
//! +-------------+---------------+----------------------+--------------------+
//! 0            92             108                                      2048
//! ```
//!
//! The batch-prepared root spelling is deliberately invisible to ordinary recovery. Once the group
//! decision is known, materialization durably rewrites only the 92-byte header to an independently
//! recoverable spelling and leaves the linked witness available to repair peers. The batch
//! recovery protocol and its crash outcomes are documented in `storage::batch::coordinator`.

use crate::{IoBufs, storage::ATOMIC_BLOB_TAG_LEN};
commonware_macros::stability_scope!(ALPHA {
    use crate::storage::{Header, Layout};
    use std::os::unix::fs::MetadataExt as _;
});
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::hex;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Seek as _, SeekFrom, Write as _},
    ops::Range,
    os::unix::fs::FileExt,
    path::Path,
};

#[cfg(test)]
std::thread_local! {
    static TRACKED_READ_BYTES: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
    static TRACKED_DURABLE_WRITES: std::cell::RefCell<Option<Vec<(u64, usize)>>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const DATA_OFFSET: u64 = 8_192;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_file() -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!(
            "commonware-atomic-append-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(DATA_OFFSET).unwrap();
        file.sync_all().unwrap();
        (path, file)
    }

    fn append(file: &File, state: &mut State, data: &[u8]) -> u64 {
        let offset = state.logical_len();
        let prepared = state
            .prepare_append(IoBufs::from(data.to_vec()))
            .unwrap()
            .unwrap();
        let mut physical = prepared.file_offset;
        prepared.data.for_each_chunk(|chunk| {
            file.write_all_at(chunk, physical).unwrap();
            physical += chunk.len() as u64;
        });
        state.finish_mutation(prepared.mutation, true);
        offset
    }

    fn commit(file: &File, state: &mut State) {
        let Some(prepared) = state.prepare_commit().unwrap() else {
            return;
        };
        file.write_all_at(&prepared.prepared_root, prepared.root_offset)
            .unwrap();
        file.sync_all().unwrap();
        write_durable_at(file, prepared.root_offset, &prepared.committed_root).unwrap();
        if prepared.requires_truncate() {
            file.set_len(prepared.raw_len()).unwrap();
        }
        state.finish_commit(prepared);
    }

    fn read(file: &File, state: &State) -> Vec<u8> {
        let mut data = vec![0; state.logical_len() as usize];
        if !data.is_empty() {
            file.read_exact_at(&mut data, DATA_OFFSET).unwrap();
        }
        data
    }

    #[test]
    fn contiguous_appends_round_trip_without_a_map() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        assert_eq!(append(&file, &mut state, b"abc"), 0);
        assert_eq!(append(&file, &mut state, b"def"), 3);
        assert_eq!(read(&file, &state), b"abcdef");
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(recovered.logical_len(), 6);
        assert_eq!(read(&file, &recovered), b"abcdef");
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 6);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn inline_batch_preparation_requires_a_complete_bounded_checksum() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        assert!(state.can_prepare_batch_inline(0).unwrap());

        append(&file, &mut state, b"abc");
        assert!(state.can_prepare_batch_inline(3).unwrap());
        assert!(!state.can_prepare_batch_inline(2).unwrap());

        state.invalidate_payload_checksum();
        assert!(!state.can_prepare_batch_inline(3).unwrap());
        state.payload_checksum = PayloadChecksumTracker::new(DATA_OFFSET);
        state.preflush_target = DATA_OFFSET + 1;
        assert!(!state.can_prepare_batch_inline(3).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rewind_to_committed_length_still_publishes_a_pending_tag() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"base");
        commit(&file, &mut state);

        state.set_tag([0xA5; ATOMIC_BLOB_TAG_LEN]).unwrap();
        append(&file, &mut state, b"pending");
        assert!(state.participates_after_rewind(4).unwrap());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unpublished_rewind_reuses_the_physical_tail() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"base");
        commit(&file, &mut state);

        append(&file, &mut state, b"abcdef");
        state.rewind(7).unwrap();
        assert_eq!(append(&file, &mut state, b"XYZ"), 7);
        assert_eq!(read(&file, &state), b"baseabcXYZ");
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 10);
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"baseabcXYZ");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn committed_rewind_fences_append_until_commit() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"abcdef");
        commit(&file, &mut state);

        state.rewind(3).unwrap();
        assert!(state.prepare_append(IoBufs::from(b"x".to_vec())).is_err());
        commit(&file, &mut state);
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 3);
        assert_eq!(append(&file, &mut state, b"XYZ"), 3);
        assert_eq!(read(&file, &state), b"abcXYZ");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_repeats_a_committed_rewind_truncate() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"abcdef");
        commit(&file, &mut state);

        state.rewind(3).unwrap();
        let prepared = state.prepare_commit().unwrap().unwrap();
        file.write_all_at(&prepared.prepared_root, prepared.root_offset)
            .unwrap();
        file.sync_all().unwrap();
        write_durable_at(&file, prepared.root_offset, &prepared.committed_root).unwrap();

        // Simulate a crash after the shorter root became durable but before the in-place truncate.
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 6);
        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"abc");
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 3);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn direct_recovery_is_atomic_for_arbitrary_unsynced_write_subsets() {
        const PAYLOAD_FIRST: u8 = 1;
        const PAYLOAD_SECOND: u8 = 2;
        const PREPARED_ROOT: u8 = 4;

        for retained in 0..=(PAYLOAD_FIRST | PAYLOAD_SECOND | PREPARED_ROOT) {
            let (path, file) = test_file();
            let mut state = State::empty(DATA_OFFSET);
            state.set_tag([0x11; ATOMIC_BLOB_TAG_LEN]).unwrap();
            append(&file, &mut state, b"old");
            commit(&file, &mut state);
            state.set_tag([0x22; ATOMIC_BLOB_TAG_LEN]).unwrap();

            for (bit, data) in [
                (PAYLOAD_FIRST, b"new-".as_slice()),
                (PAYLOAD_SECOND, b"tail"),
            ] {
                let prepared = state
                    .prepare_append(IoBufs::from(data.to_vec()))
                    .unwrap()
                    .unwrap();
                if retained & bit != 0 {
                    let mut physical = prepared.file_offset;
                    prepared.data.for_each_chunk(|chunk| {
                        file.write_all_at(chunk, physical).unwrap();
                        physical += chunk.len() as u64;
                    });
                }
                state.finish_mutation(prepared.mutation, true);
            }
            let prepared = state.prepare_commit().unwrap().unwrap();
            if retained & PREPARED_ROOT != 0 {
                file.write_all_at(&prepared.prepared_root, prepared.root_offset)
                    .unwrap();
            }
            file.sync_all().unwrap();

            let recovered = State::recover(&file, DATA_OFFSET).unwrap();
            assert_eq!(read(&file, &recovered), b"old", "retained mask {retained}");
            assert_eq!(recovered.tag(), [0x11; ATOMIC_BLOB_TAG_LEN]);
            fs::remove_file(path).unwrap();
        }

        for committed_root_retained in [false, true] {
            let (path, file) = test_file();
            let mut state = State::empty(DATA_OFFSET);
            state.set_tag([0x11; ATOMIC_BLOB_TAG_LEN]).unwrap();
            append(&file, &mut state, b"old");
            commit(&file, &mut state);
            state.set_tag([0x22; ATOMIC_BLOB_TAG_LEN]).unwrap();
            append(&file, &mut state, b"new-tail");
            let prepared = state.prepare_commit().unwrap().unwrap();
            file.write_all_at(&prepared.prepared_root, prepared.root_offset)
                .unwrap();
            file.sync_all().unwrap();
            if committed_root_retained {
                write_durable_at(&file, prepared.root_offset, &prepared.committed_root).unwrap();
            }

            let recovered = State::recover(&file, DATA_OFFSET).unwrap();
            let expected: &[u8] = if committed_root_retained {
                b"oldnew-tail"
            } else {
                b"old"
            };
            assert_eq!(read(&file, &recovered), expected);
            assert_eq!(
                recovered.tag(),
                if committed_root_retained {
                    [0x22; ATOMIC_BLOB_TAG_LEN]
                } else {
                    [0x11; ATOMIC_BLOB_TAG_LEN]
                }
            );
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn direct_recovery_rejects_arbitrary_torn_publication_roots() {
        let mut masks = (0..=ROOT_LEN)
            .map(|prefix| {
                (0..ROOT_LEN)
                    .map(|index| index < prefix)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for index in 0..ROOT_LEN {
            masks.push((0..ROOT_LEN).map(|candidate| candidate == index).collect());
            masks.push((0..ROOT_LEN).map(|candidate| candidate != index).collect());
        }
        masks.push((0..ROOT_LEN).map(|index| index % 2 == 0).collect());
        masks.push((0..ROOT_LEN).map(|index| index % 3 == 1).collect());
        masks.push(
            (0..ROOT_LEN)
                .map(|index| index.count_ones() % 2 == 0)
                .collect(),
        );

        for rewind in [false, true] {
            for (case, mask) in masks.iter().enumerate() {
                let (path, file) = test_file();
                let mut state = State::empty(DATA_OFFSET);
                state.set_tag([0x11; ATOMIC_BLOB_TAG_LEN]).unwrap();
                append(&file, &mut state, b"abcdef");
                commit(&file, &mut state);
                state.set_tag([0x22; ATOMIC_BLOB_TAG_LEN]).unwrap();

                if rewind {
                    state.rewind(3).unwrap();
                } else {
                    append(&file, &mut state, b"XYZ");
                }
                let prepared = state.prepare_commit().unwrap().unwrap();
                file.write_all_at(&prepared.prepared_root, prepared.root_offset)
                    .unwrap();
                file.sync_all().unwrap();

                let mut torn: [u8; ROOT_LEN] =
                    prepared.prepared_root[..ROOT_LEN].try_into().unwrap();
                for (index, from_committed) in mask.iter().copied().enumerate() {
                    if from_committed {
                        torn[index] = prepared.committed_root[index];
                    }
                }
                file.write_all_at(&torn, prepared.root_offset).unwrap();
                file.sync_all().unwrap();

                let recovered = State::recover(&file, DATA_OFFSET).unwrap();
                let expected: &[u8] = if torn == prepared.committed_root {
                    if rewind { b"abc" } else { b"abcdefXYZ" }
                } else {
                    b"abcdef"
                };
                assert_eq!(
                    read(&file, &recovered),
                    expected,
                    "rewind={rewind} case={case}"
                );
                assert_eq!(
                    recovered.tag(),
                    if torn == prepared.committed_root {
                        [0x22; ATOMIC_BLOB_TAG_LEN]
                    } else {
                        [0x11; ATOMIC_BLOB_TAG_LEN]
                    },
                    "rewind={rewind} case={case}"
                );
                fs::remove_file(path).unwrap();
            }
        }
    }

    #[test]
    fn oversized_pending_epoch_requests_background_preflush() {
        let mut state = State::empty(DATA_OFFSET);
        state.logical_len = MAX_VALIDATED_PAYLOAD_LEN;
        state.payload_checksum.len = MAX_VALIDATED_PAYLOAD_LEN;
        state.dirty = true;
        let prepared = state
            .prepare_append(IoBufs::from(vec![1]))
            .unwrap()
            .unwrap();
        let range = state.finish_mutation(prepared.mutation, true).unwrap();
        let commit = state.prepare_commit().unwrap().unwrap();
        assert_eq!(
            commit.payload_checksum(),
            PayloadChecksumEligibility::Eligible(None)
        );
        assert_eq!(range.end, commit.raw_len());
        assert_eq!(commit.payload_start(), commit.raw_len());
    }

    #[test]
    fn background_preflush_leaves_only_a_bounded_crc_tail() {
        let mut state = State::empty(DATA_OFFSET);
        let prefix = state
            .prepare_append(IoBufs::from(vec![7; BACKGROUND_PREFLUSH_INTERVAL as usize]))
            .unwrap()
            .unwrap();
        let range = state.finish_mutation(prefix.mutation, true).unwrap();
        let tail = state
            .prepare_append(IoBufs::from(b"tail".to_vec()))
            .unwrap()
            .unwrap();
        assert_eq!(state.finish_mutation(tail.mutation, true), None);

        let commit = state.prepare_commit().unwrap().unwrap();
        assert_eq!(commit.payload_start(), range.end);
        assert_eq!(
            commit.payload_checksum(),
            PayloadChecksumEligibility::Eligible(Some(PayloadChecksum {
                offset: range.end,
                len: 4,
                checksum: checksum(&[b"tail"]),
            }))
        );
    }

    #[test]
    fn immediate_sync_keeps_the_full_epoch_on_the_single_barrier_path() {
        let mut state = State::empty(DATA_OFFSET);
        let payload = vec![9; BACKGROUND_PREFLUSH_INTERVAL as usize];
        let expected_checksum = checksum(&[&payload]);
        let append = state
            .prepare_append(IoBufs::from(payload))
            .unwrap()
            .unwrap();
        assert_eq!(state.finish_mutation(append.mutation, false), None);
        assert_eq!(state.preflush_target(), DATA_OFFSET);

        let commit = state.prepare_commit().unwrap().unwrap();
        assert_eq!(commit.payload_start(), DATA_OFFSET);
        assert_eq!(
            commit.payload_checksum(),
            PayloadChecksumEligibility::Eligible(Some(PayloadChecksum {
                offset: DATA_OFFSET,
                len: BACKGROUND_PREFLUSH_INTERVAL,
                checksum: expected_checksum,
            }))
        );
    }

    #[test]
    fn batch_witness_write_is_not_padded_to_the_root_slot() {
        let mut state = State::empty(DATA_OFFSET);
        let append = state
            .prepare_append(IoBufs::from(b"new".to_vec()))
            .unwrap()
            .unwrap();
        state.finish_mutation(append.mutation, true);
        let mut prepared = state.prepare_commit().unwrap().unwrap();
        prepared.mark_batch_prepared();
        let witness = b"group witness";
        prepared.attach_batch_witness(witness).unwrap();

        assert_eq!(
            prepared.prepared_root.len(),
            ROOT_LEN + BATCH_WITNESS_HEADER_LEN + witness.len()
        );
        let mut slot = [0; ROOT_SLOT_LEN as usize];
        slot[..prepared.prepared_root.len()].copy_from_slice(&prepared.prepared_root);
        assert_eq!(
            decode_batch_witness(&slot),
            Some((ROOT_LEN + BATCH_WITNESS_HEADER_LEN, witness.as_slice()))
        );
    }

    #[test]
    fn one_root_page_has_two_bounded_witness_slots() {
        assert_eq!(ROOT_OFFSETS[0], 4096);
        assert_eq!(ROOT_OFFSETS[1], ROOT_OFFSETS[0] + ROOT_SLOT_LEN);
        assert_eq!(ROOT_OFFSETS[1] + ROOT_SLOT_LEN, DATA_OFFSET);
        assert_eq!(
            ROOT_LEN + BATCH_WITNESS_HEADER_LEN + MAX_BATCH_WITNESS_LEN,
            ROOT_SLOT_LEN as usize
        );

        let prepare = || {
            let mut state = State::empty(DATA_OFFSET);
            let append = state
                .prepare_append(IoBufs::from(b"new".to_vec()))
                .unwrap()
                .unwrap();
            state.finish_mutation(append.mutation, true);
            let mut prepared = state.prepare_commit().unwrap().unwrap();
            prepared.mark_batch_prepared();
            prepared
        };

        let mut exact = prepare();
        exact
            .attach_batch_witness(&vec![0x5a; MAX_BATCH_WITNESS_LEN])
            .unwrap();
        assert_eq!(exact.prepared_root.len(), ROOT_SLOT_LEN as usize);

        let mut oversized = prepare();
        let error = oversized
            .attach_batch_witness(&vec![0x5a; MAX_BATCH_WITNESS_LEN + 1])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn deletion_tombstone_preserves_open_handle_payload() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"committed");
        commit(&file, &mut state);
        append(&file, &mut state, b"-pending");

        let mut prepared = state.prepare_delete().unwrap();
        prepared.mark_batch_prepared();
        prepared.attach_batch_witness(b"delete group").unwrap();
        let candidate = prepared.candidate();
        file.write_all_at(&prepared.prepared_root, prepared.root_offset)
            .unwrap();
        file.sync_all().unwrap();
        let raw_len = file.metadata().unwrap().len();

        materialize_tombstone_candidate(&file, DATA_OFFSET, &candidate).unwrap();
        assert!(candidate_is_tombstoned(&file, &candidate).unwrap());
        assert_eq!(file.metadata().unwrap().len(), raw_len);
        assert_eq!(read(&file, &state), b"committed-pending");

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"committed");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn arbitrary_torn_tombstone_roots_keep_the_embedded_witness_repairable() {
        let mut masks = (0..=ROOT_LEN)
            .map(|prefix| {
                (0..ROOT_LEN)
                    .map(|index| index < prefix)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        masks.push((0..ROOT_LEN).map(|index| index % 2 == 0).collect());
        masks.push((0..ROOT_LEN).map(|index| index % 3 == 1).collect());
        masks.push(
            (0..ROOT_LEN)
                .map(|index| index.count_ones() % 2 == 0)
                .collect(),
        );

        for (case, mask) in masks.into_iter().enumerate() {
            let (path, file) = test_file();
            let mut state = State::empty(DATA_OFFSET);
            append(&file, &mut state, b"payload");
            commit(&file, &mut state);
            let mut prepared = state.prepare_delete().unwrap();
            prepared.mark_batch_prepared();
            let witness = format!("delete group {case}").into_bytes();
            prepared.attach_batch_witness(&witness).unwrap();
            let candidate = prepared.candidate();
            file.write_all_at(&prepared.prepared_root, prepared.root_offset)
                .unwrap();
            file.sync_all().unwrap();

            let tombstone = candidate_tombstone_root(&candidate).unwrap();
            let mut torn = candidate.prepared_root;
            for (index, from_tombstone) in mask.into_iter().enumerate() {
                if from_tombstone {
                    torn[index] = tombstone[index];
                }
            }
            file.write_all_at(&torn, candidate.root_offset).unwrap();
            file.sync_all().unwrap();

            assert!(
                candidate_has_embedded_batch_witness(&file, &candidate, &witness).unwrap(),
                "case {case}"
            );
            assert_eq!(
                embedded_batch_witnesses(&file, DATA_OFFSET).unwrap(),
                vec![EmbeddedBatchWitness {
                    root_offset: candidate.root_offset,
                    witness,
                }],
                "case {case}"
            );
            materialize_tombstone_candidate(&file, DATA_OFFSET, &candidate).unwrap();
            assert!(candidate_is_tombstoned(&file, &candidate).unwrap());
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn only_a_committed_rewind_requires_truncation_at_publication() {
        let mut state = State::empty(DATA_OFFSET);
        let append = state
            .prepare_append(IoBufs::from(b"abc".to_vec()))
            .unwrap()
            .unwrap();
        state.finish_mutation(append.mutation, true);
        let prepared = state.prepare_commit().unwrap().unwrap();
        assert!(!prepared.requires_truncate());
        state.finish_commit(prepared);

        state.rewind(2).unwrap();
        let prepared = state.prepare_commit().unwrap().unwrap();
        assert!(prepared.requires_truncate());
    }

    #[test]
    fn preflushed_rewind_to_committed_frontier_is_clean() {
        let mut state = State::empty(DATA_OFFSET);
        let committed = state
            .prepare_append(IoBufs::from(b"base".to_vec()))
            .unwrap()
            .unwrap();
        state.finish_mutation(committed.mutation, true);
        let committed = state.prepare_commit().unwrap().unwrap();
        state.finish_commit(committed);

        let tail = state
            .prepare_append(IoBufs::from(b"tail".to_vec()))
            .unwrap()
            .unwrap();
        state.finish_mutation(tail.mutation, true);
        state.rewind_preflushed(4).unwrap();

        assert!(!state.is_dirty());
        assert!(state.prepare_commit().unwrap().is_none());
    }

    #[test]
    fn reopen_reads_bounded_metadata() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, &vec![0x5a; 4 * 1024 * 1024]);
        commit(&file, &mut state);
        let ((recovered, read_bytes), durable_writes) =
            track_durable_writes(|| track_read_bytes(|| State::recover(&file, DATA_OFFSET)));
        assert_eq!(recovered.unwrap().logical_len(), 4 * 1024 * 1024);
        assert!(read_bytes < 1024, "recovery read {read_bytes} bytes");
        assert!(durable_writes.is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn root_layout_carries_a_nonuniform_64_byte_tag() {
        let tag = std::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(3));
        let encoded = encode_root(ROOT_MAGIC, 7, 11, tag);

        assert_eq!(ROOT_LEN, 92);
        assert_eq!(&encoded[..8], ROOT_MAGIC);
        assert_eq!(&encoded[8..16], &7u64.to_be_bytes());
        assert_eq!(&encoded[16..24], &11u64.to_be_bytes());
        assert_eq!(&encoded[24..88], &tag);
        assert_eq!(
            &encoded[88..92],
            &checksum(&[ROOT_DOMAIN, &encoded[..88]]).to_be_bytes()
        );
        let decoded = decode_committed_root(&encoded).unwrap();
        assert_eq!(decoded.generation, 7);
        assert_eq!(decoded.logical_len, 11);
        assert_eq!(decoded.tag, tag);

        for index in [0, 8, 16, 24, 87, 88, 91] {
            let mut corrupt = encoded;
            corrupt[index] ^= 1;
            assert!(
                decode_committed_root(&corrupt).is_none(),
                "corruption at byte {index} must be rejected"
            );
        }
    }

    #[test]
    fn legacy_atomic_root_fails_without_truncating_payload() {
        const LEGACY_ROOT_LEN: usize = 40;
        const LEGACY_BODY_LEN: usize = 36;
        let (path, file) = test_file();
        let payload = b"legacy experimental V2 payload";
        file.write_all_at(payload, DATA_OFFSET).unwrap();

        let mut root = [0u8; LEGACY_ROOT_LEN];
        root[..8].copy_from_slice(b"CWUNOR11");
        root[8..16].copy_from_slice(&1u64.to_be_bytes());
        root[16..24].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        root[24..36].copy_from_slice(&[0xA5; 12]);
        let root_checksum = checksum(&[ROOT_DOMAIN, &root[..LEGACY_BODY_LEN]]);
        root[LEGACY_BODY_LEN..].copy_from_slice(&root_checksum.to_be_bytes());
        file.write_all_at(&root, ROOT_OFFSETS[1]).unwrap();
        file.sync_all().unwrap();

        let before = fs::read(&path).unwrap();
        let error = State::recover(&file, DATA_OFFSET).expect_err("R11 must not open as empty R12");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn staged_creation_publishes_only_a_complete_inode() {
        let root = std::env::temp_dir().join(format!(
            "commonware-atomic-create-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = root.join("partition");
        fs::create_dir_all(&parent).unwrap();
        let live = parent.join(hex(b"blob"));
        let region = vec![0x5a; DATA_OFFSET as usize];
        let file = create_live(&root, "partition", b"blob", &live, &region).unwrap();
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET);
        assert!(!creation_path(&live).unwrap().exists());
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_streams_legacy_layouts_into_a_recoverable_v2_inode() {
        const VERSION: u16 = 9;
        let root = std::env::temp_dir().join(format!(
            "commonware-atomic-migrate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = root.join("partition");
        fs::create_dir_all(&parent).unwrap();

        for layout in [Layout::V0, Layout::V1] {
            for len in [0, 1, MIGRATION_COPY_LEN + 17] {
                let name = format!("{:?}-{len}", layout).into_bytes();
                let live = parent.join(hex(&name));
                let payload = (0..len)
                    .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
                    .collect::<Vec<_>>();
                let raw = match layout {
                    Layout::V0 => crate::storage::header::tests::v0_blob_bytes(VERSION, &payload),
                    Layout::V1 => crate::storage::header::tests::v1_blob_bytes(VERSION, &payload),
                    Layout::V2 => unreachable!(),
                };
                fs::write(&live, raw).unwrap();
                let source = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&live)
                    .unwrap();
                let source_ino = source.metadata().unwrap().ino();

                migrate_live(&root, "partition", &name, &source, layout.data_offset()).unwrap();

                assert!(!creation_path(&live).unwrap().exists());
                let migrated = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&live)
                    .unwrap();
                assert_ne!(migrated.metadata().unwrap().ino(), source_ino);
                let raw_len = migrated.metadata().unwrap().len();
                let mut header = vec![0; Header::resolve_len(raw_len)];
                read_exact_at(&migrated, 0, &mut header).unwrap();
                let (_, version, data_offset) =
                    Header::parse(&header, raw_len, &(VERSION..=VERSION)).unwrap();
                assert_eq!(version, VERSION);
                assert_eq!(data_offset, Layout::V2.data_offset());
                assert_eq!(
                    State::recover(&migrated, data_offset)
                        .unwrap()
                        .logical_len(),
                    len as u64
                );

                let mut migrated_payload = vec![0; len];
                read_exact_at(&migrated, data_offset, &mut migrated_payload).unwrap();
                assert_eq!(migrated_payload, payload);
                let mut prior_payload = vec![0; len];
                read_exact_at(&source, layout.data_offset(), &mut prior_payload).unwrap();
                assert_eq!(prior_payload, payload);

                // A retry after an ambiguous publication result must make the already-visible V2
                // name durable without replacing its inode or scanning its payload.
                let migrated_ino = migrated.metadata().unwrap().ino();
                migrate_live(
                    &root,
                    "partition",
                    &name,
                    &migrated,
                    Layout::V2.data_offset(),
                )
                .unwrap();
                assert_eq!(migrated.metadata().unwrap().ino(), migrated_ino);
            }
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_discards_every_retained_subset_of_an_abandoned_stage() {
        const VERSION: u16 = 11;
        const PAYLOAD: &[u8] = b"first payload chunk--second payload chunk";
        const HEADER: u8 = 1;
        const ROOT: u8 = 2;
        const PAYLOAD_FIRST: u8 = 4;
        const PAYLOAD_SECOND: u8 = 8;

        let root = std::env::temp_dir().join(format!(
            "commonware-atomic-migrate-stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = root.join("partition");
        fs::create_dir_all(&parent).unwrap();
        let split = PAYLOAD.len() / 2;

        for retained in 0..=(HEADER | ROOT | PAYLOAD_FIRST | PAYLOAD_SECOND) {
            let name = format!("stage-{retained}").into_bytes();
            let live = parent.join(hex(&name));
            fs::write(
                &live,
                crate::storage::header::tests::v1_blob_bytes(VERSION, PAYLOAD),
            )
            .unwrap();
            let source = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&live)
                .unwrap();

            let stage_path = creation_path(&live).unwrap();
            let stage = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&stage_path)
                .unwrap();
            let region = Header::create_atomic(&(VERSION..=VERSION)).0;
            if retained & HEADER != 0 {
                stage
                    .write_all_at(&region[..Layout::V1.data_offset() as usize], 0)
                    .unwrap();
            }
            if retained & ROOT != 0 {
                stage
                    .write_all_at(
                        &encode_root(
                            ROOT_MAGIC,
                            1,
                            PAYLOAD.len() as u64,
                            [0; ATOMIC_BLOB_TAG_LEN],
                        ),
                        ROOT_OFFSETS[1],
                    )
                    .unwrap();
            }
            if retained & PAYLOAD_FIRST != 0 {
                stage
                    .write_all_at(&PAYLOAD[..split], Layout::V2.data_offset())
                    .unwrap();
            }
            if retained & PAYLOAD_SECOND != 0 {
                stage
                    .write_all_at(&PAYLOAD[split..], Layout::V2.data_offset() + split as u64)
                    .unwrap();
            }
            drop(stage);

            assert_eq!(
                &fs::read(&live).unwrap()[..Header::MAGIC_LENGTH],
                &Layout::V1.magic()
            );
            migrate_live(&root, "partition", &name, &source, Layout::V1.data_offset()).unwrap();
            assert!(!stage_path.exists());

            let migrated = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&live)
                .unwrap();
            let state = State::recover(&migrated, Layout::V2.data_offset()).unwrap();
            assert_eq!(state.logical_len(), PAYLOAD.len() as u64, "mask {retained}");
            let mut payload = vec![0; PAYLOAD.len()];
            read_exact_at(&migrated, Layout::V2.data_offset(), &mut payload).unwrap();
            assert_eq!(payload, PAYLOAD, "mask {retained}");
        }

        fs::remove_dir_all(root).unwrap();
    }
}

const ROOT_MAGIC: &[u8; 8] = b"CWUNOR12";
const PREPARED_ROOT_MAGIC: &[u8; 8] = b"CWUNOP12";
const BATCH_PREPARED_ROOT_MAGIC: &[u8; 8] = b"CWUNOB12";
const MATERIALIZED_ROOT_MAGIC: &[u8; 8] = b"CWUNOM12";
const TOMBSTONE_ROOT_MAGIC: &[u8; 8] = b"CWUNOT12";
const BATCH_WITNESS_MAGIC: &[u8; 8] = b"CWUNOW12";
const LEGACY_ROOT_MAGICS: [[u8; 8]; 5] = [
    *b"CWUNOR11",
    *b"CWUNOP11",
    *b"CWUNOB11",
    *b"CWUNOM11",
    *b"CWUNOT11",
];
const CREATION_PREFIX: &str = ".commonware-uno-create-";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_LOG_ROOT";
const BATCH_WITNESS_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_BATCH_WITNESS";
const ROOT_PREFIX_LEN: usize = 24;
const ROOT_CHECKSUM_LEN: usize = std::mem::size_of::<u32>();
const ROOT_BODY_LEN: usize = ROOT_PREFIX_LEN + ATOMIC_BLOB_TAG_LEN;
pub(super) const ROOT_LEN: usize = ROOT_BODY_LEN + ROOT_CHECKSUM_LEN;
const ROOT_SLOT_LEN: u64 = 2048;
const BATCH_WITNESS_HEADER_LEN: usize = 16;
pub(super) const MAX_BATCH_WITNESS_LEN: usize =
    ROOT_SLOT_LEN as usize - ROOT_LEN - BATCH_WITNESS_HEADER_LEN;
const ROOT_OFFSETS: [u64; 2] = [4096, 6144];
pub(super) const MAX_VALIDATED_PAYLOAD_LEN: u64 = 64 * 1024 * 1024;
const TARGET_PREFLUSH_PARTICIPANTS: u64 = 4;
/// Bound the aggregate unflushed tail for the common four-participant group. Larger groups enforce
/// their smaller per-participant budget during publication.
pub(super) const BACKGROUND_PREFLUSH_INTERVAL: u64 =
    MAX_VALIDATED_PAYLOAD_LEN / TARGET_PREFLUSH_PARTICIPANTS;
const PAYLOAD_CHECKSUM_READ_LEN: usize = 64 * 1024;
#[commonware_macros::stability(ALPHA)]
const MIGRATION_COPY_LEN: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MIN_WRITEBACK_HINT_LEN: u64 = 64 * 1024;
/// Checksum of one physically contiguous payload range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PayloadChecksum {
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) checksum: u32,
}

/// Whether a prepared epoch can be verified without its first durability barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PayloadChecksumEligibility {
    /// The optional checksum is absent when the eligible epoch appended no payload bytes.
    Eligible(Option<PayloadChecksum>),
    Ineligible,
}

#[derive(Debug)]
struct PayloadChecksumTracker {
    offset: u64,
    len: u64,
    hasher: Crc32,
    eligible: bool,
}

impl PayloadChecksumTracker {
    fn new(offset: u64) -> Self {
        Self {
            offset,
            len: 0,
            hasher: Crc32::default(),
            eligible: true,
        }
    }

    fn update(&mut self, physical: u64, data_len: u64, data: &IoBufs) {
        if !self.eligible {
            return;
        }
        if self.offset.checked_add(self.len) != Some(physical) {
            self.eligible = false;
            return;
        }
        let Some(next_len) = self.len.checked_add(data_len) else {
            self.eligible = false;
            return;
        };
        if next_len > MAX_VALIDATED_PAYLOAD_LEN {
            self.eligible = false;
            return;
        }
        data.for_each_chunk(|chunk| {
            self.hasher.update(chunk);
        });
        self.len = next_len;
    }
}
fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_candidate(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    )
}

fn checked_end(offset: u64, len: u64) -> io::Result<u64> {
    offset
        .checked_add(len)
        .ok_or_else(|| invalid_input("atomic log offset overflow"))
}

fn checksum(parts: &[&[u8]]) -> u32 {
    let mut hasher = Crc32::default();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().1.as_u32()
}

fn read_exact_at(file: &File, mut offset: u64, mut out: &mut [u8]) -> io::Result<()> {
    while !out.is_empty() {
        let read = match file.read_at(out, offset) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "atomic log record is truncated",
            ));
        }
        #[cfg(test)]
        TRACKED_READ_BYTES.with(|tracked| {
            if let Some(bytes) = tracked.get() {
                tracked.set(Some(bytes + read as u64));
            }
        });
        offset = checked_end(offset, read as u64)?;
        out = &mut out[read..];
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn track_read_bytes<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    TRACKED_READ_BYTES.with(|tracked| {
        assert!(tracked.replace(Some(0)).is_none());
    });
    let result = operation();
    let bytes = TRACKED_READ_BYTES.with(|tracked| tracked.replace(None).unwrap());
    (result, bytes)
}

#[cfg(test)]
pub(super) fn track_durable_writes<T>(operation: impl FnOnce() -> T) -> (T, Vec<(u64, usize)>) {
    TRACKED_DURABLE_WRITES.with(|tracked| {
        assert!(tracked.borrow_mut().replace(Vec::new()).is_none());
    });
    let result = operation();
    let writes = TRACKED_DURABLE_WRITES.with(|tracked| tracked.borrow_mut().take().unwrap());
    (result, writes)
}

/// Start Linux writeback for the current payload while its root is built.
#[cfg(target_os = "linux")]
pub(super) fn begin_payload_writeback(file: &File, offset: u64, len: u64) -> io::Result<()> {
    // The syscall is only a scheduling hint. For small epochs its fixed cost exceeds any overlap
    // with root construction; the following inode sync remains the ordering barrier either way.
    if len < MIN_WRITEBACK_HINT_LEN {
        return Ok(());
    }
    let offset = libc::off64_t::try_from(offset)
        .map_err(|_| invalid_input("atomic payload offset exceeds off64_t"))?;
    let len = libc::off64_t::try_from(len)
        .map_err(|_| invalid_input("atomic payload length exceeds off64_t"))?;
    // SAFETY: the file descriptor remains valid for the call and both offsets fit off64_t. This only
    // initiates writeback; the existing inode sync remains the durability and ordering barrier.
    let result = unsafe {
        libc::sync_file_range(file.as_raw_fd(), offset, len, libc::SYNC_FILE_RANGE_WRITE)
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    ) {
        return Ok(());
    }
    Err(error)
}

#[cfg(not(target_os = "linux"))]
pub(super) const fn begin_payload_writeback(
    _file: &File,
    _offset: u64,
    _len: u64,
) -> io::Result<()> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadSource {
    File(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadSpan {
    pub(super) destination: usize,
    pub(super) len: usize,
    pub(super) source: ReadSource,
}

#[derive(Debug)]
pub(super) struct Mutation {
    logical_start: u64,
    logical_end: u64,
    physical: u64,
}

pub(super) struct PreparedMutation {
    pub(super) file_offset: u64,
    pub(super) data: IoBufs,
    pub(super) mutation: Mutation,
}

#[derive(Debug)]
struct Commit {
    generation: u64,
    append_offset: u64,
    truncate: bool,
}

/// Durable per-blob candidate named by an exact multi-blob decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Candidate {
    pub(crate) base_generation: u64,
    pub(crate) root_offset: u64,
    pub(crate) prepared_root: [u8; ROOT_LEN],
    pub(crate) committed_root: [u8; ROOT_LEN],
}

/// A transaction candidate recovered with its participant-embedded batch witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmbeddedBatchCandidate {
    pub(crate) candidate: Candidate,
    pub(crate) witness: Vec<u8>,
}

/// A checksummed batch witness found in one fixed root slot.
///
/// The witness is decoded independently from the root header. This lets group recovery repair
/// a root whose final durable overwrite was interrupted after another participant made the group
/// authoritative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmbeddedBatchWitness {
    pub(crate) root_offset: u64,
    pub(crate) witness: Vec<u8>,
}

/// Payload bounds recovered while validating a transaction candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateMetadata {
    payload_end: u64,
}

pub(super) struct PreparedCommit {
    payload_start: u64,
    pub(super) root_offset: u64,
    /// Transaction-ineligible root written before the prepare barrier.
    pub(super) prepared_root: Vec<u8>,
    /// Root header published only after the prepare barrier succeeds.
    pub(super) committed_root: [u8; ROOT_LEN],
    payload_checksum: PayloadChecksumEligibility,
    commit: Commit,
}

impl PreparedCommit {
    fn available_batch_witness_capacity(&self) -> Option<usize> {
        Some(MAX_BATCH_WITNESS_LEN.min(u32::MAX as usize))
    }

    /// Return the first payload byte recovery must validate.
    ///
    /// Any earlier byte in the current epoch is covered by a durability operation that completes
    /// before this commit's root may be staged.
    pub(super) const fn payload_start(&self) -> u64 {
        self.payload_start
    }

    /// Return whether this epoch's payload can be verified speculatively.
    pub(super) const fn payload_checksum(&self) -> PayloadChecksumEligibility {
        self.payload_checksum
    }

    /// Return the physical file length named by this commit.
    pub(super) const fn raw_len(&self) -> u64 {
        self.commit.append_offset
    }

    /// Return whether publishing this root must discard a committed suffix.
    pub(super) const fn requires_truncate(&self) -> bool {
        self.commit.truncate
    }

    /// Mark the complete payload prefix durable before its root is staged.
    ///
    /// Descriptor recovery may then trust the payload without rereading it because the root write
    /// is issued only after the preflush barrier completes.
    pub(super) const fn mark_payload_preflushed(&mut self) {
        self.payload_start = self.commit.append_offset;
        self.payload_checksum = PayloadChecksumEligibility::Eligible(None);
    }

    /// Mark this commit as carrying a participant-embedded batch witness.
    pub(super) fn mark_batch_prepared(&mut self) {
        self.prepared_root[..8].copy_from_slice(BATCH_PREPARED_ROOT_MAGIC);
        let root_checksum = checksum(&[ROOT_DOMAIN, &self.prepared_root[..ROOT_BODY_LEN]]);
        self.prepared_root[ROOT_BODY_LEN..ROOT_LEN].copy_from_slice(&root_checksum.to_be_bytes());
    }

    /// Return whether a witness can be embedded in this commit's root slot.
    pub(super) fn batch_witness_fits(&self, witness_len: usize) -> bool {
        u32::try_from(witness_len).is_ok()
            && self
                .available_batch_witness_capacity()
                .is_some_and(|capacity| witness_len <= capacity)
    }

    /// Append a checksummed batch witness immediately after this root.
    pub(super) fn attach_batch_witness(&mut self, witness: &[u8]) -> io::Result<()> {
        if self.prepared_root.get(..8) != Some(BATCH_PREPARED_ROOT_MAGIC) {
            return Err(invalid_input(
                "atomic batch witness requires a batch-prepared root",
            ));
        }
        if self.prepared_root.len() != ROOT_LEN {
            return Err(invalid_input(
                "atomic batch-prepared root already has trailing bytes",
            ));
        }
        if !self.batch_witness_fits(witness.len()) {
            return Err(invalid_input("atomic batch witness exceeds its root slot"));
        }

        let witness_len = u32::try_from(witness.len())
            .map_err(|_| invalid_input("atomic batch witness length exceeds u32"))?;
        let witness_len = witness_len.to_be_bytes();
        let witness_checksum = checksum(&[
            BATCH_WITNESS_DOMAIN,
            BATCH_WITNESS_MAGIC,
            &witness_len,
            witness,
        ]);
        self.prepared_root.extend_from_slice(BATCH_WITNESS_MAGIC);
        self.prepared_root.extend_from_slice(&witness_len);
        self.prepared_root
            .extend_from_slice(&witness_checksum.to_be_bytes());
        self.prepared_root.extend_from_slice(witness);
        debug_assert!(self.prepared_root.len() <= ROOT_SLOT_LEN as usize);
        Ok(())
    }

    /// Return the fixed-size identity needed to validate and install this candidate after a group
    /// decision. The logical length is self-contained in the root.
    pub(super) fn candidate(&self) -> Candidate {
        Candidate {
            base_generation: self
                .commit
                .generation
                .checked_sub(1)
                .expect("prepared generations are nonzero"),
            root_offset: self.root_offset,
            prepared_root: self.prepared_root[..ROOT_LEN]
                .try_into()
                .expect("prepared roots contain a complete header"),
            committed_root: self.committed_root,
        }
    }
}

/// Mutable state for one append-only atomic blob generation.
#[derive(Debug)]
pub(super) struct State {
    data_offset: u64,
    logical_len: u64,
    committed_len: u64,
    generation: u64,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
    committed_tag: [u8; ATOMIC_BLOB_TAG_LEN],
    /// Prefix that must be durable before a root may omit its bytes from payload validation.
    preflush_target: u64,
    payload_checksum: PayloadChecksumTracker,
    deferred_batch_root: Option<Candidate>,
    dirty: bool,
    poisoned: bool,
}

impl State {
    fn empty(data_offset: u64) -> Self {
        Self {
            data_offset,
            logical_len: 0,
            committed_len: 0,
            generation: 0,
            tag: [0; ATOMIC_BLOB_TAG_LEN],
            committed_tag: [0; ATOMIC_BLOB_TAG_LEN],
            preflush_target: data_offset,
            payload_checksum: PayloadChecksumTracker::new(data_offset),
            deferred_batch_root: None,
            dirty: false,
            poisoned: false,
        }
    }

    pub(super) fn recover(file: &File, data_offset: u64) -> io::Result<Self> {
        if data_offset < ROOT_OFFSETS[1] + ROOT_SLOT_LEN {
            return Err(invalid_input(
                "V2 data offset does not reserve both root slots",
            ));
        }
        let raw_len = file.metadata()?.len();
        if raw_len < data_offset {
            return Err(invalid_data("atomic blob is shorter than its V2 header"));
        }

        let mut roots = Vec::new();
        let mut recovery_error = None;
        let mut invalid_root_slot = false;
        let mut slot_zero = [false; ROOT_OFFSETS.len()];
        let mut observed_later_generation = false;
        for (index, offset) in ROOT_OFFSETS.into_iter().enumerate() {
            let mut encoded = [0u8; ROOT_LEN];
            read_exact_at(file, offset, &mut encoded)?;
            if encoded.iter().all(|byte| *byte == 0) {
                slot_zero[index] = true;
                continue;
            }
            if LEGACY_ROOT_MAGICS
                .iter()
                .any(|magic| encoded.starts_with(magic))
            {
                return Err(invalid_data("unsupported atomic root format"));
            }
            if let Some(root) = decode_root(&encoded) {
                if ROOT_OFFSETS[(root.generation as usize) & 1] != offset {
                    invalid_root_slot = true;
                    recovery_error.get_or_insert_with(|| {
                        invalid_data("atomic root generation is in the wrong slot")
                    });
                    continue;
                }
                observed_later_generation |= root.generation > 1;
                roots.push((root, offset));
            }
        }
        roots.sort_by_key(|(root, _)| std::cmp::Reverse(root.generation));

        let mut recovered = None;
        for (root, root_offset) in roots {
            match recover_root(file, data_offset, raw_len, root_offset, root) {
                Ok((candidate, _)) => {
                    recovered = Some(candidate);
                    break;
                }
                Err(error) if invalid_candidate(&error) => {
                    recovery_error.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        let mut state = match recovered {
            Some(state) => state,
            None if slot_zero[0] && !observed_later_generation && !invalid_root_slot => {
                Self::empty(data_offset)
            }
            None => {
                return Err(recovery_error
                    .unwrap_or_else(|| invalid_data("atomic blob has no recoverable root")));
            }
        };
        let selected_len = state.raw_len()?;
        if raw_len != selected_len {
            // The selected root is the durable authority. A crash may lose this truncate, but the
            // same root makes recovery repeat it before any discarded offset can be reused.
            file.set_len(selected_len)?;
        }
        state.dirty = false;
        Ok(state)
    }

    pub(super) fn raw_len(&self) -> io::Result<u64> {
        checked_end(self.data_offset, self.logical_len)
    }

    pub(super) const fn logical_len(&self) -> u64 {
        self.logical_len
    }

    pub(super) const fn committed_len(&self) -> u64 {
        self.committed_len
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) const fn tag(&self) -> [u8; ATOMIC_BLOB_TAG_LEN] {
        self.tag
    }

    pub(super) fn set_tag(&mut self, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        if self.tag == tag {
            return Ok(());
        }
        self.tag = tag;
        self.dirty = self.logical_len != self.committed_len || self.tag != self.committed_tag;
        Ok(())
    }

    pub(super) const fn deferred_batch_root(&self) -> Option<&Candidate> {
        self.deferred_batch_root.as_ref()
    }

    pub(super) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(super) const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Return whether applying a validated rewind would leave a root to publish.
    #[commonware_macros::stability(ALPHA)]
    pub(super) fn participates_after_rewind(&self, len: u64) -> io::Result<bool> {
        self.validate_rewind(len)?;
        if len == self.logical_len {
            return Ok(self.dirty);
        }
        Ok(len != self.committed_len || self.tag != self.committed_tag)
    }

    /// Return whether batch preparation can finish without waiting for payload durability.
    #[commonware_macros::stability(ALPHA)]
    #[cfg(any(not(feature = "iouring-storage"), test))]
    pub(super) fn can_prepare_batch_inline(&self, payload_budget: u64) -> io::Result<bool> {
        if self.poisoned || self.logical_len < self.committed_len || self.preflush_requested()? {
            return Ok(false);
        }
        if !self.dirty {
            return Ok(true);
        }
        let payload_end = self.raw_len()?;
        let committed_payload_start = if self.logical_len < self.committed_len {
            payload_end
        } else {
            checked_end(self.data_offset, self.committed_len)?
        };
        let payload_start = committed_payload_start.max(self.preflush_target);
        let payload_len = payload_end
            .checked_sub(payload_start)
            .ok_or_else(|| invalid_data("atomic preflush frontier exceeds the pending payload"))?;
        if payload_len == 0 {
            return Ok(true);
        }
        Ok(self.payload_checksum.eligible
            && self.payload_checksum.offset == payload_start
            && self.payload_checksum.len == payload_len
            && payload_len <= payload_budget)
    }

    /// Prefix that must be durable before a publication marker may omit its bytes from CRC32C.
    pub(super) const fn preflush_target(&self) -> u64 {
        self.preflush_target
    }

    /// Return whether an unpublished payload preflush must be drained before reusing offsets.
    pub(super) fn preflush_requested(&self) -> io::Result<bool> {
        Ok(self.preflush_target > checked_end(self.data_offset, self.committed_len)?)
    }

    /// Discard speculative checksum state after reusing an unpublished tail.
    pub(super) const fn invalidate_payload_checksum(&mut self) {
        self.payload_checksum.eligible = false;
    }

    fn prepare_payload_checksum(
        &mut self,
        payload_start: u64,
        payload_end: u64,
    ) -> io::Result<PayloadChecksumEligibility> {
        let payload_len = payload_end
            .checked_sub(payload_start)
            .ok_or_else(|| invalid_data("atomic payload epoch is inverted"))?;
        if payload_len == 0 {
            return Ok(PayloadChecksumEligibility::Eligible(None));
        }
        let tracker = &mut self.payload_checksum;
        if !tracker.eligible {
            return Ok(PayloadChecksumEligibility::Ineligible);
        }
        tracker.eligible = false;
        if tracker.offset != payload_start || tracker.len != payload_len {
            return Ok(PayloadChecksumEligibility::Ineligible);
        }
        let checksum = std::mem::take(&mut tracker.hasher).finalize().1.as_u32();
        Ok(PayloadChecksumEligibility::Eligible(Some(
            PayloadChecksum {
                offset: payload_start,
                len: payload_len,
                checksum,
            },
        )))
    }

    pub(super) const fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Reserve the current tail for one append.
    pub(super) fn prepare_append(&mut self, data: IoBufs) -> io::Result<Option<PreparedMutation>> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        let data_len = u64::try_from(data.len())
            .map_err(|_| invalid_input("atomic append length does not fit in u64"))?;
        if data_len == 0 {
            return Ok(None);
        }
        if self.logical_len < self.committed_len {
            return Err(invalid_input(
                "atomic append requires syncing the committed rewind first",
            ));
        }
        let logical_start = self.logical_len;
        let logical_end = checked_end(logical_start, data_len)?;
        let physical = checked_end(self.data_offset, logical_start)?;
        self.payload_checksum.update(physical, data_len, &data);
        Ok(Some(PreparedMutation {
            file_offset: physical,
            data,
            mutation: Mutation {
                logical_start,
                logical_end,
                physical,
            },
        }))
    }

    /// Finish an append and return a newly requested background writeback range.
    pub(super) fn finish_mutation(
        &mut self,
        mutation: Mutation,
        schedule_preflush: bool,
    ) -> Option<Range<u64>> {
        debug_assert_eq!(mutation.logical_start, self.logical_len);
        debug_assert_eq!(mutation.physical, self.data_offset + mutation.logical_start);
        self.logical_len = mutation.logical_end;
        self.dirty = true;
        if !schedule_preflush {
            return None;
        }
        let raw_end = self
            .data_offset
            .checked_add(self.logical_len)
            .expect("prepared atomic appends have representable physical ends");
        if raw_end - self.preflush_target < BACKGROUND_PREFLUSH_INTERVAL {
            return None;
        }
        let range = self.preflush_target..raw_end;
        self.preflush_target = range.end;
        self.payload_checksum = PayloadChecksumTracker::new(raw_end);
        Some(range)
    }

    /// Rewind to an existing logical offset.
    ///
    /// Crossing the committed frontier fences appends until this shorter length is published.
    pub(super) fn validate_rewind(&self, len: u64) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        if len > self.logical_len {
            return Err(invalid_input("atomic rewind cannot extend a blob"));
        }
        Ok(())
    }

    fn apply_rewind(&mut self, len: u64, payload_preflushed: bool) -> io::Result<()> {
        self.validate_rewind(len)?;
        if len == self.logical_len {
            return Ok(());
        }
        self.logical_len = len;
        let raw_end = self.raw_len()?;
        let frontier = checked_end(self.data_offset, self.committed_len)?;
        if len == self.committed_len {
            self.preflush_target = frontier;
            self.payload_checksum = PayloadChecksumTracker::new(frontier);
            self.dirty = self.tag != self.committed_tag;
        } else if payload_preflushed || len < self.committed_len {
            self.preflush_target = raw_end;
            self.payload_checksum = PayloadChecksumTracker::new(raw_end);
            self.dirty = true;
        } else {
            // CRC32 cannot be rewound. The large-epoch preflush path will make the retained
            // unpublished prefix durable before a root can name it.
            self.preflush_target = frontier;
            self.invalidate_payload_checksum();
            self.dirty = true;
        }
        Ok(())
    }

    pub(super) fn rewind(&mut self, len: u64) -> io::Result<()> {
        self.apply_rewind(len, false)
    }

    /// Rewind after the backend made the complete current payload durable.
    pub(super) fn rewind_preflushed(&mut self, len: u64) -> io::Result<()> {
        self.apply_rewind(len, true)
    }

    pub(super) fn read_plan(&self, offset: u64, len: usize) -> io::Result<Vec<ReadSpan>> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        let len_u64 = u64::try_from(len).map_err(|_| invalid_input("read length overflow"))?;
        let end = checked_end(offset, len_u64)?;
        if end > self.logical_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read exceeds atomic blob length",
            ));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        Ok(vec![ReadSpan {
            destination: 0,
            len,
            source: ReadSource::File(checked_end(self.data_offset, offset)?),
        }])
    }

    pub(super) fn prepare_commit(&mut self) -> io::Result<Option<PreparedCommit>> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        if !self.dirty {
            return Ok(None);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("atomic generation overflow"))?;
        let payload_end = self.raw_len()?;
        let root_offset = ROOT_OFFSETS[(generation as usize) & 1];
        let committed_root = encode_root(ROOT_MAGIC, generation, self.logical_len, self.tag);
        let prepared_root =
            encode_root(PREPARED_ROOT_MAGIC, generation, self.logical_len, self.tag).to_vec();

        let committed_payload_start = if self.logical_len < self.committed_len {
            payload_end
        } else {
            checked_end(self.data_offset, self.committed_len)?
        };
        let payload_start = committed_payload_start.max(self.preflush_target);
        if payload_start > payload_end {
            return Err(invalid_data(
                "atomic preflush frontier exceeds the pending payload",
            ));
        }
        let payload_checksum = self.prepare_payload_checksum(payload_start, payload_end)?;
        Ok(Some(PreparedCommit {
            payload_start,
            root_offset,
            prepared_root,
            committed_root,
            payload_checksum,
            commit: Commit {
                generation,
                append_offset: payload_end,
                truncate: self.logical_len < self.committed_len,
            },
        }))
    }

    /// Prepare a metadata-only generation that can witness this blob's deletion.
    ///
    /// The candidate names the last committed length rather than unpublished appends. Its durable
    /// barrier therefore need not make discarded payload durable. The state is intentionally not
    /// advanced: a committed batch invalidates this namespace generation instead of returning the
    /// deleted handle to service.
    #[commonware_macros::stability(ALPHA)]
    pub(super) fn prepare_delete(&self) -> io::Result<PreparedCommit> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("atomic generation overflow"))?;
        let payload_end = checked_end(self.data_offset, self.committed_len)?;
        let root_offset = ROOT_OFFSETS[(generation as usize) & 1];
        Ok(PreparedCommit {
            payload_start: payload_end,
            root_offset,
            prepared_root: encode_root(
                PREPARED_ROOT_MAGIC,
                generation,
                self.committed_len,
                self.committed_tag,
            )
            .to_vec(),
            committed_root: encode_root(
                ROOT_MAGIC,
                generation,
                self.committed_len,
                self.committed_tag,
            ),
            payload_checksum: PayloadChecksumEligibility::Eligible(None),
            commit: Commit {
                generation,
                append_offset: payload_end,
                truncate: false,
            },
        })
    }

    fn apply_commit(&mut self, prepared: PreparedCommit) {
        self.generation = prepared.commit.generation;
        self.committed_len = self.logical_len;
        self.committed_tag = self.tag;
        self.preflush_target = prepared.commit.append_offset;
        self.payload_checksum = PayloadChecksumTracker::new(prepared.commit.append_offset);
        self.dirty = false;
    }

    pub(super) fn finish_commit(&mut self, prepared: PreparedCommit) {
        self.apply_commit(prepared);
        self.deferred_batch_root = None;
    }

    pub(super) fn finish_batch_commit(&mut self, prepared: PreparedCommit) -> Candidate {
        let candidate = prepared.candidate();
        self.apply_commit(prepared);
        self.deferred_batch_root = Some(candidate.clone());
        candidate
    }
}

fn encode_root(
    magic: &[u8; 8],
    generation: u64,
    logical_len: u64,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
) -> [u8; ROOT_LEN] {
    let mut root = [0u8; ROOT_LEN];
    root[..8].copy_from_slice(magic);
    root[8..16].copy_from_slice(&generation.to_be_bytes());
    root[16..24].copy_from_slice(&logical_len.to_be_bytes());
    root[ROOT_PREFIX_LEN..ROOT_BODY_LEN].copy_from_slice(&tag);
    let root_checksum = checksum(&[ROOT_DOMAIN, &root[..ROOT_BODY_LEN]]);
    root[ROOT_BODY_LEN..ROOT_LEN].copy_from_slice(&root_checksum.to_be_bytes());
    root
}

#[derive(Clone, Copy, Debug)]
struct Root {
    generation: u64,
    logical_len: u64,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
}

fn decode_root_with_magic(encoded: &[u8; ROOT_LEN], magic: &[u8; 8]) -> Option<Root> {
    if &encoded[..8] != magic {
        return None;
    }
    let root_checksum = u32::from_be_bytes(encoded[ROOT_BODY_LEN..ROOT_LEN].try_into().unwrap());
    if root_checksum != checksum(&[ROOT_DOMAIN, &encoded[..ROOT_BODY_LEN]]) {
        return None;
    }
    decode_root_fields(encoded)
}

fn decode_root_fields(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    let generation = u64::from_be_bytes(encoded[8..16].try_into().unwrap());
    let logical_len = u64::from_be_bytes(encoded[16..24].try_into().unwrap());
    let tag = encoded[ROOT_PREFIX_LEN..ROOT_BODY_LEN].try_into().unwrap();
    (generation != 0).then_some(Root {
        generation,
        logical_len,
        tag,
    })
}

fn decode_committed_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, ROOT_MAGIC)
}

fn decode_materialized_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, MATERIALIZED_ROOT_MAGIC)
}

fn decode_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_committed_root(encoded).or_else(|| decode_materialized_root(encoded))
}

fn decode_prepared_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, PREPARED_ROOT_MAGIC)
        .or_else(|| decode_root_with_magic(encoded, BATCH_PREPARED_ROOT_MAGIC))
}

fn decode_batch_prepared_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, BATCH_PREPARED_ROOT_MAGIC)
}

fn decode_batch_witness(slot: &[u8]) -> Option<(usize, &[u8])> {
    let header_end = ROOT_LEN.checked_add(BATCH_WITNESS_HEADER_LEN)?;
    let header = slot.get(ROOT_LEN..header_end)?;
    if &header[..8] != BATCH_WITNESS_MAGIC {
        return None;
    }
    let witness_len = u32::from_be_bytes(header[8..12].try_into().unwrap());
    let witness_len = usize::try_from(witness_len).ok()?;
    let witness_offset = header_end;
    let witness_end = witness_offset.checked_add(witness_len)?;
    let witness = slot.get(witness_offset..witness_end)?;
    let stored_checksum = u32::from_be_bytes(header[12..16].try_into().unwrap());
    let expected_checksum = checksum(&[BATCH_WITNESS_DOMAIN, &header[..12], witness]);
    (stored_checksum == expected_checksum).then_some((witness_offset, witness))
}

fn read_root_slot(
    file: &File,
    root_offset: u64,
) -> io::Result<Option<[u8; ROOT_SLOT_LEN as usize]>> {
    let mut slot = [0u8; ROOT_SLOT_LEN as usize];
    match read_exact_at(file, root_offset, &mut slot) {
        Ok(()) => Ok(Some(slot)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}

fn candidate_roots_match(candidate: &Candidate, prepared: Root, committed: Root) -> bool {
    candidate.base_generation.checked_add(1) == Some(committed.generation)
        && committed.generation == prepared.generation
        && committed.logical_len == prepared.logical_len
        && committed.tag == prepared.tag
        && ROOT_OFFSETS[(committed.generation as usize) & 1] == candidate.root_offset
}

fn candidate_materialized_root(candidate: &Candidate) -> Option<[u8; ROOT_LEN]> {
    let prepared = decode_batch_prepared_root(&candidate.prepared_root)?;
    let committed = decode_committed_root(&candidate.committed_root)?;
    if !candidate_roots_match(candidate, prepared, committed) {
        return None;
    }
    Some(encode_root(
        MATERIALIZED_ROOT_MAGIC,
        committed.generation,
        committed.logical_len,
        committed.tag,
    ))
}

fn candidate_tombstone_root(candidate: &Candidate) -> Option<[u8; ROOT_LEN]> {
    let prepared = decode_batch_prepared_root(&candidate.prepared_root)?;
    let committed = decode_committed_root(&candidate.committed_root)?;
    if !candidate_roots_match(candidate, prepared, committed) {
        return None;
    }
    Some(encode_root(
        TOMBSTONE_ROOT_MAGIC,
        committed.generation,
        committed.logical_len,
        committed.tag,
    ))
}

/// Return the independently recoverable spelling of a valid batch candidate root.
pub(super) fn materialized_candidate_root(candidate: &Candidate) -> io::Result<[u8; ROOT_LEN]> {
    candidate_materialized_root(candidate)
        .ok_or_else(|| invalid_data("transaction candidate cannot be materialized"))
}

fn candidate_root_is_transition(installed: &[u8; ROOT_LEN], candidate: &Candidate) -> bool {
    installed
        .iter()
        .zip(
            candidate
                .prepared_root
                .iter()
                .zip(&candidate.committed_root),
        )
        .all(|(installed, (prepared, committed))| installed == prepared || installed == committed)
}

fn candidate_root_is_batch_transition(installed: &[u8; ROOT_LEN], candidate: &Candidate) -> bool {
    let Some(materialized) = candidate_materialized_root(candidate) else {
        return candidate_root_is_transition(installed, candidate);
    };
    installed
        .iter()
        .zip(
            candidate
                .prepared_root
                .iter()
                .zip(&candidate.committed_root)
                .zip(materialized),
        )
        .all(|(installed, ((prepared, committed), materialized))| {
            installed == prepared || installed == committed || *installed == materialized
        })
}

fn candidate_root_is_delete_transition(installed: &[u8; ROOT_LEN], candidate: &Candidate) -> bool {
    let Some(materialized) = candidate_materialized_root(candidate) else {
        return candidate_root_is_transition(installed, candidate);
    };
    let Some(tombstone) = candidate_tombstone_root(candidate) else {
        return false;
    };
    installed
        .iter()
        .zip(
            candidate
                .prepared_root
                .iter()
                .zip(&candidate.committed_root)
                .zip(materialized)
                .zip(tombstone),
        )
        .all(
            |(installed, (((prepared, committed), materialized), tombstone))| {
                installed == prepared
                    || installed == committed
                    || *installed == materialized
                    || *installed == tombstone
            },
        )
}

fn embedded_batch_candidates_with_materialized(
    file: &File,
    data_offset: u64,
    include_materialized: bool,
) -> io::Result<Vec<EmbeddedBatchCandidate>> {
    if data_offset < ROOT_OFFSETS[1] + ROOT_SLOT_LEN {
        return Err(invalid_input(
            "V2 data offset does not reserve both root slots",
        ));
    }
    let raw_len = file.metadata()?.len();
    if raw_len < data_offset {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::with_capacity(ROOT_OFFSETS.len());
    for root_offset in ROOT_OFFSETS {
        let Some(slot) = read_root_slot(file, root_offset)? else {
            continue;
        };
        let encoded: [u8; ROOT_LEN] = slot[..ROOT_LEN]
            .try_into()
            .expect("root slots contain a complete root header");
        let Some(root) = decode_root_fields(&encoded) else {
            continue;
        };
        let prepared_root = encode_root(
            BATCH_PREPARED_ROOT_MAGIC,
            root.generation,
            root.logical_len,
            root.tag,
        );
        let committed_root = encode_root(ROOT_MAGIC, root.generation, root.logical_len, root.tag);
        let candidate = Candidate {
            base_generation: root.generation - 1,
            root_offset,
            prepared_root,
            committed_root,
        };
        let Some(materialized_root) = candidate_materialized_root(&candidate) else {
            continue;
        };
        if encoded == materialized_root && !include_materialized {
            continue;
        }
        if !candidate_root_is_delete_transition(&encoded, &candidate) {
            continue;
        }
        let Some((witness_offset, witness)) = decode_batch_witness(&slot) else {
            continue;
        };
        if ROOT_OFFSETS[(root.generation as usize) & 1] != root_offset {
            continue;
        }
        if witness_offset < ROOT_LEN {
            continue;
        }
        if checked_end(data_offset, root.logical_len)
            .ok()
            .is_none_or(|end| end > raw_len)
        {
            continue;
        }
        candidates.push(EmbeddedBatchCandidate {
            candidate,
            witness: witness.to_vec(),
        });
    }
    candidates.sort_by_key(|embedded| std::cmp::Reverse(embedded.candidate.base_generation));
    Ok(candidates)
}

/// Discover intact embedded witnesses even when their root header was torn during installation.
pub(crate) fn embedded_batch_witnesses(
    file: &File,
    data_offset: u64,
) -> io::Result<Vec<EmbeddedBatchWitness>> {
    if data_offset < ROOT_OFFSETS[1] + ROOT_SLOT_LEN {
        return Err(invalid_input(
            "V2 data offset does not reserve both root slots",
        ));
    }
    if file.metadata()?.len() < data_offset {
        return Ok(Vec::new());
    }

    let mut witnesses = Vec::with_capacity(ROOT_OFFSETS.len());
    for root_offset in ROOT_OFFSETS {
        let Some(slot) = read_root_slot(file, root_offset)? else {
            continue;
        };
        let Some((witness_offset, witness)) = decode_batch_witness(&slot) else {
            continue;
        };
        if witness_offset < ROOT_LEN {
            continue;
        }
        witnesses.push(EmbeddedBatchWitness {
            root_offset,
            witness: witness.to_vec(),
        });
    }
    Ok(witnesses)
}

/// Discover witnesses retained beside independently recoverable roots or tombstones.
///
/// Unresolved-candidate selection ignores these stale witnesses. A separate transfer pass uses
/// them to make dependent peers independently recoverable before this witness is reused or removed.
pub(crate) fn materialized_batch_candidates(
    file: &File,
    data_offset: u64,
) -> io::Result<Vec<EmbeddedBatchCandidate>> {
    let candidates = embedded_batch_candidates_with_materialized(file, data_offset, true)?;
    let mut materialized = Vec::with_capacity(candidates.len());
    for embedded in candidates {
        let (Some(expected), Some(tombstone)) = (
            candidate_materialized_root(&embedded.candidate),
            candidate_tombstone_root(&embedded.candidate),
        ) else {
            continue;
        };
        let Some(slot) = read_root_slot(file, embedded.candidate.root_offset)? else {
            continue;
        };
        if slot[..ROOT_LEN] == expected || slot[..ROOT_LEN] == tombstone {
            materialized.push(embedded);
        }
    }
    Ok(materialized)
}

/// Verify that an exact witness remains beside a known batch candidate's root transition.
pub(crate) fn candidate_has_embedded_batch_witness(
    file: &File,
    candidate: &Candidate,
    witness: &[u8],
) -> io::Result<bool> {
    let Some(prepared) = decode_batch_prepared_root(&candidate.prepared_root) else {
        return Ok(false);
    };
    let Some(committed) = decode_committed_root(&candidate.committed_root) else {
        return Ok(false);
    };
    if !candidate_roots_match(candidate, prepared, committed) {
        return Ok(false);
    }
    if witness.len()
        > (ROOT_SLOT_LEN as usize)
            .saturating_sub(ROOT_LEN)
            .saturating_sub(BATCH_WITNESS_HEADER_LEN)
    {
        return Ok(false);
    }

    let mut candidate_slot = None;
    for root_offset in ROOT_OFFSETS {
        let Some(slot) = read_root_slot(file, root_offset)? else {
            continue;
        };
        let encoded: [u8; ROOT_LEN] = slot[..ROOT_LEN]
            .try_into()
            .expect("root slots contain a complete root header");
        if decode_root(&encoded).is_some_and(|root| {
            ROOT_OFFSETS[(root.generation as usize) & 1] == root_offset
                && root.generation > committed.generation
        }) {
            return Ok(false);
        }
        if root_offset == candidate.root_offset {
            candidate_slot = Some(slot);
        }
    }
    let Some(slot) = candidate_slot else {
        return Ok(false);
    };
    let installed: [u8; ROOT_LEN] = slot[..ROOT_LEN]
        .try_into()
        .expect("root slots contain a complete root header");
    if !candidate_root_is_delete_transition(&installed, candidate) {
        return Ok(false);
    }
    Ok(decode_batch_witness(&slot)
        .is_some_and(|(offset, found)| offset >= ROOT_LEN && found == witness))
}

/// Return whether a candidate's exact committed header is installed in its generation slot.
pub(crate) fn candidate_is_committed(file: &File, candidate: &Candidate) -> io::Result<bool> {
    let Some(prepared) = decode_prepared_root(&candidate.prepared_root) else {
        return Ok(false);
    };
    let Some(committed) = decode_committed_root(&candidate.committed_root) else {
        return Ok(false);
    };
    if !candidate_roots_match(candidate, prepared, committed) {
        return Ok(false);
    }

    let mut installed = [0u8; ROOT_LEN];
    match read_exact_at(file, candidate.root_offset, &mut installed) {
        Ok(()) => Ok(installed == candidate.committed_root),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

/// Return whether a batch candidate's exact materialized header is installed.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn candidate_is_materialized(file: &File, candidate: &Candidate) -> io::Result<bool> {
    let Some(materialized_root) = candidate_materialized_root(candidate) else {
        return Ok(false);
    };

    let mut installed = [0u8; ROOT_LEN];
    match read_exact_at(file, candidate.root_offset, &mut installed) {
        Ok(()) => Ok(installed == materialized_root),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

/// Return whether a batch candidate's exact independently recoverable tombstone is installed.
pub(crate) fn candidate_is_tombstoned(file: &File, candidate: &Candidate) -> io::Result<bool> {
    let Some(tombstone_root) = candidate_tombstone_root(candidate) else {
        return Ok(false);
    };

    let mut installed = [0u8; ROOT_LEN];
    match read_exact_at(file, candidate.root_offset, &mut installed) {
        Ok(()) => Ok(installed == tombstone_root),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

/// Validate and durably publish a batch candidate as independently recoverable.
pub(crate) fn materialize_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<()> {
    let materialized_root = materialized_candidate_root(candidate)?;
    validate_candidate(file, data_offset, candidate)?;
    // A live inode may already contain the next unpublished append epoch. The materialized root
    // names the older durable length; reopening can reclaim any surplus after selecting that root.
    write_durable_at(file, candidate.root_offset, &materialized_root)
}

/// Validate and durably replace a prepared candidate with a payload-preserving tombstone.
pub(crate) fn materialize_tombstone_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<()> {
    let tombstone_root = candidate_tombstone_root(candidate)
        .ok_or_else(|| invalid_data("transaction candidate cannot become a tombstone"))?;
    let committed = decode_committed_root(&candidate.committed_root)
        .ok_or_else(|| invalid_data("transaction candidate has an invalid committed root"))?;
    let payload_end = checked_end(data_offset, committed.logical_len)?;
    if payload_end > file.metadata()?.len() {
        return Err(invalid_data("transaction tombstone payload end is invalid"));
    }
    let mut installed = [0u8; ROOT_LEN];
    read_exact_at(file, candidate.root_offset, &mut installed)?;
    if !candidate_root_is_delete_transition(&installed, candidate) {
        return Err(invalid_data(
            "transaction candidate root is not a recoverable tombstone transition",
        ));
    }
    write_durable_at(file, candidate.root_offset, &tombstone_root)
}

fn recover_root(
    _file: &File,
    data_offset: u64,
    raw_len: u64,
    root_offset: u64,
    root: Root,
) -> io::Result<(State, CandidateMetadata)> {
    if ROOT_OFFSETS[(root.generation as usize) & 1] != root_offset {
        return Err(invalid_data("atomic root generation is in the wrong slot"));
    }
    let payload_end = checked_end(data_offset, root.logical_len)
        .map_err(|_| invalid_data("atomic logical length overflows its data offset"))?;
    if payload_end > raw_len {
        return Err(invalid_data("atomic payload end is invalid"));
    }

    let mut state = State::empty(data_offset);
    state.logical_len = root.logical_len;
    state.committed_len = root.logical_len;
    state.generation = root.generation;
    state.tag = root.tag;
    state.committed_tag = root.tag;
    state.preflush_target = payload_end;
    state.payload_checksum = PayloadChecksumTracker::new(payload_end);
    Ok((state, CandidateMetadata { payload_end }))
}

/// Write a small publication record and make that write durable before returning.
pub(super) fn write_durable_at(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    let tracked_write = (offset, bytes.len());

    #[cfg(target_os = "linux")]
    {
        let mut offset = offset;
        let mut bytes = bytes;
        while !bytes.is_empty() {
            let offset_i64 = i64::try_from(offset)
                .map_err(|_| invalid_input("durable write offset exceeds off_t"))?;
            let iovec = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: `iovec` references readable `bytes` for the duration of the syscall, the file
            // file descriptor remains open, and the checked offset is representable by the ABI.
            let written = unsafe {
                libc::pwritev2(
                    file.as_raw_fd(),
                    &raw const iovec,
                    1,
                    offset_i64,
                    libc::RWF_DSYNC,
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "durable publication write made no progress",
                ));
            }
            let written = written as usize;
            offset = checked_end(offset, written as u64)?;
            bytes = &bytes[written..];
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        file.write_all_at(bytes, offset)?;
        file.sync_all()?;
    }

    #[cfg(test)]
    TRACKED_DURABLE_WRITES.with(|tracked| {
        if let Some(writes) = tracked.borrow_mut().as_mut() {
            writes.push(tracked_write);
        }
    });
    Ok(())
}

/// Validate a transaction-bound candidate without changing its root.
///
/// A prepared root is deliberately invisible to ordinary blob recovery. An exact durable batch
/// witness supplies the prepared and committed headers, allowing validation to accept any
/// bytewise prefix-independent transition between those headers.
fn validate_candidate_transition(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
    deletion: bool,
) -> io::Result<CandidateMetadata> {
    let committed = decode_committed_root(&candidate.committed_root)
        .ok_or_else(|| invalid_data("transaction candidate has an invalid committed root"))?;
    let prepared = decode_prepared_root(&candidate.prepared_root)
        .ok_or_else(|| invalid_data("transaction candidate has an invalid prepared root"))?;
    if committed.generation
        != candidate
            .base_generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("transaction candidate generation overflow"))?
        || committed.generation != prepared.generation
        || committed.logical_len != prepared.logical_len
        || committed.tag != prepared.tag
        || ROOT_OFFSETS[(committed.generation as usize) & 1] != candidate.root_offset
    {
        return Err(invalid_data("transaction candidate roots do not match"));
    }

    let raw_len = file.metadata()?.len();
    if raw_len < data_offset {
        return Err(invalid_data(
            "transaction candidate blob is shorter than its header",
        ));
    }

    let mut installed = [0u8; ROOT_LEN];
    read_exact_at(file, candidate.root_offset, &mut installed)?;
    // The durable batch witness is the authority for this exact self-contained
    // candidate. Its prior base root may already have been reused while preparing a later batch,
    // so validation must not depend on finding that base in the other root slot.
    let torn_transition = if deletion {
        candidate_root_is_delete_transition(&installed, candidate)
    } else {
        candidate_root_is_batch_transition(&installed, candidate)
    };
    if !torn_transition {
        return Err(invalid_data(
            "transaction candidate root is not a recoverable publication transition",
        ));
    }

    let (_, metadata) = recover_root(file, data_offset, raw_len, candidate.root_offset, committed)?;
    Ok(metadata)
}

pub(super) fn validate_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<CandidateMetadata> {
    validate_candidate_transition(file, data_offset, candidate, false)
}

pub(super) fn validate_delete_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<CandidateMetadata> {
    validate_candidate_transition(file, data_offset, candidate, true)
}

/// Verify a bounded speculative payload suffix without publishing its candidate root.
pub(super) fn validate_payload_checksum(
    file: &File,
    data_offset: u64,
    metadata: &CandidateMetadata,
    payload_start: u64,
    checksum: Option<&PayloadChecksum>,
) -> io::Result<()> {
    if payload_start < data_offset || metadata.payload_end < payload_start {
        return Err(invalid_data(
            "transaction payload checksum range is outside its data region",
        ));
    }
    let Some(checksum) = checksum else {
        return (payload_start == metadata.payload_end)
            .then_some(())
            .ok_or_else(|| invalid_data("transaction payload checksum is missing"));
    };
    if checksum.len == 0 {
        return Err(invalid_data(
            "transaction payload checksum has an empty range",
        ));
    }
    if checksum.len > MAX_VALIDATED_PAYLOAD_LEN {
        return Err(invalid_data(
            "transaction payload checksum exceeds the recovery bound",
        ));
    }
    let end = checksum
        .offset
        .checked_add(checksum.len)
        .ok_or_else(|| invalid_data("transaction payload checksum range overflows"))?;
    if checksum.offset != payload_start || end != metadata.payload_end {
        return Err(invalid_data(
            "transaction payload checksum does not cover the candidate payload epoch",
        ));
    }

    let mut hasher = Crc32::default();
    let mut buffer = vec![0u8; PAYLOAD_CHECKSUM_READ_LEN];
    let mut offset = checksum.offset;
    let mut remaining = checksum.len;
    while remaining != 0 {
        let len = usize::try_from(remaining.min(PAYLOAD_CHECKSUM_READ_LEN as u64))
            .expect("checksum chunks fit in usize");
        read_exact_at(file, offset, &mut buffer[..len])?;
        hasher.update(&buffer[..len]);
        offset = offset
            .checked_add(len as u64)
            .expect("validated checksum ranges do not overflow");
        remaining -= len as u64;
    }
    if hasher.finalize().1.as_u32() != checksum.checksum {
        return Err(invalid_data("transaction payload checksum mismatch"));
    }
    Ok(())
}

fn creation_path(live_path: &Path) -> io::Result<std::path::PathBuf> {
    let file_name = live_path
        .file_name()
        .ok_or_else(|| invalid_input("atomic blob has no file name"))?;
    let mut staging_name = OsString::from(CREATION_PREFIX);
    staging_name.push(file_name);
    Ok(live_path.with_file_name(staging_name))
}

pub(super) fn is_creation_file_name(name: &OsStr) -> bool {
    name.as_encoded_bytes()
        .starts_with(CREATION_PREFIX.as_bytes())
}

/// Create and durably initialize a new V2 live inode.
///
/// The live name is published only after its complete header is durable. A crash can therefore
/// leave either no live name or a parseable V2 file, without broadening legacy torn-header
/// recovery to cover the larger V2 header region.
pub(super) fn create_live(
    root: &Path,
    _partition: &str,
    _name: &[u8],
    live_path: &Path,
    region: &[u8],
) -> io::Result<File> {
    let creation_path = creation_path(live_path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&creation_path)?;
    file.write_all(region)?;
    file.sync_all()?;
    fs::rename(&creation_path, live_path)?;
    let parent = live_path
        .parent()
        .ok_or_else(|| invalid_input("atomic blob has no parent directory"))?;
    File::open(parent)?.sync_all()?;
    File::open(root)?.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Durably replace an opened V0/V1 live inode with an equivalent V2 inode, or finish making an
/// already-visible V2 name durable after an ambiguous migration result.
///
/// The source is synchronized before it is copied. The replacement remains unreachable under a
/// hidden creation name until its complete header, initial committed root, and payload are durable.
/// An ordinary same-directory rename then publishes the replacement atomically. The caller must
/// serialize namespace operations and prevent concurrent mutation through other source handles.
#[commonware_macros::stability(ALPHA)]
pub(super) fn migrate_live(
    root: &Path,
    partition: &str,
    name: &[u8],
    source: &File,
    expected_data_offset: u64,
) -> Result<(), crate::Error> {
    let encoded_name = hex(name);
    source.sync_all().map_err(|error| {
        crate::Error::BlobSyncFailed(partition.into(), encoded_name.clone(), error.into())
    })?;

    let source_metadata = source.metadata()?;
    if !source_metadata.is_file() {
        return Err(invalid_input("migration source is not a regular file").into());
    }
    let raw_len = source_metadata.len();
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    read_exact_at(source, 0, &mut raw)?;
    let (logical_len, blob_version, data_offset) = Header::parse(&raw, raw_len, &(0..=u16::MAX))
        .map_err(|error| error.into_error(partition, name))?;
    if data_offset != expected_data_offset {
        return Err(crate::Error::BlobCorrupt(
            partition.into(),
            encoded_name,
            "opened blob layout does not match its live header".into(),
        ));
    }
    let live_path = root.join(partition).join(hex(name));
    let live_metadata = fs::symlink_metadata(&live_path)?;
    if !live_metadata.file_type().is_file()
        || live_metadata.dev() != source_metadata.dev()
        || live_metadata.ino() != source_metadata.ino()
    {
        return Err(invalid_input("migration source is no longer the live blob").into());
    }
    if data_offset == Layout::V2.data_offset() {
        sync_live_directories(root, &live_path)?;
        return Ok(());
    }
    Layout::V2
        .data_offset()
        .checked_add(logical_len)
        .ok_or(crate::Error::OffsetOverflow)?;

    discard(root, partition, name)?;
    let creation_path = creation_path(&live_path)?;
    let mut replacement = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&creation_path)?;
    let mut region = Header::create_atomic(&(blob_version..=blob_version)).0;
    let initial_root = encode_root(ROOT_MAGIC, 1, logical_len, [0; ATOMIC_BLOB_TAG_LEN]);
    let root_offset = ROOT_OFFSETS[1] as usize;
    region[root_offset..root_offset + ROOT_LEN].copy_from_slice(&initial_root);
    replacement.write_all(&region)?;

    let buffer_len = usize::try_from(logical_len.min(MIGRATION_COPY_LEN as u64))
        .expect("migration chunks fit in usize");
    let mut buffer = vec![0u8; buffer_len];
    let mut copied = 0u64;
    while copied < logical_len {
        let remaining = logical_len - copied;
        let len = usize::try_from(remaining.min(MIGRATION_COPY_LEN as u64))
            .expect("migration chunks fit in usize");
        read_exact_at(source, data_offset + copied, &mut buffer[..len])?;
        replacement.write_all_at(&buffer[..len], Layout::V2.data_offset() + copied)?;
        copied += len as u64;
    }
    replacement.sync_all()?;

    // Detect stale handles and accidental concurrent resize before replacing the live name. The
    // namespace lock excludes Commonware namespace operations, the caller excludes other handle
    // mutations, and inode identity also catches an external rename.
    let source_after = source.metadata()?;
    let live_after = fs::symlink_metadata(&live_path)?;
    if source_after.len() != raw_len
        || source_after.dev() != source_metadata.dev()
        || source_after.ino() != source_metadata.ino()
        || !live_after.file_type().is_file()
        || live_after.dev() != source_metadata.dev()
        || live_after.ino() != source_metadata.ino()
    {
        return Err(invalid_input("migration source changed while it was copied").into());
    }

    fs::rename(&creation_path, &live_path)?;
    sync_live_directories(root, &live_path)?;
    Ok(())
}

/// Persist a same-directory live-name update after its target inode is durable.
#[commonware_macros::stability(ALPHA)]
fn sync_live_directories(root: &Path, live_path: &Path) -> io::Result<()> {
    let parent = live_path
        .parent()
        .ok_or_else(|| invalid_input("atomic blob has no parent directory"))?;
    File::open(parent)?.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

/// Discard a V2 creation inode left before publication.
pub(super) fn discard(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
    let live_path = root.join(partition).join(hex(name));
    let creation_path = creation_path(&live_path)?;
    match fs::remove_file(creation_path) {
        Ok(()) => File::open(
            live_path
                .parent()
                .ok_or_else(|| invalid_input("atomic blob has no parent directory"))?,
        )?
        .sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// V2 state is contained in the live inode, so partition removal needs no sidecar cleanup.
pub(super) const fn discard_partition(_root: &Path, _partition: &str) -> io::Result<()> {
    Ok(())
}
