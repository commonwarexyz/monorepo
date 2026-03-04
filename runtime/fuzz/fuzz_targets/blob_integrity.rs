//! Fuzz test for blob integrity verification.
//!
//! This test verifies that random bit corruptions in persisted blob data are appropriately
//! detected and gracefully handled by page-oriented blob wrappers.
//!
//! Strategy:
//! 1. Write several pages worth of data to an Append blob
//! 2. Flip a random bit in the underlying blob
//! 3. Attempt to read various ranges:
//!    - Reads from uncorrupted pages should succeed with correct data
//!    - Reads from corrupted pages should either fail OR return correct data
//!      (if the bit flip was in padding/unused bytes)
//! 4. Test both Append.read_at() and Replay

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{
    buffer::paged::{Append, CacheRef},
    deterministic, Blob, Buf, Error, Runner, Storage,
};
use commonware_utils::{NZUsize, NZU16};
use libfuzzer_sys::fuzz_target;

/// CRC record size.
const CRC_SIZE: u64 = 12;
/// Buffer capacity for the Append wrapper.
const BUFFER_CAPACITY: usize = 1024;
/// Buffer capacity for the blob reader.
const READER_BUFFER_CAPACITY: usize = 256;
/// Maximum number of read operations to perform.
const MAX_READS: usize = 20;

#[derive(Debug)]
struct FuzzInput {
    /// Seed for deterministic execution.
    seed: u64,
    /// Logical page size (1-255).
    page_size: u8,
    /// Page cache capacity (1-10).
    cache_capacity: u8,
    /// Number of pages to write (1-10).
    num_pages: u8,
    /// Byte offset within the blob to corrupt (will be modulo physical_size).
    corrupt_byte_offset: u16,
    /// Bit position within the byte to flip (0-7).
    corrupt_bit: u8,
    /// Read operations to perform after corruption.
    reads: Vec<ReadOp>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_reads = u.int_in_range(0..=MAX_READS)?;
        let reads = (0..num_reads)
            .map(|_| ReadOp::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FuzzInput {
            seed: u.arbitrary()?,
            page_size: u.int_in_range(1..=255)?,
            cache_capacity: u.int_in_range(1..=10)?,
            num_pages: u.int_in_range(1..=10)?,
            corrupt_byte_offset: u.arbitrary()?,
            corrupt_bit: u.int_in_range(0..=7)?,
            reads,
        })
    }
}

#[derive(Debug)]
struct ReadOp {
    /// Logical offset to read from.
    offset: u16,
    /// Number of bytes to read (1-256).
    len: u16,
    /// Whether to use the Read wrapper (true) or Append.read_at (false).
    use_reader: bool,
}

impl<'a> Arbitrary<'a> for ReadOp {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(ReadOp {
            offset: u.arbitrary()?,
            len: u.int_in_range(1..=256)?,
            use_reader: u.arbitrary()?,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let page_size = input.page_size as u64;
        let physical_page_size = page_size + CRC_SIZE;
        let cache_capacity = input.cache_capacity as usize;
        let cache_ref = CacheRef::from_pooler(
            &context,
            NZU16!(page_size as u16),
            NZUsize!(cache_capacity),
        );

        // Compute logical size from number of pages.
        let logical_size = input.num_pages as u64 * page_size;

        // Generate deterministic data based on seed.
        let expected_data: Vec<u8> = (0..logical_size)
            .map(|i| ((input.seed.wrapping_add(i)) & 0xFF) as u8)
            .collect();

        // Step 1: Write data to the blob.
        let (blob, _) = context
            .open("test_partition", b"integrity_test")
            .await
            .expect("cannot open blob");

        let append = Append::new(blob.clone(), 0, BUFFER_CAPACITY, cache_ref.clone())
            .await
            .expect("cannot create append wrapper");

        append
            .append(&expected_data)
            .await
            .expect("cannot append data");
        append.sync().await.expect("cannot sync");
        drop(append);

        // Step 2: Corrupt a single bit in the blob.
        // Calculate physical size: full pages + partial page (if any).
        let full_pages = logical_size / page_size;
        let partial_bytes = logical_size % page_size;
        let physical_size = if partial_bytes > 0 {
            (full_pages + 1) * physical_page_size
        } else {
            full_pages * physical_page_size
        };
        let corrupt_offset = (input.corrupt_byte_offset as u64) % physical_size;
        let corrupt_bit = input.corrupt_bit;

        // Read the byte, flip the bit, write it back.
        let byte_buf = blob
            .read_at(corrupt_offset, 1)
            .await
            .expect("cannot read byte to corrupt")
            .coalesce();
        let corrupted_byte = byte_buf.as_ref()[0] ^ (1 << corrupt_bit);
        blob.write_at(corrupt_offset, vec![corrupted_byte])
            .await
            .expect("cannot write corrupted byte");
        blob.sync().await.expect("cannot sync corruption");

        // Determine which logical page was corrupted.
        let corrupted_page = corrupt_offset / physical_page_size;

        // Step 3: Re-open and attempt reads.
        let (blob, size) = context
            .open("test_partition", b"integrity_test")
            .await
            .expect("cannot reopen blob");

        // The append wrapper may truncate if the corruption affected the last page's CRC
        // during initialization, so we handle both cases.
        let append = match Append::new(blob, size, BUFFER_CAPACITY, cache_ref.clone()).await {
            Ok(a) => a,
            Err(_) => {
                // Corruption was severe enough to fail initialization - this is acceptable.
                return;
            }
        };

        let reported_size = append.size().await;

        // Step 4: Perform read operations and verify results.
        for read_op in &input.reads {
            let offset = read_op.offset as u64;
            let len = read_op.len as usize;

            // Skip reads that would be entirely out of bounds.
            if offset >= reported_size {
                continue;
            }

            // Clamp length to not exceed reported size.
            let len = len.min((reported_size - offset) as usize);

            // Determine which pages this read spans.
            let start_page = offset / page_size;
            let end_page = (offset + len as u64 + READER_BUFFER_CAPACITY as u64) / page_size;
            let read_touches_corrupted_page =
                start_page <= corrupted_page && corrupted_page <= end_page;

            if read_op.use_reader {
                // Replay is for streaming replay, not random access.
                // Test integrity via Replay by ensuring bytes and reading.
                let replay_result = append.replay(NZUsize!(READER_BUFFER_CAPACITY)).await;
                let mut replay = match replay_result {
                    Ok(r) => r,
                    Err(_) => continue, // Replay creation failed due to corruption, skip.
                };

                // Skip to the offset by ensuring and advancing
                if offset > 0 {
                    match replay.ensure(offset as usize).await {
                        Ok(true) => replay.advance(offset as usize),
                        Ok(false) => continue, // Not enough data, skip
                        Err(_) => {
                            // Error during skip - acceptable if corruption is involved
                            assert!(
                                read_touches_corrupted_page || offset / page_size >= corrupted_page,
                                "Replay skip failed but didn't touch corrupted page"
                            );
                            continue;
                        }
                    }
                }

                // Ensure we have enough bytes for the read
                match replay.ensure(len).await {
                    Ok(true) => {
                        // Read the data using the Buf trait
                        let mut buf = vec![0u8; len];
                        let mut bytes_read = 0;
                        while bytes_read < len && replay.remaining() > 0 {
                            let chunk = replay.chunk();
                            let to_copy = chunk.len().min(len - bytes_read);
                            buf[bytes_read..bytes_read + to_copy]
                                .copy_from_slice(&chunk[..to_copy]);
                            replay.advance(to_copy);
                            bytes_read += to_copy;
                        }

                        // Verify data matches expected
                        let expected_slice =
                            &expected_data[offset as usize..offset as usize + len];
                        assert_eq!(
                            &buf, expected_slice,
                            "Read via Replay returned wrong data at offset {}, len {}",
                            offset, len
                        );
                    }
                    Ok(false) => {
                        // Not enough data available - skip
                        continue;
                    }
                    Err(Error::InvalidChecksum) => {
                        // Ensure failed due to CRC error - acceptable if we touch corrupted page
                        assert!(
                            read_touches_corrupted_page,
                            "Replay ensure failed at offset {}, len {} but didn't touch corrupted page {}",
                            offset, len, corrupted_page
                        );
                    }
                    Err(err) => {
                        panic!("Replay ensure failed at offset {}, len {} with unexpected error: {:?}", offset, len, err);
                    }
                }
            } else {
                // Use Append.read_at directly.
                let read_result = append.read_at(offset, len).await;

                match read_result {
                    Ok(buf) => {
                        // Read succeeded - data must match expected.
                        let expected_slice = &expected_data[offset as usize..offset as usize + len];
                        assert_eq!(
                            buf.coalesce(), expected_slice,
                            "Read via Append returned wrong data at offset {}, len {}",
                            offset, len
                        );
                    }
                    Err(_) => {
                        // Read failed - this is only acceptable if the read touched
                        // the corrupted page.
                        assert!(
                            read_touches_corrupted_page,
                            "Read via Append failed at offset {}, len {} but didn't touch corrupted page {}",
                            offset, len, corrupted_page
                        );
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
