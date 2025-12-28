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
//! 4. Test both Append.read_at() and as_blob_reader()

#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{
    buffer::pool::{Append, PoolRef},
    deterministic, Blob, Runner, Storage,
};
use commonware_utils::{NZUsize, NZU16};
use libfuzzer_sys::fuzz_target;

/// CRC record size.
const CRC_SIZE: u64 = 12;
/// Buffer capacity for the Append wrapper.
const BUFFER_CAPACITY: usize = 1024;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Seed for deterministic execution.
    seed: u64,
    /// Logical page size (will be clamped to 1..255).
    page_size: u8,
    /// Pool page cache capacity (will be clamped to 1..10).
    pool_capacity: u8,
    /// Number of bytes to write (will be clamped to 1..10 pages worth).
    num_bytes: u16,
    /// Byte offset within the blob to corrupt.
    corrupt_byte_offset: u16,
    /// Bit position within the byte to flip (0-7).
    corrupt_bit: u8,
    /// Read operations to perform after corruption.
    reads: Vec<ReadOp>,
}

#[derive(Arbitrary, Debug)]
struct ReadOp {
    /// Logical offset to read from.
    offset: u16,
    /// Number of bytes to read.
    len: u16,
    /// Whether to use the Read wrapper (true) or Append.read_at (false).
    use_reader: bool,
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Use dynamic page size from input (1-255).
        let page_size = input.page_size.max(1) as u64;
        let physical_page_size = page_size + CRC_SIZE;
        // Pool capacity is number of pages to cache (1-10).
        let pool_capacity = (input.pool_capacity % 10 + 1) as usize;
        let pool_ref = PoolRef::new(NZU16!(page_size as u16), NZUsize!(pool_capacity));

        // Determine how many bytes to write (1 to 10 pages worth).
        let max_bytes = 10 * page_size as usize;
        let logical_size = (input.num_bytes as usize).clamp(1, max_bytes) as u64;

        // Generate deterministic data based on seed.
        let expected_data: Vec<u8> = (0..logical_size)
            .map(|i| ((input.seed.wrapping_add(i)) & 0xFF) as u8)
            .collect();

        // Step 1: Write data to the blob.
        let (blob, _) = context
            .open("test_partition", b"integrity_test")
            .await
            .expect("cannot open blob");

        let append = Append::new(blob.clone(), 0, BUFFER_CAPACITY, pool_ref.clone())
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
        let corrupt_bit = input.corrupt_bit % 8;

        // Read the byte, flip the bit, write it back.
        let byte_buf = blob
            .read_at(vec![0u8; 1], corrupt_offset)
            .await
            .expect("cannot read byte to corrupt");
        let corrupted_byte = byte_buf.as_ref()[0] ^ (1 << corrupt_bit);
        blob.write_at(vec![corrupted_byte], corrupt_offset)
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
        let append = match Append::new(blob, size, BUFFER_CAPACITY, pool_ref.clone()).await {
            Ok(a) => a,
            Err(_) => {
                // Corruption was severe enough to fail initialization - this is acceptable.
                return;
            }
        };

        let reported_size = append.size().await;

        // Step 4: Perform read operations and verify results.
        for read_op in input.reads.iter().take(20) {
            let offset = read_op.offset as u64;
            let len = (read_op.len as usize).clamp(1, 256);

            // Skip reads that would be entirely out of bounds.
            if offset >= reported_size {
                continue;
            }

            // Clamp length to not exceed reported size.
            let len = len.min((reported_size - offset) as usize);
            if len == 0 {
                continue;
            }

            // Determine which pages this read spans.
            let start_page = offset / page_size;
            let end_page = (offset + len as u64 - 1) / page_size;
            let read_touches_corrupted_page =
                start_page <= corrupted_page && corrupted_page <= end_page;

            if read_op.use_reader {
                // Use as_blob_reader.
                // Note: The Read wrapper buffers multiple pages at once, so corruption on ANY
                // page in the buffer can cause a read to fail - not just the page being accessed.
                // We can only verify that successful reads return correct data.
                let reader_result = append.as_blob_reader(NZUsize!(256)).await;
                let mut reader = match reader_result {
                    Ok(r) => r,
                    Err(_) => continue, // Reader creation failed, skip.
                };

                // Seek to the read offset.
                if reader.seek_to(offset).is_err() {
                    continue;
                }

                let mut buf = vec![0u8; len];
                let read_result = reader.read_exact(&mut buf, len).await;

                if let Ok(()) = read_result {
                    // Read succeeded - data must match expected.
                    let expected_slice = &expected_data[offset as usize..offset as usize + len];
                    assert_eq!(
                        &buf, expected_slice,
                        "Read via reader returned wrong data at offset {}, len {}",
                        offset, len
                    );
                }
                // Read failures are acceptable due to buffering behavior.
            } else {
                // Use Append.read_at directly.
                let buf = vec![0u8; len];
                let read_result = append.read_at(buf, offset).await;

                match read_result {
                    Ok(buf) => {
                        // Read succeeded - data must match expected.
                        let buf: Vec<u8> = buf.into();
                        let expected_slice = &expected_data[offset as usize..offset as usize + len];
                        assert_eq!(
                            &buf, expected_slice,
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
