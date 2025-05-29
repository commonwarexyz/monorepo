//! Buffers for reading and writing to [crate::Blob]s.

mod read;
mod write;

pub use read::Read;
pub use write::Write;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Blob as _, Error, Runner, Storage};
    use commonware_macros::test_traced;

    #[test_traced]
    fn test_read_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"Hello, world! This is a test.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with a small buffer size
            let lookahead = 10;
            let mut reader = Read::new(blob, size, lookahead);

            // Read some data
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"Hello");

            // Read more data that requires a refill
            let mut buf = [0u8; 14];
            reader.read_exact(&mut buf, 14).await.unwrap();
            assert_eq!(&buf, b", world! This ");

            // Verify position
            assert_eq!(reader.position(), 19);

            // Read the rest
            let mut buf = [0u8; 10];
            reader.read_exact(&mut buf, 7).await.unwrap();
            assert_eq!(&buf[..7], b"is a te");

            // Try to read beyond the end
            let mut buf = [0u8; 5];
            let result = reader.read_exact(&mut buf, 5).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    #[should_panic(expected = "buffer size must be greater than zero")]
    fn test_read_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"Hello, world! This is a test.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with a small buffer size
            let lookahead = 0;
            Read::new(blob, size, lookahead);
        });
    }

    #[test_traced]
    fn test_read_cross_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with buffer size 10
            let buffer_size = 10;
            let mut reader = Read::new(blob, size, buffer_size);

            // Read data that crosses a buffer boundary
            let mut buf = [0u8; 15];
            reader.read_exact(&mut buf, 15).await.unwrap();
            assert_eq!(&buf, b"ABCDEFGHIJKLMNO");

            // Position should be 15
            assert_eq!(reader.position(), 15);

            // Read the rest
            let mut buf = [0u8; 11];
            reader.read_exact(&mut buf, 11).await.unwrap();
            assert_eq!(&buf, b"PQRSTUVWXYZ");

            // Position should be 26
            assert_eq!(reader.position(), 26);
            assert_eq!(reader.blob_remaining(), 0);
        });
    }

    #[test_traced]
    fn test_read_with_known_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"This is a test with known size limitations.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with a buffer smaller than the data
            let buffer_size = 10;
            let mut reader = Read::new(blob, size, buffer_size);

            // Check remaining bytes in the blob
            assert_eq!(reader.blob_remaining(), size);

            // Read half the buffer size
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"This ");

            // Check remaining after read
            assert_eq!(reader.blob_remaining(), size - 5);

            // Try to read exactly up to the size limit
            let mut buf = vec![0u8; (size - 5) as usize];
            reader
                .read_exact(&mut buf, (size - 5) as usize)
                .await
                .unwrap();
            assert_eq!(&buf, b"is a test with known size limitations.");

            // Now we should be at the end
            assert_eq!(reader.blob_remaining(), 0);

            // Trying to read more should fail
            let mut buf = [0u8; 1];
            let result = reader.read_exact(&mut buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_read_large_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a larger blob for testing with larger data
            let data_size = 1024 * 256; // 256KB of data
            let data = vec![0x42; data_size];
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.clone(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer with size smaller than the data
            let buffer_size = 64 * 1024; // 64KB
            let mut reader = Read::new(blob, size, buffer_size);

            // Read all the data in chunks
            let mut total_read = 0;
            let chunk_size = 8 * 1024; // 8KB chunks
            let mut buf = vec![0u8; chunk_size];

            while total_read < data_size {
                let to_read = std::cmp::min(chunk_size, data_size - total_read);
                reader
                    .read_exact(&mut buf[..to_read], to_read)
                    .await
                    .unwrap();

                // Verify the data is correct (all bytes should be 0x42)
                assert!(
                    buf[..to_read].iter().all(|&b| b == 0x42),
                    "Data at position {} is not correct",
                    total_read
                );

                total_read += to_read;
            }

            // Verify we read everything
            assert_eq!(total_read, data_size);

            // Trying to read more should fail
            let mut extra_buf = [0u8; 1];
            let result = reader.read_exact(&mut extra_buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_read_exact_size_reads() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a blob with exactly 2.5 buffer sizes of data
            let buffer_size = 1024;
            let data_size = buffer_size * 5 / 2; // 2.5 buffers
            let data = vec![0x37; data_size];

            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.clone(), 0).await.unwrap();
            let size = data.len() as u64;

            let mut reader = Read::new(blob, size, buffer_size);

            // Read exactly one buffer size
            let mut buf1 = vec![0u8; buffer_size];
            reader.read_exact(&mut buf1, buffer_size).await.unwrap();
            assert!(buf1.iter().all(|&b| b == 0x37));

            // Read exactly one buffer size more
            let mut buf2 = vec![0u8; buffer_size];
            reader.read_exact(&mut buf2, buffer_size).await.unwrap();
            assert!(buf2.iter().all(|&b| b == 0x37));

            // Read the remaining half buffer
            let half_buffer = buffer_size / 2;
            let mut buf3 = vec![0u8; half_buffer];
            reader.read_exact(&mut buf3, half_buffer).await.unwrap();
            assert!(buf3.iter().all(|&b| b == 0x37));

            // Verify we're at the end
            assert_eq!(reader.blob_remaining(), 0);
            assert_eq!(reader.position(), size);
        });
    }

    #[test_traced]
    fn test_read_seek_to() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader
            let buffer_size = 10;
            let mut reader = Read::new(blob, size, buffer_size);

            // Read some data to advance the position
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"ABCDE");
            assert_eq!(reader.position(), 5);

            // Seek to a specific position
            reader.seek_to(10).unwrap();
            assert_eq!(reader.position(), 10);

            // Read data from the new position
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"KLMNO");

            // Seek to beginning
            reader.seek_to(0).unwrap();
            assert_eq!(reader.position(), 0);

            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"ABCDE");

            // Seek to end
            reader.seek_to(size).unwrap();
            assert_eq!(reader.position(), size);

            // Trying to read should fail
            let mut buf = [0u8; 1];
            let result = reader.read_exact(&mut buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));

            // Seek beyond end should fail
            let result = reader.seek_to(size + 10);
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_read_seek_with_refill() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with longer data
            let data = vec![0x41; 1000]; // 1000 'A' characters
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.clone(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with small buffer
            let buffer_size = 10;
            let mut reader = Read::new(blob, size, buffer_size);

            // Read some data
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();

            // Seek far ahead, past the current buffer
            reader.seek_to(500).unwrap();

            // Read data - should get data from position 500
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"AAAAA"); // Should still be 'A's
            assert_eq!(reader.position(), 505);

            // Seek backwards
            reader.seek_to(100).unwrap();

            // Read again - should be at position 100
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(reader.position(), 105);
        });
    }

    #[test_traced]
    fn test_read_truncate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let data_len = data.len() as u64;

            // Create a buffer reader
            let buffer_size = 10;
            let reader = Read::new(blob.clone(), data_len, buffer_size);

            // Truncate the blob to half its size
            let truncate_len = data_len / 2;
            reader.truncate(truncate_len).await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, truncate_len, "Blob should be truncated to half size");

            // Create a new buffer and read to verify truncation
            let mut new_reader = Read::new(blob, size, buffer_size);

            // Read the content
            let mut buf = vec![0u8; size as usize];
            new_reader
                .read_exact(&mut buf, size as usize)
                .await
                .unwrap();
            assert_eq!(&buf, b"ABCDEFGHIJKLM", "Truncated content should match");

            // Reading beyond truncated size should fail
            let mut extra_buf = [0u8; 1];
            let result = new_reader.read_exact(&mut extra_buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_read_truncate_to_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let data_len = data.len() as u64;
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();

            // Create a buffer reader
            let buffer_size = 10;
            let reader = Read::new(blob.clone(), data_len, buffer_size);

            // Truncate the blob to zero
            reader.truncate(0).await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0, "Blob should be truncated to zero");

            // Create a new buffer and try to read (should fail)
            let mut new_reader = Read::new(blob, size, buffer_size);

            // Reading from truncated blob should fail
            let mut buf = [0u8; 1];
            let result = new_reader.read_exact(&mut buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_write_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test basic write_at and sync functionality.
            let (blob, size) = context.open("partition", b"write_basic").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::new(blob.clone(), 0, 8);
            writer.write_at(b"hello".to_vec(), 0).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"write_basic").await.unwrap();
            assert_eq!(size, 5);
            let mut reader = Read::new(blob, size, 8);
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"hello");
        });
    }

    #[test_traced]
    fn test_write_multiple_flushes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing data that causes multiple buffer flushes.
            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::new(blob.clone(), 0, 4);
            writer.write_at(b"abc".to_vec(), 0).await.unwrap();
            writer.write_at(b"defg".to_vec(), 3).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 7);
            let mut reader = Read::new(blob, size, 4);
            let mut buf = [0u8; 7];
            reader.read_exact(&mut buf, 7).await.unwrap();
            assert_eq!(&buf, b"abcdefg");
        });
    }

    #[test_traced]
    fn test_write_large_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing data significantly larger than the buffer capacity.
            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::new(blob.clone(), 0, 4);
            writer.write_at(b"abc".to_vec(), 0).await.unwrap();
            writer
                .write_at(b"defghijklmnopqrstuvwxyz".to_vec(), 3)
                .await
                .unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 26);
            let mut reader = Read::new(blob, size, 4);
            let mut buf = [0u8; 26];
            reader.read_exact(&mut buf, 26).await.unwrap();
            assert_eq!(&buf, b"abcdefghijklmnopqrstuvwxyz");
        });
    }

    #[test_traced]
    #[should_panic(expected = "buffer capacity must be greater than zero")]
    fn test_write_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test creating a writer with zero buffer capacity.
            let (blob, size) = context.open("partition", b"write_empty").await.unwrap();
            assert_eq!(size, 0);
            Write::new(blob, 0, 0);
        });
    }

    #[test_traced]
    fn test_write_append_to_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test appending data that partially fits and then exceeds buffer capacity, causing a flush.
            let (blob, _) = context.open("partition", b"append_buf").await.unwrap();
            let writer = Write::new(blob.clone(), 0, 10);

            // Write "hello" (5 bytes) - fits in buffer
            writer.write_at(b"hello".to_vec(), 0).await.unwrap();
            // Append " world" (6 bytes) - "hello world" is 11 bytes, exceeds buffer
            // "hello" is flushed, " world" is buffered
            writer.write_at(b" world".to_vec(), 5).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"append_buf").await.unwrap();
            assert_eq!(size, 11);
            let mut reader = Read::new(blob, size, 10);
            let mut buf = vec![0u8; 11];
            reader.read_exact(&mut buf, 11).await.unwrap();
            assert_eq!(&buf, b"hello world");
        });
    }

    #[test_traced]
    fn test_write_into_middle_of_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing data into the middle of an existing, partially filled buffer.
            let (blob, _) = context.open("partition", b"middle_buf").await.unwrap();
            let writer = Write::new(blob.clone(), 0, 20);

            // Write "abcdefghij" (10 bytes)
            writer.write_at(b"abcdefghij".to_vec(), 0).await.unwrap();
            // Write "01234" into the middle (offset 2, 5 bytes) -> "ab01234hij"
            writer.write_at(b"01234".to_vec(), 2).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"middle_buf").await.unwrap();
            assert_eq!(size, 10); // Original length, as it's an overwrite
            let mut reader = Read::new(blob, size, 10);
            let mut buf = vec![0u8; 10];
            reader.read_exact(&mut buf, 10).await.unwrap();
            assert_eq!(&buf, b"ab01234hij");

            // Write "klmnopqrst" (10 bytes) - buffer becomes "ab01234hijklmnopqrst" (20 bytes)
            writer.write_at(b"klmnopqrst".to_vec(), 10).await.unwrap();
            // Overwrite "jklm" with "wxyz" -> buffer becomes "ab01234hiwxyzopqrst"
            writer.write_at(b"wxyz".to_vec(), 9).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"middle_buf").await.unwrap();
            assert_eq!(size, 20);
            let mut reader = Read::new(blob, size, 20);
            let mut buf = vec![0u8; 20];
            reader.read_exact(&mut buf, 20).await.unwrap();
            assert_eq!(&buf, b"ab01234hiwxyznopqrst");
        });
    }

    #[test_traced]
    fn test_write_before_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing data at an offset that precedes the current buffered data range.
            let (blob, _) = context.open("partition", b"before_buf").await.unwrap();
            let writer = Write::new(blob.clone(), 10, 10); // Buffer starts at blob offset 10

            // Buffer some data at offset 10: "0123456789"
            writer.write_at(b"0123456789".to_vec(), 10).await.unwrap();

            // Write "abcde" at offset 0. This is before the current buffer.
            // Current buffer should be flushed. "abcde" written directly.
            // New buffer position will be 5.
            writer.write_at(b"abcde".to_vec(), 0).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            // Expected: "abcde" at 0 (5 bytes) + "0123456789" at 10 (10 bytes) = 20 total size.
            // The underlying blob previously had "0123456789" written starting at 10.
            // Then "abcde" was written starting at 0.
            // The blob size should be 20 if the original data at 10 was preserved.
            assert_eq!(size, 20);
            let mut reader = Read::new(blob, size, 20);
            let mut buf = vec![0u8; 20];
            reader.read_exact(&mut buf, 20).await.unwrap();

            let mut expected = vec![0u8; 20];
            expected[0..5].copy_from_slice("abcde".as_bytes());
            expected[10..20].copy_from_slice("0123456789".as_bytes());
            assert_eq!(buf, expected);

            // Write "fghij" at offset 5. This will append to the "abcde"
            // The buffer for writer is now at position 5 with capacity 10.
            // This write will be buffered.
            writer.write_at(b"fghij".to_vec(), 5).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            assert_eq!(size, 20); // Size remains 20 as "fghij" overwrites part of the gap + start of old data.
            let mut reader = Read::new(blob, size, 20);
            let mut buf = vec![0u8; 20];
            reader.read_exact(&mut buf, 20).await.unwrap();

            expected[0..10].copy_from_slice("abcdefghij".as_bytes());
            // The "0123456789" part originally at 10-19 is still there.
            assert_eq!(buf, expected);
        });
    }

    #[test_traced]
    fn test_write_truncate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test truncating the blob via the writer and subsequent write behaviors.
            let (blob, _) = context.open("partition", b"truncate_write").await.unwrap();
            let writer = Write::new(blob, 0, 10);

            writer.write_at(b"hello world".to_vec(), 0).await.unwrap(); // 11 bytes
            writer.sync().await.unwrap();

            let (blob_check, size_check) =
                context.open("partition", b"truncate_write").await.unwrap();
            assert_eq!(size_check, 11);
            drop(blob_check);

            // Truncate to 5 bytes ("hello")
            writer.truncate(5).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"truncate_write").await.unwrap();
            assert_eq!(size, 5);
            let mut reader = Read::new(blob, size, 5);
            let mut buf = vec![0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"hello");

            // Write more data, buffer position should be reset by truncate implicitly
            // or write_at should handle it.
            // After truncate, the writer's internal state (position, buffer) needs to be consistent.
            // Let's assume truncate implies a flush and reset of position to 0 for the writer if not specified.
            // The `Blob::truncate` itself doesn't dictate writer state.
            // The current `Write::truncate` flushes then truncates. The writer's `position` is not reset.
            // This means subsequent writes might be to unexpected locations if not careful.
            // Let's test current behavior:
            // inner.position was 11 after "hello world". Flush happens. Blob truncated to 5.
            // writer.inner.position is still 11.
            // This is a bit tricky. For `Write::new(blob, position, capacity)`, `position` is the *start* of the buffer.
            // After flush, `inner.position` becomes `inner.position + len_flushed`.
            // So after writing "hello world" (11 bytes) with buffer 10:
            // 1. "hello worl" (10 bytes) written to buffer. inner.buffer.len() = 10, inner.position = 0.
            // 2. "d" (1 byte) written. Buffer has "hello worl". write("d") called.
            //    buffer.len (10) + "d".len (1) > capacity (10). So flush.
            //    blob.write_at("hello worl", 0). inner.position becomes 10. inner.buffer is empty.
            //    Then "d" is buffered. inner.buffer = "d".
            // 3. sync() called. Flushes "d". blob.write_at("d", 10). inner.position becomes 11. inner.buffer empty.
            // 4. truncate(5). Flushes (empty buffer). inner.blob.truncate(5). inner.position is still 11.

            // If we now write "X" at offset 0:
            // write_start = 0. buffer_start = 11. buffer_end = 11.
            // Not scenario 1 (0 != 11).
            // Not scenario 2 (0 < 11).
            // Scenario 3: flush (empty). blob.write_at("X", 0). inner.position = 0 + 1 = 1.
            writer.write_at(b"X".to_vec(), 0).await.unwrap();
            writer.sync().await.unwrap();

            let (blob, size) = context.open("partition", b"truncate_write").await.unwrap();
            assert_eq!(size, 5); // Blob was "hello", truncated to 5, now overwritten at 0 with "X", size remains 5.
            let mut reader = Read::new(blob, size, 5);
            let mut buf = vec![0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"Xello");

            // Test truncate to 0
            let (blob_zero, _) = context.open("partition", b"truncate_zero").await.unwrap();
            let writer_zero = Write::new(blob_zero.clone(), 0, 10);
            writer_zero
                .write_at(b"some data".to_vec(), 0)
                .await
                .unwrap();
            writer_zero.sync().await.unwrap();
            writer_zero.truncate(0).await.unwrap();
            writer_zero.sync().await.unwrap();

            let (_, size_z) = context.open("partition", b"truncate_zero").await.unwrap();
            assert_eq!(size_z, 0);
        });
    }

    #[test_traced]
    fn test_write_read_at_on_writer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test reading data through the writer's read_at method, covering buffer and blob reads.
            let (blob, _) = context.open("partition", b"read_at_writer").await.unwrap();
            let writer = Write::new(blob.clone(), 0, 10); // Buffer capacity 10, starts at blob offset 0

            // 1. Write "buffered" (8 bytes) - stays in buffer
            writer.write_at(b"buffered".to_vec(), 0).await.unwrap();

            // Read from buffer: "buff" at offset 0
            let mut read_buf_vec = vec![0u8; 4].into();
            read_buf_vec = writer.read_at(read_buf_vec, 0).await.unwrap();
            assert_eq!(read_buf_vec.as_ref(), b"buff");

            // Read from buffer: "ered" at offset 4
            read_buf_vec = writer.read_at(read_buf_vec, 4).await.unwrap();
            assert_eq!(read_buf_vec.as_ref(), b"ered");

            // Read past buffer end (buffered data is "buffered" at 0-7)
            let small_buf_vec = vec![0u8; 1];
            assert!(writer.read_at(small_buf_vec, 8).await.is_err());

            // 2. Write " and flushed" (12 bytes) at offset 8.
            // "buffered" (8 bytes) is at 0-7. New write starts at 8.
            // This is an append to buffer. writer.write_at(" and flushed", 8)
            // inner.write will be called. buffer.len (8) + " and flushed".len (12) = 20 > capacity (10)
            // So, "buffered" is flushed. blob.write_at("buffered", 0). inner.position = 8.
            // Then " and flushed" (12 bytes) is written. Since 12 > 10 (capacity), it's a direct write.
            // blob.write_at(" and flushed", 8). inner.position = 8 + 12 = 20.
            writer.write_at(b" and flushed".to_vec(), 8).await.unwrap();
            writer.sync().await.unwrap(); // Syncs any remaining (should be none from this op)

            // Blob now contains "buffered and flushed" (8 + 12 = 20 bytes)
            // Writer's inner.position = 20. Buffer is empty.

            // Read from underlying blob through writer: "buff" at offset 0
            let mut read_buf_vec_2 = vec![0u8; 4].into();
            read_buf_vec_2 = writer.read_at(read_buf_vec_2, 0).await.unwrap();
            assert_eq!(read_buf_vec_2.as_ref(), b"buff");

            // Read from underlying blob: "flushed" at offset 13
            let mut read_buf_7_vec = vec![0u8; 7].into();
            read_buf_7_vec = writer.read_at(read_buf_7_vec, 13).await.unwrap();
            assert_eq!(read_buf_7_vec.as_ref(), b"flushed");

            // 3. Buffer new data without flushing previous
            // Writer inner.position = 20. Buffer is empty.
            // Write " more data" (9 bytes) at offset 20. This fits in buffer.
            writer.write_at(b" more data".to_vec(), 20).await.unwrap();

            // Read the newly buffered data: "more"
            let mut read_buf_vec_3 = vec![0u8; 5].into();
            read_buf_vec_3 = writer.read_at(read_buf_vec_3, 20).await.unwrap();
            assert_eq!(read_buf_vec_3.as_ref(), b" more");

            // Read part from blob, part from buffer (not directly supported by current read_at logic, it seems)
            // `read_at` logic:
            // If data_end <= buffer_start: read from blob. (buffer_start is inner.position where buffer *would* start if written)
            // If offset >= buffer_start: read from buffer (if it contains the data)
            // Combination case: read blob part, then buffer part.

            // Current state:
            // Blob: "buffered and flushed" (0-19)
            // Buffer: " more data" (starts at blob offset 20, covers 20-29)
            // writer.inner.position = 20 (start of buffered data " more data")
            // writer.inner.buffer = " more data"

            // Try to read "flushed more " (12 bytes: ("shed " - 5) from blob, ("more da" - 7) from buffer) starting at offset 16
            // offset = 16, data_len = 12. data_end = 28.
            // buffer_start (inner.position) = 20. buffer_end = 20 + 9 = 29.
            // data_end (28) > buffer_start (20) is true.
            // offset (16) < buffer_start (20) is true. -> This is the combined case.
            let mut combo_read_buf_vec = vec![0u8; 12].into();
            combo_read_buf_vec = writer.read_at(combo_read_buf_vec, 16).await.unwrap();
            assert_eq!(combo_read_buf_vec.as_ref(), b"shed more da");

            // Verify full content by reopening and reading
            writer.sync().await.unwrap(); // Flush "more data"
            let (final_blob, final_size) =
                context.open("partition", b"read_at_writer").await.unwrap();
            assert_eq!(final_size, 30); // "buffered and flushed more data"
            let mut final_reader = Read::new(final_blob, final_size, 30);
            let mut full_content = vec![0u8; 30];
            final_reader
                .read_exact(&mut full_content, 30)
                .await
                .unwrap();
            assert_eq!(&full_content, b"buffered and flushed more data");
        });
    }

    #[test_traced]
    fn test_write_straddling_non_mergeable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test write operations that are non-contiguous with the current buffer, forcing flushes.
            let (blob, _) = context.open("partition", b"write_straddle").await.unwrap();
            let writer = Write::new(blob.clone(), 0, 10); // buffer capacity 10

            // Buffer "0123456789" (10 bytes)
            writer.write_at(b"0123456789".to_vec(), 0).await.unwrap();
            // At this point, inner.buffer = "0123456789", inner.position = 0

            // Write "abc" at offset 15.
            // This is scenario 3: write is after buffer, non-contiguous.
            // Current buffer "0123456789" is flushed. blob gets "0123456789". inner.position becomes 10.
            // Then "abc" is written directly to blob at offset 15. inner.position becomes 15 + 3 = 18.
            writer.write_at(b"abc".to_vec(), 15).await.unwrap();
            writer.sync().await.unwrap(); // syncs blob state

            let (blob_check, size_check) =
                context.open("partition", b"write_straddle").await.unwrap();
            // Expected: "0123456789" at 0-9, then "abc" at 15-17. Size should be 18.
            // The space between 9 and 15 will be undefined or zeros depending on blob impl.
            // For memory blob, it extends and fills with zeros.
            assert_eq!(size_check, 18);
            let mut reader = Read::new(blob_check, size_check, 20);
            let mut buf = vec![0u8; 18];
            reader.read_exact(&mut buf, 18).await.unwrap();

            let mut expected = vec![0u8; 18];
            expected[0..10].copy_from_slice(b"0123456789");
            // Bytes 10-14 are zeros for memory blob
            expected[15..18].copy_from_slice(b"abc");
            assert_eq!(buf, expected);

            // Reset for a new scenario: Write that overwrites end of buffer and extends
            let (blob2, _) = context.open("partition", b"write_straddle2").await.unwrap();
            let writer2 = Write::new(blob2.clone(), 0, 10);
            writer2.write_at(b"0123456789".to_vec(), 0).await.unwrap(); // Buffer full: "0123456789", position 0

            // Write "ABCDEFGHIJKL" (12 bytes) at offset 5.
            // write_start = 5. data_len = 12.
            // buffer_start = 0. buffer_end = 10.
            // Scenario 1: no (5 != 10)
            // Scenario 2: can_write_into_buffer?
            //   write_start (5) >= buffer_start (0) -> true
            //   (write_start - buffer_start) (5) + data_len (12) = 17 <= capacity (10) -> false
            // So, Scenario 3.
            // Flush "0123456789". blob gets it. writer2.inner.position becomes 10.
            // blob.write_at("ABCDEFGHIJKL", 5).
            // Underlying blob becomes "01234ABCDEFGHIJKL" (len 17).
            // writer2.inner.position becomes 5 + 12 = 17.
            writer2.write_at(b"ABCDEFGHIJKL".to_vec(), 5).await.unwrap();
            writer2.sync().await.unwrap();

            let (blob_check2, size_check2) =
                context.open("partition", b"write_straddle2").await.unwrap();
            assert_eq!(size_check2, 17);
            let mut reader2 = Read::new(blob_check2, size_check2, 20);
            let mut buf2 = vec![0u8; 17];
            reader2.read_exact(&mut buf2, 17).await.unwrap();
            assert_eq!(&buf2, b"01234ABCDEFGHIJKL");
        });
    }

    #[test_traced]
    fn test_write_close() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test that closing the writer flushes any pending data in the buffer.
            let (blob_orig, _) = context.open("partition", b"write_close").await.unwrap();
            let writer = Write::new(blob_orig.clone(), 0, 8);
            writer.write_at(b"pending".to_vec(), 0).await.unwrap(); // 7 bytes, buffered
                                                                    // Data "pending" is in the writer's buffer, not yet on disk.

            // Closing the writer should flush and sync the data.
            writer.close().await.unwrap();

            // Reopen and verify
            let (blob_check, size_check) = context.open("partition", b"write_close").await.unwrap();
            assert_eq!(size_check, 7);
            let mut reader = Read::new(blob_check, size_check, 8);
            let mut buf = [0u8; 7];
            reader.read_exact(&mut buf, 7).await.unwrap();
            assert_eq!(&buf, b"pending");
        });
    }

    #[test_traced]
    fn test_write_direct_due_to_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, _) = context
                .open("partition", b"write_direct_size")
                .await
                .unwrap();
            // Buffer capacity 5, initial position 0
            let writer = Write::new(blob.clone(), 0, 5);

            // Write 10 bytes, which is > capacity. Should be a direct write.
            let data_large = b"0123456789";
            writer.write_at(data_large.to_vec(), 0).await.unwrap();
            // Inner state: buffer should be empty, position should be 10.
            // We can't directly check inner state here, so we rely on observable behavior.

            // Sync to ensure data is on disk
            writer.sync().await.unwrap();

            let (blob_check, size_check) = context
                .open("partition", b"write_direct_size")
                .await
                .unwrap();
            assert_eq!(size_check, 10);
            let mut reader = Read::new(blob_check, size_check, 10);
            let mut buf = vec![0u8; 10];
            reader.read_exact(&mut buf, 10).await.unwrap();
            assert_eq!(&buf, data_large.as_slice());

            // Now, buffer something small
            writer.write_at(b"abc".to_vec(), 10).await.unwrap(); // This should be buffered
                                                                 // Attempt to read it back using writer.read_at to see if it's in buffer
            let mut read_small_buf_vec = vec![0u8; 3].into();
            read_small_buf_vec = writer.read_at(read_small_buf_vec, 10).await.unwrap();
            assert_eq!(read_small_buf_vec.as_ref(), b"abc");

            writer.sync().await.unwrap();
            let (blob_check2, size_check2) = context
                .open("partition", b"write_direct_size")
                .await
                .unwrap();
            assert_eq!(size_check2, 13);
            let mut reader2 = Read::new(blob_check2, size_check2, 13);
            let mut buf2 = vec![0u8; 13];
            reader2.read_exact(&mut buf2, 13).await.unwrap();
            assert_eq!(&buf2[10..], b"abc".as_slice());
        });
    }

    #[test_traced]
    fn test_write_overwrite_and_extend_in_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, _) = context
                .open("partition", b"overwrite_extend_buf")
                .await
                .unwrap();
            let writer = Write::new(blob.clone(), 0, 15); // buffer capacity 15

            // 1. Buffer initial data: "0123456789" (10 bytes) at offset 0
            writer.write_at(b"0123456789".to_vec(), 0).await.unwrap();
            // Inner buffer: "0123456789", position 0

            // 2. Overwrite and extend: write "ABCDEFGHIJ" (10 bytes) at offset 5
            // This should result in "01234ABCDEFGHIJ" (15 bytes) in the buffer.
            // write_start = 5, data_len = 10.
            // buffer_start = 0, buffer_end = 0 + 10 = 10 (current buffer data length)
            // Scenario 2: can_write_into_buffer
            //   write_start (5) >= buffer_start (0) -> true
            //   (write_start - buffer_start) (5) + data_len (10) = 15 <= capacity (15) -> true
            // Buffer internal offset = 5.
            // Required buffer len = 5 + 10 = 15.
            // Current buffer len is 10. Resize to 15.
            // buffer[5..15] gets "ABCDEFGHIJ"
            writer.write_at(b"ABCDEFGHIJ".to_vec(), 5).await.unwrap();

            // Check buffer content via read_at on writer
            let mut read_buf_vec = vec![0u8; 15].into();
            read_buf_vec = writer.read_at(read_buf_vec, 0).await.unwrap();
            assert_eq!(read_buf_vec.as_ref(), b"01234ABCDEFGHIJ");

            writer.sync().await.unwrap();

            let (blob_check, size_check) = context
                .open("partition", b"overwrite_extend_buf")
                .await
                .unwrap();
            assert_eq!(size_check, 15);
            let mut reader = Read::new(blob_check, size_check, 15);
            let mut final_buf = vec![0u8; 15];
            reader.read_exact(&mut final_buf, 15).await.unwrap();
            assert_eq!(&final_buf, b"01234ABCDEFGHIJ".as_slice());
        });
    }
}
