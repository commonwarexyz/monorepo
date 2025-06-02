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
            // Test basic buffered reading functionality with sequential reads
            let data = b"Hello, world! This is a test.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffered reader with small buffer to test refilling
            let buffer_size = 10;
            let mut reader = Read::new(blob, size, buffer_size);

            // Read some data
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"Hello");

            // Read more data that requires a buffer refill
            let mut buf = [0u8; 14];
            reader.read_exact(&mut buf, 14).await.unwrap();
            assert_eq!(&buf, b", world! This ");

            // Verify position tracking
            assert_eq!(reader.position(), 19);

            // Read the remaining data
            let mut buf = [0u8; 10];
            reader.read_exact(&mut buf, 7).await.unwrap();
            assert_eq!(&buf[..7], b"is a te");

            // Attempt to read beyond the end should fail
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
            // Test that creating a reader with zero buffer size panics
            let data = b"Hello, world! This is a test.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // This should panic
            let buffer_size = 0;
            Read::new(blob, size, buffer_size);
        });
    }

    #[test_traced]
    fn test_read_cross_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test reading data that spans multiple buffer refills
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Use a buffer smaller than the total data size
            let buffer_size = 10;
            let mut reader = Read::new(blob, size, buffer_size);

            // Read data that crosses buffer boundaries
            let mut buf = [0u8; 15];
            reader.read_exact(&mut buf, 15).await.unwrap();
            assert_eq!(&buf, b"ABCDEFGHIJKLMNO");

            // Verify position tracking
            assert_eq!(reader.position(), 15);

            // Read the remaining data
            let mut buf = [0u8; 11];
            reader.read_exact(&mut buf, 11).await.unwrap();
            assert_eq!(&buf, b"PQRSTUVWXYZ");

            // Verify we're at the end
            assert_eq!(reader.position(), 26);
            assert_eq!(reader.blob_remaining(), 0);
        });
    }

    #[test_traced]
    fn test_read_with_known_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test reader behavior with known blob size limits
            let data = b"This is a test with known size limitations.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffered reader with buffer smaller than total data
            let buffer_size = 10;
            let mut reader = Read::new(blob, size, buffer_size);

            // Check initial remaining bytes
            assert_eq!(reader.blob_remaining(), size);

            // Read partial data
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"This ");

            // Check remaining bytes after partial read
            assert_eq!(reader.blob_remaining(), size - 5);

            // Read exactly up to the size limit
            let mut buf = vec![0u8; (size - 5) as usize];
            reader
                .read_exact(&mut buf, (size - 5) as usize)
                .await
                .unwrap();
            assert_eq!(&buf, b"is a test with known size limitations.");

            // Verify we're at the end
            assert_eq!(reader.blob_remaining(), 0);

            // Reading beyond the end should fail
            let mut buf = [0u8; 1];
            let result = reader.read_exact(&mut buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_read_large_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test reading large amounts of data in chunks
            let data_size = 1024 * 256; // 256KB of data
            let data = vec![0x42; data_size];
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.clone(), 0).await.unwrap();
            let size = data.len() as u64;

            // Use a buffer much smaller than the total data
            let buffer_size = 64 * 1024; // 64KB buffer
            let mut reader = Read::new(blob, size, buffer_size);

            // Read all data in smaller chunks
            let mut total_read = 0;
            let chunk_size = 8 * 1024; // 8KB chunks
            let mut buf = vec![0u8; chunk_size];

            while total_read < data_size {
                let to_read = std::cmp::min(chunk_size, data_size - total_read);
                reader
                    .read_exact(&mut buf[..to_read], to_read)
                    .await
                    .unwrap();

                // Verify data integrity
                assert!(
                    buf[..to_read].iter().all(|&b| b == 0x42),
                    "Data at position {} is not correct",
                    total_read
                );

                total_read += to_read;
            }

            // Verify we read everything
            assert_eq!(total_read, data_size);

            // Reading beyond the end should fail
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
            // Test basic buffered write and sync functionality
            let (blob, size) = context.open("partition", b"write_basic").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::new(blob.clone(), size, 8);
            writer.write_at("hello".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 5);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 5);

            // Verify data was written correctly
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
            // Test writes that cause buffer flushes due to capacity limits
            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::new(blob.clone(), size, 4);
            writer.write_at("abc".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 3);
            writer.write_at("defg".as_bytes(), 3).await.unwrap();
            assert_eq!(writer.size().await, 7);
            writer.sync().await.unwrap();

            // Verify the final result
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
            // Test writing data larger than buffer capacity (direct write)
            let (blob, size) = context.open("partition", b"write_large").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::new(blob.clone(), size, 4);
            writer.write_at("abc".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 3);
            writer
                .write_at(b"defghijklmnopqrstuvwxyz".to_vec(), 3)
                .await
                .unwrap();
            assert_eq!(writer.size().await, 26);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 26);

            // Verify the complete data
            let (blob, size) = context.open("partition", b"write_large").await.unwrap();
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
            // Test that creating a writer with zero buffer capacity panics
            let (blob, size) = context.open("partition", b"write_empty").await.unwrap();
            assert_eq!(size, 0);
            Write::new(blob, size, 0);
        });
    }

    #[test_traced]
    fn test_write_append_to_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test sequential appends that exceed buffer capacity
            let (blob, size) = context.open("partition", b"append_buf").await.unwrap();
            let writer = Write::new(blob.clone(), size, 10);

            // Write data that fits in buffer
            writer.write_at("hello".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 5);

            // Append data that causes buffer flush
            writer.write_at(" world".as_bytes(), 5).await.unwrap();
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 11);

            // Verify the complete result
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
            // Test overwriting data within the buffer and extending it
            let (blob, size) = context.open("partition", b"middle_buf").await.unwrap();
            let writer = Write::new(blob.clone(), size, 20);

            // Initial write
            writer.write_at("abcdefghij".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Overwrite middle section
            writer.write_at("01234".as_bytes(), 2).await.unwrap();
            assert_eq!(writer.size().await, 10);
            writer.sync().await.unwrap();

            // Verify overwrite result
            let (blob, size) = context.open("partition", b"middle_buf").await.unwrap();
            assert_eq!(size, 10);
            let mut reader = Read::new(blob, size, 10);
            let mut buf = vec![0u8; 10];
            reader.read_exact(&mut buf, 10).await.unwrap();
            assert_eq!(&buf, b"ab01234hij");

            // Extend buffer and do partial overwrite
            writer.write_at("klmnopqrst".as_bytes(), 10).await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.write_at("wxyz".as_bytes(), 9).await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();

            // Verify final result
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
            // Test writing at offsets before the current buffer position
            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            let writer = Write::new(blob.clone(), size, 10);

            // Write data at a later offset first
            writer.write_at("0123456789".as_bytes(), 10).await.unwrap();
            assert_eq!(writer.size().await, 20);

            // Write at an earlier offset (should flush buffer first)
            writer.write_at("abcde".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();

            // Verify data placement with gap
            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            assert_eq!(size, 20);
            let mut reader = Read::new(blob, size, 20);
            let mut buf = vec![0u8; 20];
            reader.read_exact(&mut buf, 20).await.unwrap();
            let mut expected = vec![0u8; 20];
            expected[0..5].copy_from_slice("abcde".as_bytes());
            expected[10..20].copy_from_slice("0123456789".as_bytes());
            assert_eq!(buf, expected);

            // Fill the gap between existing data
            writer.write_at("fghij".as_bytes(), 5).await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 20);

            // Verify gap is filled
            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            assert_eq!(size, 20);
            let mut reader = Read::new(blob, size, 20);
            let mut buf = vec![0u8; 20];
            reader.read_exact(&mut buf, 20).await.unwrap();
            expected[0..10].copy_from_slice("abcdefghij".as_bytes());
            assert_eq!(buf, expected);
        });
    }

    #[test_traced]
    fn test_write_truncate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test blob truncation functionality and subsequent writes
            let (blob, size) = context.open("partition", b"truncate_write").await.unwrap();
            let writer = Write::new(blob, size, 10);

            // Write initial data
            writer.write_at("hello world".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 11);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 11);

            let (blob_check, size_check) =
                context.open("partition", b"truncate_write").await.unwrap();
            assert_eq!(size_check, 11);
            drop(blob_check);

            // Truncate to smaller size
            writer.truncate(5).await.unwrap();
            assert_eq!(writer.size().await, 5);
            writer.sync().await.unwrap();

            // Verify truncation
            let (blob, size) = context.open("partition", b"truncate_write").await.unwrap();
            assert_eq!(size, 5);
            let mut reader = Read::new(blob, size, 5);
            let mut buf = vec![0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"hello");

            // Write to truncated blob
            writer.write_at("X".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 5);
            writer.sync().await.unwrap();

            // Verify overwrite
            let (blob, size) = context.open("partition", b"truncate_write").await.unwrap();
            assert_eq!(size, 5);
            let mut reader = Read::new(blob, size, 5);
            let mut buf = vec![0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"Xello");

            // Test truncate to zero
            let (blob_zero, size) = context.open("partition", b"truncate_zero").await.unwrap();
            let writer_zero = Write::new(blob_zero.clone(), size, 10);
            writer_zero
                .write_at(b"some data".to_vec(), 0)
                .await
                .unwrap();
            assert_eq!(writer_zero.size().await, 9);
            writer_zero.sync().await.unwrap();
            assert_eq!(writer_zero.size().await, 9);
            writer_zero.truncate(0).await.unwrap();
            assert_eq!(writer_zero.size().await, 0);
            writer_zero.sync().await.unwrap();
            assert_eq!(writer_zero.size().await, 0);

            // Ensure the blob is empty
            let (_, size_z) = context.open("partition", b"truncate_zero").await.unwrap();
            assert_eq!(size_z, 0);
        });
    }

    #[test_traced]
    fn test_write_read_at_on_writer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test reading through writer's read_at method (buffer + blob reads)
            let (blob, size) = context.open("partition", b"read_at_writer").await.unwrap();
            let writer = Write::new(blob.clone(), size, 10);

            // Write data that stays in buffer
            writer.write_at("buffered".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 8);

            // Read from buffer via writer
            let mut read_buf_vec = vec![0u8; 4];
            read_buf_vec = writer.read_at(read_buf_vec, 0).await.unwrap();
            assert_eq!(read_buf_vec.as_ref(), b"buff");

            read_buf_vec = writer.read_at(read_buf_vec, 4).await.unwrap();
            assert_eq!(read_buf_vec.as_ref(), b"ered");

            // Reading past buffer end should fail
            let small_buf_vec = vec![0u8; 1];
            assert!(writer.read_at(small_buf_vec, 8).await.is_err());

            // Write large data that flushes buffer
            writer.write_at(" and flushed".as_bytes(), 8).await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 20);

            // Read from underlying blob through writer
            let mut read_buf_vec_2 = vec![0u8; 4];
            read_buf_vec_2 = writer.read_at(read_buf_vec_2, 0).await.unwrap();
            assert_eq!(read_buf_vec_2.as_ref(), b"buff");

            let mut read_buf_7_vec = vec![0u8; 7];
            read_buf_7_vec = writer.read_at(read_buf_7_vec, 13).await.unwrap();
            assert_eq!(read_buf_7_vec.as_ref(), b"flushed");

            // Buffer new data at the end
            writer.write_at(" more data".as_bytes(), 20).await.unwrap();
            assert_eq!(writer.size().await, 30);

            // Read newly buffered data
            let mut read_buf_vec_3 = vec![0u8; 5];
            read_buf_vec_3 = writer.read_at(read_buf_vec_3, 20).await.unwrap();
            assert_eq!(read_buf_vec_3.as_ref(), b" more");

            // Read spanning both blob and buffer
            let mut combo_read_buf_vec = vec![0u8; 12];
            combo_read_buf_vec = writer.read_at(combo_read_buf_vec, 16).await.unwrap();
            assert_eq!(combo_read_buf_vec.as_ref(), b"shed more da");

            // Verify complete content by reopening
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 30);
            let (final_blob, final_size) =
                context.open("partition", b"read_at_writer").await.unwrap();
            assert_eq!(final_size, 30);
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
            // Test writes that cannot be merged into buffer (non-contiguous/too large)
            let (blob, size) = context.open("partition", b"write_straddle").await.unwrap();
            let writer = Write::new(blob.clone(), size, 10);

            // Fill buffer completely
            writer.write_at("0123456789".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Write at non-contiguous offset (should flush then write directly)
            writer.write_at("abc".as_bytes(), 15).await.unwrap();
            assert_eq!(writer.size().await, 18);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 18);

            // Verify data with gap
            let (blob_check, size_check) =
                context.open("partition", b"write_straddle").await.unwrap();
            assert_eq!(size_check, 18);
            let mut reader = Read::new(blob_check, size_check, 20);
            let mut buf = vec![0u8; 18];
            reader.read_exact(&mut buf, 18).await.unwrap();

            let mut expected = vec![0u8; 18];
            expected[0..10].copy_from_slice(b"0123456789");
            expected[15..18].copy_from_slice(b"abc");
            assert_eq!(buf, expected);

            // Test write that exceeds buffer capacity
            let (blob2, size) = context.open("partition", b"write_straddle2").await.unwrap();
            let writer2 = Write::new(blob2.clone(), size, 10);
            writer2.write_at("0123456789".as_bytes(), 0).await.unwrap();
            assert_eq!(writer2.size().await, 10);

            // Write large data that exceeds capacity
            writer2
                .write_at("ABCDEFGHIJKL".as_bytes(), 5)
                .await
                .unwrap();
            assert_eq!(writer2.size().await, 17);
            writer2.sync().await.unwrap();
            assert_eq!(writer2.size().await, 17);

            // Verify overwrite result
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
            // Test that closing writer flushes and persists buffered data
            let (blob_orig, size) = context.open("partition", b"write_close").await.unwrap();
            let writer = Write::new(blob_orig.clone(), size, 8);
            writer.write_at("pending".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 7);

            // Close should flush and sync data
            writer.close().await.unwrap();

            // Verify data persistence
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
            // Test direct writes when data exceeds buffer capacity
            let (blob, size) = context
                .open("partition", b"write_direct_size")
                .await
                .unwrap();
            let writer = Write::new(blob.clone(), size, 5);

            // Write data larger than buffer capacity (should write directly)
            let data_large = b"0123456789";
            writer.write_at(data_large.as_slice(), 0).await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Sync to ensure data is persisted
            writer.sync().await.unwrap();

            // Verify direct write worked
            let (blob_check, size_check) = context
                .open("partition", b"write_direct_size")
                .await
                .unwrap();
            assert_eq!(size_check, 10);
            let mut reader = Read::new(blob_check, size_check, 10);
            let mut buf = vec![0u8; 10];
            reader.read_exact(&mut buf, 10).await.unwrap();
            assert_eq!(&buf, data_large.as_slice());

            // Now write small data that should be buffered
            writer.write_at(b"abc".as_slice(), 10).await.unwrap();
            assert_eq!(writer.size().await, 13);

            // Verify it's in buffer by reading through writer
            let mut read_small_buf_vec = vec![0u8; 3];
            read_small_buf_vec = writer.read_at(read_small_buf_vec, 10).await.unwrap();
            assert_eq!(read_small_buf_vec.as_ref(), b"abc");

            writer.sync().await.unwrap();

            // Verify final state
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
            // Test complex buffer operations: overwrite and extend within capacity
            let (blob, size) = context
                .open("partition", b"overwrite_extend_buf")
                .await
                .unwrap();
            let writer = Write::new(blob.clone(), size, 15);

            // Write initial data
            writer.write_at("0123456789".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Overwrite and extend within buffer capacity
            writer.write_at("ABCDEFGHIJ".as_bytes(), 5).await.unwrap();
            assert_eq!(writer.size().await, 15);

            // Verify buffer content through writer
            let mut read_buf_vec = vec![0u8; 15];
            read_buf_vec = writer.read_at(read_buf_vec, 0).await.unwrap();
            assert_eq!(read_buf_vec.as_ref(), b"01234ABCDEFGHIJ");

            writer.sync().await.unwrap();

            // Verify persisted result
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

    #[test_traced]
    fn test_write_at_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing at the current logical end of the blob
            let (blob, size) = context.open("partition", b"write_end").await.unwrap();
            let writer = Write::new(blob.clone(), size, 20);

            // Write initial data
            writer.write_at("0123456789".as_bytes(), 0).await.unwrap();
            assert_eq!(writer.size().await, 10);
            writer.sync().await.unwrap();

            // Append at the current size (logical end)
            writer
                .write_at("abc".as_bytes(), writer.size().await)
                .await
                .unwrap();
            assert_eq!(writer.size().await, 13);
            writer.sync().await.unwrap();

            // Verify complete result
            let (blob_check, size_check) = context.open("partition", b"write_end").await.unwrap();
            assert_eq!(size_check, 13);
            let mut reader = Read::new(blob_check, size_check, 13);
            let mut buf = vec![0u8; 13];
            reader.read_exact(&mut buf, 13).await.unwrap();
            assert_eq!(&buf, b"0123456789abc");
        });
    }
}
