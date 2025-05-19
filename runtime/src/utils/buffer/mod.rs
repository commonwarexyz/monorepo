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
    #[should_panic(expected = "Buffer size must be greater than zero")]
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

            // Refill the buffer at the new position
            reader.refill().await.unwrap();

            // Read data - should get data from position 500
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"AAAAA"); // Should still be 'A's
            assert_eq!(reader.position(), 505);

            // Seek backwards
            reader.seek_to(100).unwrap();
            reader.refill().await.unwrap();

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
            let (blob, size) = context.open("partition", b"write_basic").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::new(blob.clone(), 0, 8);
            writer.write("hello".as_bytes()).await.unwrap();
            assert_eq!(writer.position().await, 5);
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
            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 0);

            let mut writer = Write::new(blob.clone(), 0, 4);
            writer.write("abc".as_bytes()).await.unwrap();
            writer.write("defg".as_bytes()).await.unwrap();
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
            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 0);

            let mut writer = Write::new(blob.clone(), 0, 4);
            writer.write("abc".as_bytes()).await.unwrap();
            writer
                .write("defghijklmnopqrstuvwxyz".as_bytes())
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
    #[should_panic(expected = "Buffer capacity must be greater than zero")]
    fn test_write_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, size) = context.open("partition", b"write_empty").await.unwrap();
            assert_eq!(size, 0);
            Write::new(blob, 0, 0);
        });
    }
}
