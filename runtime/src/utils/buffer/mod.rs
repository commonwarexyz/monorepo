//! Buffers for reading and writing to [crate::Blob]s.

pub mod paged;
mod read;
mod tip;
mod write;

pub use read::Read;
pub use write::Write;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deterministic, reschedule, Blob as _, BufMut, Error, IoBufMut, IoBufs, IoBufsMut, Runner,
        Spawner, Storage,
    };
    use commonware_macros::test_traced;
    use commonware_utils::{channel::oneshot, sync::Mutex, NZUsize};
    use futures::{pin_mut, FutureExt};
    use std::sync::Arc;

    struct BlockingReadGate {
        read_started: Option<oneshot::Sender<()>>,
        release_read: Option<oneshot::Receiver<()>>,
    }

    /// Test-only blob wrapper that blocks exactly one read call until explicitly released.
    ///
    /// Used to assert lock ordering / contention behavior in writer read-path tests.
    #[derive(Clone)]
    struct BlockingReadBlob {
        data: Arc<Vec<u8>>,
        gate: Arc<Mutex<BlockingReadGate>>,
    }

    impl BlockingReadBlob {
        fn new(data: Vec<u8>) -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
            let (read_started_tx, read_started_rx) = oneshot::channel();
            let (release_read_tx, release_read_rx) = oneshot::channel();
            (
                Self {
                    data: Arc::new(data),
                    gate: Arc::new(Mutex::new(BlockingReadGate {
                        read_started: Some(read_started_tx),
                        release_read: Some(release_read_rx),
                    })),
                },
                read_started_rx,
                release_read_tx,
            )
        }

        async fn block_once_on_read(&self) {
            let rx = {
                let mut gate = self.gate.lock();
                if let Some(tx) = gate.read_started.take() {
                    let _ = tx.send(());
                }
                gate.release_read.take()
            };
            if let Some(rx) = rx {
                let _ = rx.await;
            }
        }
    }

    impl crate::Blob for BlockingReadBlob {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            buf: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            self.block_once_on_read().await;

            let start = usize::try_from(offset).map_err(|_| Error::OffsetOverflow)?;
            let end = start.checked_add(len).ok_or(Error::OffsetOverflow)?;
            if end > self.data.len() {
                return Err(Error::BlobInsufficientLength);
            }

            let mut out = buf.into();
            out.copy_from_slice(&self.data[start..end]);
            Ok(out)
        }

        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.block_once_on_read().await;

            let start = usize::try_from(offset).map_err(|_| Error::OffsetOverflow)?;
            let end = start.checked_add(len).ok_or(Error::OffsetOverflow)?;
            if end > self.data.len() {
                return Err(Error::BlobInsufficientLength);
            }

            let mut out = IoBufMut::default();
            out.put_slice(&self.data[start..end]);
            Ok(out.into())
        }

        async fn write_at(
            &self,
            _offset: u64,
            _buf: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test_traced]
    fn test_read_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test basic buffered reading functionality with sequential reads
            let data = b"Hello, world! This is a test.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, data).await.unwrap();
            let size = data.len() as u64;

            // Create a buffered reader with small buffer to test refilling
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));

            // Read some data
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"Hello");

            // Read more data that requires a buffer refill
            let read = reader.read(14).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b", world! This ");

            // Verify position tracking
            assert_eq!(reader.position(), 19);

            // Read the remaining data
            let read = reader.read(7).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"is a te");

            // Attempt to read beyond the end should fail
            let result = reader.read(5).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
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
            blob.write_at(0, data).await.unwrap();
            let size = data.len() as u64;

            // Use a buffer smaller than the total data size
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));

            // Read data that crosses buffer boundaries
            let read = reader.read(15).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ABCDEFGHIJKLMNO");

            // Verify position tracking
            assert_eq!(reader.position(), 15);

            // Read the remaining data
            let read = reader.read(11).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"PQRSTUVWXYZ");

            // Verify we're at the end
            assert_eq!(reader.position(), 26);
            assert_eq!(reader.blob_remaining(), 0);
        });
    }

    // Regression test for https://github.com/commonwarexyz/monorepo/issues/1348
    #[test_traced]
    fn test_read_to_end_then_rewind_and_read_again() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, data).await.unwrap();
            let size = data.len() as u64;

            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(20));

            // Read data that crosses buffer boundaries
            let read = reader.read(21).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ABCDEFGHIJKLMNOPQRSTU");

            // Verify position tracking
            assert_eq!(reader.position(), 21);

            // Read the remaining data
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"VWXYZ");

            // Rewind and read again
            reader.seek_to(0).unwrap();
            let read = reader.read(21).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ABCDEFGHIJKLMNOPQRSTU");
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
            blob.write_at(0, data).await.unwrap();
            let size = data.len() as u64;

            // Create a buffered reader with buffer smaller than total data
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));

            // Check initial remaining bytes
            assert_eq!(reader.blob_remaining(), size);

            // Read partial data
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"This ");

            // Check remaining bytes after partial read
            assert_eq!(reader.blob_remaining(), size - 5);

            // Read exactly up to the size limit
            let read = reader.read((size - 5) as usize).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"is a test with known size limitations.");

            // Verify we're at the end
            assert_eq!(reader.blob_remaining(), 0);

            // Reading beyond the end should fail
            let result = reader.read(1).await;
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
            blob.write_at(0, data.clone()).await.unwrap();
            let size = data.len() as u64;

            // Use a buffer much smaller than the total data
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(64 * 1024));

            // Read all data in smaller chunks
            let mut total_read = 0;
            let chunk_size = 8 * 1024; // 8KB chunks

            while total_read < data_size {
                let to_read = std::cmp::min(chunk_size, data_size - total_read);
                let read = reader.read(to_read).await.unwrap().coalesce();

                // Verify data integrity
                assert!(
                    read.as_ref().iter().all(|&b| b == 0x42),
                    "Data at position {total_read} is not correct"
                );

                total_read += to_read;
            }

            // Verify we read everything
            assert_eq!(total_read, data_size);

            // Reading beyond the end should fail
            let result = reader.read(1).await;
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
            blob.write_at(0, data.clone()).await.unwrap();
            let size = data.len() as u64;

            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(buffer_size));

            // Read exactly one buffer size
            let read = reader.read(buffer_size).await.unwrap().coalesce();
            assert!(read.as_ref().iter().all(|&b| b == 0x37));

            // Read exactly one buffer size more
            let read = reader.read(buffer_size).await.unwrap().coalesce();
            assert!(read.as_ref().iter().all(|&b| b == 0x37));

            // Read the remaining half buffer
            let half_buffer = buffer_size / 2;
            let read = reader.read(half_buffer).await.unwrap().coalesce();
            assert!(read.as_ref().iter().all(|&b| b == 0x37));

            // Verify we're at the end
            assert_eq!(reader.blob_remaining(), 0);
            assert_eq!(reader.position(), size);
        });
    }

    #[test_traced]
    fn test_read_exact_structure_single_vs_chunked() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let data = b"ABCDEFGHIJKL";
            let (blob, size) = context.open("partition", b"structural").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, data).await.unwrap();

            let mut reader = Read::from_pooler(&context, blob, data.len() as u64, NZUsize!(5));

            // First read fits in one fetched chunk.
            let first = reader.read(3).await.unwrap();
            assert_eq!(first.coalesce().as_ref(), b"ABC");

            // This read spans refill boundaries and is returned as one contiguous buffer.
            let second = reader.read(7).await.unwrap();
            assert_eq!(second.coalesce().as_ref(), b"DEFGHIJ");
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
            blob.write_at(0, data).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));

            // Read some data to advance the position
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ABCDE");
            assert_eq!(reader.position(), 5);

            // Seek to a specific position
            reader.seek_to(10).unwrap();
            assert_eq!(reader.position(), 10);

            // Read data from the new position
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"KLMNO");

            // Seek to beginning
            reader.seek_to(0).unwrap();
            assert_eq!(reader.position(), 0);

            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ABCDE");

            // Seek to end
            reader.seek_to(size).unwrap();
            assert_eq!(reader.position(), size);

            // Trying to read should fail
            let result = reader.read(1).await;
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
            blob.write_at(0, data.clone()).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with small buffer
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));

            // Read some data
            let _ = reader.read(5).await.unwrap().coalesce();

            // Seek far ahead, past the current buffer
            reader.seek_to(500).unwrap();

            // Read data - should get data from position 500
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"AAAAA"); // Should still be 'A's);
            assert_eq!(reader.position(), 505);

            // Seek backwards
            reader.seek_to(100).unwrap();

            // Read again - should be at position 100
            let _ = reader.read(5).await.unwrap().coalesce();
            assert_eq!(reader.position(), 105);
        });
    }

    #[test_traced]
    fn test_read_seek_within_buffered_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, data).await.unwrap();

            let mut reader = Read::from_pooler(&context, blob, data.len() as u64, NZUsize!(10));

            // Reads 0..=5, while the internal fetch cursor advances to 10.
            let read = reader.read(6).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ABCDEF");
            assert_eq!(reader.position(), 6);

            // Seek back within [buffer_start, fetch_position).
            reader.seek_to(3).unwrap();
            assert_eq!(reader.position(), 3);

            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"DEFGH");
            assert_eq!(reader.position(), 8);
        });
    }

    #[test_traced]
    fn test_read_seek_within_unread_buffer_does_not_refill() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context
                .open("partition", b"seek_unread_no_refill")
                .await
                .unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, data).await.unwrap();

            let mut reader = Read::from_pooler(&context, blob, data.len() as u64, NZUsize!(10));

            // First read triggers a single refill of 10 bytes.
            let first = reader.read(6).await.unwrap();
            assert_eq!(first.coalesce().as_ref(), b"ABCDEF");
            assert_eq!(reader.position(), 6);
            assert_eq!(reader.buffer_remaining(), 4);

            // Seek within the unread buffered window [6, 10).
            reader.seek_to(7).unwrap();
            assert_eq!(reader.position(), 7);
            assert_eq!(reader.buffer_remaining(), 3);

            // Consume only from the already buffered window.
            let second = reader.read(3).await.unwrap();
            assert_eq!(second.coalesce().as_ref(), b"HIJ");
            assert_eq!(reader.position(), 10);
            assert_eq!(reader.buffer_remaining(), 0);
        });
    }

    #[test_traced]
    fn test_read_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, data).await.unwrap();
            let data_len = data.len() as u64;

            // Create a buffer reader
            let reader = Read::from_pooler(&context, blob.clone(), data_len, NZUsize!(10));

            // Resize the blob to half its size
            let resize_len = data_len / 2;
            reader.resize(resize_len).await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, resize_len, "Blob should be resized to half size");

            // Create a new buffer and read to verify truncation
            let mut new_reader = Read::from_pooler(&context, blob, size, NZUsize!(10));

            // Read the content
            let read = new_reader.read(size as usize).await.unwrap().coalesce();
            assert_eq!(
                read.as_ref(),
                b"ABCDEFGHIJKLM",
                "Resized content should match"
            );

            // Reading beyond resized size should fail
            let result = new_reader.read(1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));

            // Test resize to larger size
            new_reader.resize(data_len * 2).await.unwrap();

            // Reopen to check resize
            let (blob, new_size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(new_size, data_len * 2);

            // Create a new buffer and read to verify resize
            let mut new_reader = Read::from_pooler(&context, blob, new_size, NZUsize!(10));
            let read = new_reader.read(new_size as usize).await.unwrap().coalesce();
            assert_eq!(&read.as_ref()[..size as usize], b"ABCDEFGHIJKLM");
            assert_eq!(
                &read.as_ref()[size as usize..],
                vec![0u8; new_size as usize - size as usize]
            );
        });
    }

    #[test_traced]
    fn test_read_resize_to_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let data_len = data.len() as u64;
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, data).await.unwrap();

            // Create a buffer reader
            let reader = Read::from_pooler(&context, blob.clone(), data_len, NZUsize!(10));

            // Resize the blob to zero
            reader.resize(0).await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0, "Blob should be resized to zero");

            // Create a new buffer and try to read (should fail)
            let mut new_reader = Read::from_pooler(&context, blob, size, NZUsize!(10));

            // Reading from resized blob should fail
            let result = new_reader.read(1).await;
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

            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(8));
            writer.write_at(0, b"hello").await.unwrap();
            assert_eq!(writer.size().await, 5);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 5);

            // Verify data was written correctly
            let (blob, size) = context.open("partition", b"write_basic").await.unwrap();
            assert_eq!(size, 5);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(8));
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"hello");
        });
    }

    #[test_traced]
    fn test_write_multiple_flushes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writes that cause buffer flushes due to capacity limits
            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(4));
            writer.write_at(0, b"abc").await.unwrap();
            assert_eq!(writer.size().await, 3);
            writer.write_at(3, b"defg").await.unwrap();
            assert_eq!(writer.size().await, 7);
            writer.sync().await.unwrap();

            // Verify the final result
            let (blob, size) = context.open("partition", b"write_multi").await.unwrap();
            assert_eq!(size, 7);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(4));
            let read = reader.read(7).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"abcdefg");
        });
    }

    #[test_traced]
    fn test_write_large_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing data larger than buffer capacity (direct write)
            let (blob, size) = context.open("partition", b"write_large").await.unwrap();
            assert_eq!(size, 0);

            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(4));
            writer.write_at(0, b"abc").await.unwrap();
            assert_eq!(writer.size().await, 3);
            writer
                .write_at(3, b"defghijklmnopqrstuvwxyz")
                .await
                .unwrap();
            assert_eq!(writer.size().await, 26);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 26);

            // Verify the complete data
            let (blob, size) = context.open("partition", b"write_large").await.unwrap();
            assert_eq!(size, 26);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(4));
            let read = reader.read(26).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"abcdefghijklmnopqrstuvwxyz");
        });
    }

    #[test_traced]
    fn test_write_append_to_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test sequential appends that exceed buffer capacity
            let (blob, size) = context.open("partition", b"append_buf").await.unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(10));

            // Write data that fits in buffer
            writer.write_at(0, b"hello").await.unwrap();
            assert_eq!(writer.size().await, 5);

            // Append data that causes buffer flush
            writer.write_at(5, b" world").await.unwrap();
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 11);

            // Verify the complete result
            let (blob, size) = context.open("partition", b"append_buf").await.unwrap();
            assert_eq!(size, 11);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));
            let read = reader.read(11).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"hello world");
        });
    }

    #[test_traced]
    fn test_write_into_middle_of_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test overwriting data within the buffer and extending it
            let (blob, size) = context.open("partition", b"middle_buf").await.unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(20));

            // Initial write
            writer.write_at(0, b"abcdefghij").await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Overwrite middle section
            writer.write_at(2, b"01234").await.unwrap();
            assert_eq!(writer.size().await, 10);
            writer.sync().await.unwrap();

            // Verify overwrite result
            let (blob, size) = context.open("partition", b"middle_buf").await.unwrap();
            assert_eq!(size, 10);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));
            let read = reader.read(10).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ab01234hij");

            // Extend buffer and do partial overwrite
            writer.write_at(10, b"klmnopqrst").await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.write_at(9, b"wxyz").await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();

            // Verify final result
            let (blob, size) = context.open("partition", b"middle_buf").await.unwrap();
            assert_eq!(size, 20);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(20));
            let read = reader.read(20).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"ab01234hiwxyznopqrst");
        });
    }

    #[test_traced]
    fn test_write_before_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing at offsets before the current buffer position
            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(10));

            // Write data at a later offset first
            writer.write_at(10, b"0123456789").await.unwrap();
            assert_eq!(writer.size().await, 20);

            // Write at an earlier offset (should flush buffer first)
            writer.write_at(0, b"abcde").await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();

            // Verify data placement with gap
            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            assert_eq!(size, 20);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(20));
            let read = reader.read(20).await.unwrap().coalesce();
            let mut expected = vec![0u8; 20];
            expected[0..5].copy_from_slice("abcde".as_bytes());
            expected[10..20].copy_from_slice("0123456789".as_bytes());
            assert_eq!(read.as_ref(), expected.as_slice());

            // Fill the gap between existing data
            writer.write_at(5, b"fghij").await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 20);

            // Verify gap is filled
            let (blob, size) = context.open("partition", b"before_buf").await.unwrap();
            assert_eq!(size, 20);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(20));
            let read = reader.read(20).await.unwrap().coalesce();
            expected[0..10].copy_from_slice("abcdefghij".as_bytes());
            assert_eq!(read.as_ref(), expected.as_slice());
        });
    }

    #[test_traced]
    fn test_write_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test blob resize functionality and subsequent writes
            let (blob, size) = context.open("partition", b"resize_write").await.unwrap();
            let writer = Write::from_pooler(&context, blob, size, NZUsize!(10));

            // Write initial data
            writer.write_at(0, b"hello world").await.unwrap();
            assert_eq!(writer.size().await, 11);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 11);

            let (blob_check, size_check) =
                context.open("partition", b"resize_write").await.unwrap();
            assert_eq!(size_check, 11);
            drop(blob_check);

            // Resize to smaller size
            writer.resize(5).await.unwrap();
            assert_eq!(writer.size().await, 5);
            writer.sync().await.unwrap();

            // Verify resize
            let (blob, size) = context.open("partition", b"resize_write").await.unwrap();
            assert_eq!(size, 5);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(5));
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"hello");

            // Write to resized blob
            writer.write_at(0, b"X").await.unwrap();
            assert_eq!(writer.size().await, 5);
            writer.sync().await.unwrap();

            // Verify overwrite
            let (blob, size) = context.open("partition", b"resize_write").await.unwrap();
            assert_eq!(size, 5);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(5));
            let read = reader.read(5).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"Xello");

            // Test resize to larger size
            writer.resize(10).await.unwrap();
            assert_eq!(writer.size().await, 10);
            writer.sync().await.unwrap();

            // Verify resize
            let (blob, size) = context.open("partition", b"resize_write").await.unwrap();
            assert_eq!(size, 10);
            let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(10));
            let read = reader.read(10).await.unwrap().coalesce();
            assert_eq!(&read.as_ref()[0..5], b"Xello");
            assert_eq!(&read.as_ref()[5..10], [0u8; 5]);

            // Test resize to zero
            let (blob_zero, size) = context.open("partition", b"resize_zero").await.unwrap();
            let writer_zero = Write::from_pooler(&context, blob_zero.clone(), size, NZUsize!(10));
            writer_zero.write_at(0, b"some data").await.unwrap();
            assert_eq!(writer_zero.size().await, 9);
            writer_zero.sync().await.unwrap();
            assert_eq!(writer_zero.size().await, 9);
            writer_zero.resize(0).await.unwrap();
            assert_eq!(writer_zero.size().await, 0);
            writer_zero.sync().await.unwrap();
            assert_eq!(writer_zero.size().await, 0);

            // Ensure the blob is empty
            let (_, size_z) = context.open("partition", b"resize_zero").await.unwrap();
            assert_eq!(size_z, 0);
        });
    }

    #[test_traced]
    fn test_write_read_at_on_writer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test reading through writer's read_at method (buffer + blob reads)
            let (blob, size) = context.open("partition", b"read_at_writer").await.unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(10));

            // Write data that stays in buffer
            writer.write_at(0, b"buffered").await.unwrap();
            assert_eq!(writer.size().await, 8);

            // Read from buffer via writer
            let read_buf_vec = writer.read_at(0, 4).await.unwrap().coalesce();
            assert_eq!(read_buf_vec, b"buff");

            let read_buf_vec = writer.read_at(4, 4).await.unwrap().coalesce();
            assert_eq!(read_buf_vec, b"ered");

            // Reading past buffer end should fail
            assert!(writer.read_at(8, 1).await.is_err());

            // Write large data that flushes buffer
            writer.write_at(8, b" and flushed").await.unwrap();
            assert_eq!(writer.size().await, 20);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 20);

            // Read from underlying blob through writer
            let read_buf_vec_2 = writer.read_at(0, 4).await.unwrap().coalesce();
            assert_eq!(read_buf_vec_2, b"buff");

            let read_buf_7_vec = writer.read_at(13, 7).await.unwrap().coalesce();
            assert_eq!(read_buf_7_vec, b"flushed");

            // Buffer new data at the end
            writer.write_at(20, b" more data").await.unwrap();
            assert_eq!(writer.size().await, 30);

            // Read newly buffered data
            let read_buf_vec_3 = writer.read_at(20, 5).await.unwrap().coalesce();
            assert_eq!(read_buf_vec_3, b" more");

            // Read spanning both blob and buffer
            let combo_read_buf_vec = writer.read_at(16, 12).await.unwrap();
            assert_eq!(combo_read_buf_vec.coalesce(), b"shed more da");

            // Verify complete content by reopening
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 30);
            let (final_blob, final_size) =
                context.open("partition", b"read_at_writer").await.unwrap();
            assert_eq!(final_size, 30);
            let mut final_reader =
                Read::from_pooler(&context, final_blob, final_size, NZUsize!(30));
            let read = final_reader.read(30).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"buffered and flushed more data");
        });
    }

    #[test_traced]
    fn test_write_read_at_blocks_concurrent_write_until_persisted_read_completes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, read_started_rx, release_read_tx) =
                BlockingReadBlob::new(b"abcdefghij".to_vec());
            let writer = Write::from_pooler(&context, blob, 10, NZUsize!(8));

            let read_writer = writer.clone();
            let read_task = context.clone().spawn(move |_| async move {
                read_writer.read_at(0, 4).await.expect("read failed")
            });

            // Wait until read_at reached underlying blob I/O while holding the tip lock.
            read_started_rx.await.expect("read start signal missing");

            let write_writer = writer.clone();
            let write_task = context.clone().spawn(move |_| async move {
                write_writer
                    .write_at(0, b"WXYZ")
                    .await
                    .expect("write failed");
            });
            pin_mut!(write_task);

            // Let scheduler poll the write task; it should be blocked on the tip write lock.
            reschedule().await;
            assert!(
                write_task.as_mut().now_or_never().is_none(),
                "write_at completed while read_at still held lock over blob I/O"
            );

            // Unblock persisted read and ensure both operations complete.
            release_read_tx
                .send(())
                .expect("failed to release blocked read");
            let read_result = read_task.await.expect("read task failed").coalesce();
            assert_eq!(read_result.as_ref(), b"abcd");
            write_task.await.expect("write task failed");
        });
    }

    #[test_traced]
    fn test_write_read_at_overlap_blocks_concurrent_write_until_persisted_read_completes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, read_started_rx, release_read_tx) =
                BlockingReadBlob::new(b"abcdefghij".to_vec());
            let writer = Write::from_pooler(&context, blob, 10, NZUsize!(8));
            writer.write_at(10, b"XYZ").await.unwrap();

            let read_writer = writer.clone();
            let read_task = context.clone().spawn(move |_| async move {
                read_writer.read_at(8, 5).await.expect("read failed")
            });

            // Wait until overlap read reaches persisted blob I/O while holding the tip lock.
            read_started_rx.await.expect("read start signal missing");

            let write_writer = writer.clone();
            let write_task = context.clone().spawn(move |_| async move {
                write_writer
                    .write_at(10, b"UVW")
                    .await
                    .expect("write failed");
            });
            pin_mut!(write_task);

            // Write should remain blocked on the tip write lock until read releases it.
            reschedule().await;
            assert!(
                write_task.as_mut().now_or_never().is_none(),
                "write_at completed while overlap read_at still held lock over blob I/O"
            );

            release_read_tx
                .send(())
                .expect("failed to release blocked read");
            let read_result = read_task.await.expect("read task failed").coalesce();
            assert_eq!(read_result.as_ref(), b"ijXYZ");
            write_task.await.expect("write task failed");
        });
    }

    #[test_traced]
    fn test_write_straddling_non_mergeable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writes that cannot be merged into buffer (non-contiguous/too large)
            let (blob, size) = context.open("partition", b"write_straddle").await.unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(10));

            // Fill buffer completely
            writer.write_at(0, b"0123456789").await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Write at non-contiguous offset (should flush then write directly)
            writer.write_at(15, b"abc").await.unwrap();
            assert_eq!(writer.size().await, 18);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 18);

            // Verify data with gap
            let (blob_check, size_check) =
                context.open("partition", b"write_straddle").await.unwrap();
            assert_eq!(size_check, 18);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(20));
            let read = reader.read(18).await.unwrap().coalesce();

            let mut expected = vec![0u8; 18];
            expected[0..10].copy_from_slice(b"0123456789");
            expected[15..18].copy_from_slice(b"abc");
            assert_eq!(read.as_ref(), expected.as_slice());

            // Test write that exceeds buffer capacity
            let (blob2, size) = context.open("partition", b"write_straddle2").await.unwrap();
            let writer2 = Write::from_pooler(&context, blob2.clone(), size, NZUsize!(10));
            writer2.write_at(0, b"0123456789").await.unwrap();
            assert_eq!(writer2.size().await, 10);

            // Write large data that exceeds capacity
            writer2.write_at(5, b"ABCDEFGHIJKL").await.unwrap();
            assert_eq!(writer2.size().await, 17);
            writer2.sync().await.unwrap();
            assert_eq!(writer2.size().await, 17);

            // Verify overwrite result
            let (blob_check2, size_check2) =
                context.open("partition", b"write_straddle2").await.unwrap();
            assert_eq!(size_check2, 17);
            let mut reader2 = Read::from_pooler(&context, blob_check2, size_check2, NZUsize!(20));
            let read = reader2.read(17).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"01234ABCDEFGHIJKL");
        });
    }

    #[test_traced]
    fn test_write_close() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test that closing writer flushes and persists buffered data
            let (blob_orig, size) = context.open("partition", b"write_close").await.unwrap();
            let writer = Write::from_pooler(&context, blob_orig.clone(), size, NZUsize!(8));
            writer.write_at(0, b"pending").await.unwrap();
            assert_eq!(writer.size().await, 7);

            // Sync writer to persist data
            writer.sync().await.unwrap();

            // Verify data persistence
            let (blob_check, size_check) = context.open("partition", b"write_close").await.unwrap();
            assert_eq!(size_check, 7);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(8));
            let read = reader.read(7).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"pending");
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
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(5));

            // Write data larger than buffer capacity (should write directly)
            let data_large = b"0123456789";
            writer.write_at(0, data_large).await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Sync to ensure data is persisted
            writer.sync().await.unwrap();

            // Verify direct write worked
            let (blob_check, size_check) = context
                .open("partition", b"write_direct_size")
                .await
                .unwrap();
            assert_eq!(size_check, 10);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(10));
            let read = reader.read(10).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), data_large.as_slice());

            // Now write small data that should be buffered
            writer.write_at(10, b"abc").await.unwrap();
            assert_eq!(writer.size().await, 13);

            // Verify it's in buffer by reading through writer
            let read_small_buf_vec = writer.read_at(10, 3).await.unwrap().coalesce();
            assert_eq!(read_small_buf_vec, b"abc");

            writer.sync().await.unwrap();

            // Verify final state
            let (blob_check2, size_check2) = context
                .open("partition", b"write_direct_size")
                .await
                .unwrap();
            assert_eq!(size_check2, 13);
            let mut reader2 = Read::from_pooler(&context, blob_check2, size_check2, NZUsize!(13));
            let read = reader2.read(13).await.unwrap().coalesce();
            assert_eq!(&read.as_ref()[10..], b"abc".as_slice());
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
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(15));

            // Write initial data
            writer.write_at(0, b"0123456789").await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Overwrite and extend within buffer capacity
            writer.write_at(5, b"ABCDEFGHIJ").await.unwrap();
            assert_eq!(writer.size().await, 15);

            // Verify buffer content through writer
            let read_buf_vec = writer.read_at(0, 15).await.unwrap().coalesce();
            assert_eq!(read_buf_vec, b"01234ABCDEFGHIJ");

            writer.sync().await.unwrap();

            // Verify persisted result
            let (blob_check, size_check) = context
                .open("partition", b"overwrite_extend_buf")
                .await
                .unwrap();
            assert_eq!(size_check, 15);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(15));
            let read = reader.read(15).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"01234ABCDEFGHIJ".as_slice());
        });
    }

    #[test_traced]
    fn test_write_at_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing at the current logical end of the blob
            let (blob, size) = context.open("partition", b"write_end").await.unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(20));

            // Write initial data
            writer.write_at(0, b"0123456789").await.unwrap();
            assert_eq!(writer.size().await, 10);
            writer.sync().await.unwrap();

            // Append at the current size (logical end)
            writer.write_at(writer.size().await, b"abc").await.unwrap();
            assert_eq!(writer.size().await, 13);
            writer.sync().await.unwrap();

            // Verify complete result
            let (blob_check, size_check) = context.open("partition", b"write_end").await.unwrap();
            assert_eq!(size_check, 13);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(13));
            let read = reader.read(13).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"0123456789abc");
        });
    }

    #[test_traced]
    fn test_write_at_size_multiple_appends() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test multiple appends using writer.size()
            let (blob, size) = context
                .open("partition", b"write_multiple_appends_at_size")
                .await
                .unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(5));

            // First write
            writer.write_at(0, b"AAA").await.unwrap();
            assert_eq!(writer.size().await, 3);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 3);

            // Append using size()
            writer.write_at(writer.size().await, b"BBB").await.unwrap();
            assert_eq!(writer.size().await, 6); // 3 (AAA) + 3 (BBB)
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 6);

            // Append again using size()
            writer.write_at(writer.size().await, b"CCC").await.unwrap();
            assert_eq!(writer.size().await, 9); // 6 + 3 (CCC)
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 9);

            // Verify final content
            let (blob_check, size_check) = context
                .open("partition", b"write_multiple_appends_at_size")
                .await
                .unwrap();
            assert_eq!(size_check, 9);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(9));
            let read = reader.read(9).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"AAABBBCCC");
        });
    }

    #[test_traced]
    fn test_write_non_contiguous_then_append_at_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test writing non-contiguously, then appending at the new size
            let (blob, size) = context
                .open("partition", b"write_non_contiguous_then_append")
                .await
                .unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(10));

            // Initial buffered write
            writer.write_at(0, b"INITIAL").await.unwrap(); // 7 bytes
            assert_eq!(writer.size().await, 7);
            // Buffer contains "INITIAL", inner.position = 0

            // Non-contiguous write, forces flush of "INITIAL" and direct write of "NONCONTIG"
            writer.write_at(20, b"NONCONTIG").await.unwrap();
            assert_eq!(writer.size().await, 29);
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 29);

            // Append at the new size
            writer
                .write_at(writer.size().await, b"APPEND")
                .await
                .unwrap();
            assert_eq!(writer.size().await, 35); // 29 + 6
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 35);

            // Verify final content
            let (blob_check, size_check) = context
                .open("partition", b"write_non_contiguous_then_append")
                .await
                .unwrap();
            assert_eq!(size_check, 35);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(35));
            let read = reader.read(35).await.unwrap().coalesce();

            let mut expected = vec![0u8; 35];
            expected[0..7].copy_from_slice(b"INITIAL");
            expected[20..29].copy_from_slice(b"NONCONTIG");
            expected[29..35].copy_from_slice(b"APPEND");
            assert_eq!(read.as_ref(), expected.as_slice());
        });
    }

    #[test_traced]
    fn test_resize_then_append_at_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test truncating, then appending at the new size
            let (blob, size) = context
                .open("partition", b"resize_then_append_at_size")
                .await
                .unwrap();
            let writer = Write::from_pooler(&context, blob.clone(), size, NZUsize!(10));

            // Write initial data and sync
            writer.write_at(0, b"0123456789ABCDEF").await.unwrap(); // 16 bytes
            assert_eq!(writer.size().await, 16);
            writer.sync().await.unwrap(); // inner.position = 16, buffer empty
            assert_eq!(writer.size().await, 16);

            // Resize
            let resize_to = 5;
            writer.resize(resize_to).await.unwrap();
            // after resize, inner.position should be `resize_to` (5)
            // buffer should be empty
            assert_eq!(writer.size().await, resize_to);
            writer.sync().await.unwrap(); // Ensure truncation is persisted for verify step
            assert_eq!(writer.size().await, resize_to);

            // Append at the new (resized) size
            writer
                .write_at(writer.size().await, b"XXXXX")
                .await
                .unwrap(); // 5 bytes
                           // inner.buffer = "XXXXX", inner.position = 5
            assert_eq!(writer.size().await, 10); // 5 (resized) + 5 (XXXXX)
            writer.sync().await.unwrap();
            assert_eq!(writer.size().await, 10);

            // Verify final content
            let (blob_check, size_check) = context
                .open("partition", b"resize_then_append_at_size")
                .await
                .unwrap();
            assert_eq!(size_check, 10);
            let mut reader = Read::from_pooler(&context, blob_check, size_check, NZUsize!(10));
            let read = reader.read(10).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"01234XXXXX");
        });
    }
}
