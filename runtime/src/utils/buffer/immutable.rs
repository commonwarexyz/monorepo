use crate::{
    buffer::{Append, PoolRef},
    Blob, Error,
};
use commonware_utils::StableBuf;
use std::num::NonZeroUsize;

/// A [Blob] wrapper that provides read-only access with buffer-pool managed read caching.
///
/// Calls to [Blob::write_at] and [Blob::resize] will panic, since the blob is meant to be
/// immutable. The [Blob] being wrapped *must* already have been synced beforehand,
/// otherwise any unflushed data may be lost. In this wrapper [Blob::sync] is a no-op.
#[derive(Clone)]
pub struct Immutable<B: Blob> {
    /// The underlying blob being wrapped.
    blob: B,

    /// Unique id assigned by the buffer pool.
    id: u64,

    /// Buffer pool to use for caching.
    pool_ref: PoolRef,

    /// The size of the blob at creation time.
    size: u64,
}

impl<B: Blob> Immutable<B> {
    /// Create a new [Immutable] wrapper for a blob of the given size.
    pub async fn new(blob: B, size: u64, pool_ref: PoolRef) -> Self {
        Self {
            blob,
            id: pool_ref.next_id().await,
            pool_ref,
            size,
        }
    }

    /// Create a new [Immutable] wrapper with a specific pool ID.
    ///
    /// This is used internally when converting from [Append] to reuse the same pool ID.
    pub(crate) fn new_in_pool(blob: B, size: u64, id: u64, pool_ref: PoolRef) -> Self {
        Self {
            blob,
            id,
            pool_ref,
            size,
        }
    }

    /// Convert this [Immutable] wrapper back to an [Append] wrapper with a write buffer
    /// with capacity `buffer_size`.
    pub async fn into_append(self, buffer_size: NonZeroUsize) -> Result<Append<B>, Error> {
        Append::new_in_pool(self.blob, self.size, buffer_size, self.id, self.pool_ref).await
    }

    /// Clones and returns the underlying blob.
    pub fn clone_blob(&self) -> B {
        self.blob.clone()
    }
}

impl<B: Blob> Blob for Immutable<B> {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        let mut buf = buf.into();

        // Ensure the read doesn't overflow.
        let end_offset = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > self.size {
            return Err(Error::BlobInsufficientLength);
        }

        // Calculate where the trailing bytes start.
        let page_size = self.pool_ref.page_size as u64;
        let trailing_bytes_start = (self.size / page_size) * page_size;

        // Read as much as we can from the pool.
        let pool_read_len = trailing_bytes_start
            .saturating_sub(offset)
            .min(buf.len() as u64) as usize;

        if pool_read_len > 0 {
            self.pool_ref
                .read(
                    &self.blob,
                    self.id,
                    &mut buf.as_mut()[..pool_read_len],
                    offset,
                )
                .await?;
        }

        // If we need to read trailing bytes, read them directly from the blob.
        if pool_read_len < buf.len() {
            let mut trailing_part = buf.split_off(pool_read_len);

            trailing_part = self
                .blob
                .read_at(trailing_part, offset + pool_read_len as u64)
                .await?;

            buf.unsplit(trailing_part);
        }

        Ok(buf)
    }

    async fn write_at(&self, _buf: impl Into<StableBuf> + Send, _offset: u64) -> Result<(), Error> {
        panic!("immutable blob does not support writes")
    }

    async fn resize(&self, _size: u64) -> Result<(), Error> {
        panic!("immutable blob does not support resize")
    }

    async fn sync(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{buffer::Append, deterministic, Runner, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::NZUsize;

    const PAGE_SIZE: usize = 1024;
    const BUFFER_SIZE: usize = PAGE_SIZE * 2;

    #[test_traced]
    #[should_panic(expected = "immutable blob does not support writes")]
    fn test_immutable_blob_write_at_panics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            let blob = Immutable::new(blob, size, pool_ref).await;
            blob.write_at(vec![0], 0).await.unwrap();
        });
    }

    #[test_traced]
    #[should_panic(expected = "immutable blob does not support resize")]
    fn test_immutable_blob_resize_panics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            let blob = Immutable::new(blob, size, pool_ref).await;
            blob.resize(100).await.unwrap();
        });
    }

    #[test_traced]
    fn test_immutable_blob_read_at() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 0);

            // Write 5 full pages
            for i in 0..5 {
                let buf = vec![i as u8; PAGE_SIZE];
                blob.write_at(buf, i as u64 * PAGE_SIZE as u64)
                    .await
                    .unwrap();
            }

            // Add trailing bytes (half page)
            let trailing_data = vec![0xFF; PAGE_SIZE / 2];
            blob.write_at(trailing_data, 5 * PAGE_SIZE as u64)
                .await
                .unwrap();

            blob.sync().await.unwrap();
            let total_size = 5 * PAGE_SIZE + PAGE_SIZE / 2;

            // Now wrap it as immutable
            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            let immutable = Immutable::new(blob, total_size as u64, pool_ref).await;

            // Read from various full page positions
            for i in 0..5 {
                let mut buf = vec![0; PAGE_SIZE];
                buf = immutable
                    .read_at(buf, i as u64 * PAGE_SIZE as u64)
                    .await
                    .unwrap()
                    .into();

                assert_eq!(buf, vec![i as u8; PAGE_SIZE]);
            }

            // Read across page boundaries
            let mut buf = vec![0; 100];
            buf = immutable
                .read_at(buf, PAGE_SIZE as u64 - 50)
                .await
                .unwrap()
                .into();

            let mut expected = vec![0; 50];
            expected.extend_from_slice(&[1; 50]);
            assert_eq!(buf, expected);

            // Read only the trailing bytes
            let mut buf = vec![0; PAGE_SIZE / 2];
            buf = immutable
                .read_at(buf, 5 * PAGE_SIZE as u64)
                .await
                .unwrap()
                .into();

            assert_eq!(buf, vec![0xFF; PAGE_SIZE / 2]);

            // Read across the boundary into trailing bytes
            let mut buf = vec![0; PAGE_SIZE];
            buf = immutable
                .read_at(buf, (5 * PAGE_SIZE - PAGE_SIZE / 2) as u64)
                .await
                .unwrap()
                .into();

            let mut expected = vec![4; PAGE_SIZE / 2];
            expected.extend_from_slice(&vec![0xFF; PAGE_SIZE / 2]);
            assert_eq!(buf, expected);

            // Test read beyond size fails
            let result = immutable.read_at(vec![0; 10], total_size as u64).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_immutable_round_trip_append_conversion() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 0);

            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));

            let append = Append::new(blob, size, NZUsize!(BUFFER_SIZE), pool_ref.clone())
                .await
                .unwrap();

            // Write 2.5 pages of data
            append.append(vec![1u8; PAGE_SIZE]).await.unwrap();
            append.append(vec![2u8; PAGE_SIZE]).await.unwrap();
            append.append(vec![3u8; PAGE_SIZE / 2]).await.unwrap();
            append.sync().await.unwrap();

            // Convert to Immutable
            let immutable = append.into_immutable().await;

            // Read and verify data
            let mut buf = vec![0; PAGE_SIZE];
            buf = immutable.read_at(buf, 0).await.unwrap().into();
            assert_eq!(buf, vec![1u8; PAGE_SIZE]);

            buf = immutable
                .read_at(buf, PAGE_SIZE as u64)
                .await
                .unwrap()
                .into();
            assert_eq!(buf, vec![2u8; PAGE_SIZE]);

            let mut buf = vec![0; PAGE_SIZE / 2];
            buf = immutable
                .read_at(buf, (PAGE_SIZE * 2) as u64)
                .await
                .unwrap()
                .into();
            assert_eq!(buf, vec![3u8; PAGE_SIZE / 2]);

            // Convert back to Append
            let append = immutable.into_append(NZUsize!(BUFFER_SIZE)).await.unwrap();

            // Append more data
            append.append(vec![4u8; PAGE_SIZE / 2]).await.unwrap();
            append.append(vec![5u8; PAGE_SIZE]).await.unwrap();
            append.sync().await.unwrap();

            // Verify all data is preserved
            let mut buf = vec![0; PAGE_SIZE * 4];
            buf = append.read_at(buf, 0).await.unwrap().into();

            let mut expected = vec![1u8; PAGE_SIZE];
            expected.extend_from_slice(&vec![2u8; PAGE_SIZE]);
            expected.extend_from_slice(&vec![3u8; PAGE_SIZE / 2]);
            expected.extend_from_slice(&vec![4u8; PAGE_SIZE / 2]);
            expected.extend_from_slice(&vec![5u8; PAGE_SIZE]);
            assert_eq!(buf, expected);
        });
    }
}
