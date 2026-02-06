//! Implementations of the `Storage` trait that can be used by the runtime.

use commonware_macros::stability_scope;

stability_scope!(ALPHA {
    pub mod audited;
    pub mod faulty;
    pub mod memory;
});
stability_scope!(ALPHA, cfg(feature = "iouring-storage") {
    pub mod iouring;
});
stability_scope!(BETA, cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage"))) {
    pub mod tokio;
});
stability_scope!(BETA {
    use crate::{Buf, BufMut};
    use commonware_codec::{DecodeExt, FixedSize, Read as CodecRead, Write as CodecWrite};
    use commonware_utils::hex;
    use std::ops::RangeInclusive;

    pub mod metered;

    /// Errors that can occur when validating a blob header.
    #[derive(Debug)]
    pub(crate) enum HeaderError {
        InvalidMagic {
            expected: [u8; 4],
            found: [u8; 4],
        },
        UnsupportedRuntimeVersion {
            expected: u16,
            found: u16,
        },
        VersionMismatch {
            expected: RangeInclusive<u16>,
            found: u16,
        },
    }

    impl HeaderError {
        /// Converts this error into an [`Error`](enum@crate::Error) with partition and name context.
        pub(crate) fn into_error(self, partition: &str, name: &[u8]) -> crate::Error {
            match self {
                Self::InvalidMagic { expected, found } => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    format!("invalid magic: expected {expected:?}, found {found:?}"),
                ),
                Self::UnsupportedRuntimeVersion { expected, found } => crate::Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    format!("unsupported runtime version: expected {expected}, found {found}"),
                ),
                Self::VersionMismatch { expected, found } => {
                    crate::Error::BlobVersionMismatch { expected, found }
                }
            }
        }
    }

    /// Fixed-size header at the start of each [crate::Blob].
    ///
    /// On-disk layout (8 bytes, big-endian):
    /// - Bytes 0-3: [Header::MAGIC]
    /// - Bytes 4-5: Runtime Version (u16)
    /// - Bytes 6-7: Blob Version (u16)
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Header {
        magic: [u8; Self::MAGIC_LENGTH],
        runtime_version: u16,
        pub(crate) blob_version: u16,
    }

    impl Header {
        /// Size of the header in bytes.
        pub(crate) const SIZE: usize = 8;

        /// Size of the header as u64 for offset calculations.
        pub(crate) const SIZE_U64: u64 = Self::SIZE as u64;

        /// Length of magic bytes.
        pub(crate) const MAGIC_LENGTH: usize = 4;

        /// Length of version fields.
        #[cfg(test)]
        pub(crate) const VERSION_LENGTH: usize = 2;

        /// Magic bytes identifying a valid commonware blob.
        pub(crate) const MAGIC: [u8; Self::MAGIC_LENGTH] = *b"CWIC"; // Commonware Is CWIC

        /// The current version of the header format.
        pub(crate) const RUNTIME_VERSION: u16 = 0;

        /// Returns true if a blob is missing a valid header (new or corrupted).
        pub(crate) const fn missing(raw_len: u64) -> bool {
            raw_len < Self::SIZE_U64
        }

        /// Creates a header for a new blob using the latest version from the range.
        /// Returns (header, blob_version).
        pub(crate) const fn new(versions: &std::ops::RangeInclusive<u16>) -> (Self, u16) {
            let blob_version = *versions.end();
            let header = Self {
                magic: Self::MAGIC,
                runtime_version: Self::RUNTIME_VERSION,
                blob_version,
            };
            (header, blob_version)
        }

        /// Parses and validates an existing header, returning the blob version and logical size.
        pub(crate) fn from(
            raw_bytes: [u8; Self::SIZE],
            raw_len: u64,
            versions: &RangeInclusive<u16>,
        ) -> Result<(u16, u64), HeaderError> {
            let header: Self = Self::decode(raw_bytes.as_slice())
                .expect("header decode should never fail for correct size input");
            header.validate(versions)?;
            Ok((header.blob_version, raw_len - Self::SIZE_U64))
        }

        /// Validates the magic bytes, runtime version, and blob version.
        pub(crate) fn validate(
            &self,
            blob_versions: &RangeInclusive<u16>,
        ) -> Result<(), HeaderError> {
            if self.magic != Self::MAGIC {
                return Err(HeaderError::InvalidMagic {
                    expected: Self::MAGIC,
                    found: self.magic,
                });
            }
            if self.runtime_version != Self::RUNTIME_VERSION {
                return Err(HeaderError::UnsupportedRuntimeVersion {
                    expected: Self::RUNTIME_VERSION,
                    found: self.runtime_version,
                });
            }
            if !blob_versions.contains(&self.blob_version) {
                return Err(HeaderError::VersionMismatch {
                    expected: blob_versions.clone(),
                    found: self.blob_version,
                });
            }
            Ok(())
        }
    }

    impl FixedSize for Header {
        const SIZE: usize = Self::SIZE;
    }

    impl CodecWrite for Header {
        fn write(&self, buf: &mut impl BufMut) {
            buf.put_slice(&self.magic);
            buf.put_u16(self.runtime_version);
            buf.put_u16(self.blob_version);
        }
    }

    impl CodecRead for Header {
        type Cfg = ();
        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            if buf.remaining() < Self::SIZE {
                return Err(commonware_codec::Error::EndOfBuffer);
            }
            let mut magic = [0u8; Self::MAGIC_LENGTH];
            buf.copy_to_slice(&mut magic);
            let runtime_version = buf.get_u16();
            let blob_version = buf.get_u16();
            Ok(Self {
                magic,
                runtime_version,
                blob_version,
            })
        }
    }

    /// Validate that a partition name contains only allowed characters.
    ///
    /// Partition names must only contain alphanumeric characters, dashes ('-'),
    /// or underscores ('_').
    pub fn validate_partition_name(partition: &str) -> Result<(), crate::Error> {
        if partition.is_empty()
            || partition
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || ['_', '-'].contains(&c)))
        {
            return Err(crate::Error::PartitionNameInvalid(partition.into()));
        }
        Ok(())
    }
});

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Header {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let version: u16 = u.arbitrary()?;
        Ok(Self::new(&(version..=version)).0)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Header, HeaderError};
    use crate::{Blob, Buf, IoBuf, IoBufMut, IoBufsMut, Storage};
    use futures::FutureExt;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_header_fields() {
        let (header, _) = Header::new(&(42..=42));
        assert_eq!(header.magic, Header::MAGIC);
        assert_eq!(header.runtime_version, Header::RUNTIME_VERSION);
        assert_eq!(header.blob_version, 42);
    }

    #[test]
    fn test_header_validate_success() {
        let (header, _) = Header::new(&(5..=5));
        assert!(header.validate(&(3..=7)).is_ok());
        assert!(header.validate(&(5..=5)).is_ok());
    }

    #[test]
    fn test_header_validate_magic_mismatch() {
        let (mut header, _) = Header::new(&(5..=5));
        header.magic = *b"XXXX";
        let result = header.validate(&(3..=7));
        assert!(matches!(
            result,
            Err(HeaderError::InvalidMagic { expected, found })
            if expected == Header::MAGIC && found == *b"XXXX"
        ));
    }

    #[test]
    fn test_header_validate_runtime_version_mismatch() {
        let (mut header, _) = Header::new(&(5..=5));
        header.runtime_version = 99;
        let result = header.validate(&(3..=7));
        assert!(matches!(
            result,
            Err(HeaderError::UnsupportedRuntimeVersion { expected, found })
            if expected == Header::RUNTIME_VERSION && found == 99
        ));
    }

    #[test]
    fn test_header_validate_blob_version_out_of_range() {
        let (header, _) = Header::new(&(10..=10));
        let result = header.validate(&(3..=7));
        assert!(matches!(
            result,
            Err(HeaderError::VersionMismatch { expected, found })
            if expected == (3..=7) && found == 10
        ));
    }

    #[test]
    fn test_header_bytes_round_trip() {
        let (header, _) = Header::new(&(123..=123));
        let bytes = header.encode();
        let decoded: Header = Header::decode(bytes.as_ref()).unwrap();
        assert_eq!(header, decoded);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::Header;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Header>
        }
    }

    /// Runs the full suite of tests on the provided storage implementation.
    pub(crate) async fn run_storage_tests<S>(storage: S)
    where
        S: Storage + Send + Sync + 'static,
        S::Blob: Send + Sync,
    {
        test_open_and_write(&storage).await;
        test_remove(&storage).await;
        test_scan(&storage).await;
        test_concurrent_access(&storage).await;
        test_large_data(&storage).await;
        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_append_data(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
        test_resize_then_open(&storage).await;
        test_partition_name_validation(&storage).await;
        test_blob_version_mismatch(&storage).await;
        test_read_zero_length(&storage).await;
        test_read_at_buf_returns_same_buffer(&storage).await;
        test_read_at_buf_insufficient_capacity(&storage).await;
        test_read_at_buf_larger_capacity(&storage).await;
    }

    /// Test opening a blob, writing to it, and reading back the data.
    async fn test_open_and_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(0, b"hello world").await.unwrap();
        let read = blob.read_at(0, 11).await.unwrap();

        assert_eq!(
            read.coalesce(),
            b"hello world",
            "Blob content does not match expected value"
        );
    }

    /// Test removing a blob from storage.
    async fn test_remove<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"test_blob").await.unwrap();
        storage
            .remove("partition", Some(b"test_blob"))
            .await
            .unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert!(blobs.is_empty(), "Blob was not removed as expected");
    }

    /// Test scanning a partition for blobs.
    async fn test_scan<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"blob1").await.unwrap();
        storage.open("partition", b"blob2").await.unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert_eq!(
            blobs.len(),
            2,
            "Scan did not return the expected number of blobs"
        );
        assert!(
            blobs.contains(&b"blob1".to_vec()),
            "Blob1 is missing from scan results"
        );
        assert!(
            blobs.contains(&b"blob2".to_vec()),
            "Blob2 is missing from scan results"
        );
    }

    /// Test concurrent access to the same blob.
    async fn test_concurrent_access<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Initialize blob with data of sufficient length first
        blob.write_at(0, b"concurrent write").await.unwrap();

        // Read and write concurrently
        let write_task = tokio::spawn({
            let blob = blob.clone();
            async move {
                blob.write_at(0, IoBuf::from(b"concurrent write"))
                    .await
                    .unwrap();
            }
        });

        let read_task = tokio::spawn({
            let blob = blob.clone();
            async move { blob.read_at(0, 16).await.unwrap() }
        });

        write_task.await.unwrap();
        let buffer = read_task.await.unwrap();

        assert_eq!(
            buffer.coalesce(),
            b"concurrent write",
            "Concurrent access failed"
        );
    }

    /// Test handling of large data sizes.
    async fn test_large_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"large_blob").await.unwrap();

        let large_data = vec![42u8; 10 * 1024 * 1024]; // 10 MB
        blob.write_at(0, large_data.clone()).await.unwrap();

        let read = blob.read_at(0, 10 * 1024 * 1024).await.unwrap().coalesce();

        assert_eq!(read, large_data.as_slice(), "Large data read/write failed");
    }

    /// Test overwriting data in a blob.
    async fn test_overwrite_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_overwrite_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(0, b"initial data").await.unwrap();

        // Overwrite part of the data
        blob.write_at(8, b"overwrite").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 17).await.unwrap().coalesce();

        assert_eq!(
            read, b"initial overwrite",
            "Data was not overwritten correctly"
        );
    }

    /// Test reading from an offset beyond the written data.
    async fn test_read_beyond_bound<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_beyond_written_data", b"test_blob")
            .await
            .unwrap();

        // Write some data
        blob.write_at(0, b"hello").await.unwrap();

        // Attempt to read beyond the written data
        let result = blob.read_at(6, 10).await;
        assert!(
            result.is_err(),
            "Reading beyond written data should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(10);
        let result = blob.read_at_buf(6, 10, buf).await;
        assert!(
            result.is_err(),
            "read_at_buf beyond written data should return an error"
        );
    }

    /// Test writing data at a large offset.
    async fn test_write_at_large_offset<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        // Write data at a large offset
        blob.write_at(10_000, b"offset data").await.unwrap();

        // Read back the data
        let read = blob.read_at(10_000, 11).await.unwrap().coalesce();
        assert_eq!(read, b"offset data", "Data at large offset is incorrect");
    }

    /// Test appending data to a blob.
    async fn test_append_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_append_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(0, b"first").await.unwrap();

        // Append data
        blob.write_at(5, b"second").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read, b"firstsecond", "Appended data is incorrect");
    }

    /// Test reading and writing with interleaved offsets.
    async fn test_sequential_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Write data at different offsets
        blob.write_at(0, b"first").await.unwrap();
        blob.write_at(10, b"second").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read, b"first", "Data at offset 0 is incorrect");

        let read = blob.read_at(10, 6).await.unwrap().coalesce();
        assert_eq!(read, b"second", "Data at offset 10 is incorrect");
    }

    /// Test writing and reading large data in chunks.
    async fn test_sequential_chunk_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_large_data_in_chunks", b"large_blob")
            .await
            .unwrap();

        let chunk_size = 1024 * 1024; // 1 MB
        let num_chunks = 10;
        let data = vec![7u8; chunk_size];

        // Write data in chunks
        for i in 0..num_chunks {
            blob.write_at((i * chunk_size) as u64, data.clone())
                .await
                .unwrap();
        }

        // Read back the data in chunks
        for i in 0..num_chunks {
            let read = blob
                .read_at((i * chunk_size) as u64, chunk_size)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read, data.as_slice(), "Chunk {i} is incorrect");
        }
    }

    /// Test reading from an empty blob.
    async fn test_read_empty_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_empty_blob", b"empty_blob")
            .await
            .unwrap();

        let result = blob.read_at(0, 1).await;
        assert!(
            result.is_err(),
            "Reading from an empty blob should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(1);
        let result = blob.read_at_buf(0, 1, buf).await;
        assert!(
            result.is_err(),
            "read_at_buf from an empty blob should return an error"
        );
    }

    /// Test writing and reading with overlapping writes.
    async fn test_overlapping_writes<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_overlapping_writes", b"test_blob")
            .await
            .unwrap();

        // Write overlapping data
        blob.write_at(0, b"overlap").await.unwrap();
        blob.write_at(4, b"map").await.unwrap();

        // Read back the data
        let read = blob.read_at(0, 7).await.unwrap().coalesce();
        assert_eq!(read, b"overmap", "Overlapping writes are incorrect");
    }

    async fn test_resize_then_open<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        {
            let (blob, _) = storage
                .open("test_resize_then_open", b"test_blob")
                .await
                .unwrap();

            // Write some data
            blob.write_at(0, b"hello world").await.unwrap();

            // Resize the blob
            blob.resize(5).await.unwrap();

            // Sync the blob
            blob.sync().await.unwrap();
        }

        // Reopen the blob
        let (blob, len) = storage
            .open("test_resize_then_open", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 5, "Blob length after resize is incorrect");

        // Read back the data
        let read = blob.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(read, b"hello", "Resized data is incorrect");
    }

    /// Test that partition names are validated correctly.
    async fn test_partition_name_validation<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Valid partition names should not return PartitionNameInvalid
        for valid in [
            "partition",
            "my_partition",
            "my-partition",
            "partition123",
            "A1",
        ] {
            assert!(
                !matches!(
                    storage.open(valid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by open"
            );
            assert!(
                !matches!(
                    storage.remove(valid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by remove"
            );
            assert!(
                !matches!(
                    storage.scan(valid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by scan"
            );
        }

        // Invalid partition names should return PartitionNameInvalid
        for invalid in [
            "my/partition",
            "my.partition",
            "my partition",
            "../escape",
            "",
        ] {
            assert!(
                matches!(
                    storage.open(invalid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by open"
            );
            assert!(
                matches!(
                    storage.remove(invalid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by remove"
            );
            assert!(
                matches!(
                    storage.scan(invalid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by scan"
            );
        }
    }

    /// Test that opening a blob with an incompatible version range returns an error.
    async fn test_blob_version_mismatch<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create a blob with version 1
        let (blob, _, version) = storage
            .open_versioned("test_version_mismatch", b"blob", 1..=1)
            .await
            .unwrap();
        assert_eq!(version, 1);
        blob.sync().await.unwrap();
        drop(blob);

        // Reopen with a range that includes version 1
        let (_, _, version) = storage
            .open_versioned("test_version_mismatch", b"blob", 0..=2)
            .await
            .unwrap();
        assert_eq!(version, 1);

        // Try to open with version range that excludes version 1
        let result = storage
            .open_versioned("test_version_mismatch", b"blob", 2..=3)
            .await;
        assert!(
            matches!(
                result,
                Err(crate::Error::BlobVersionMismatch { expected, found })
                if expected == (2..=3) && found == 1
            ),
            "Expected BlobVersionMismatch error"
        );
    }

    /// Test that read_at with zero length returns an empty buffer.
    async fn test_read_zero_length<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_zero_len", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello").await.unwrap();

        // read_at with len=0 should succeed and return empty
        let output = blob.read_at(0, 0).await.unwrap();
        assert_eq!(output.len(), 0);

        // read_at_buf with len=0 should also succeed
        let buf = IoBufMut::with_capacity(16);
        let output = blob.read_at_buf(0, 0, buf).await.unwrap();
        assert_eq!(output.len(), 0);
    }

    /// Test that read_at_buf returns the same buffer that was passed in (contract verification).
    async fn test_read_at_buf_returns_same_buffer<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_contract", b"blob")
            .await
            .unwrap();

        // Write test data
        blob.write_at(0, b"hello world").await.unwrap();

        // Test with single buffer - verify same buffer is returned
        let input_buf = IoBufMut::zeroed(11);
        let input_ptr = input_buf.as_ref().as_ptr();
        let output = blob.read_at_buf(0, 11, input_buf).await.unwrap();
        assert!(
            output.is_single(),
            "Single input should return single output"
        );
        let output_ptr = output.chunk().as_ptr();
        assert_eq!(
            input_ptr, output_ptr,
            "read_at must return the same buffer that was passed in"
        );
        assert_eq!(output.chunk(), b"hello world");

        // Test with chunked buffers - verify same buffers are returned with correct data
        let buf1 = IoBufMut::zeroed(5);
        let buf2 = IoBufMut::zeroed(6);
        let ptr1 = buf1.as_ref().as_ptr();
        let ptr2 = buf2.as_ref().as_ptr();
        let input_bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!input_bufs.is_single(), "Should be chunked");

        let output = blob.read_at_buf(0, 11, input_bufs).await.unwrap();
        assert!(
            !output.is_single(),
            "Chunked input should return chunked output"
        );

        // Verify the buffers are the same and contain correct data
        match output {
            IoBufsMut::Chunked(chunks) => {
                assert_eq!(chunks.len(), 2);
                assert_eq!(
                    chunks[0].as_ref().as_ptr(),
                    ptr1,
                    "First chunk must be the same buffer"
                );
                assert_eq!(
                    chunks[1].as_ref().as_ptr(),
                    ptr2,
                    "Second chunk must be the same buffer"
                );
                assert_eq!(chunks[0], b"hello");
                assert_eq!(chunks[1], b" world");
            }
            _ => panic!("Expected Chunked variant"),
        }
    }

    /// Test that read_at_buf panics when buffer capacity < len.
    async fn test_read_at_buf_insufficient_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_capacity", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world").await.unwrap();

        // Single buffer with capacity 5, request 11 bytes
        let buf = IoBufMut::with_capacity(5);
        let result =
            std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, buf)).catch_unwind().await;
        assert!(result.is_err(), "Expected panic for insufficient single buffer capacity");

        // Chunked buffers with total capacity 8, request 11 bytes
        let bufs = IoBufsMut::from(vec![IoBufMut::with_capacity(4), IoBufMut::with_capacity(4)]);
        let result =
            std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, bufs)).catch_unwind().await;
        assert!(result.is_err(), "Expected panic for insufficient chunked buffer capacity");
    }

    /// Test that read_at_buf works when buffer capacity exceeds len.
    async fn test_read_at_buf_larger_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_large_cap", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world").await.unwrap();

        // Buffer with capacity 64, request only 11 bytes
        let buf = IoBufMut::with_capacity(64);
        assert_eq!(buf.len(), 0, "with_capacity should start at len 0");
        let output = blob.read_at_buf(0, 11, buf).await.unwrap();
        assert_eq!(output.len(), 11);
        assert_eq!(output.coalesce(), b"hello world");

        // Buffer with capacity 64, request only 5 bytes (partial read)
        let buf = IoBufMut::with_capacity(64);
        let output = blob.read_at_buf(0, 5, buf).await.unwrap();
        assert_eq!(output.len(), 5);
        assert_eq!(output.coalesce(), b"hello");
    }
}
