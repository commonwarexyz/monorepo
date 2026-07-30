//! Validation and canonicalization of storage namespace operation sets.
//!
//! Duplicate removals are discarded, and a partition removal subsumes every blob removal in that
//! partition. Duplicate blob mutations with identical inputs are discarded. A mutation conflicts
//! with an exact or partition removal that covers the same blob.

use crate::{BatchOperation, Error, IoBuf, RemoveTarget};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::{self, ErrorKind},
};

/// An exact namespace operation used for validation and canonicalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    /// Remove an exact namespace target.
    Remove(RemoveTarget),
    /// Resize an exact blob to `len` bytes.
    Resize {
        partition: String,
        name: Vec<u8>,
        len: u64,
    },
    /// Write an exact range and resize an exact blob to `len` bytes.
    Update {
        partition: String,
        name: Vec<u8>,
        offset: u64,
        data: IoBuf,
        len: u64,
    },
}

#[cfg(not(target_arch = "wasm32"))]
impl Operation {
    fn partition(&self) -> &str {
        match self {
            Self::Remove(RemoveTarget::Blob { partition, .. })
            | Self::Remove(RemoveTarget::Partition(partition))
            | Self::Resize { partition, .. }
            | Self::Update { partition, .. } => partition,
        }
    }

    fn name(&self) -> Option<&[u8]> {
        match self {
            Self::Remove(RemoveTarget::Partition(_)) => None,
            Self::Remove(RemoveTarget::Blob { name, .. })
            | Self::Resize { name, .. }
            | Self::Update { name, .. } => Some(name),
        }
    }

    pub(super) const fn partition_mut(&mut self) -> &mut String {
        match self {
            Self::Remove(RemoveTarget::Blob { partition, .. })
            | Self::Remove(RemoveTarget::Partition(partition))
            | Self::Resize { partition, .. }
            | Self::Update { partition, .. } => partition,
        }
    }
}

#[derive(Eq, PartialEq)]
enum BlobOperation {
    Remove,
    Resize(u64),
    Update { offset: u64, data: IoBuf, len: u64 },
}

enum PartitionOperations {
    Blobs(BTreeMap<Vec<u8>, BlobOperation>),
    Remove,
}

fn invalid_operations(message: &'static str) -> Error {
    io::Error::new(ErrorKind::InvalidInput, message).into()
}

pub(crate) fn validate_update(offset: u64, data_len: usize, len: u64) -> Result<(), Error> {
    let data_len = u64::try_from(data_len)
        .map_err(|_| invalid_operations("batch update data length overflows u64"))?;
    let end = offset
        .checked_add(data_len)
        .ok_or_else(|| invalid_operations("batch update range overflows u64"))?;
    if end > len {
        return Err(invalid_operations(
            "batch update range exceeds its final blob length",
        ));
    }
    Ok(())
}

fn insert_mutation(
    partitions: &mut BTreeMap<String, PartitionOperations>,
    partition: String,
    name: Vec<u8>,
    operation: BlobOperation,
) -> Result<(), Error> {
    match partitions.entry(partition) {
        Entry::Vacant(entry) => {
            entry.insert(PartitionOperations::Blobs(BTreeMap::from([(
                name, operation,
            )])));
        }
        Entry::Occupied(mut entry) => match entry.get_mut() {
            PartitionOperations::Remove => {
                return Err(invalid_operations(
                    "batch cannot mutate a blob in a removed partition",
                ));
            }
            PartitionOperations::Blobs(blobs) => match blobs.entry(name) {
                Entry::Vacant(entry) => {
                    entry.insert(operation);
                }
                Entry::Occupied(entry) if entry.get() == &operation => {}
                Entry::Occupied(entry) if matches!(entry.get(), BlobOperation::Remove) => {
                    return Err(invalid_operations(
                        "batch cannot remove and mutate the same blob",
                    ));
                }
                Entry::Occupied(_) => {
                    return Err(invalid_operations(
                        "batch contains conflicting blob mutations",
                    ));
                }
            },
        },
    }
    Ok(())
}

/// Map blob handles without changing the operation set.
pub(crate) fn map_blobs<B, C>(
    operations: Vec<BatchOperation<B>>,
    mut map: impl FnMut(B) -> C,
) -> Vec<BatchOperation<C>> {
    operations
        .into_iter()
        .map(|operation| match operation {
            BatchOperation::Remove(target) => BatchOperation::Remove(target),
            BatchOperation::Resize { blob, len } => BatchOperation::Resize {
                blob: map(blob),
                len,
            },
            BatchOperation::Update {
                blob,
                offset,
                data,
                len,
            } => BatchOperation::Update {
                blob: map(blob),
                offset,
                data,
                len,
            },
        })
        .collect()
}

/// Describe, validate, and canonicalize a batch without consuming its blob handles.
pub(crate) fn canonicalize_descriptors<B>(
    operations: &[BatchOperation<B>],
    mut location: impl FnMut(&B) -> (String, Vec<u8>),
) -> Result<Vec<Operation>, Error> {
    let descriptors = operations
        .iter()
        .map(|operation| match operation {
            BatchOperation::Remove(target) => Operation::Remove(target.clone()),
            BatchOperation::Resize { blob, len } => {
                let (partition, name) = location(blob);
                Operation::Resize {
                    partition,
                    name,
                    len: *len,
                }
            }
            BatchOperation::Update {
                blob,
                offset,
                data,
                len,
            } => {
                let (partition, name) = location(blob);
                Operation::Update {
                    partition,
                    name,
                    offset: *offset,
                    data: data.clone(),
                    len: *len,
                }
            }
        })
        .collect();
    canonicalize_operations(descriptors)
}

/// Validate and reduce a removal batch to its exact namespace set.
#[cfg(test)]
pub(crate) fn canonicalize_removals(
    targets: Vec<RemoveTarget>,
) -> Result<Vec<RemoveTarget>, Error> {
    canonicalize_operations(targets.into_iter().map(Operation::Remove).collect()).map(
        |operations| {
            operations
                .into_iter()
                .map(|operation| match operation {
                    Operation::Remove(target) => target,
                    Operation::Resize { .. } => {
                        unreachable!("removal-only input produced a blob mutation")
                    }
                    Operation::Update { .. } => {
                        unreachable!("removal-only input produced a blob mutation")
                    }
                })
                .collect()
        },
    )
}

/// Validate and reduce a mixed batch to a deterministic exact operation set.
pub(crate) fn canonicalize_operations(operations: Vec<Operation>) -> Result<Vec<Operation>, Error> {
    let mut partitions = BTreeMap::<String, PartitionOperations>::new();
    for operation in operations {
        match operation {
            Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                super::validate_partition_name(&partition)?;
                match partitions.entry(partition) {
                    Entry::Vacant(entry) => {
                        entry.insert(PartitionOperations::Blobs(BTreeMap::from([(
                            name,
                            BlobOperation::Remove,
                        )])));
                    }
                    Entry::Occupied(mut entry) => match entry.get_mut() {
                        PartitionOperations::Remove => {}
                        PartitionOperations::Blobs(blobs) => match blobs.entry(name) {
                            Entry::Vacant(entry) => {
                                entry.insert(BlobOperation::Remove);
                            }
                            Entry::Occupied(entry) => {
                                if !matches!(entry.get(), BlobOperation::Remove) {
                                    return Err(invalid_operations(
                                        "batch cannot remove and mutate the same blob",
                                    ));
                                }
                            }
                        },
                    },
                }
            }
            Operation::Remove(RemoveTarget::Partition(partition)) => {
                super::validate_partition_name(&partition)?;
                match partitions.entry(partition) {
                    Entry::Vacant(entry) => {
                        entry.insert(PartitionOperations::Remove);
                    }
                    Entry::Occupied(mut entry) => match entry.get() {
                        PartitionOperations::Remove => {}
                        PartitionOperations::Blobs(blobs)
                            if blobs
                                .values()
                                .any(|operation| !matches!(operation, BlobOperation::Remove)) =>
                        {
                            return Err(invalid_operations(
                                "batch cannot remove a partition containing a mutated blob",
                            ));
                        }
                        PartitionOperations::Blobs(_) => {
                            entry.insert(PartitionOperations::Remove);
                        }
                    },
                }
            }
            Operation::Resize {
                partition,
                name,
                len,
            } => {
                super::validate_partition_name(&partition)?;
                insert_mutation(&mut partitions, partition, name, BlobOperation::Resize(len))?;
            }
            Operation::Update {
                partition,
                name,
                offset,
                data,
                len,
            } => {
                super::validate_partition_name(&partition)?;
                validate_update(offset, data.len(), len)?;
                insert_mutation(
                    &mut partitions,
                    partition,
                    name,
                    BlobOperation::Update { offset, data, len },
                )?;
            }
        }
    }

    let mut canonical = Vec::new();
    for (partition, operations) in partitions {
        match operations {
            PartitionOperations::Remove => {
                canonical.push(Operation::Remove(RemoveTarget::Partition(partition)));
            }
            PartitionOperations::Blobs(blobs) => {
                canonical.extend(blobs.into_iter().map(|(name, operation)| match operation {
                    BlobOperation::Remove => Operation::Remove(RemoveTarget::Blob {
                        partition: partition.clone(),
                        name,
                    }),
                    BlobOperation::Resize(len) => Operation::Resize {
                        partition: partition.clone(),
                        name,
                        len,
                    },
                    BlobOperation::Update { offset, data, len } => Operation::Update {
                        partition: partition.clone(),
                        name,
                        offset,
                        data,
                        len,
                    },
                }));
            }
        }
    }
    Ok(canonical)
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn is_canonical_operations(operations: &[Operation]) -> Result<bool, Error> {
    let mut previous: Option<&Operation> = None;
    for operation in operations {
        super::validate_partition_name(operation.partition())?;
        if let Operation::Update {
            offset, data, len, ..
        } = operation
        {
            validate_update(*offset, data.len(), *len)?;
        }
        if let Some(previous) = previous {
            match previous.partition().cmp(operation.partition()) {
                std::cmp::Ordering::Greater => return Ok(false),
                std::cmp::Ordering::Equal => match (previous.name(), operation.name()) {
                    (Some(previous_name), Some(name)) if previous_name < name => {}
                    _ => return Ok(false),
                },
                std::cmp::Ordering::Less => {}
            }
        }
        previous = Some(operation);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remove(partition: &str, name: &[u8]) -> Operation {
        Operation::Remove(RemoveTarget::Blob {
            partition: partition.into(),
            name: name.to_vec(),
        })
    }

    fn resize(partition: &str, name: &[u8], len: u64) -> Operation {
        Operation::Resize {
            partition: partition.into(),
            name: name.to_vec(),
            len,
        }
    }

    fn update(
        partition: &str,
        name: &[u8],
        offset: u64,
        data: &'static [u8],
        len: u64,
    ) -> Operation {
        Operation::Update {
            partition: partition.into(),
            name: name.to_vec(),
            offset,
            data: data.into(),
            len,
        }
    }

    #[test]
    fn canonicalizes_mixed_operations() {
        let operations = vec![
            resize("beta", b"two", 22),
            remove("alpha", b"two"),
            resize("alpha", b"one", 11),
            update("beta", b"one", 1, b"new", 9),
            remove("alpha", b"two"),
            resize("beta", b"two", 22),
            update("beta", b"one", 1, b"new", 9),
            Operation::Remove(RemoveTarget::Blob {
                partition: "gamma".into(),
                name: b"subsumed".to_vec(),
            }),
            Operation::Remove(RemoveTarget::Partition("gamma".into())),
        ];

        assert_eq!(
            canonicalize_operations(operations).unwrap(),
            vec![
                resize("alpha", b"one", 11),
                remove("alpha", b"two"),
                update("beta", b"one", 1, b"new", 9),
                resize("beta", b"two", 22),
                Operation::Remove(RemoveTarget::Partition("gamma".into())),
            ]
        );
    }

    #[test]
    fn rejects_mixed_conflicts_and_invalid_partitions() {
        for operations in [
            vec![
                remove("partition", b"blob"),
                resize("partition", b"blob", 1),
            ],
            vec![
                resize("partition", b"blob", 1),
                remove("partition", b"blob"),
            ],
            vec![
                Operation::Remove(RemoveTarget::Partition("partition".into())),
                resize("partition", b"blob", 1),
            ],
            vec![
                resize("partition", b"blob", 1),
                Operation::Remove(RemoveTarget::Partition("partition".into())),
            ],
            vec![
                resize("partition", b"blob", 1),
                resize("partition", b"blob", 2),
            ],
            vec![
                resize("partition", b"blob", 4),
                update("partition", b"blob", 1, b"new", 4),
            ],
            vec![
                update("partition", b"blob", 1, b"new", 4),
                update("partition", b"blob", 0, b"old", 4),
            ],
            vec![update("partition", b"blob", u64::MAX, b"x", u64::MAX)],
            vec![update("partition", b"blob", 2, b"new", 4)],
        ] {
            let error = canonicalize_operations(operations).unwrap_err();
            match error {
                Error::Io(error) => assert_eq!(error.kind(), ErrorKind::InvalidInput),
                error => panic!("unexpected error: {error}"),
            }
        }

        assert!(canonicalize_operations(vec![resize("../invalid", b"blob", 1)]).is_err());
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod manifest {
    //! Crash-recoverable manifest for applying an exact storage operation set.
    //!
    //! Every batch is validated and canonicalized before the namespace is mutated. The manifest
    //! has one durable commit point:
    //!
    //! 1. Write and sync the operation set as the prepared manifest.
    //! 2. Rename it to the committed manifest and sync the control directory. Completion of this
    //!    directory sync commits the batch.
    //! 3. Apply every operation idempotently, sync mutated files, and sync affected directories.
    //! 4. Remove the committed manifest and sync the control directory.
    //!
    //! The prepared file is renamed only after `write_all` and `sync_all` succeed. A short or
    //! interrupted write therefore cannot commit and is discarded during recovery. The manifest
    //! has a bounded length and a CRC32 over its complete body. Recovery validates the checksum,
    //! magic, version, operation count, encoding, and canonical order before applying any
    //! operation. An invalid committed manifest blocks namespace access instead of guessing which
    //! targets were recorded.
    //!
    //! Recovery runs while the storage namespace is locked and before another namespace operation
    //! is exposed. It discards a prepared manifest. Before acting on a committed manifest or
    //! trusting its absence, it syncs the control directory so the visible marker state is
    //! authoritative.
    //!
    //! | Control state | Meaning | Recovery action |
    //! | --- | --- | --- |
    //! | No manifest | No batch awaits recovery | Continue without batch recovery |
    //! | Prepared manifest | The batch is not committed | Discard the prepared manifest |
    //! | Committed manifest | The whole batch is committed | Replay and remove the marker |
    //!
    //! Removal, resize, and exact update are idempotent, so recovery may safely repeat any
    //! completed prefix after an error, cancellation, or crash. A missing removal target succeeds,
    //! while a missing mutation target is fatal because a committed mutation must remain bound to
    //! its validated blob generation. The committed marker is removed only after every operation
    //! is synced. If marker removal itself was not durable, the marker may reappear after a crash
    //! and the same batch is completed again.
    //!
    //! A filesystem storage root must not be accessed concurrently by another storage instance or
    //! process. The manifest protocol relies on serialized namespace operations. CRC32 detects
    //! accidental corruption and torn data, but does not authenticate a manifest against another
    //! process with write access to the root.

    use super::{Operation, is_canonical_operations};
    use crate::RemoveTarget;
    use commonware_cryptography::Crc32;
    use commonware_formatting::hex;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::{self, File, OpenOptions},
        io::{self, ErrorKind, Read, Seek, SeekFrom, Write},
        path::{Path, PathBuf},
    };

    const CONTROL_DIRECTORY: &str = ".commonware";
    const COMMITTED_MANIFEST: &str = "_COMMONWARE_RUNTIME_STORAGE_BATCH";
    const PREPARED_MANIFEST: &str = "_COMMONWARE_RUNTIME_STORAGE_BATCH_PREPARED";
    const MANIFEST_MAGIC: &[u8] = COMMITTED_MANIFEST.as_bytes();
    const MANIFEST_VERSION: u16 = 1;
    const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;
    const MAX_OPERATIONS: usize = 1_000_000;
    const TAG_PARTITION: u8 = 0;
    const TAG_BLOB: u8 = 1;
    const TAG_RESIZE: u8 = 2;
    const TAG_UPDATE: u8 = 3;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Progress {
        Prepared,
        Committed,
        Applied(usize),
        MarkerRemoved,
    }

    fn invalid_data(message: &'static str) -> io::Error {
        io::Error::new(ErrorKind::InvalidData, message)
    }

    fn invalid_input(message: &'static str) -> io::Error {
        io::Error::new(ErrorKind::InvalidInput, message)
    }

    fn checked_add(total: &mut usize, amount: usize) -> io::Result<()> {
        *total = total
            .checked_add(amount)
            .ok_or_else(|| invalid_input("storage batch manifest length overflow"))?;
        if *total as u64 > MAX_MANIFEST_SIZE {
            return Err(invalid_input("storage batch manifest is too large"));
        }
        Ok(())
    }

    fn encoded_len(operations: &[Operation]) -> io::Result<usize> {
        if operations.len() > MAX_OPERATIONS || u32::try_from(operations.len()).is_err() {
            return Err(invalid_input("storage batch has too many operations"));
        }

        let mut len = MANIFEST_MAGIC.len() + size_of::<u16>() + size_of::<u32>();
        for operation in operations {
            let (partition, name) = match operation {
                Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                    (partition, Some(name))
                }
                Operation::Remove(RemoveTarget::Partition(partition)) => (partition, None),
                Operation::Resize {
                    partition, name, ..
                }
                | Operation::Update {
                    partition, name, ..
                } => (partition, Some(name)),
            };
            u32::try_from(partition.len())
                .map_err(|_| invalid_input("storage batch partition name is too large"))?;
            checked_add(&mut len, 1 + size_of::<u32>())?;
            checked_add(&mut len, partition.len())?;
            if let Some(name) = name {
                u32::try_from(name.len())
                    .map_err(|_| invalid_input("storage batch blob name is too large"))?;
                checked_add(&mut len, size_of::<u32>())?;
                checked_add(&mut len, name.len())?;
            }
            match operation {
                Operation::Resize { .. } => checked_add(&mut len, size_of::<u64>())?,
                Operation::Update { data, .. } => {
                    u32::try_from(data.len())
                        .map_err(|_| invalid_input("storage batch update data is too large"))?;
                    checked_add(
                        &mut len,
                        size_of::<u64>() + size_of::<u32>() + size_of::<u64>(),
                    )?;
                    checked_add(&mut len, data.len())?;
                }
                Operation::Remove(_) => {}
            }
        }
        checked_add(&mut len, size_of::<u32>())?;
        Ok(len)
    }

    /// Validate that a canonical operation set can be represented by the durable manifest.
    pub(crate) fn preflight(operations: &[Operation]) -> io::Result<()> {
        let canonical = is_canonical_operations(operations)
            .map_err(|_| invalid_input("storage batch contains an invalid operation"))?;
        if !canonical {
            return Err(invalid_input("storage batch operations are not canonical"));
        }
        encoded_len(operations)?;
        Ok(())
    }

    fn encode_manifest(operations: &[Operation]) -> io::Result<Vec<u8>> {
        preflight(operations)?;

        let mut encoded = Vec::with_capacity(encoded_len(operations)?);
        encoded.extend_from_slice(MANIFEST_MAGIC);
        encoded.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(operations.len() as u32).to_be_bytes());
        for operation in operations {
            match operation {
                Operation::Remove(RemoveTarget::Partition(partition)) => {
                    encoded.push(TAG_PARTITION);
                    encoded.extend_from_slice(&(partition.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(partition.as_bytes());
                }
                Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                    encoded.push(TAG_BLOB);
                    encoded.extend_from_slice(&(partition.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(partition.as_bytes());
                    encoded.extend_from_slice(&(name.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(name);
                }
                Operation::Resize {
                    partition,
                    name,
                    len,
                } => {
                    encoded.push(TAG_RESIZE);
                    encoded.extend_from_slice(&(partition.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(partition.as_bytes());
                    encoded.extend_from_slice(&(name.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(name);
                    encoded.extend_from_slice(&len.to_be_bytes());
                }
                Operation::Update {
                    partition,
                    name,
                    offset,
                    data,
                    len,
                } => {
                    encoded.push(TAG_UPDATE);
                    encoded.extend_from_slice(&(partition.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(partition.as_bytes());
                    encoded.extend_from_slice(&(name.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(name);
                    encoded.extend_from_slice(&offset.to_be_bytes());
                    encoded.extend_from_slice(&(data.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(data.as_ref());
                    encoded.extend_from_slice(&len.to_be_bytes());
                }
            }
        }
        let checksum = Crc32::checksum(&encoded);
        encoded.extend_from_slice(&checksum.to_be_bytes());
        Ok(encoded)
    }

    struct Cursor<'a> {
        bytes: &'a [u8],
        position: usize,
    }

    impl<'a> Cursor<'a> {
        const fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, position: 0 }
        }

        fn read(&mut self, len: usize) -> io::Result<&'a [u8]> {
            let end = self
                .position
                .checked_add(len)
                .ok_or_else(|| invalid_data("storage batch manifest length overflow"))?;
            let bytes = self
                .bytes
                .get(self.position..end)
                .ok_or_else(|| invalid_data("storage batch manifest is truncated"))?;
            self.position = end;
            Ok(bytes)
        }

        fn read_u8(&mut self) -> io::Result<u8> {
            Ok(self.read(1)?[0])
        }

        fn read_u16(&mut self) -> io::Result<u16> {
            Ok(u16::from_be_bytes(
                self.read(size_of::<u16>())?.try_into().unwrap(),
            ))
        }

        fn read_u32(&mut self) -> io::Result<u32> {
            Ok(u32::from_be_bytes(
                self.read(size_of::<u32>())?.try_into().unwrap(),
            ))
        }

        fn read_u64(&mut self) -> io::Result<u64> {
            Ok(u64::from_be_bytes(
                self.read(size_of::<u64>())?.try_into().unwrap(),
            ))
        }

        const fn finished(&self) -> bool {
            self.position == self.bytes.len()
        }
    }

    fn decode_manifest(encoded: &[u8]) -> io::Result<Vec<Operation>> {
        let minimum_len =
            MANIFEST_MAGIC.len() + size_of::<u16>() + size_of::<u32>() + size_of::<u32>();
        if encoded.len() < minimum_len || encoded.len() as u64 > MAX_MANIFEST_SIZE {
            return Err(invalid_data("storage batch manifest has an invalid length"));
        }

        let checksum_offset = encoded.len() - size_of::<u32>();
        let (body, checksum) = encoded.split_at(checksum_offset);
        let checksum = u32::from_be_bytes(checksum.try_into().unwrap());
        if Crc32::checksum(body) != checksum {
            return Err(invalid_data("storage batch manifest checksum mismatch"));
        }

        let mut cursor = Cursor::new(body);
        if cursor.read(MANIFEST_MAGIC.len())? != MANIFEST_MAGIC {
            return Err(invalid_data("storage batch manifest magic mismatch"));
        }
        if cursor.read_u16()? != MANIFEST_VERSION {
            return Err(invalid_data("unsupported storage batch manifest version"));
        }
        let count = usize::try_from(cursor.read_u32()?)
            .map_err(|_| invalid_data("storage batch operation count overflow"))?;
        if count == 0 || count > MAX_OPERATIONS {
            return Err(invalid_data(
                "storage batch manifest has an invalid operation count",
            ));
        }
        const MIN_OPERATION_SIZE: usize = 1 + size_of::<u32>() + 1;
        let remaining = cursor.bytes.len() - cursor.position;
        if count > remaining / MIN_OPERATION_SIZE {
            return Err(invalid_data(
                "storage batch operation count exceeds the manifest length",
            ));
        }

        let mut operations = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = cursor.read_u8()?;
            let partition_len = usize::try_from(cursor.read_u32()?)
                .map_err(|_| invalid_data("storage batch partition length overflow"))?;
            let partition = std::str::from_utf8(cursor.read(partition_len)?)
                .map_err(|_| invalid_data("storage batch partition is not UTF-8"))?
                .to_string();
            let operation = match tag {
                TAG_PARTITION => Operation::Remove(RemoveTarget::Partition(partition)),
                TAG_BLOB => {
                    let name_len = usize::try_from(cursor.read_u32()?)
                        .map_err(|_| invalid_data("storage batch blob length overflow"))?;
                    let name = cursor.read(name_len)?.to_vec();
                    Operation::Remove(RemoveTarget::Blob { partition, name })
                }
                TAG_RESIZE => {
                    let name_len = usize::try_from(cursor.read_u32()?)
                        .map_err(|_| invalid_data("storage batch blob length overflow"))?;
                    let name = cursor.read(name_len)?.to_vec();
                    let len = cursor.read_u64()?;
                    Operation::Resize {
                        partition,
                        name,
                        len,
                    }
                }
                TAG_UPDATE => {
                    let name_len = usize::try_from(cursor.read_u32()?)
                        .map_err(|_| invalid_data("storage batch blob length overflow"))?;
                    let name = cursor.read(name_len)?.to_vec();
                    let offset = cursor.read_u64()?;
                    let data_len = usize::try_from(cursor.read_u32()?)
                        .map_err(|_| invalid_data("storage batch update length overflow"))?;
                    let data = cursor.read(data_len)?.to_vec().into();
                    let len = cursor.read_u64()?;
                    Operation::Update {
                        partition,
                        name,
                        offset,
                        data,
                        len,
                    }
                }
                _ => {
                    return Err(invalid_data(
                        "storage batch manifest operation tag is invalid",
                    ));
                }
            };
            operations.push(operation);
        }
        if !cursor.finished() {
            return Err(invalid_data("storage batch manifest has trailing bytes"));
        }

        let canonical = is_canonical_operations(&operations)
            .map_err(|_| invalid_data("storage batch manifest contains an invalid operation"))?;
        if !canonical {
            return Err(invalid_data(
                "storage batch manifest operations are not canonical",
            ));
        }
        Ok(operations)
    }

    fn control_directory(root: &Path) -> PathBuf {
        root.join(CONTROL_DIRECTORY)
    }

    fn committed_manifest(root: &Path) -> PathBuf {
        control_directory(root).join(COMMITTED_MANIFEST)
    }

    fn prepared_manifest(root: &Path) -> PathBuf {
        control_directory(root).join(PREPARED_MANIFEST)
    }

    /// Resolve the stored spelling of an existing partition without conflating distinct directories
    /// on case-sensitive filesystems.
    pub(crate) fn resolve_partition_name(root: &Path, requested: &str) -> io::Result<String> {
        let requested_path = root.join(requested);
        match fs::symlink_metadata(&requested_path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Ok(requested.to_string()),
            Err(error) if path_is_missing(&error) => return Ok(requested.to_string()),
            Err(error) => return Err(error),
        }

        let mut alias = None;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Ok(actual) = entry.file_name().into_string() else {
                continue;
            };
            if actual == requested {
                return Ok(actual);
            }
            if !actual.eq_ignore_ascii_case(requested) {
                continue;
            }
            if alias.replace(actual).is_some() {
                return Err(invalid_data(
                    "storage partition name has ambiguous case aliases",
                ));
            }
        }

        alias.ok_or_else(|| {
            invalid_data("storage partition directory entry is not present in its root")
        })
    }

    /// Bind every existing partition reference to its physical directory spelling.
    pub(crate) fn resolve_operation_partitions(
        root: &Path,
        operations: &mut [Operation],
    ) -> io::Result<()> {
        let mut resolved = BTreeMap::new();
        for operation in operations {
            let partition = operation.partition_mut();
            if let Some(existing) = resolved.get(partition) {
                partition.clone_from(existing);
                continue;
            }
            let requested = partition.clone();
            let actual = resolve_partition_name(root, &requested)?;
            partition.clone_from(&actual);
            resolved.insert(requested, actual);
        }
        Ok(())
    }

    fn sync_directory(path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }

    fn require_directory(path: &Path) -> io::Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
            Ok(_) => Err(invalid_data(
                "storage batch control path is not a directory",
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn ensure_control_directory(root: &Path) -> io::Result<PathBuf> {
        let control = control_directory(root);
        if !require_directory(&control)? {
            fs::create_dir(&control)?;
        }
        // A visible control directory does not prove its root entry is durable. Establish that
        // prerequisite before every manifest commit.
        sync_directory(root)?;
        Ok(control)
    }

    fn discard_prepared(root: &Path) -> io::Result<()> {
        let prepared = prepared_manifest(root);
        match fs::symlink_metadata(&prepared) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(prepared)?;
                sync_directory(&control_directory(root))?;
            }
            Ok(_) => {
                return Err(invalid_data(
                    "prepared storage batch manifest is not a file",
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn read_committed(root: &Path) -> io::Result<Option<Vec<Operation>>> {
        let path = committed_manifest(root);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            Ok(_) => {
                return Err(invalid_data(
                    "committed storage batch manifest is not a file",
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if metadata.len() > MAX_MANIFEST_SIZE {
            return Err(invalid_data(
                "committed storage batch manifest is too large",
            ));
        }

        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take(MAX_MANIFEST_SIZE + 1)
            .read_to_end(&mut encoded)?;
        if encoded.len() as u64 > MAX_MANIFEST_SIZE {
            return Err(invalid_data(
                "committed storage batch manifest is too large",
            ));
        }
        decode_manifest(&encoded).map(Some)
    }

    fn remove_target(root: &Path, target: &RemoveTarget) -> io::Result<()> {
        let result = match target {
            RemoveTarget::Blob { partition, name } => {
                if name.is_empty() {
                    return Ok(());
                }
                let partition = root.join(partition);
                match fs::symlink_metadata(&partition) {
                    Ok(metadata) if metadata.file_type().is_dir() => {}
                    Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
                    Err(error) if path_is_missing(&error) => return Ok(()),
                    Err(error) => return Err(error),
                }
                fs::remove_file(partition.join(hex(name)))
            }
            RemoveTarget::Partition(partition) => {
                let partition = root.join(partition);
                match fs::symlink_metadata(&partition) {
                    Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(partition),
                    Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(partition),
                    Ok(_) => return Err(invalid_data("partition path is not a directory")),
                    Err(error) if path_is_missing(&error) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) if path_is_missing(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn path_is_missing(error: &io::Error) -> bool {
        if error.kind() == ErrorKind::NotFound {
            return true;
        }
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ENAMETOOLONG) {
            return true;
        }
        false
    }

    fn open_blob_for_mutation(root: &Path, partition: &str, name: &[u8]) -> io::Result<File> {
        let partition_path = root.join(partition);
        match fs::symlink_metadata(&partition_path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
            Err(error) => return Err(error),
        }

        let blob_path = partition_path.join(hex(name));
        match fs::symlink_metadata(&blob_path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(invalid_data("mutated blob path is not a regular file")),
            Err(error) => return Err(error),
        }

        OpenOptions::new().write(true).open(blob_path)
    }

    fn resize_blob(root: &Path, partition: &str, name: &[u8], len: u64) -> io::Result<()> {
        let file = open_blob_for_mutation(root, partition, name)?;
        file.set_len(len)?;
        file.sync_all()
    }

    fn update_blob(
        root: &Path,
        partition: &str,
        name: &[u8],
        offset: u64,
        data: &[u8],
        len: u64,
    ) -> io::Result<()> {
        let mut file = open_blob_for_mutation(root, partition, name)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        file.set_len(len)?;
        file.sync_all()
    }

    fn sync_operations(root: &Path, operations: &[Operation]) -> io::Result<()> {
        let partitions = operations
            .iter()
            .filter_map(|operation| match operation {
                Operation::Remove(RemoveTarget::Blob { partition, .. })
                | Operation::Resize { partition, .. }
                | Operation::Update { partition, .. } => Some(root.join(partition)),
                Operation::Remove(RemoveTarget::Partition(_)) => None,
            })
            .collect::<BTreeSet<_>>();
        for partition in partitions {
            match fs::symlink_metadata(&partition) {
                Ok(metadata) if metadata.file_type().is_dir() => sync_directory(&partition)?,
                Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
                Err(error) if path_is_missing(&error) => {}
                Err(error) => return Err(error),
            }
        }
        sync_directory(root)
    }

    fn finish_committed<F, S>(
        root: &Path,
        operations: &[Operation],
        hook: &mut F,
        sync_control: &mut S,
    ) -> io::Result<()>
    where
        F: FnMut(Progress) -> io::Result<()>,
        S: FnMut(&Path) -> io::Result<()>,
    {
        for (index, operation) in operations.iter().enumerate() {
            match operation {
                Operation::Remove(target) => remove_target(root, target)?,
                Operation::Resize {
                    partition,
                    name,
                    len,
                } => resize_blob(root, partition, name, *len)?,
                Operation::Update {
                    partition,
                    name,
                    offset,
                    data,
                    len,
                } => update_blob(root, partition, name, *offset, data.as_ref(), *len)?,
            }
            hook(Progress::Applied(index + 1))?;
        }
        sync_operations(root, operations)?;
        fs::remove_file(committed_manifest(root))?;
        hook(Progress::MarkerRemoved)?;
        sync_control(&control_directory(root))
    }

    fn apply_batch_with_callbacks<C, F, S>(
        root: &Path,
        operations: &[Operation],
        on_commit: C,
        mut hook: F,
        mut sync_control: S,
    ) -> io::Result<()>
    where
        C: FnOnce(&[Operation]),
        F: FnMut(Progress) -> io::Result<()>,
        S: FnMut(&Path) -> io::Result<()>,
    {
        if operations.is_empty() {
            return Ok(());
        }
        let encoded = encode_manifest(operations)?;
        let removal_only = operations
            .iter()
            .all(|operation| matches!(operation, Operation::Remove(_)));

        let root_metadata = match fs::metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound && removal_only => return Ok(()),
            Err(error) => return Err(error),
        };
        if !root_metadata.is_dir() {
            if removal_only {
                // No control directory can exist below a non-directory root. Missing removals
                // remain idempotent even when the storage root itself has been replaced.
                return Ok(());
            }
            return Err(invalid_data("storage batch root is not a directory"));
        }

        let control = ensure_control_directory(root)?;
        let prepared = prepared_manifest(root);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&prepared)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        hook(Progress::Prepared)?;

        fs::rename(prepared, committed_manifest(root))?;
        sync_control(&control)?;
        on_commit(operations);
        hook(Progress::Committed)?;
        finish_committed(root, operations, &mut hook, &mut sync_control)
    }

    #[cfg(test)]
    fn apply_batch_with<F>(root: &Path, operations: &[Operation], hook: F) -> io::Result<()>
    where
        F: FnMut(Progress) -> io::Result<()>,
    {
        apply_batch_with_callbacks(root, operations, |_| {}, hook, sync_directory)
    }

    fn recover_with_callbacks<C, S>(
        root: &Path,
        on_commit: C,
        mut sync_control: S,
    ) -> io::Result<()>
    where
        C: FnOnce(&[Operation]),
        S: FnMut(&Path) -> io::Result<()>,
    {
        let root_metadata = match fs::metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !root_metadata.is_dir() {
            // No control directory can exist below a non-directory root. Let the requested
            // namespace operation preserve its more specific error classification.
            return Ok(());
        }
        let control = control_directory(root);
        if !require_directory(&control)? {
            return Ok(());
        }

        discard_prepared(root)?;
        let operations = read_committed(root)?;
        // Marker presence and absence become authoritative only after this directory is synced.
        sync_control(&control)?;
        let Some(operations) = operations else {
            return Ok(());
        };
        on_commit(&operations);
        finish_committed(root, &operations, &mut |_| Ok(()), &mut sync_control)
    }

    fn recover_with<S>(root: &Path, sync_control: S) -> io::Result<()>
    where
        S: FnMut(&Path) -> io::Result<()>,
    {
        recover_with_callbacks(root, |_| {}, sync_control)
    }

    /// Complete or discard any batch state before exposing the storage namespace.
    pub(crate) fn recover(root: &Path) -> io::Result<()> {
        recover_with(root, sync_directory)
    }

    /// Complete or discard batch state and notify after observing a durable commit.
    pub(crate) fn recover_notifying<C>(root: &Path, on_commit: C) -> io::Result<()>
    where
        C: FnOnce(&[Operation]),
    {
        recover_with_callbacks(root, on_commit, sync_directory)
    }

    /// Durably commit and complete a canonical storage operation batch.
    ///
    /// `on_commit` runs after the commit marker is durable and before any committed operation is
    /// applied. It is not called for a logical no-op that needs no manifest.
    pub(crate) fn apply_batch<C>(
        root: &Path,
        operations: &[Operation],
        on_commit: C,
    ) -> io::Result<()>
    where
        C: FnOnce(&[Operation]),
    {
        apply_batch_with_callbacks(root, operations, on_commit, |_| Ok(()), sync_directory)
    }

    #[cfg(test)]
    pub(crate) fn interrupt_committed_for_test(
        root: &Path,
        operations: &[Operation],
        after_operations: usize,
    ) -> io::Result<()> {
        apply_batch_with(root, operations, |progress| {
            let stop = if after_operations == 0 {
                progress == Progress::Committed
            } else {
                progress == Progress::Applied(after_operations)
            };
            if stop {
                return Err(io::Error::other(
                    "injected committed storage batch interruption",
                ));
            }
            Ok(())
        })
    }

    #[cfg(all(test, not(feature = "iouring-storage")))]
    pub(crate) fn fail_final_control_sync_for_test<C>(
        root: &Path,
        operations: &[Operation],
        on_commit: C,
    ) -> io::Result<()>
    where
        C: FnOnce(&[Operation]),
    {
        let mut control_syncs = 0;
        apply_batch_with_callbacks(
            root,
            operations,
            on_commit,
            |_| Ok(()),
            |path| {
                control_syncs += 1;
                if control_syncs == 2 {
                    return Err(io::Error::other("injected final control sync failure"));
                }
                sync_directory(path)
            },
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::storage::batch::{canonicalize_operations, canonicalize_removals};
        use std::{
            cell::Cell,
            sync::atomic::{AtomicU64, Ordering},
        };

        static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

        fn test_root(name: &str) -> PathBuf {
            std::env::temp_dir().join(format!(
                "runtime_storage_batch_{name}_{}_{}",
                std::process::id(),
                NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
            ))
        }

        fn create_blob(root: &Path, partition: &str, name: &[u8]) -> PathBuf {
            let directory = root.join(partition);
            fs::create_dir_all(&directory).unwrap();
            let path = directory.join(hex(name));
            fs::write(&path, b"blob").unwrap();
            path
        }

        fn removals(targets: Vec<RemoveTarget>) -> Vec<Operation> {
            canonicalize_removals(targets)
                .unwrap()
                .into_iter()
                .map(Operation::Remove)
                .collect()
        }

        fn resize(partition: &str, name: &[u8], len: u64) -> Operation {
            Operation::Resize {
                partition: partition.into(),
                name: name.to_vec(),
                len,
            }
        }

        fn update(
            partition: &str,
            name: &[u8],
            offset: u64,
            data: &'static [u8],
            len: u64,
        ) -> Operation {
            Operation::Update {
                partition: partition.into(),
                name: name.to_vec(),
                offset,
                data: data.into(),
                len,
            }
        }

        #[test]
        fn canonicalizes_and_validates_before_returning() {
            let targets = vec![
                RemoveTarget::Blob {
                    partition: "beta".into(),
                    name: b"two".to_vec(),
                },
                RemoveTarget::Blob {
                    partition: "alpha".into(),
                    name: b"one".to_vec(),
                },
                RemoveTarget::Blob {
                    partition: "beta".into(),
                    name: b"two".to_vec(),
                },
                RemoveTarget::Partition("beta".into()),
            ];
            assert_eq!(
                canonicalize_removals(targets).unwrap(),
                vec![
                    RemoveTarget::Blob {
                        partition: "alpha".into(),
                        name: b"one".to_vec(),
                    },
                    RemoveTarget::Partition("beta".into()),
                ]
            );

            assert!(
                canonicalize_removals(vec![
                    RemoveTarget::Partition("valid".into()),
                    RemoveTarget::Partition("../invalid".into()),
                ])
                .is_err()
            );
        }

        #[test]
        fn recovery_discards_uncommitted_staging() {
            let root = test_root("prepared");
            let blob = create_blob(&root, "partition", b"blob");
            let operations = removals(vec![RemoveTarget::Blob {
                partition: "partition".into(),
                name: b"blob".to_vec(),
            }]);

            let result = apply_batch_with(&root, &operations, |progress| {
                if progress == Progress::Prepared {
                    return Err(io::Error::other("stop before commit"));
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(blob.exists());
            assert!(prepared_manifest(&root).exists());

            recover(&root).unwrap();
            assert!(blob.exists());
            assert!(!prepared_manifest(&root).exists());
            assert!(!committed_manifest(&root).exists());
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn recovery_completes_partially_applied_commit() {
            let root = test_root("committed");
            let first = create_blob(&root, "alpha", b"remove");
            let keep = create_blob(&root, "alpha", b"keep");
            let partition = create_blob(&root, "beta", b"remove");
            let untouched = create_blob(&root, "gamma", b"keep");
            let operations = removals(vec![
                RemoveTarget::Partition("beta".into()),
                RemoveTarget::Blob {
                    partition: "alpha".into(),
                    name: b"remove".to_vec(),
                },
            ]);

            let result = apply_batch_with(&root, &operations, |progress| {
                if progress == Progress::Applied(1) {
                    return Err(io::Error::other("stop after first deletion"));
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(!first.exists());
            assert!(partition.exists());
            assert!(committed_manifest(&root).exists());

            recover(&root).unwrap();
            assert!(!first.exists());
            assert!(!root.join("beta").exists());
            assert!(keep.exists());
            assert!(untouched.exists());
            assert!(!committed_manifest(&root).exists());
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn recovery_replays_partially_applied_mutations_and_removal() {
            let root = test_root("mixed_committed");
            let resized = create_blob(&root, "alpha", b"resize");
            fs::write(&resized, b"resize contents").unwrap();
            let updated = create_blob(&root, "beta", b"update");
            fs::write(&updated, b"update-old").unwrap();
            let removed = create_blob(&root, "gamma", b"remove");
            let target = RemoveTarget::Blob {
                partition: "gamma".into(),
                name: b"remove".to_vec(),
            };
            let operations = canonicalize_operations(vec![
                Operation::Remove(target),
                resize("alpha", b"resize", 3),
                update("beta", b"update", 2, b"NEW", 5),
            ])
            .unwrap();

            let error = interrupt_committed_for_test(&root, &operations, 2).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Other);
            assert_eq!(fs::metadata(&resized).unwrap().len(), 3);
            assert_eq!(fs::read(&updated).unwrap(), b"upNEW");
            assert!(removed.exists());
            assert!(committed_manifest(&root).exists());

            recover(&root).unwrap();
            assert_eq!(fs::metadata(&resized).unwrap().len(), 3);
            assert_eq!(fs::read(&updated).unwrap(), b"upNEW");
            assert!(!removed.exists());
            assert!(!committed_manifest(&root).exists());

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn recovery_repairs_a_partially_applied_update() {
            let root = test_root("partial_update");
            let updated = create_blob(&root, "partition", b"update");
            fs::write(&updated, b"update-old").unwrap();
            let operations = vec![update("partition", b"update", 2, b"NEW", 5)];

            let error = interrupt_committed_for_test(&root, &operations, 0).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Other);
            fs::write(&updated, b"upNate-old").unwrap();

            recover(&root).unwrap();
            assert_eq!(fs::read(&updated).unwrap(), b"upNEW");
            assert!(!committed_manifest(&root).exists());

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn recovery_finishes_a_partially_removed_partition() {
            let root = test_root("partial_partition");
            let first = create_blob(&root, "partition", b"first");
            let second = create_blob(&root, "partition", b"second");
            let operations = vec![Operation::Remove(RemoveTarget::Partition(
                "partition".into(),
            ))];

            let error = interrupt_committed_for_test(&root, &operations, 0).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Other);
            fs::remove_file(first).unwrap();
            assert!(second.exists());

            recover(&root).unwrap();
            assert!(!root.join("partition").exists());
            assert!(!committed_manifest(&root).exists());

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn commit_notification_survives_final_control_sync_failure() {
            let root = test_root("commit_notification");
            let blob = create_blob(&root, "partition", b"blob");
            let operations = removals(vec![RemoveTarget::Blob {
                partition: "partition".into(),
                name: b"blob".to_vec(),
            }]);
            let notified = Cell::new(false);
            let control_syncs = Cell::new(0);

            let result = apply_batch_with_callbacks(
                &root,
                &operations,
                |_| notified.set(true),
                |_| Ok(()),
                |path| {
                    let next = control_syncs.get() + 1;
                    control_syncs.set(next);
                    if next == 2 {
                        return Err(io::Error::other("injected final control sync failure"));
                    }
                    sync_directory(path)
                },
            );
            assert!(result.is_err());
            assert!(notified.get());
            assert!(!blob.exists());
            assert!(!committed_manifest(&root).exists());

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn precommit_failure_does_not_notify() {
            let root = test_root("precommit_notification");
            let blob = create_blob(&root, "partition", b"blob");
            let operations = removals(vec![RemoveTarget::Blob {
                partition: "partition".into(),
                name: b"blob".to_vec(),
            }]);
            let notified = Cell::new(false);

            let result = apply_batch_with_callbacks(
                &root,
                &operations,
                |_| notified.set(true),
                |progress| {
                    if progress == Progress::Prepared {
                        return Err(io::Error::other("injected precommit failure"));
                    }
                    Ok(())
                },
                sync_directory,
            );
            assert!(result.is_err());
            assert!(!notified.get());
            assert!(blob.exists());

            recover(&root).unwrap();
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn committed_resize_requires_an_existing_regular_blob() {
            let root = test_root("missing_resize");
            fs::create_dir_all(&root).unwrap();
            let operations = vec![resize("partition", b"missing", 1)];

            let error = apply_batch(&root, &operations, |_| {}).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound);
            assert!(committed_manifest(&root).exists());
            assert_eq!(recover(&root).unwrap_err().kind(), ErrorKind::NotFound);

            fs::remove_file(committed_manifest(&root)).unwrap();
            fs::remove_dir(control_directory(&root)).unwrap();
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn recovery_retries_marker_removal_sync() {
            let root = test_root("marker_sync");
            let blob = create_blob(&root, "partition", b"blob");
            let operations = removals(vec![RemoveTarget::Blob {
                partition: "partition".into(),
                name: b"blob".to_vec(),
            }]);
            let result = apply_batch_with(&root, &operations, |progress| {
                if progress == Progress::MarkerRemoved {
                    return Err(io::Error::other("injected marker sync failure"));
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(!blob.exists());
            assert!(!committed_manifest(&root).exists());

            // The marker's absence is not durable until recovery can open and sync its directory.
            assert!(
                recover_with(&root, |_| Err(io::Error::other("injected sync failure"))).is_err()
            );
            recover(&root).unwrap();
            let recreated = create_blob(&root, "partition", b"blob");
            recover(&root).unwrap();
            assert!(recreated.exists());

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn recovery_publishes_visible_commit_before_deleting() {
            let root = test_root("commit_sync");
            let blob = create_blob(&root, "partition", b"blob");
            let operations = removals(vec![RemoveTarget::Blob {
                partition: "partition".into(),
                name: b"blob".to_vec(),
            }]);
            let result = apply_batch_with(&root, &operations, |progress| {
                if progress == Progress::Committed {
                    return Err(io::Error::other("injected committed interruption"));
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(blob.exists());
            assert!(committed_manifest(&root).exists());

            // Recovery cannot delete until the visible commit is durably published.
            assert!(
                recover_with(&root, |_| Err(io::Error::other("injected sync failure"))).is_err()
            );
            assert!(blob.exists());
            recover(&root).unwrap();
            assert!(!blob.exists());

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn malformed_committed_manifest_blocks_recovery() {
            let root = test_root("malformed");
            let blob = create_blob(&root, "partition", b"blob");
            let operations = removals(vec![RemoveTarget::Blob {
                partition: "partition".into(),
                name: b"blob".to_vec(),
            }]);
            let control = ensure_control_directory(&root).unwrap();
            let mut encoded = encode_manifest(&operations).unwrap();
            encoded[0] ^= 1;
            fs::write(committed_manifest(&root), encoded).unwrap();

            let error = recover(&root).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(blob.exists());
            assert!(committed_manifest(&root).exists());

            fs::remove_file(committed_manifest(&root)).unwrap();
            fs::remove_dir(control).unwrap();
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn decoder_rejects_excessive_operation_count_before_allocating() {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(MANIFEST_MAGIC);
            encoded.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
            encoded.extend_from_slice(&((MAX_OPERATIONS as u32) + 1).to_be_bytes());
            let checksum = Crc32::checksum(&encoded);
            encoded.extend_from_slice(&checksum.to_be_bytes());

            let error = decode_manifest(&encoded).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }

        #[test]
        fn decoder_rejects_checksum_valid_invalid_update() {
            let mut encoded =
                encode_manifest(&[update("partition", b"blob", 2, b"new", 5)]).unwrap();
            let checksum_offset = encoded.len() - size_of::<u32>();
            let len_offset = checksum_offset - size_of::<u64>();
            encoded[len_offset..checksum_offset].copy_from_slice(&4u64.to_be_bytes());
            let checksum = Crc32::checksum(&encoded[..checksum_offset]);
            encoded[checksum_offset..].copy_from_slice(&checksum.to_be_bytes());

            let error = decode_manifest(&encoded).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }

        #[test]
        fn manifest_layout_and_checksum_round_trip() {
            let operations = vec![
                Operation::Remove(RemoveTarget::Partition("alpha".into())),
                Operation::Remove(RemoveTarget::Blob {
                    partition: "beta".into(),
                    name: vec![0, 0xff],
                }),
                resize("gamma", &[1, 2, 3], 0x0102_0304_0506_0708),
                update(
                    "theta",
                    &[4, 5],
                    0x1112_1314_1516_1718,
                    b"new",
                    0x2122_2324_2526_2728,
                ),
            ];
            let encoded = encode_manifest(&operations).unwrap();

            let mut expected = Vec::new();
            expected.extend_from_slice(MANIFEST_MAGIC);
            expected.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
            expected.extend_from_slice(&4u32.to_be_bytes());
            expected.push(TAG_PARTITION);
            expected.extend_from_slice(&5u32.to_be_bytes());
            expected.extend_from_slice(b"alpha");
            expected.push(TAG_BLOB);
            expected.extend_from_slice(&4u32.to_be_bytes());
            expected.extend_from_slice(b"beta");
            expected.extend_from_slice(&2u32.to_be_bytes());
            expected.extend_from_slice(&[0, 0xff]);
            expected.push(TAG_RESIZE);
            expected.extend_from_slice(&5u32.to_be_bytes());
            expected.extend_from_slice(b"gamma");
            expected.extend_from_slice(&3u32.to_be_bytes());
            expected.extend_from_slice(&[1, 2, 3]);
            expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
            expected.push(TAG_UPDATE);
            expected.extend_from_slice(&5u32.to_be_bytes());
            expected.extend_from_slice(b"theta");
            expected.extend_from_slice(&2u32.to_be_bytes());
            expected.extend_from_slice(&[4, 5]);
            expected.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());
            expected.extend_from_slice(&3u32.to_be_bytes());
            expected.extend_from_slice(b"new");
            expected.extend_from_slice(&0x2122_2324_2526_2728u64.to_be_bytes());
            let checksum = Crc32::checksum(&expected);
            expected.extend_from_slice(&checksum.to_be_bytes());

            assert_eq!(encoded, expected);
            assert_eq!(decode_manifest(&encoded).unwrap(), operations);
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
pub(crate) use manifest::fail_final_control_sync_for_test;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use manifest::interrupt_committed_for_test;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use manifest::{
    apply_batch, preflight, recover, recover_notifying, resolve_operation_partitions,
    resolve_partition_name,
};
