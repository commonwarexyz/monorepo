//! Validation and canonicalization of storage namespace operation sets.
//!
//! Duplicate removals are discarded, and a partition removal subsumes every blob removal in that
//! partition. Duplicate blob mutations with identical inputs are discarded. A mutation conflicts
//! with an exact or partition removal that covers the same blob, and a blob cannot be both resized
//! and updated in one batch.

use crate::{Error, IoBuf, RemoveTarget};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::{self, ErrorKind},
};

/// A validated filesystem operation whose mutation target has already been bound to a live handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    /// Remove an exact namespace target.
    Remove(RemoveTarget),
    /// Resize an exact blob to a raw physical length.
    Resize {
        partition: String,
        name: Vec<u8>,
        len: u64,
    },
    /// Write bytes and resize an exact blob using raw physical offsets and lengths.
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
}

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

fn validate_update(offset: u64, data_len: usize, len: u64) -> Result<(), Error> {
    let data_len = u64::try_from(data_len)
        .map_err(|_| invalid_operations("batch update data length overflows u64"))?;
    let end = offset
        .checked_add(data_len)
        .ok_or_else(|| invalid_operations("batch update range overflows u64"))?;
    if end > len {
        return Err(invalid_operations(
            "batch update data extends beyond its final length",
        ));
    }
    Ok(())
}

/// Validate and reduce a removal batch to its exact namespace set.
#[cfg(test)]
pub(crate) fn canonicalize(targets: Vec<RemoveTarget>) -> Result<Vec<RemoveTarget>, Error> {
    canonicalize_operations(targets.into_iter().map(Operation::Remove).collect()).map(
        |operations| {
            operations
                .into_iter()
                .map(|operation| match operation {
                    Operation::Remove(target) => target,
                    Operation::Resize { .. } | Operation::Update { .. } => {
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
                match partitions.entry(partition) {
                    Entry::Vacant(entry) => {
                        entry.insert(PartitionOperations::Blobs(BTreeMap::from([(
                            name,
                            BlobOperation::Resize(len),
                        )])));
                    }
                    Entry::Occupied(mut entry) => match entry.get_mut() {
                        PartitionOperations::Remove => {
                            return Err(invalid_operations(
                                "batch cannot resize a blob in a removed partition",
                            ));
                        }
                        PartitionOperations::Blobs(blobs) => match blobs.entry(name) {
                            Entry::Vacant(entry) => {
                                entry.insert(BlobOperation::Resize(len));
                            }
                            Entry::Occupied(entry) => match entry.get() {
                                BlobOperation::Remove => {
                                    return Err(invalid_operations(
                                        "batch cannot remove and resize the same blob",
                                    ));
                                }
                                BlobOperation::Resize(existing) if *existing == len => {}
                                BlobOperation::Resize(_) => {
                                    return Err(invalid_operations(
                                        "batch contains conflicting resize lengths",
                                    ));
                                }
                                BlobOperation::Update { .. } => {
                                    return Err(invalid_operations(
                                        "batch cannot resize and update the same blob",
                                    ));
                                }
                            },
                        },
                    },
                }
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
                match partitions.entry(partition) {
                    Entry::Vacant(entry) => {
                        entry.insert(PartitionOperations::Blobs(BTreeMap::from([(
                            name,
                            BlobOperation::Update { offset, data, len },
                        )])));
                    }
                    Entry::Occupied(mut entry) => match entry.get_mut() {
                        PartitionOperations::Remove => {
                            return Err(invalid_operations(
                                "batch cannot update a blob in a removed partition",
                            ));
                        }
                        PartitionOperations::Blobs(blobs) => match blobs.entry(name) {
                            Entry::Vacant(entry) => {
                                entry.insert(BlobOperation::Update { offset, data, len });
                            }
                            Entry::Occupied(entry) => match entry.get() {
                                BlobOperation::Remove => {
                                    return Err(invalid_operations(
                                        "batch cannot remove and update the same blob",
                                    ));
                                }
                                BlobOperation::Resize(_) => {
                                    return Err(invalid_operations(
                                        "batch cannot resize and update the same blob",
                                    ));
                                }
                                BlobOperation::Update {
                                    offset: existing_offset,
                                    data: existing_data,
                                    len: existing_len,
                                } if *existing_offset == offset
                                    && *existing_len == len
                                    && *existing_data == data => {}
                                BlobOperation::Update { .. } => {
                                    return Err(invalid_operations(
                                        "batch contains conflicting blob updates",
                                    ));
                                }
                            },
                        },
                    },
                }
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

    fn update(partition: &str, name: &[u8], offset: u64, data: &[u8], len: u64) -> Operation {
        Operation::Update {
            partition: partition.into(),
            name: name.to_vec(),
            offset,
            data: data.to_vec().into(),
            len,
        }
    }

    #[test]
    fn canonicalizes_mixed_operations() {
        let operations = vec![
            resize("beta", b"two", 22),
            update("delta", b"three", 3, b"data", 9),
            update("delta", b"three", 3, b"data", 9),
            remove("alpha", b"two"),
            resize("alpha", b"one", 11),
            remove("alpha", b"two"),
            resize("beta", b"two", 22),
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
                resize("beta", b"two", 22),
                update("delta", b"three", 3, b"data", 9),
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
                remove("partition", b"blob"),
                update("partition", b"blob", 0, b"x", 1),
            ],
            vec![
                update("partition", b"blob", 0, b"x", 1),
                remove("partition", b"blob"),
            ],
            vec![
                Operation::Remove(RemoveTarget::Partition("partition".into())),
                update("partition", b"blob", 0, b"x", 1),
            ],
            vec![
                update("partition", b"blob", 0, b"x", 1),
                Operation::Remove(RemoveTarget::Partition("partition".into())),
            ],
            vec![
                resize("partition", b"blob", 1),
                update("partition", b"blob", 0, b"x", 1),
            ],
            vec![
                update("partition", b"blob", 0, b"x", 1),
                resize("partition", b"blob", 1),
            ],
            vec![
                update("partition", b"blob", 0, b"x", 1),
                update("partition", b"blob", 0, b"y", 1),
            ],
            vec![update("partition", b"blob", 1, b"x", 1)],
            vec![update("partition", b"blob", u64::MAX, b"x", u64::MAX)],
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
