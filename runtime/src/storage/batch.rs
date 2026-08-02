//! Validation and canonicalization of storage namespace operation sets.
//!
//! Public atomic batches remove exact blob handles. The internal operation form also represents
//! ordinary whole-partition invalidation, where a partition removal subsumes its blob removals.
//! Identical operations are discarded, while different mutations of one blob conflict.
//!
//! The participant-replicated filesystem protocol is documented in the `coordinator` submodule;
//! despite the historical module name, it creates no coordinator file.

use crate::{BatchOperation, Error, RemoveTarget};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::{self, ErrorKind},
};

/// An exact namespace operation used for validation and canonicalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    /// Remove an exact namespace target.
    Remove(RemoveTarget),
    /// Publish the pending epoch of an exact atomic blob.
    Publish { partition: String, name: Vec<u8> },
    /// Rewind an exact blob to `len` bytes.
    Rewind {
        partition: String,
        name: Vec<u8>,
        len: u64,
    },
}

#[cfg(not(target_arch = "wasm32"))]
impl Operation {
    fn partition(&self) -> &str {
        match self {
            Self::Remove(RemoveTarget::Blob { partition, .. })
            | Self::Remove(RemoveTarget::Partition(partition))
            | Self::Publish { partition, .. }
            | Self::Rewind { partition, .. } => partition,
        }
    }

    fn name(&self) -> Option<&[u8]> {
        match self {
            Self::Remove(RemoveTarget::Partition(_)) => None,
            Self::Remove(RemoveTarget::Blob { name, .. })
            | Self::Publish { name, .. }
            | Self::Rewind { name, .. } => Some(name),
        }
    }
}

#[derive(Eq, PartialEq)]
enum BlobOperation {
    Remove,
    Publish,
    Rewind(u64),
}

enum PartitionOperations {
    Blobs(BTreeMap<Vec<u8>, BlobOperation>),
    Remove,
}

fn invalid_operations(message: &'static str) -> Error {
    io::Error::new(ErrorKind::InvalidInput, message).into()
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
            BatchOperation::Remove(blob) => BatchOperation::Remove(map(blob)),
            BatchOperation::Publish(blob) => BatchOperation::Publish(map(blob)),
            BatchOperation::Rewind { blob, len } => BatchOperation::Rewind {
                blob: map(blob),
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
            BatchOperation::Remove(blob) => {
                let (partition, name) = location(blob);
                Operation::Remove(RemoveTarget::Blob { partition, name })
            }
            BatchOperation::Publish(blob) => {
                let (partition, name) = location(blob);
                Operation::Publish { partition, name }
            }
            BatchOperation::Rewind { blob, len } => {
                let (partition, name) = location(blob);
                Operation::Rewind {
                    partition,
                    name,
                    len: *len,
                }
            }
        })
        .collect();
    canonicalize_operations(descriptors)
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
            Operation::Rewind {
                partition,
                name,
                len,
            } => {
                super::validate_partition_name(&partition)?;
                insert_mutation(&mut partitions, partition, name, BlobOperation::Rewind(len))?;
            }
            Operation::Publish { partition, name } => {
                super::validate_partition_name(&partition)?;
                insert_mutation(&mut partitions, partition, name, BlobOperation::Publish)?;
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
                    BlobOperation::Publish => Operation::Publish {
                        partition: partition.clone(),
                        name,
                    },
                    BlobOperation::Rewind(len) => Operation::Rewind {
                        partition: partition.clone(),
                        name,
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

    fn rewind(partition: &str, name: &[u8], len: u64) -> Operation {
        Operation::Rewind {
            partition: partition.into(),
            name: name.to_vec(),
            len,
        }
    }

    fn publish(partition: &str, name: &[u8]) -> Operation {
        Operation::Publish {
            partition: partition.into(),
            name: name.to_vec(),
        }
    }

    #[test]
    fn canonicalizes_mixed_operations() {
        let operations = vec![
            rewind("beta", b"two", 22),
            publish("delta", b"one"),
            publish("delta", b"one"),
            remove("alpha", b"two"),
            rewind("alpha", b"one", 11),
            remove("beta", b"one"),
            remove("alpha", b"two"),
            rewind("beta", b"two", 22),
            remove("beta", b"one"),
            Operation::Remove(RemoveTarget::Blob {
                partition: "gamma".into(),
                name: b"subsumed".to_vec(),
            }),
            Operation::Remove(RemoveTarget::Partition("gamma".into())),
        ];

        assert_eq!(
            canonicalize_operations(operations).unwrap(),
            vec![
                rewind("alpha", b"one", 11),
                remove("alpha", b"two"),
                remove("beta", b"one"),
                rewind("beta", b"two", 22),
                publish("delta", b"one"),
                Operation::Remove(RemoveTarget::Partition("gamma".into())),
            ]
        );
    }

    #[test]
    fn rejects_mixed_conflicts_and_invalid_partitions() {
        for operations in [
            vec![
                remove("partition", b"blob"),
                rewind("partition", b"blob", 1),
            ],
            vec![
                rewind("partition", b"blob", 1),
                remove("partition", b"blob"),
            ],
            vec![
                Operation::Remove(RemoveTarget::Partition("partition".into())),
                rewind("partition", b"blob", 1),
            ],
            vec![
                rewind("partition", b"blob", 1),
                Operation::Remove(RemoveTarget::Partition("partition".into())),
            ],
            vec![
                rewind("partition", b"blob", 1),
                rewind("partition", b"blob", 2),
            ],
            vec![
                publish("partition", b"blob"),
                rewind("partition", b"blob", 1),
            ],
            vec![publish("partition", b"blob"), remove("partition", b"blob")],
        ] {
            let error = canonicalize_operations(operations).unwrap_err();
            match error {
                Error::Io(error) => assert_eq!(error.kind(), ErrorKind::InvalidInput),
                error => panic!("unexpected error: {error}"),
            }
        }

        assert!(canonicalize_operations(vec![rewind("../invalid", b"blob", 1)]).is_err());
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod coordinator;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use coordinator::{
    Participant, can_supersede_embedded, materialize_embedded, preflight, prepare_embedded,
    recover, recover_embedded, recover_named_embedded, recover_notifying,
    recover_partition_embedded, recover_removal_witnesses, resolve_partition_name,
    supports_speculation,
};
