//! Validation and canonicalization of exact storage namespace removal sets.
//!
//! Duplicate targets are removed, and a partition target subsumes every blob target in that
//! partition.

use crate::{Error, RemoveTarget};
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

enum PartitionTargets {
    Blobs(BTreeSet<Vec<u8>>),
    Partition,
}

/// Validate and reduce a batch to its exact namespace set.
pub(crate) fn canonicalize(targets: Vec<RemoveTarget>) -> Result<Vec<RemoveTarget>, Error> {
    let mut partitions = BTreeMap::<String, PartitionTargets>::new();
    for target in targets {
        match target {
            RemoveTarget::Blob { partition, name } => {
                super::validate_partition_name(&partition)?;
                match partitions.entry(partition) {
                    Entry::Vacant(entry) => {
                        entry.insert(PartitionTargets::Blobs(BTreeSet::from([name])));
                    }
                    Entry::Occupied(mut entry) => {
                        if let PartitionTargets::Blobs(names) = entry.get_mut() {
                            names.insert(name);
                        }
                    }
                }
            }
            RemoveTarget::Partition(partition) => {
                super::validate_partition_name(&partition)?;
                partitions.insert(partition, PartitionTargets::Partition);
            }
        }
    }

    let mut canonical = Vec::new();
    for (partition, targets) in partitions {
        match targets {
            PartitionTargets::Partition => canonical.push(RemoveTarget::Partition(partition)),
            PartitionTargets::Blobs(names) => {
                canonical.extend(names.into_iter().map(|name| RemoveTarget::Blob {
                    partition: partition.clone(),
                    name,
                }));
            }
        }
    }
    Ok(canonical)
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn is_canonical(targets: &[RemoveTarget]) -> Result<bool, Error> {
    let mut previous: Option<&RemoveTarget> = None;
    for target in targets {
        let partition = match target {
            RemoveTarget::Blob { partition, .. } | RemoveTarget::Partition(partition) => partition,
        };
        super::validate_partition_name(partition)?;

        if let Some(previous) = previous {
            let previous_partition = match previous {
                RemoveTarget::Blob { partition, .. } | RemoveTarget::Partition(partition) => {
                    partition
                }
            };
            match previous_partition.cmp(partition) {
                std::cmp::Ordering::Greater => return Ok(false),
                std::cmp::Ordering::Equal => match (previous, target) {
                    (
                        RemoveTarget::Blob {
                            name: previous_name,
                            ..
                        },
                        RemoveTarget::Blob { name, .. },
                    ) if previous_name < name => {}
                    _ => return Ok(false),
                },
                std::cmp::Ordering::Less => {}
            }
        }
        previous = Some(target);
    }
    Ok(true)
}
