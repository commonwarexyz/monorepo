//! The namespace one WAL owns: partitions and blob rows, as a fold over records.
//!
//! [Catalog::apply] is the only way state changes, at replay and at runtime alike, so
//! there is exactly one state-mutation code path to reason about. A checkpoint
//! snapshot is nothing but [Catalog::snapshot]: the whole catalog re-stated as records
//! at the head of a fresh extent.

use super::format::{Kind, Record};
use std::collections::{BTreeMap, HashMap};

/// One blob's row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Row {
    /// Never reused: minted monotonically across the WAL's whole life, so a stale
    /// handle can never alias a recreated name.
    pub id: u64,
    pub kind: Kind,
    pub version: u16,
}

/// The partitions and blobs of one family.
#[derive(Debug, Default)]
pub(super) struct Catalog {
    /// Partition -> blob name -> row. A partition with no blobs persists (matching
    /// per-file backends, where an emptied directory persists).
    partitions: BTreeMap<String, BTreeMap<Vec<u8>, Row>>,
    /// Reverse index for deletes, which address blobs by id.
    ids: HashMap<u64, (String, Vec<u8>)>,
    /// Id minting floor.
    next_blob_id: u64,
}

impl Catalog {
    /// Starts from the id floor a root carries.
    pub fn new(next_blob_id: u64) -> Self {
        Self {
            next_blob_id,
            ..Self::default()
        }
    }

    /// Applies one record. An error means the record stream is corrupt: the writer
    /// validates before journaling, so replay can never legitimately see these.
    pub fn apply(&mut self, record: &Record) -> Result<(), String> {
        match record {
            Record::Create {
                id,
                kind,
                version,
                partition,
                name,
            } => {
                let blobs = self.partitions.entry(partition.clone()).or_default();
                if blobs.contains_key(name) {
                    return Err("blob already exists".into());
                }
                if self.ids.contains_key(id) {
                    return Err("blob id already in use".into());
                }
                blobs.insert(
                    name.clone(),
                    Row {
                        id: *id,
                        kind: *kind,
                        version: *version,
                    },
                );
                self.ids.insert(*id, (partition.clone(), name.clone()));
                self.next_blob_id = self.next_blob_id.max(id + 1);
                Ok(())
            }
            // Deleting something already gone is a no-op, not corruption: a checkpoint
            // may snapshot state that already excludes the row while the delete record
            // lands just after it.
            Record::Delete { id } => {
                if let Some((partition, name)) = self.ids.remove(id) {
                    self.partitions
                        .get_mut(&partition)
                        .expect("id index points at partition")
                        .remove(&name);
                }
                Ok(())
            }
            Record::Partition { partition } => {
                self.partitions.entry(partition.clone()).or_default();
                Ok(())
            }
            Record::DeletePartition { partition } => {
                if let Some(blobs) = self.partitions.remove(partition) {
                    for row in blobs.values() {
                        self.ids.remove(&row.id);
                    }
                }
                Ok(())
            }
        }
    }

    /// Mints the next blob id.
    pub const fn mint_id(&mut self) -> u64 {
        let id = self.next_blob_id;
        self.next_blob_id += 1;
        id
    }

    /// The id floor to publish in the next root.
    pub const fn next_blob_id(&self) -> u64 {
        self.next_blob_id
    }

    /// The whole catalog as records: replaying these into an empty catalog with the
    /// same id floor reproduces it exactly.
    pub fn snapshot(&self) -> Vec<Record> {
        let mut records = Vec::new();
        for (partition, blobs) in &self.partitions {
            if blobs.is_empty() {
                records.push(Record::Partition {
                    partition: partition.clone(),
                });
            }
            for (name, row) in blobs {
                records.push(Record::Create {
                    id: row.id,
                    kind: row.kind,
                    version: row.version,
                    partition: partition.clone(),
                    name: name.clone(),
                });
            }
        }
        records
    }

    /// Looks up one blob.
    pub fn get(&self, partition: &str, name: &[u8]) -> Option<&Row> {
        self.partitions.get(partition)?.get(name)
    }

    /// Lists a partition's blob names, or None if the partition does not exist.
    pub fn scan(&self, partition: &str) -> Option<Vec<Vec<u8>>> {
        Some(self.partitions.get(partition)?.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(id: u64, partition: &str, name: &[u8]) -> Record {
        Record::Create {
            id,
            kind: Kind::Ordinary,
            version: 1,
            partition: partition.into(),
            name: name.to_vec(),
        }
    }

    #[test]
    fn create_delete_and_partition_persistence() {
        let mut catalog = Catalog::new(0);
        catalog.apply(&create(0, "p", b"a")).unwrap();
        catalog.apply(&create(1, "p", b"b")).unwrap();
        assert_eq!(catalog.scan("p").unwrap().len(), 2);

        catalog.apply(&Record::Delete { id: 0 }).unwrap();
        assert_eq!(catalog.scan("p").unwrap(), vec![b"b".to_vec()]);

        // Emptying a partition keeps its row.
        catalog.apply(&Record::Delete { id: 1 }).unwrap();
        assert_eq!(catalog.scan("p").unwrap(), Vec::<Vec<u8>>::new());
        assert!(catalog.scan("missing").is_none());

        catalog
            .apply(&Record::DeletePartition {
                partition: "p".into(),
            })
            .unwrap();
        assert!(catalog.scan("p").is_none());
    }

    #[test]
    fn duplicate_create_is_corrupt() {
        let mut catalog = Catalog::new(0);
        catalog.apply(&create(0, "p", b"a")).unwrap();
        assert!(catalog.apply(&create(1, "p", b"a")).is_err()); // same name
        assert!(catalog.apply(&create(0, "p", b"z")).is_err()); // same id
    }

    #[test]
    fn deletes_of_missing_state_are_no_ops() {
        let mut catalog = Catalog::new(0);
        catalog.apply(&Record::Delete { id: 5 }).unwrap();
        catalog
            .apply(&Record::DeletePartition {
                partition: "p".into(),
            })
            .unwrap();
    }

    #[test]
    fn id_minting_never_reuses() {
        let mut catalog = Catalog::new(0);
        assert_eq!(catalog.mint_id(), 0);
        catalog.apply(&create(0, "p", b"a")).unwrap();
        catalog.apply(&Record::Delete { id: 0 }).unwrap();
        // The name is free again; the id is not.
        assert_eq!(catalog.mint_id(), 1);
        // Replaying a foreign-minted higher id advances the floor past it.
        catalog.apply(&create(7, "p", b"b")).unwrap();
        assert_eq!(catalog.mint_id(), 8);
    }

    #[test]
    fn snapshot_round_trips() {
        let mut catalog = Catalog::new(0);
        for (id, (partition, name)) in [
            ("orders", b"a".as_slice()),
            ("orders", b"b"),
            ("index", b"x"),
        ]
        .into_iter()
        .enumerate()
        {
            catalog.apply(&create(id as u64, partition, name)).unwrap();
        }
        // An emptied partition must survive the round trip too.
        catalog.apply(&create(3, "emptied", b"gone")).unwrap();
        catalog.apply(&Record::Delete { id: 3 }).unwrap();

        let mut restored = Catalog::new(catalog.next_blob_id());
        for record in catalog.snapshot() {
            restored.apply(&record).unwrap();
        }
        assert_eq!(restored.snapshot(), catalog.snapshot());
        assert_eq!(restored.next_blob_id(), catalog.next_blob_id());
        assert_eq!(restored.scan("emptied").unwrap(), Vec::<Vec<u8>>::new());
    }
}
