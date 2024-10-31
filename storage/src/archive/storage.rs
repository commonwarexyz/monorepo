use super::{Config, Error};
use crate::journal::{Config as JConfig, Journal};
use bytes::{Buf, Bytes};
use commonware_runtime::{Blob, Storage};
use futures::{pin_mut, StreamExt};
use std::collections::{hash_map::Entry, HashMap};
use tracing::debug;

struct Index {
    section: u64,
    offset: usize,
    next: Option<Box<Index>>,
}

pub struct Archive<B: Blob, E: Storage<B>> {
    cfg: Config,

    journal: Journal<B, E>,

    keys: HashMap<Vec<u8>, Index>,
}

impl<B: Blob, E: Storage<B>> Archive<B, E> {
    fn extract_key(mut data: Bytes) -> Result<Vec<u8>, Error> {
        if data.remaining() == 0 {
            return Err(Error::RecordCorrupted);
        }
        let key_len = data.get_u8() as usize;
        if data.remaining() < key_len {
            return Err(Error::RecordCorrupted);
        }
        let key = data.copy_to_bytes(key_len);
        Ok(key.to_vec())
    }

    pub async fn init(runtime: E, cfg: Config) -> Result<Self, Error> {
        // Initialize journal
        let mut journal = Journal::init(
            runtime,
            JConfig {
                partition: cfg.partition.clone(),
            },
        )
        .await
        .map_err(Error::Journal)?;

        // Initialize keys and run corruption check
        let mut keys = HashMap::new();
        let mut overlaps: u128 = 0;
        {
            let stream = journal.replay();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (index, offset, data) = result?;
                let key = Self::extract_key(data)?;

                // Create index key
                let key = if key.len() > cfg.index_key_len {
                    key[..cfg.index_key_len].to_vec()
                } else {
                    key
                };

                // Store index
                match keys.entry(key) {
                    Entry::Occupied(entry) => {
                        let entry: &mut Index = entry.into_mut();
                        entry.next = Some(Box::new(Index {
                            section: index,
                            offset,
                            next: entry.next.take(),
                        }));
                        overlaps += 1;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(Index {
                            section: index,
                            offset,
                            next: None,
                        });
                    }
                };
            }
        }
        debug!(keys = keys.len(), overlaps, "archive initialized");

        // Return populated archive
        Ok(Self { cfg, journal, keys })
    }
}
