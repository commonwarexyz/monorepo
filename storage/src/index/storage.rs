use super::{Config, Error};
use commonware_runtime::{Blob, Error as RError, Storage};
use commonware_utils::hex;
use std::collections::{BTreeMap, HashMap};
use tracing::debug;

pub struct Index<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    oldest_allowed: Option<u64>,

    blobs: BTreeMap<u64, B>,
}

impl<B: Blob, E: Storage<B>> Index<B, E> {
    pub async fn new(runtime: E, cfg: Config) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match runtime.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };
        for name in stored_blobs {
            let blob = runtime
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            let hex_name = hex(&name);
            let section = match name.try_into() {
                Ok(section) => u64::from_be_bytes(section),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, "loaded section");
            blobs.insert(section, blob);
        }
        Ok(Self {
            runtime,
            cfg,
            oldest_allowed: None,
            blobs,
        })
    }
}
