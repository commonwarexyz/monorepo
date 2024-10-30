use super::{Config, Error};
use commonware_runtime::{Blob, Storage};
use std::{collections::BTreeMap, marker::PhantomData};
use tracing::debug;

pub struct Journal<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    blobs: BTreeMap<u64, B>,

    _phantom_b: PhantomData<B>,
}

impl<B: Blob, E: Storage<B>> Journal<B, E> {
    pub async fn init(mut runtime: E, cfg: Config) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = runtime.scan(&cfg.partition).await.map_err(Error::Runtime)?;
        for name in stored_blobs {
            let blob = runtime
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            let name_bytes = name
                .as_bytes()
                .try_into()
                .map_err(|_| Error::InvalidBlobName(name))?;
            let blob_index = u64::from_be_bytes(name_bytes);
            debug!(blob = blob_index, "loaded blob");
            blobs.insert(blob_index, blob);
        }

        // Create journal instance
        Ok(Self {
            runtime,
            cfg,

            blobs,

            _phantom_b: PhantomData,
        })
    }
}
