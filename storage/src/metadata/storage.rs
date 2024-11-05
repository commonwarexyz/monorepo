use super::{Error,Config};
use commonware_runtime::{Blob, Storage};

const BLOB_NAMES: [&str; 2] = ["primary", "secondary"];

pub struct Metadata<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    cursor: usize,
    blobs: [B; 2],
}

impl <B: Blob, E: Storage<B>> Metadata<B,E> {
    pub async init(runtime: E, cfg: Config) -> Result<Self, Error> {
        // Open dedicated blobs
        let primary = runtime.open_blob(&cfg.partition, BLOB_NAMES[0]).await?;
        let secondary = runtime.open_blob(&cfg.partition, BLOB_NAMES[1]).await?;

        // Find latest blob (check which includes a hash of the other)
    }
}
