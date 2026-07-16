//! A storage layer that selects between a direct backend and a
//! [`super::volume`] over it, at construction time.
//!
//! Runtimes wire this under their metering/auditing layers so a single
//! compile-time context type can serve both storage models; the choice is a
//! runtime configuration (e.g. `deterministic::Config::with_storage_volume`).

use super::volume;
use crate::{Error, Handle, IoBufs, IoBufsMut};
use std::ops::RangeInclusive;

/// Either a direct backend or a volume over it.
pub enum Storage<S: crate::Storage> {
    Direct(S),
    Volume(volume::Storage<S>),
}

impl<S: crate::Storage> Clone for Storage<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Direct(s) => Self::Direct(s.clone()),
            Self::Volume(v) => Self::Volume(v.clone()),
        }
    }
}

impl<S: crate::Storage> Storage<S> {
    /// The underlying backend (the volume's inner storage in volume mode).
    pub fn inner(&self) -> &S {
        match self {
            Self::Direct(s) => s,
            Self::Volume(v) => v.inner(),
        }
    }

    /// The volume configuration, when in volume mode.
    pub fn volume_config(&self) -> Option<volume::Config> {
        match self {
            Self::Direct(_) => None,
            Self::Volume(v) => Some(v.config().clone()),
        }
    }
}

impl<S: crate::Batchable> crate::Batchable for Storage<S> {
    type Batch = Batch<S>;

    async fn batch(&self) -> Result<Batch<S>, Error> {
        match self {
            Self::Direct(s) => Ok(Batch::Direct(s.batch().await?)),
            Self::Volume(v) => Ok(Batch::Volume(v.batch().await?)),
        }
    }
}

/// A batch from either storage model.
pub enum Batch<S: crate::Batchable> {
    Direct(S::Batch),
    Volume(volume::Batch<S>),
}

/// Unwrap a direct blob handle (batches only stage blobs from their own
/// storage mode).
fn direct_blob<S: crate::Batchable>(blob: &Blob<S>) -> &S::Blob {
    match blob {
        Blob::Direct(b) => b,
        Blob::Volume(_) => panic!("volume blob staged in a direct batch"),
    }
}

/// Unwrap a volume blob handle.
fn volume_blob<S: crate::Batchable>(blob: &Blob<S>) -> &volume::Blob<S> {
    match blob {
        Blob::Volume(b) => b,
        Blob::Direct(_) => panic!("direct blob staged in a volume batch"),
    }
}

impl<S: crate::Batchable> crate::WriteBatch for Batch<S> {
    type Blob = Blob<S>;

    async fn write_at(
        &mut self,
        blob: &Self::Blob,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.write_at(direct_blob(blob), offset, bufs).await,
            Self::Volume(b) => b.write_at(volume_blob(blob), offset, bufs).await,
        }
    }

    async fn resize(&mut self, blob: &Self::Blob, len: u64) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.resize(direct_blob(blob), len).await,
            Self::Volume(b) => b.resize(volume_blob(blob), len).await,
        }
    }

    fn sync(&mut self, blob: &Self::Blob) {
        match self {
            Self::Direct(b) => b.sync(direct_blob(blob)),
            Self::Volume(b) => b.sync(volume_blob(blob)),
        }
    }

    fn remove(&mut self, partition: &str, name: Option<&[u8]>) {
        match self {
            Self::Direct(b) => b.remove(partition, name),
            Self::Volume(b) => b.remove(partition, name),
        }
    }

    async fn apply(self) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.apply().await,
            Self::Volume(b) => b.apply().await,
        }
    }

    async fn apply_sync(self) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.apply_sync().await,
            Self::Volume(b) => b.apply_sync().await,
        }
    }
}

impl<S: crate::Storage> crate::Storage for Storage<S> {
    type Blob = Blob<S>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        match self {
            Self::Direct(s) => {
                let (blob, len, version) = s.open_versioned(partition, name, versions).await?;
                Ok((Blob::Direct(blob), len, version))
            }
            Self::Volume(v) => {
                let (blob, len, version) = v.open_versioned(partition, name, versions).await?;
                Ok((Blob::Volume(blob), len, version))
            }
        }
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        match self {
            Self::Direct(s) => s.remove(partition, name).await,
            Self::Volume(v) => v.remove(partition, name).await,
        }
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        match self {
            Self::Direct(s) => s.scan(partition).await,
            Self::Volume(v) => v.scan(partition).await,
        }
    }
}

/// A blob from either storage model.
pub enum Blob<S: crate::Storage> {
    Direct(S::Blob),
    Volume(volume::Blob<S>),
}

impl<S: crate::Storage> Clone for Blob<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Direct(b) => Self::Direct(b.clone()),
            Self::Volume(b) => Self::Volume(b.clone()),
        }
    }
}

impl<S: crate::Storage> crate::Blob for Blob<S> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        match self {
            Self::Direct(b) => b.read_at(offset, len).await,
            Self::Volume(b) => b.read_at(offset, len).await,
        }
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        match self {
            Self::Direct(b) => b.read_at_buf(offset, len, bufs).await,
            Self::Volume(b) => b.read_at_buf(offset, len, bufs).await,
        }
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.write_at(offset, bufs).await,
            Self::Volume(b) => b.write_at(offset, bufs).await,
        }
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.write_at_sync(offset, bufs).await,
            Self::Volume(b) => b.write_at_sync(offset, bufs).await,
        }
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.resize(len).await,
            Self::Volume(b) => b.resize(len).await,
        }
    }

    async fn sync(&self) -> Result<(), Error> {
        match self {
            Self::Direct(b) => b.sync().await,
            Self::Volume(b) => b.sync().await,
        }
    }

    async fn start_sync(&self) -> Handle<()> {
        match self {
            Self::Direct(b) => b.start_sync().await,
            Self::Volume(b) => b.start_sync().await,
        }
    }
}
