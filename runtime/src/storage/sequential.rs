//! The sequential [`crate::WriteBatch`] fallback for per-blob backends.
//!
//! Stages operations in memory and replays them IN ORDER at apply — exactly
//! the behavior of issuing them unbatched. There is no cross-blob
//! atomicity: a crash mid-apply can persist a prefix of the staged
//! operations, which is the crash model per-blob backends already have.
//! Structures that rely on batch atomicity for crash safety are only
//! crash-safe on an atomic backend (the volume); this fallback keeps them
//! on one code path and preserves their pre-batch sequential behavior
//! everywhere else.

use crate::{Blob as _, Error, IoBufs, Storage};

/// One staged operation.
enum Op<B> {
    Write(B, u64, IoBufs),
    Resize(B, u64),
    /// Durability-only membership: the blob is synced at `apply_sync`.
    Sync(B),
    Remove(String, Option<Vec<u8>>),
}

/// A sequential batch over any [`Storage`] (see the module docs).
pub struct Batch<S: Storage> {
    storage: S,
    ops: Vec<Op<S::Blob>>,
    removals: usize,
}

impl<S: Storage> Batch<S> {
    /// Start an empty batch over `storage`.
    pub const fn new(storage: S) -> Self {
        Self {
            storage,
            ops: Vec::new(),
            removals: 0,
        }
    }

    async fn apply_inner(mut self, sync: bool) -> Result<(), Error> {
        assert!(
            self.removals == 0 || sync,
            "staged removals require apply_sync"
        );
        // Replay writes and resizes in staging order.
        for op in &mut self.ops {
            match op {
                Op::Write(blob, offset, bufs) => {
                    blob.write_at(*offset, std::mem::take(bufs)).await?;
                }
                Op::Resize(blob, len) => blob.resize(*len).await?,
                Op::Sync(_) | Op::Remove(..) => {}
            }
        }
        if !sync {
            return Ok(());
        }
        // Durability pass: sync every staged blob (in staging order; a blob
        // staged more than once syncs more than once), then removals (which
        // are durable by the [`Storage::remove`] contract).
        for op in &self.ops {
            match op {
                Op::Write(blob, ..) | Op::Resize(blob, _) | Op::Sync(blob) => {
                    blob.sync().await?;
                }
                Op::Remove(..) => {}
            }
        }
        for op in self.ops {
            if let Op::Remove(partition, name) = op {
                self.storage.remove(&partition, name.as_deref()).await?;
            }
        }
        Ok(())
    }
}

impl<S: Storage + Clone> crate::WriteBatch for Batch<S> {
    type Blob = S::Blob;

    async fn write_at(
        &mut self,
        blob: &Self::Blob,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.ops.push(Op::Write(blob.clone(), offset, bufs.into()));
        Ok(())
    }

    async fn resize(&mut self, blob: &Self::Blob, len: u64) -> Result<(), Error> {
        self.ops.push(Op::Resize(blob.clone(), len));
        Ok(())
    }

    fn sync(&mut self, blob: &Self::Blob) {
        self.ops.push(Op::Sync(blob.clone()));
    }

    fn remove(&mut self, partition: &str, name: Option<&[u8]>) {
        self.removals += 1;
        self.ops
            .push(Op::Remove(partition.into(), name.map(<[u8]>::to_vec)));
    }

    async fn apply(self) -> Result<(), Error> {
        self.apply_inner(false).await
    }

    async fn apply_sync(self) -> Result<(), Error> {
        self.apply_inner(true).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        storage::memory, telemetry::metrics::Registry, Batchable as _, Blob as _, BufferPool,
        BufferPoolConfig, Storage as _, WriteBatch as _,
    };

    fn test_storage() -> memory::Storage {
        let mut registry = Registry::default();
        memory::Storage::new(BufferPool::new(
            BufferPoolConfig::for_storage(),
            &mut registry,
        ))
    }

    /// Staged operations are invisible until apply, then replay in order;
    /// staged removals land at apply_sync.
    #[tokio::test]
    async fn test_sequential_batch_applies_in_order() {
        let storage = test_storage();
        let (a, _) = storage.open("p", b"a").await.unwrap();
        let (b, _) = storage.open("p", b"b").await.unwrap();
        let (dead, _) = storage.open("p", b"dead").await.unwrap();
        dead.write_at(0, b"x".as_slice()).await.unwrap();

        let mut batch = storage.batch().await.unwrap();
        batch.write_at(&a, 0, b"hello".as_slice()).await.unwrap();
        batch.write_at(&b, 0, b"world!".as_slice()).await.unwrap();
        // A later staged resize wins over the earlier write (in-order replay).
        batch.resize(&b, 5).await.unwrap();
        batch.remove("p", Some(b"dead"));

        // Nothing is visible before apply.
        let (_, len) = storage.open("p", b"a").await.unwrap();
        assert_eq!(len, 0);

        batch.apply_sync().await.unwrap();
        let (a, len) = storage.open("p", b"a").await.unwrap();
        assert_eq!(len, 5);
        let got = a.read_at(0, 5).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), b"hello");
        let (_, len) = storage.open("p", b"b").await.unwrap();
        assert_eq!(len, 5);
        assert!(!storage.scan("p").await.unwrap().contains(&b"dead".to_vec()));
    }

    /// Removals require apply_sync.
    #[tokio::test]
    #[should_panic(expected = "staged removals require apply_sync")]
    async fn test_sequential_batch_apply_rejects_removals() {
        let storage = test_storage();
        let mut batch = storage.batch().await.unwrap();
        batch.remove("p", None);
        let _ = batch.apply().await;
    }
}
